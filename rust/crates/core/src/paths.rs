//! Path canonicalisation for filesystem policy.
//!
//! Every filesystem decision runs on a *canonical, absolute* path:
//!
//! 1. expand a leading `~` against the invoking user's home directory,
//! 2. resolve relative paths against the request's working directory,
//! 3. resolve symlinks via [`std::fs::canonicalize`],
//! 4. for paths that do not exist yet (e.g. a write target), walk the
//!    deepest existing ancestor and resolve symlinks there — a symlink
//!    escape that only appears in a non-existent tail cannot be detected
//!    any other way, so the ancestor walk is conservative: the final
//!    non-existing segments are appended without symlink resolution and
//!    `resolved_by_ancestor` reports that.
//!
//! This is a *decision-time* guard: it tells the agent and the audit
//! journal which real location an access would hit. It is not a kernel
//! boundary; see docs/ENFORCEMENT-LIMITS.md for what is guaranteed
//! versus advisory.

use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    /// The absolute, symlink-resolved path (or ancestor-resolved best
    /// effort when the tail does not exist).
    pub path: PathBuf,
    /// `true` when the full path exists and was canonicalised in one step.
    pub fully_resolved: bool,
}

fn home_dir() -> std::result::Result<PathBuf, Error> {
    #[cfg(unix)]
    let var = "HOME";
    #[cfg(windows)]
    let var = "USERPROFILE";
    let home = std::env::var(var)
        .map(PathBuf::from)
        .map_err(|_| {
            Error::PathError("cannot determine home directory; use absolute paths".into())
        })?;
    if !home.is_absolute() {
        return Err(Error::PathError(
            "home directory env var is not an absolute path; use absolute paths".into(),
        ));
    }
    Ok(home)
}

pub fn expand_tilde(path: &str, home: &Path) -> String {
    if path == "~" {
        return home.to_string_lossy().into_owned();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return home.join(rest).to_string_lossy().into_owned();
    }
    path.to_string()
}

/// Expand `~` and resolve `raw` (absolute or relative to `cwd`).
pub fn resolve(raw: &str, cwd: &Path, home: &Path) -> Result<ResolvedPath> {
    if raw.trim().is_empty() {
        return Err(Error::PathError("empty path".into()));
    }
    let raw = raw.trim();
    let expanded = expand_tilde(raw, home);
    let candidate = if Path::new(&expanded).is_absolute() {
        PathBuf::from(&expanded)
    } else {
        cwd.join(&expanded)
    };
    // Collapse `.` and lexical `..` before touching the filesystem so a
    // `../../etc/passwd` request becomes `/etc/passwd` even in lexicon.
    let candidate = collapse_lexically(&candidate);
    if !candidate.is_absolute() {
        return Err(Error::PathError(
            "path does not resolve to an absolute location".into(),
        ));
    }
    canonical_or_ancestor(&candidate)
}

/// Lexical `.`/`..` folding that never escapes the root.
pub fn collapse_lexically(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::RootDir => out.push(Component::RootDir),
            Component::CurDir => {}
            Component::ParentDir => {
                // `..` at the root is a no-op (POSIX); on Windows the
                // logical drive root behaves the same way.
                if out.components().count() > 1 {
                    out.pop();
                }
            }
            c => out.push(c),
        }
    }
    out
}

fn canonical_or_ancestor(p: &Path) -> Result<ResolvedPath> {
    if let Ok(c) = std::fs::canonicalize(p) {
        return Ok(ResolvedPath {
            path: c,
            fully_resolved: true,
        });
    }
    // Walk up to the deepest existing ancestor and canonicalise there.
    let mut ancestor = Some(p);
    while let Some(a) = ancestor {
        if a.is_absolute() && a.exists() {
            let canon = std::fs::canonicalize(a)
                .map_err(|e| Error::PathError(format!("canonicalize({a:?}): {e}")))?;
            // Re-attach the non-existing suffix on top of the resolved
            // ancestor: the trailing components of `p` that extend past `a`.
            let p_comps: Vec<_> = p.components().collect();
            let a_comps: usize = a.components().count();
            let n_suffix = p_comps
                .len()
                .saturating_sub(a_comps);
            let mut acc = PathBuf::new();
            if n_suffix > 0 {
                for c in p_comps.iter().rev().take(n_suffix).rev() {
                    match c {
                        Component::Normal(s) => {
                            acc.push(s);
                        }
                        other => {
                            return Err(Error::PathError(format!(
                                "cannot re-attach non-ordinary component {other:?} on non-existing tail"
                            )));
                        }
                    }
                }
            }
            let resolved = if acc.as_os_str().is_empty() {
                canon
            } else {
                canon.join(&acc)
            };
            return Ok(ResolvedPath {
                path: resolved,
                fully_resolved: false,
            });
        }
        ancestor = a.parent();
    }
    Err(Error::PathError(
        "path has no existing ancestor; cannot determine canonical location".into(),
    ))
}

/// Prefix containment check on canonical paths. `path` is "inside"
/// `root` when equal to root or with root as a strict *component* prefix
/// (so `/repo` is not inside `/repo-other`).
pub fn inside(canonical_path: &Path, canonical_root: &Path) -> bool {
    canonical_path.starts_with(canonical_root)
}

/// Glob used by `deny_paths` / `allow_paths` rules, matched on the
/// canonical path: `*` matches within a path segment, `?` one character
/// within a segment, `**` (a whole segment) matches zero or more
/// segments. Absolute patterns must include the leading `/`.
pub fn glob_match(pattern: &str, target: &str) -> bool {
    let p: Vec<&str> = pattern
        .split('/')
        .filter(|s| !s.is_empty() || *s == "**")
        .collect();
    let t: Vec<&str> = target.split('/').filter(|s| !s.is_empty()).collect();
    // A leading "/" in the pattern pins the target to be absolute,
    // which after filtering is expressed by an empty pattern head.
    let anchored = pattern.starts_with('/');
    match_segments(&p, 0, &t, 0)
        && (!anchored || target.starts_with('/'))
}

/// Segment-wise glob: `*`/`?` match within a segment, a standalone `**`
/// segment matches zero or more whole segments.
fn match_segments(p: &[&str], pi: usize, t: &[&str], ti: usize) -> bool {
    if pi == p.len() {
        return ti == t.len();
    }
    if p[pi] == "**" {
        // Skip zero segments here, or skip one and keep trying.
        return match_segments(p, pi + 1, t, ti)
            || (ti < t.len() && match_segments(p, pi, t, ti + 1));
    }
    if ti == t.len() {
        return false;
    }
    if !seg_match(p[pi], t[ti]) {
        return false;
    }
    match_segments(p, pi + 1, t, ti + 1)
}

fn seg_match(pat: &str, seg: &str) -> bool {
    if !pat.contains('*') {
        return pat == seg;
    }
    let parts: Vec<&str> = pat.split('*').collect();
    let mut cursor = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match seg[cursor..].find(part) {
            Some(off) => {
                cursor += off + part.len();
                if i + 1 == parts.len() {
                    return true;
                }
            }
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn lexical_collapse_and_traversal() {
        // `.` is dropped; `..` pops the previous component (bounded at root).
        let p = collapse_lexically(&PathBuf::from("/work/repo/.//src/../docs"));
        assert_eq!(p, PathBuf::from("/work/repo/docs"));
        let p = collapse_lexically(&PathBuf::from("/work/repo/src/../../docs"));
        assert_eq!(p, PathBuf::from("/work/docs"));
        let p = collapse_lexically(&PathBuf::from("/a/b/../../../etc/passwd"));
        assert_eq!(p, PathBuf::from("/etc/passwd"));
        let p = collapse_lexically(&PathBuf::from("/.."));
        assert_eq!(p, PathBuf::from("/"));
    }

    #[test]
    fn inside_requires_component_boundary() {
        assert!(inside(Path::new("/work/repo/src"), Path::new("/work/repo")));
        assert!(!inside(Path::new("/work/repo-other"), Path::new("/work/repo")));
        assert!(inside(Path::new("/work/repo"), Path::new("/work/repo")));
    }

    #[test]
    fn tilde_expansion() {
        let home = PathBuf::from("/Users/tester");
        assert_eq!(expand_tilde("~/x", &home), "/Users/tester/x");
        assert_eq!(expand_tilde("~", &home), "/Users/tester");
        assert_eq!(expand_tilde("/abs", &home), "/abs");
    }

    #[test]
    fn globs() {
        assert!(glob_match("**", "/anything"));
        assert!(glob_match("*.env", "a.env"));
        assert!(!glob_match("*.env", "dir/a.env"));
        assert!(glob_match("secrets/**", "secrets/deep/key"));
        // a `**` segment matches zero or more segments, so the
        // base directory is included
        assert!(glob_match("secrets/**", "secrets"));
        assert!(glob_match("/tmp/run*sock", "/tmp/runtime-sock"));
        assert!(!glob_match("/tmp/run*sock", "tmp/runtime-sock"));
        assert!(glob_match("/home/x/**/.env", "/home/x/a/b/.env"));
    }
}
