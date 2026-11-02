// Line-based diff of two policy JSON documents for the version diff view.
// Pretty-prints each side, runs a classic LCS line diff, then trims
// unchanged context around the change runs. Display-only — the diff is
// never a security decision.

export type DiffRow =
  | { kind: "ctx"; left: string; right: string }
  | { kind: "add"; left: string; right: string }
  | { kind: "del"; left: string; right: string };

export interface DiffResult {
  rows: DiffRow[];
  added: number;
  removed: number;
  changed: number;
}

export function diffDocuments(before: unknown, after: unknown): DiffResult {
  const a = pretty(before).split("\n");
  const b = pretty(after).split("\n");
  const n = a.length;
  const m = b.length;

  // LCS length table.
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n; i > 0; i--) {
    const row = dp[i]!;
    const up = dp[i - 1]!;
    for (let j = m; j > 0; j--) {
      row[j] = a[i - 1] === b[j - 1] ? up[j - 1]! + 1 : Math.max(up[j]!, row[j - 1]!);
    }
  }

  // Back-track into a flat opcode list: equal | ins | del.
  type Op = { kind: "eq" | "ins" | "del"; ai: number; bj: number };
  const ops: Op[] = [];
  let i = n;
  let j = m;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) {
      ops.push({ kind: "eq", ai: i - 1, bj: j - 1 });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i]![j - 1]! >= dp[i - 1]![j]!)) {
      ops.push({ kind: "ins", ai: i, bj: j - 1 });
      j--;
    } else {
      ops.push({ kind: "del", ai: i - 1, bj: j });
      i--;
    }
  }
  ops.reverse();

  // Flat rows: unchanged lines stay in both columns so readers can follow
  // the JSON structure across the change. Policy documents are short, so no
  // context trimming is needed.
  const rows: DiffRow[] = [];
  let added = 0;
  let removed = 0;

  for (const op of ops) {
    if (op.kind === "ins") {
      rows.push({ kind: "add", left: "", right: b[op.bj] ?? "" });
      added++;
    } else if (op.kind === "del") {
      rows.push({ kind: "del", left: a[op.ai] ?? "", right: "" });
      removed++;
    } else {
      rows.push({ kind: "ctx", left: a[op.ai] ?? "", right: b[op.bj] ?? "" });
    }
  }

  return { rows, added, removed, changed: added + removed };
}

function pretty(v: unknown): string {
  try {
    const o = typeof v === "string" ? JSON.parse(v) : v;
    return JSON.stringify(o, null, 2) ?? "";
  } catch {
    return String(v ?? "");
  }
}
