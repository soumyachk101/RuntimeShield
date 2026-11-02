// The three example profiles that ship in examples/ (repository-development,
// restricted, inspect-only). They are the policy editor's starting templates,
// labelled "sample" wherever they appear in the UI (spec §12 anti-pattern:
// no fabricated data without a sample label). Kept in the console so the
// editor works before a single policy row exists in the control plane.

import type { PolicyDocument } from "./types";

export interface SampleProfile {
  name: string; // "sample:repository-development"
  source: string;
  description: string;
  document: PolicyDocument;
}

export const SAMPLE_PROFILES: SampleProfile[] = [
  {
    name: "sample:repository-development",
    source: "examples/policy-repository-development.json",
    description: "Build, test and inspect a repository; block secrets and unlisted network.",
    document: {
      version: 1,
      policy_version: "0.1.0",
      profile: "repository-development",
      description: "Build, test and inspect a repository; block secrets and unlisted network.",
      default_action: "deny",
      filesystem: {
        workspace: { access: "read-write", roots: ["~/repo"] },
        temp: { access: "read-write" },
        sensitive_paths: ["~/.ssh", "~/.aws", "~/.config/gcloud", "~/.gnupg"],
      },
      network: {
        default: "deny",
        allow: [
          { host: "registry.npmjs.org", ports: [443] },
          { host: "*.crates.io", ports: [443] },
          { host: "pypi.org", ports: [443] },
        ],
      },
      process: {
        allow: [
          { executable: "git", actions: ["status", "diff", "log", "add", "commit"] },
          { executable: "npm", actions: ["install", "test", "run"] },
          { executable: "cargo", actions: ["build", "test", "check"] },
        ],
        require_approval: [
          { executable: "sudo" },
          { executable: "curl", note: "arbitrary outbound transfer — needs approval" },
        ],
        deny: [{ executable: "rm", actions: ["-rf", "-fr", "-rf"] }],
      },
      secrets: {
        deny_env_keys: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY"],
      },
    },
  },
  {
    name: "sample:restricted",
    source: "examples/policy-restricted.json",
    description: "Minimal-privilege CI profile: read-only workspace, no network.",
    document: {
      version: 1,
      policy_version: "0.1.0",
      profile: "restricted",
      description: "Minimal-privilege CI profile: read-only workspace, no network.",
      default_action: "deny",
      filesystem: {
        workspace: { access: "read-only", roots: ["~/repo"] },
        temp: { access: "deny" },
        sensitive_paths: ["~/.ssh", "~/.aws", "~/.config/gcloud"],
      },
      network: { default: "deny" },
      process: {
        allow: [{ executable: "git", actions: ["status", "diff", "log"] }],
        require_approval: [{ executable: "cargo" }],
        deny: [
          { executable: "sudo" },
          { executable: "curl" },
          { executable: "wget" },
        ],
      },
      secrets: {
        deny_env_keys: ["AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "OPENAI_API_KEY", "DATABASE_URL"],
      },
    },
  },
  {
    name: "sample:inspect-only",
    source: "examples/policy-inspect-only.json",
    description: "Observation profile: nothing is blocked, everything is recorded (audit_only).",
    document: {
      version: 1,
      policy_version: "0.1.0",
      profile: "inspect-only",
      description: "Observation profile: nothing is blocked, everything is recorded (audit_only).",
      default_action: "audit_only",
      filesystem: {
        workspace: { access: "read-only", roots: ["~/repo"] },
      },
      network: { default: "allow" },
      process: {},
      secrets: { deny_env_keys: ["AWS_SECRET_ACCESS_KEY"] },
    },
  },
];

export function sampleByProfileName(profile: string | undefined): SampleProfile | undefined {
  if (!profile) return undefined;
  return SAMPLE_PROFILES.find((s) => s.document.profile === profile);
}
