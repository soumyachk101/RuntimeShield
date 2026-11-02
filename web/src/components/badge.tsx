// Semantic badges used across the console (decision kinds, policy status,
// approval status). The class names come from global.css.
import type { ReactNode } from "react";

export function Badge({ variant, label, dot = true }: { variant: string; label: string; dot?: boolean }) {
  return (
    <span className={`rs-badge rs-badge--${variant}`}>
      {dot ? <span className="dot" aria-hidden="true" /> : null}
      {label}
    </span>
  );
}

// Maps a decision / status string to a badge variant + readable label.
const DECISION_VARIANT: Record<string, string> = {
  allow: "allow",
  deny: "deny",
  require_approval: "require_approval",
  audit_only: "audit_only",
  pending: "pending",
  approved: "approved",
  denied: "denied",
  expired: "neutral",
  draft: "draft",
  published: "success",
  rolled_back: "neutral",
};

export function DecisionBadge({ value }: { value: string }) {
  const variant = DECISION_VARIANT[value] ?? "neutral";
  const pretty =
    value === "require_approval" ? "approval required" : value === "audit_only" ? "audit only" : value;
  return (
    <Badge variant={variant} label={pretty} />
  );
}

export function StatusBadge({ value }: { value: string }) {
  return <Badge variant={DECISION_VARIANT[value] ?? "neutral"} label={value} dot={false} />;
}

export function Toast({ tone, children }: { tone: "ok" | "err"; children: ReactNode }) {
  return <div className={`rs-toast ${tone === "ok" ? "rs-toast--ok" : "rs-toast--err"}`} role="status">{children}</div>;
}
