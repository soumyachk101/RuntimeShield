// Two-column diff view for two policy documents (version vs version, or a
// draft vs the version it was based on). Uses the LCS diff in lib/diff.ts
// and the .rs-diff styles in global.css: additions green, deletions red,
// unchanged lines dimmed.
import { useMemo } from "react";
import { diffDocuments } from "../lib/diff";
import type { DiffResult } from "../lib/diff";

export function DiffView({
  before,
  after,
  beforeLabel = "before",
  afterLabel = "after",
}: {
  before: unknown;
  after: unknown;
  beforeLabel?: string;
  afterLabel?: string;
}) {
  const result: DiffResult = useMemo(() => diffDocuments(before, after), [before, after]);

  return (
    <div>
      <div className="rs-row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <span className="rs-mono" style={{ fontSize: "0.75rem", color: "var(--rs-text-3)" }}>
          <span style={{ color: "var(--rs-success)" }}>+{result.added}</span>{" "}
          <span style={{ color: "var(--rs-danger)" }}>−{result.removed}</span>
          <span> · {result.changed} changed line(s)</span>
        </span>
        <span className="rs-mono" style={{ fontSize: "0.7rem", color: "var(--rs-text-3)" }}>
          {beforeLabel} → {afterLabel}
        </span>
      </div>
      {result.changed === 0 ? (
        <div className="rs-state" style={{ padding: "24px 16px" }}>
          <h3>No differences</h3>
          <p>Both documents are identical.</p>
        </div>
      ) : (
        <div className="rs-diff" aria-label={`diff between ${beforeLabel} and ${afterLabel}`}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={{ textAlign: "left", padding: "4px 10px", color: "var(--rs-text-3)" }}>
                  {beforeLabel}
                </th>
                <th style={{ textAlign: "left", padding: "4px 10px", color: "var(--rs-text-3)" }}>
                  {afterLabel}
                </th>
              </tr>
            </thead>
            <tbody>
              {result.rows.map((r, i) => (
                <tr key={i}>
                  <Td kind={r.kind} side="left" text={r.left} />
                  <Td kind={r.kind} side="right" text={r.right} />
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Td({
  kind,
  side,
  text,
}: {
  kind: "add" | "del" | "ctx";
  side: "left" | "right";
  text: string;
}) {
  // A changed row colours the column being edited; the other column is the
  // dimmed counterpart (blank for pure adds/dels).
  const colorKind =
    kind === "add" ? (side === "right" ? "add" : "ctx") : kind === "del" ? (side === "left" ? "del" : "ctx") : "ctx";
  const blank = (kind === "add" && side === "left") || (kind === "del" && side === "right");
  return (
    <td className={`rs-diff ${colorKind}`} style={{ padding: "0 10px" }}>
      {blank ? "" : text || " "}
    </td>
  );
}
