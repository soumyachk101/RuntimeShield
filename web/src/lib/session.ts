// Operator session for the reference build. The control plane requires an
// operator identity on every /v1 operator route (X-RS-Operator); there is no
// SSO in this build, so the console keeps it as a local setting. The
// organisation scope is also a local choice until team admin provisioning
// lands (FR-08 is the read side of that).

import { setOperatorId } from "./api";

const OP_KEY = "runshield.operator";
const ORG_KEY = "runshield.organization";

export function loadOperator(): string {
  const stored = localStorage.getItem(OP_KEY) ?? "operator";
  setOperatorId(stored);
  return stored;
}

export function saveOperator(id: string): string {
  localStorage.setItem(OP_KEY, id);
  setOperatorId(id);
  return id;
}

export function loadOrganization(defaultOrg: string): string {
  return localStorage.getItem(ORG_KEY) ?? defaultOrg;
}

export function saveOrganization(org: string) {
  localStorage.setItem(ORG_KEY, org);
}

// Apply the light/dark theme attribute the design system keys off
// (:root[data-theme="light"] in global.css).
export function loadTheme(): "dark" | "light" {
  const t = localStorage.getItem("runshield.theme") ?? "dark";
  document.documentElement.dataset.theme = t === "light" ? "light" : "dark";
  return t === "light" ? "light" : "dark";
}

export function saveTheme(t: "dark" | "light") {
  localStorage.setItem("runshield.theme", t);
  document.documentElement.dataset.theme = t;
}
