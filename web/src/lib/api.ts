// Thin typed client for the control plane. Every screen calls a real /v1
// endpoint; there is no in-app mock layer. The console assumes it is served
// from the same origin as the API (vite proxy in dev, reverse proxy in prod)
// — the control-plane address is never hardcoded here.
//
// Operator routes (policy, orgs, users, devices, decisions, approvals) sit
// behind an operator identity: the server requires a non-empty
// `X-RS-Operator` header or `Authorization` bearer. This reference build has
// no SSO; the operator id is a local setting (see session.ts). Device-facing
// routes (healthz, device policy, events) are open/rate-limited.

import type {
  ApprovalsListResponse,
  ApprovalCreateBody,
  ApprovalCreateResponse,
  ApprovalDecisionBody,
  ApprovalDecisionResponse,
  Decision,
  DecisionFilter,
  DecisionsListResponse,
  Device,
  DevicePolicyResponse,
  DeviceTokenResponse,
  ExecutionRequest,
  HealthResponse,
  ItemsResponse,
  Org,
  PolicyCreateBody,
  PolicyCreateResponse,
  PolicyGetResponse,
  PolicyActionResponse,
  PolicyVersion,
  User,
} from "./types";

const BASE = "/v1";

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

// The operator id is not part of the URL; it is sent as a header. Keep it as a
// module-level mutable so any screen can read it without prop drilling.
let operatorId = "operator";
export function setOperatorId(id: string) {
  operatorId = id.trim() || "operator";
}
export function getOperatorId(): string {
  return operatorId;
}

async function request<T>(path: string, init: RequestInit = {}, opts: { operator?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string> | undefined),
  };
  if (opts.operator) headers["X-RS-Operator"] = operatorId;
  const resp = await fetch(BASE + path, { ...init, headers, method: init.method ?? "GET" });
  if (!resp.ok) {
    let body: unknown = null;
    let msg = resp.statusText;
    try {
      body = await resp.json();
      if (body && typeof body === "object" && "error" in body) msg = String((body as { error: string }).error);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(resp.status, msg, body);
  }
  return (await resp.json()) as T;
}

// Convenience wrappers that always send the operator header.
async function opGet<T>(path: string): Promise<T> {
  return request<T>(path, {}, { operator: true });
}
async function opPost<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: "POST", body: JSON.stringify(body) }, { operator: true });
}

export const api = {
  // --- operator: team admin ------------------------------------------------
  orgs: () => opGet<ItemsResponse<Org>>("/organizations"),
  users: (organization: string) =>
    opGet<ItemsResponse<User>>(`/users?organization=${encodeURIComponent(organization)}`),
  devices: (organization: string) =>
    opGet<ItemsResponse<Device>>(`/devices?organization=${encodeURIComponent(organization)}`),
  deviceToken: (deviceId: string, organization: string) =>
    // Device-facing public route (rate-limited), not operator-scoped: no
    // operator header. The Go handler reads the device id from the path and
    // the org from the query.
    request<DeviceTokenResponse>(
      `/devices/${encodeURIComponent(deviceId)}/token?organization=${encodeURIComponent(organization)}`,
      { method: "POST" },
    ),

  // --- operator: policies ---------------------------------------------------
  policies: (organization: string) =>
    opGet<ItemsResponse<PolicyVersion>>(
      `/policies?organization=${encodeURIComponent(organization)}`,
    ),
  policySchema: () => request<Record<string, unknown>>("/policies/schema", {}, { operator: true }),
  policy: (id: string) => opGet<PolicyGetResponse>(`/policies/${encodeURIComponent(id)}`),
  createPolicy: (body: PolicyCreateBody) => opPost<PolicyCreateResponse>("/policies", body),
  publishPolicy: (id: string) => opPost<PolicyActionResponse>(`/policies/${encodeURIComponent(id)}/publish`, {}),
  rollbackPolicy: (id: string) => opPost<PolicyActionResponse>(`/policies/${encodeURIComponent(id)}/rollback`, {}),

  // --- operator: audit timeline ---------------------------------------------
  decisions: (filter: DecisionFilter = {}) => {
    const q = new URLSearchParams();
    if (filter.device_id) q.set("device_id", filter.device_id);
    if (filter.policy_version) q.set("policy_version", filter.policy_version);
    if (filter.decision) q.set("decision", filter.decision);
    q.set("limit", String(filter.limit ?? 200));
    return opGet<DecisionsListResponse>(`/decisions?${q.toString()}`);
  },

  // --- operator: approvals workspace ----------------------------------------
  approvals: (status: string = "") =>
    opGet<ApprovalsListResponse>(`/approvals${status ? `?status=${encodeURIComponent(status)}` : ""}`),
  createApproval: (body: ApprovalCreateBody) => opPost<ApprovalCreateResponse>("/approvals", body),
  decideApproval: (id: string, body: ApprovalDecisionBody) =>
    opPost<ApprovalDecisionResponse>(`/approvals/${encodeURIComponent(id)}/decision`, body),

  // --- device-facing (what the Rust agent calls) ----------------------------
  health: () => request<HealthResponse>("/healthz"),
  devicePolicy: (organization: string, deviceId?: string) =>
    request<DevicePolicyResponse>(`/devices/${encodeURIComponent(deviceId ?? "local-dev")}/policy?organization=${encodeURIComponent(organization)}`),
  executions: (workspace: string, limit = 50) =>
    opGet<{ workspace: string; limit: number; items: ExecutionRequest[] }>(
      `/workspaces/${encodeURIComponent(workspace)}/executions?limit=${limit}`,
    ),
};

// Decision kinds for filter selects (kept in one place so the timeline and
// approval history stay consistent).
export const DECISION_KINDS: Decision[] = ["allow", "deny", "require_approval", "audit_only"];
