// Shared types for the control-plane API. Mirrors the data model in
// 01-RuntimeShield.md §9 and the Go store rows (controlplane/internal/store/repo.go)
// — no invented fields.

export type Decision = "allow" | "deny" | "require_approval" | "audit_only";
export type FsAccess = "read-write" | "read-only" | "deny";
export type PolicyStatus = "draft" | "published" | "rolled_back";
export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface Org {
  id: string;
  name: string;
  plan: string;
  created_at: string;
}

export interface User {
  id: string;
  organization_id: string;
  identity_provider_id: string;
  role: string;
}

export interface Device {
  id: string;
  organization: string;
  public_key: string;
  platform: string;
  agent_version: string;
  last_seen_at: string;
}

export interface PolicyVersion {
  id: string;
  organization_id: string;
  version: number;
  document: string; // JSON-encoded policy document
  signature: string;
  status: PolicyStatus;
  created_at: string;
}

export interface Approval {
  id: string;
  request_id: string;
  approver_id: string;
  scope: string;
  expires_at: string;
  status: ApprovalStatus;
  created_at: string;
}

export interface ExecutionRequest {
  id: string;
  device_id: string;
  workspace_id: string;
  executable: string;
  argv_digest: string;
  cwd_digest: string;
  requested_at: string;
}

export interface DecisionRecord {
  id: string;
  request_id: string;
  decision: Decision;
  rule_ids: string; // JSON array, e.g. ["net-default-deny"]
  policy_version: string;
  decided_at: string;
}

// store.DecisionRow: a decision enriched with its requesting device, what
// the audit-timeline screen renders.
export interface DecisionRow extends DecisionRecord {
  device_id: string;
}

export interface DevicePolicyResponse {
  organization: string;
  document: unknown | null;
  signature: string;
  version: number | string;
  expires_in: number;
  note?: string;
}

// Shape of a validated policy document (spec §8, policies/schema/policy.schema.json).
export interface PolicyDocument {
  version: number;
  policy_version?: string;
  profile: string;
  description?: string;
  default_action: Decision;
  filesystem?: {
    workspace?: { access: FsAccess; roots: string[] };
    temp?: { access: FsAccess };
    sensitive_paths?: string[];
    deny_paths?: string[];
    allow_paths?: string[];
  };
  network?: {
    default?: "allow" | "deny";
    allow?: Array<{ host: string; ports?: number[] }>;
    deny?: Array<{ host: string; ports?: number[] }>;
  };
  process?: {
    allow?: Array<{ executable: string; actions?: string[]; note?: string }>;
    deny?: Array<{ executable: string; actions?: string[]; note?: string }>;
    require_approval?: Array<{ executable: string; actions?: string[]; note?: string }>;
  };
  secrets?: {
    deny_env_keys?: string[];
    patterns?: Array<{ id: string; regex: string; description?: string }>;
  };
  rules?: Array<{
    id: string;
    effect: Decision;
    capability: "filesystem" | "network" | "process" | "secret";
    priority?: number;
    path?: string;
    host?: string;
    port?: number;
    executable?: string;
    actions?: string[];
    note?: string;
  }>;
}

// --- operator endpoints: request / response shapes -------------------------

export interface HealthResponse {
  status: string;
  backend: string;
  nats: boolean;
  timestamp: string;
}

export interface PolicyGetResponse {
  policy: PolicyVersion;
  document: unknown;
}

export interface PolicyCreateBody {
  organization: string;
  document: unknown;
}

export interface PolicyCreateResponse {
  status: string;
  id: string;
  version: number;
  status_out: string;
}

export interface PolicyActionResponse {
  status: string;
  id: string;
}

export interface DeviceTokenResponse {
  status: string;
  device: string;
  token: string;
  expires: string;
}

export interface ApprovalCreateBody {
  request_id: string;
  scope: string;
  reason?: string;
}

export interface ApprovalCreateResponse {
  status: string;
  id: string;
  request_id: string;
  approver_id: string;
  scope: string;
  expires_at: string;
}

export interface ApprovalDecisionBody {
  decision: "allow" | "deny";
  reason?: string;
}

export interface ApprovalDecisionResponse {
  status: string;
  id: string;
  decision: string;
  approver_id: string;
}

export interface ApprovalsListResponse {
  items: Approval[];
  status: string;
}

// GET /v1/decisions filter parameters (store.DecisionFilter).
export interface DecisionFilter {
  device_id?: string;
  policy_version?: string;
  decision?: Decision;
  limit?: number;
}

export interface DecisionsListResponse {
  items: DecisionRow[];
  limit: number;
}

export interface ItemsResponse<T> {
  items: T[];
}

export interface ApiErrorShape extends Error {
  status?: number;
}
