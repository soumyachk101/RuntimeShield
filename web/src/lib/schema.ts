// Client-side JSON-schema validation for the policy editor. The schema comes
// from the control plane's GET /v1/policies/schema — the same source of truth
// the server validates against (spec §5 "single source of truth") — so a
// locally-valid document is accepted by POST /v1/policies. The schema is
// JSON Schema 2020-12; ajv's 2020-12 dialect compiles it. Its $id is a fixed
// https URL and its $defs refs are local, so no remote loading is required.
import Ajv2020 from "ajv/dist/2020";

import type { PolicyDocument } from "./types";

type Schema = Record<string, unknown>;
// The compiled validator's type is derived from the 2020-12 instance so it
// matches what `compile` actually returns (no separate base-ajv import).
type Validator = ReturnType<Ajv2020["compile"]>;

export interface ValidationErrors {
  valid: boolean;
  errors: Array<{ path: string; message: string }>;
}

// Cache compiled validators per schema-object reference. The policy schema
// carries a fixed $id, so recompiling it into a *shared* compiler throws
// "schema with id already exists". A fresh compiler per cache-miss (each
// with its own registry) plus this cache avoids both the throw and repeated
// compilation; the schema object is stable (held in React state), so the
// cache hits on every keystroke.
const validatorCache = new Map<Schema, Validator>();

function compileValidator(schema: Schema): Validator {
  const cached = validatorCache.get(schema);
  if (cached) return cached;
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  const validator = ajv.compile(schema);
  validatorCache.set(schema, validator);
  return validator;
}

// Validates a parsed policy document against the fetched schema. When the
// schema has not loaded yet (control plane unreachable), it falls back to a
// structural check of the required top-level fields so the editor still
// refuses obviously broken documents offline.
export function validatePolicyDocument(schema: Schema | null, document: unknown): ValidationErrors {
  if (schema) {
    try {
      const validator = compileValidator(schema);
      const valid = validator(document);
      const errors = (validator.errors ?? []).map((e) => ({
        path: e.instancePath || "(root)",
        message: e.message ?? "invalid",
      }));
      if (valid) return { valid: true, errors: [] };
      if (errors.length > 0) return { valid: false, errors };
      return { valid: false, errors: [{ path: "", message: "document failed schema validation" }] };
    } catch {
      /* fall through to the structural check below */
    }
  }
  return structuralCheck(document);
}

function structuralCheck(doc: unknown): ValidationErrors {
  const errors: ValidationErrors["errors"] = [];
  if (typeof doc !== "object" || doc === null) {
    return { valid: false, errors: [{ path: "", message: "document must be an object" }] };
  }
  const d = doc as Partial<PolicyDocument>;
  if (d.version !== 1) errors.push({ path: "version", message: "must be 1" });
  if (typeof d.profile !== "string" || d.profile.length === 0)
    errors.push({ path: "profile", message: "required (non-empty string)" });
  if (!["allow", "deny", "require_approval", "audit_only"].includes(d.default_action as string))
    errors.push({ path: "default_action", message: "must be allow | deny | require_approval | audit_only" });
  return { valid: errors.length === 0, errors };
}
