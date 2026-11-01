//! runtime-shield-core: deterministic policy engine for RuntimeShield.
//!
//! This crate owns every security-critical decision. It is deliberately
//! free of I/O: evaluation is a pure function of (policy, context, request)
//! so it can be fuzzed, unit-tested and run offline by the local agent.

pub mod eval;
pub mod error;
pub mod netmatch;
pub mod paths;
pub mod policy;
pub mod request;
pub mod secret;

pub use eval::{EvalContext, EvalResult, evaluate};
pub use error::{Error, Result};
pub use policy::{Decision, Policy, POLICY_SCHEMA, POLICY_SCHEMA_VERSION};
pub use request::{Capability, ExecutionRequest, Principal, REQUEST_SCHEMA};
