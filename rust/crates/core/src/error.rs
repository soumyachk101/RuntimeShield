use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    /// The execution request failed structured validation (unknown
    /// capability kind, non-array argv, oversized argument list, ...).
    #[error("execution request is invalid: {0}")]
    InvalidRequest(String),

    /// The policy document failed JSON-Schema validation or used an
    /// unsupported schema version.
    #[error("policy document is invalid: {0}")]
    InvalidPolicy(String),

    /// A path could not be resolved or canonicalised.
    #[error("path error: {0}")]
    PathError(String),

    /// A network destination could not be parsed.
    #[error("network destination error: {0}")]
    DestinationError(String),

    /// I/O failure inside an optional component (logger, cache file...).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Human-safe remediation text attached to every DENY. Kept in the engine
/// (not the UI) so denial output is identical across CLI, agents and API.
pub struct Denial {
    pub rule_id: String,
    pub explanation: String,
    pub remediation: String,
}
