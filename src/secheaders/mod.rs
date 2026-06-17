//! Passive security-header & cookie audit (OWASP A05) module.

pub mod detector;

pub use detector::{audit_headers, HeaderIssue};
