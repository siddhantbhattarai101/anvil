//! Sensitive data / secret exposure detection (OWASP A02) module.

pub mod detector;

pub use detector::{scan_secrets, SecretFinding};
