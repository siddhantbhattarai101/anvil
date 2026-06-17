//! Vulnerable / outdated component detection (OWASP A06) module.

pub mod detector;

pub use detector::{scan_components, ComponentFinding};
