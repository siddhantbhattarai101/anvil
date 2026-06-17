//! Missing Subresource Integrity (SRI) detection (OWASP A08) module.

pub mod detector;

pub use detector::{scan_sri, SriFinding};
