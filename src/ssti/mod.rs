//! Server-Side Template Injection (CWE-1336) detection module.

pub mod detector;

pub use detector::{check_ssti, SstiVector};
