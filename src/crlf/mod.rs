//! CRLF / HTTP response header injection (CWE-113) detection module.

pub mod detector;

pub use detector::{check_crlf, CrlfVector};
