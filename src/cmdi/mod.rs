//! OS command-injection (CWE-78) detection module.

pub mod detector;

pub use detector::{check_cmdi, CmdiVector};
