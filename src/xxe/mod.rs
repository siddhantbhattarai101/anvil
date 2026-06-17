//! XML External Entity (XXE) injection (CWE-611) detection module.

pub mod detector;

pub use detector::{check_xxe, XxeVector};
