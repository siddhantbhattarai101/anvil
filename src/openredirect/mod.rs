//! Open redirect (CWE-601) detection module.

pub mod detector;

pub use detector::{check_open_redirect, OpenRedirVector};
