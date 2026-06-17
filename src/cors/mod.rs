//! CORS misconfiguration (CWE-942) detection module.

pub mod detector;

pub use detector::{check_cors, CorsVector};
