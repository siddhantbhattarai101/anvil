//! JSON Web Token weakness detection (CWE-347) module.

pub mod detector;

pub use detector::{analyze_jwt, extract_jwts, JwtIssue};
