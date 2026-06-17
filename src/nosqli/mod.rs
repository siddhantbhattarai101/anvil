//! NoSQL injection (CWE-943) detection module.

pub mod detector;

pub use detector::{check_nosqli, NoSqlVector};
