//! Path traversal / Local File Inclusion (CWE-22 / CWE-98) detection module.

pub mod detector;

pub use detector::{check_path_traversal, PathTravVector};
