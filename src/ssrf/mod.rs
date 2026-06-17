//! SSRF Detection Module - Evidence-Driven, Low-False-Positive Model
//!
//! This module treats Server-Side Request Forgery as a controlled server-initiated
//! network interaction problem, not a simple "URL reflection" issue. Detection is based
//! on provable server-side request behavior rather than payload presence.
//!
//! ## Detection Methodology
//!
//! 1. **Parameter Identification**: Identify parameters that plausibly influence outbound requests
//! 2. **Reachability Phase**: Confirm server actually initiates outbound requests
//! 3. **Controlled Probes**: Test internal addresses and non-HTTP schemes
//! 4. **Evidence Analysis**: Require positive evidence of server-side network interaction
//! 5. **Classification**: Classify SSRF type based on strongest evidence observed
//!
//! ## SSRF Classifications
//!
//! - **Confirmed SSRF (Critical)**: OOB callback received or metadata access proven
//! - **Internal Network SSRF (High)**: Internal IP reachable with response/timing proof
//! - **Blind SSRF (High)**: Asynchronous OOB only
//! - **Limited SSRF (Medium)**: Outbound request control but restricted
//! - **SSRF Candidate (Info)**: Parameter influences fetch but not proven
//!
//! ## Key Principles
//!
//! - Reflection ≠ SSRF (same as XSS principle)
//! - Errors ≠ Proof
//! - Outbound behavior must be demonstrated
//! - OOB beats everything
//! - Internal vs external targets must behave differently
//! - Classification matters more than payload count

pub mod detector;
pub mod evidence;
pub mod oob;
pub mod params;
pub mod probes;
pub mod scanner;

pub use detector::SsrfDetector;
pub use evidence::{Evidence, EvidenceType, SsrfClassification, SsrfResult};
pub use scanner::SsrfScanner;

/// SSRF detection configuration
#[derive(Debug, Clone)]
pub struct SsrfConfig {
    /// OOB callback domain for blind SSRF detection
    pub oob_callback: Option<String>,
    
    /// Test internal network ranges (RFC1918, loopback, link-local)
    pub test_internal: bool,
    
    /// Test cloud metadata endpoints
    pub test_metadata: bool,
    
    /// Test non-HTTP schemes (file, gopher, ftp, dict)
    pub test_schemes: bool,
    
    /// Timeout for external requests (ms)
    pub external_timeout: u64,
    
    /// Timeout for internal requests (ms)
    pub internal_timeout: u64,
    
    /// Confidence threshold for reporting (0.0-1.0)
    pub confidence_threshold: f32,
    
    /// Maximum payloads to test per parameter
    pub max_payloads: usize,

    /// When set, payloads are injected into this POST body (form or JSON,
    /// auto-detected) instead of the URL query string.
    pub post_body: Option<String>,
}

impl Default for SsrfConfig {
    fn default() -> Self {
        Self {
            oob_callback: None,
            test_internal: true,
            test_metadata: true,
            test_schemes: true,
            external_timeout: 5000,
            internal_timeout: 2000,
            confidence_threshold: 0.7,
            max_payloads: 20,
            post_body: None,
        }
    }
}

