//! Evidence collection and SSRF classification

use std::time::Duration;

/// Type of evidence collected for SSRF
#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceType {
    /// OOB callback received (strongest evidence)
    OobCallback {
        callback_url: String,
        received_at: String,
    },
    
    /// Cloud metadata access confirmed
    MetadataAccess {
        endpoint: String,
        response_snippet: String,
    },
    
    /// Internal IP reachable with distinct response
    InternalIpReachable {
        ip: String,
        response_diff: String,
    },
    
    /// Timing differential consistent with internal network
    TimingDifferential {
        internal_time: Duration,
        external_time: Duration,
        delta_ms: i64,
    },
    
    /// Protocol-specific error signature
    ProtocolError {
        scheme: String,
        error_signature: String,
    },
    
    /// Response behavior difference (internal vs external)
    ResponseBehaviorDiff {
        internal_status: u16,
        external_status: u16,
        behavior: String,
    },
    
    /// DNS resolution observation
    DnsResolution {
        hostname: String,
        resolved: bool,
    },
    
    /// Parameter controls request destination (weak evidence)
    ParameterControl {
        param: String,
        evidence: String,
    },
}

/// SSRF classification based on evidence strength and impact type
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SsrfClassification {
    /// OOB callback received or cloud metadata access proven (network SSRF)
    ConfirmedNetworkSsrf,
    
    /// Internal IP reachable with response/timing proof (network SSRF)
    InternalNetworkSsrf,
    
    /// Local file system access via server-side fetch (SSRF-like impact, not network)
    LocalResourceAccess,
    
    /// Asynchronous OOB only (blind network SSRF)
    BlindSsrf,
    
    /// Outbound request control but restricted (network SSRF)
    LimitedSsrf,
    
    /// Parameter influences fetch but not fully proven
    SsrfCandidate,
}

impl SsrfClassification {
    /// Get severity level
    pub fn severity(&self) -> &'static str {
        match self {
            SsrfClassification::ConfirmedNetworkSsrf => "CRITICAL",
            SsrfClassification::InternalNetworkSsrf => "HIGH",
            SsrfClassification::LocalResourceAccess => "HIGH",
            SsrfClassification::BlindSsrf => "HIGH",
            SsrfClassification::LimitedSsrf => "MEDIUM",
            SsrfClassification::SsrfCandidate => "INFO",
        }
    }
    
    /// Get confidence score
    pub fn base_confidence(&self) -> f32 {
        match self {
            SsrfClassification::ConfirmedNetworkSsrf => 0.95,
            SsrfClassification::InternalNetworkSsrf => 0.85,
            SsrfClassification::LocalResourceAccess => 0.90,
            SsrfClassification::BlindSsrf => 0.80,
            SsrfClassification::LimitedSsrf => 0.70,
            SsrfClassification::SsrfCandidate => 0.50,
        }
    }
    
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            SsrfClassification::ConfirmedNetworkSsrf => 
                "Server-Side Request Forgery confirmed through out-of-band callback or cloud metadata access",
            SsrfClassification::InternalNetworkSsrf => 
                "Server-Side Request Forgery to internal network confirmed through response/timing analysis",
            SsrfClassification::LocalResourceAccess => 
                "Internal Resource Access via Server-Side Fetch (SSRF-like impact)",
            SsrfClassification::BlindSsrf => 
                "Blind Server-Side Request Forgery confirmed through asynchronous callback",
            SsrfClassification::LimitedSsrf => 
                "Limited Server-Side Request Forgery - outbound request control with restrictions",
            SsrfClassification::SsrfCandidate => 
                "Potential SSRF - parameter influences request destination but execution not fully proven",
        }
    }
    
    /// Check if this is network SSRF (vs local resource access)
    pub fn is_network_ssrf(&self) -> bool {
        matches!(
            self,
            SsrfClassification::ConfirmedNetworkSsrf
                | SsrfClassification::InternalNetworkSsrf
                | SsrfClassification::BlindSsrf
                | SsrfClassification::LimitedSsrf
        )
    }
    
    /// Check if this is local resource access
    pub fn is_local_resource_access(&self) -> bool {
        matches!(self, SsrfClassification::LocalResourceAccess)
    }
}

/// Evidence container for a single piece of SSRF evidence
#[derive(Debug, Clone)]
pub struct Evidence {
    pub evidence_type: EvidenceType,
    pub confidence: f32,
    pub description: String,
}

impl Evidence {
    pub fn new(evidence_type: EvidenceType, confidence: f32, description: String) -> Self {
        Self {
            evidence_type,
            confidence,
            description,
        }
    }
}

/// Negative evidence - why SSRF was ruled out
#[derive(Debug, Clone)]
pub enum NegativeEvidence {
    /// No outbound request capability detected
    NoOutboundRequest,
    
    /// Internal IP access blocked
    InternalIpBlocked { ip: String },
    
    /// Scheme restricted (file://, gopher://, etc.)
    SchemeRestricted { scheme: String },
    
    /// Cloud metadata access blocked
    MetadataBlocked { endpoint: String },
    
    /// Parameter doesn't influence server behavior
    NoParameterControl,
    
    /// Responses identical regardless of input
    NoResponseVariation,
}

/// Complete SSRF detection result
#[derive(Debug, Clone)]
pub struct SsrfResult {
    /// Endpoint where SSRF was detected
    pub endpoint: String,
    
    /// Parameter that triggers SSRF
    pub parameter: String,
    
    /// SSRF classification
    pub classification: SsrfClassification,
    
    /// Overall confidence (0.0-1.0)
    pub confidence: f32,
    
    /// Request control certainty (0.0-1.0)
    pub request_control_confidence: f32,
    
    /// Impact reachability certainty (0.0-1.0)
    pub impact_reachability_confidence: f32,
    
    /// All evidence collected
    pub evidence: Vec<Evidence>,
    
    /// Successful payload
    pub payload: String,
    
    /// Target that was reached (if any)
    pub target_reached: Option<String>,
    
    /// Technical details
    pub details: String,
    
    /// Destination control score (0.0-1.0) - can control where request goes
    pub destination_control_score: f32,
    
    /// Protocol control score (0.0-1.0) - can control protocol/scheme
    pub protocol_control_score: f32,
    
    /// Capability boundaries - what attacker can/cannot do
    pub capability_boundaries: CapabilityBoundaries,
}

/// Explicit boundaries of what attacker can control
#[derive(Debug, Clone, Default)]
pub struct CapabilityBoundaries {
    /// Can control destination (where request goes)
    pub can_control_destination: bool,
    
    /// Can control protocol/scheme
    pub can_control_protocol: bool,
    
    /// Can inject headers
    pub can_inject_headers: bool,
    
    /// Can control request method
    pub can_control_method: bool,
    
    /// Can read response content
    pub can_read_response: bool,
    
    /// Observed restrictions/filters
    pub restrictions: Vec<String>,
}

/// Negative result - why SSRF was ruled out
#[derive(Debug, Clone)]
pub struct SsrfNegativeResult {
    pub endpoint: String,
    pub parameter: String,
    pub negative_evidence: Vec<NegativeEvidence>,
    pub gates_passed: Vec<String>,
    pub gates_failed: Vec<String>,
}

impl SsrfResult {
    /// Create a new SSRF result
    pub fn new(
        endpoint: String,
        parameter: String,
        classification: SsrfClassification,
        payload: String,
    ) -> Self {
        Self {
            endpoint,
            parameter,
            classification: classification.clone(),
            confidence: classification.base_confidence(),
            request_control_confidence: 0.0,
            impact_reachability_confidence: 0.0,
            evidence: Vec::new(),
            payload,
            target_reached: None,
            details: String::new(),
            destination_control_score: 0.0,
            protocol_control_score: 0.0,
            capability_boundaries: CapabilityBoundaries::default(),
        }
    }
    
    /// Generate human-readable capability boundary description
    pub fn capability_narrative(&self) -> String {
        let mut capabilities = Vec::new();
        let mut restrictions = Vec::new();
        
        if self.capability_boundaries.can_control_destination {
            capabilities.push("control destination");
        } else {
            restrictions.push("destination restricted");
        }
        
        if self.capability_boundaries.can_control_protocol {
            capabilities.push("control protocol");
        } else {
            restrictions.push("protocol restricted");
        }
        
        if self.capability_boundaries.can_inject_headers {
            capabilities.push("inject headers");
        } else {
            restrictions.push("header injection blocked");
        }
        
        if self.capability_boundaries.can_control_method {
            capabilities.push("control method");
        } else {
            restrictions.push("method fixed");
        }
        
        if self.capability_boundaries.can_read_response {
            capabilities.push("read response");
        } else {
            restrictions.push("response blind");
        }
        
        let mut narrative = String::new();
        
        if !capabilities.is_empty() {
            narrative.push_str("Attacker can ");
            narrative.push_str(&capabilities.join(", "));
        }
        
        if !restrictions.is_empty() {
            if !narrative.is_empty() {
                narrative.push_str("; ");
            }
            narrative.push_str(&restrictions.join(", "));
        }
        
        // Add observed restrictions
        if !self.capability_boundaries.restrictions.is_empty() {
            narrative.push_str(". Observed filters: ");
            narrative.push_str(&self.capability_boundaries.restrictions.join(", "));
        }
        
        narrative
    }
    
    /// Add evidence to the result
    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.evidence.push(evidence);
        self.recalculate_confidence();
    }
    
    /// Recalculate confidence based on all evidence
    fn recalculate_confidence(&mut self) {
        if self.evidence.is_empty() {
            return;
        }
        
        // Take the maximum confidence from all evidence
        let max_evidence_confidence = self.evidence
            .iter()
            .map(|e| e.confidence)
            .fold(0.0f32, f32::max);

        // Confidence is driven by the STRONGEST evidence, not diluted by
        // averaging it with the base classification. Averaging previously turned
        // a concrete 0.95 content-based proof into 0.725. Floor at the best of
        // (base classification, strongest evidence), then add a small bounded
        // bonus when multiple independent signals corroborate.
        let base = self.classification.base_confidence();
        let mut combined = base.max(max_evidence_confidence);
        let corroborating = self
            .evidence
            .iter()
            .filter(|e| e.confidence >= 0.5)
            .count();
        if corroborating > 1 {
            combined += 0.03 * (corroborating.min(4) as f32 - 1.0);
        }
        self.confidence = combined.min(0.99);
    }
    
    /// Check if this result should be reported based on thresholds
    pub fn should_report(&self, threshold: f32) -> bool {
        // Must cross both request control AND impact reachability thresholds
        self.confidence >= threshold
            && self.request_control_confidence >= threshold
            && self.impact_reachability_confidence >= threshold
    }
    
    /// Get severity string
    pub fn severity(&self) -> &'static str {
        self.classification.severity()
    }
}

