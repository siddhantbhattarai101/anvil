//! SSRF detector - Core detection logic with evidence-driven analysis

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::ssrf::evidence::{Evidence, EvidenceType, SsrfClassification, SsrfResult};
use crate::ssrf::oob::{generate_identifier, OobCallbackGenerator, OobCallbackListener};
use crate::ssrf::probes::{SsrfProbe, SsrfProbeGenerator, SsrfProbeType};
use crate::ssrf::SsrfConfig;
use crate::sqli::request::InjectionPoint;
use crate::validation::baseline::Baseline;
use crate::validation::diff::diff;
use reqwest::Method;
use std::time::{Duration, Instant};
use url::Url;

/// SSRF detector implementing evidence-driven detection
pub struct SsrfDetector {
    config: SsrfConfig,
    probe_generator: SsrfProbeGenerator,
    oob_generator: Option<OobCallbackGenerator>,
    oob_listener: Option<OobCallbackListener>,
}

impl SsrfDetector {
    pub fn new(config: SsrfConfig) -> Self {
        let (oob_generator, oob_listener) = if let Some(ref callback_domain) = config.oob_callback {
            (
                Some(OobCallbackGenerator::new(callback_domain.clone())),
                Some(OobCallbackListener::new(callback_domain.clone())),
            )
        } else {
            (None, None)
        };

        Self {
            config,
            probe_generator: SsrfProbeGenerator::new(),
            oob_generator,
            oob_listener,
        }
    }

    /// Detect SSRF in a parameter
    pub async fn detect(
        &self,
        client: &HttpClient,
        url: &Url,
        param_name: &str,
        original_value: &str,
    ) -> anyhow::Result<Option<SsrfResult>> {
        tracing::debug!("Testing parameter '{}' for SSRF", param_name);

        // Phase 1: Reachability testing - confirm server makes outbound requests
        if !self.test_reachability(client, url, param_name).await? {
            tracing::debug!("No outbound request behavior detected for '{}'", param_name);
            return Ok(None);
        }

        tracing::debug!("Outbound request behavior confirmed for '{}'", param_name);

        // Phase 2: Generate and test probes
        let mut probes = self.probe_generator.generate_all_probes(original_value);

        // Sort by priority
        probes.sort_by_key(|p| p.priority());

        // Limit number of probes
        if probes.len() > self.config.max_payloads {
            probes.truncate(self.config.max_payloads);
        }

        let mut best_result: Option<SsrfResult> = None;

        for probe in &probes {
            if let Some(result) = self.test_probe(client, url, param_name, probe).await? {
                // Update best result if this is better
                if let Some(ref current_best) = best_result {
                    if result.classification > current_best.classification
                        || (result.classification == current_best.classification
                            && result.confidence > current_best.confidence)
                    {
                        best_result = Some(result);
                    }
                } else {
                    best_result = Some(result);
                }

                // If we found confirmed SSRF, we can stop
                if let Some(ref result) = best_result {
                    if result.classification == SsrfClassification::ConfirmedNetworkSsrf {
                        break;
                    }
                }
            }
        }

        // Phase 3: OOB testing if enabled and no confirmed SSRF yet
        if self.oob_generator.is_some() && best_result.is_none() {
            if let Some(oob_result) = self.test_oob(client, url, param_name).await? {
                best_result = Some(oob_result);
            }
        }

        // Check if result meets reporting threshold
        if let Some(result) = best_result {
            if result.should_report(self.config.confidence_threshold) {
                return Ok(Some(result));
            }
        }

        Ok(None)
    }

    /// Build a request that injects `payload` at the configured location: the
    /// POST body when `config.post_body` is set (form or JSON auto-detected),
    /// otherwise the URL query string. `extra_headers` carries probe-specific
    /// headers (e.g. cloud-metadata headers). Auth cookies/headers travel via
    /// the HTTP client, so they are not duplicated here.
    fn build_injected(
        &self,
        url: &Url,
        param: &str,
        payload: &str,
        extra_headers: &[(String, String)],
    ) -> HttpRequest {
        let point = match &self.config.post_body {
            Some(body) => InjectionPoint::from_context(
                Method::POST,
                url.clone(),
                param,
                Some(body.clone()),
                Vec::new(),
                extra_headers.to_vec(),
            ),
            None => {
                let mut p = InjectionPoint::query(url.clone(), param);
                p.headers = extra_headers.to_vec();
                p
            }
        };
        point.build_request(payload)
    }

    /// Execute a request injecting `value` at the configured location.
    async fn request_with_param(
        &self,
        client: &HttpClient,
        url: &Url,
        param_name: &str,
        value: &str,
    ) -> anyhow::Result<crate::http::response::HttpResponse> {
        let request = self.build_injected(url, param_name, value, &[]);
        client.execute(request).await
    }

    /// Phase 1: Test whether the parameter actually influences server-side
    /// fetch/file behaviour. Evidence-based: we establish a baseline with a
    /// benign inert value, then require either (a) outbound-fetch indicators or
    /// (b) a material divergence from baseline for a fetch-like test value.
    /// Returns `false` when there is no evidence the parameter drives a request
    /// — previously this returned `true` unconditionally, marking every
    /// parameter reachable and producing false positives downstream.
    async fn test_reachability(
        &self,
        client: &HttpClient,
        url: &Url,
        param_name: &str,
    ) -> anyhow::Result<bool> {
        // Baseline: an inert, non-fetching value for the parameter.
        let baseline = match self
            .request_with_param(client, url, param_name, "anvilbaselineprobe")
            .await
        {
            Ok(resp) => Baseline::from_response(&resp),
            Err(_) => return Ok(false),
        };

        // Fetch-like / file-like test values. If the parameter drives an
        // outbound request or a local read, the response should diverge from
        // baseline or expose fetched content.
        let test_values = [
            "http://example.com",
            "https://example.com",
            "file:///etc/hosts",
            "test.txt",
        ];

        for test_val in test_values {
            let response = match self
                .request_with_param(client, url, param_name, test_val)
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Strong signal: server fetched and reflected external content.
            if self.has_outbound_indicators(&response.body_text()) {
                return Ok(true);
            }

            // Behavioural signal: the response materially differs from baseline
            // (status flip or a meaningful body-length change), indicating the
            // parameter changes server-side behaviour.
            let d = diff(&baseline, &response);
            if d.status_changed || d.body_len_delta.abs() > 100 {
                return Ok(true);
            }
        }

        // No evidence the parameter influences outbound/file behaviour.
        Ok(false)
    }

    /// Test a specific SSRF probe
    async fn test_probe(
        &self,
        client: &HttpClient,
        url: &Url,
        param_name: &str,
        probe: &SsrfProbe,
    ) -> anyhow::Result<Option<SsrfResult>> {
        tracing::debug!("Testing probe: {} ({})", probe.description, probe.payload);

        // Build the request, injecting the probe payload at the configured
        // location (query or POST body) and attaching any provider-required
        // headers (e.g. GCP Metadata-Flavor, Azure Metadata: true — without
        // which those metadata endpoints return 403).
        let request = self.build_injected(url, param_name, &probe.payload, &probe.headers);

        // Measure timing
        let start = Instant::now();
        let response = match client.execute(request).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("Request failed: {}", e);
                return Ok(None);
            }
        };
        let elapsed = start.elapsed();

        // Analyze response for evidence
        self.analyze_response(url, param_name, probe, &response.body_text(), elapsed)
            .await
    }

    /// Analyze response for SSRF evidence
    async fn analyze_response(
        &self,
        url: &Url,
        param_name: &str,
        probe: &SsrfProbe,
        response_body: &str,
        elapsed: Duration,
    ) -> anyhow::Result<Option<SsrfResult>> {
        let mut evidence_list = Vec::new();

        // Check for different types of evidence based on probe type
        match probe.probe_type {
            SsrfProbeType::CloudMetadata => {
                // Check for cloud metadata signatures
                if self.has_metadata_signatures(response_body) {
                    evidence_list.push(Evidence::new(
                        EvidenceType::MetadataAccess {
                            endpoint: probe.target.clone(),
                            response_snippet: response_body.chars().take(200).collect(),
                        },
                        0.95,
                        "Cloud metadata endpoint accessible".to_string(),
                    ));

                    let mut result = SsrfResult::new(
                        url.to_string(),
                        param_name.to_string(),
                        SsrfClassification::ConfirmedNetworkSsrf,
                        probe.payload.clone(),
                    );

                    result.target_reached = Some(probe.target.clone());
                    result.request_control_confidence = 0.95;
                    result.impact_reachability_confidence = 0.95;
                    result.destination_control_score = 0.95;
                    result.protocol_control_score = 0.90;
                    
                    // Set capability boundaries
                    result.capability_boundaries.can_control_destination = true;
                    result.capability_boundaries.can_control_protocol = true;
                    result.capability_boundaries.can_read_response = true;
                    result.capability_boundaries.can_control_method = false; // Usually GET only
                    result.capability_boundaries.can_inject_headers = false; // Typically blocked

                    for ev in evidence_list {
                        result.add_evidence(ev);
                    }

                    result.details = format!(
                        "Server successfully fetched cloud metadata endpoint: {}. \
                         This confirms network SSRF with high-value target access (cloud credentials). {}",
                        probe.target,
                        result.capability_narrative()
                    );

                    return Ok(Some(result));
                }
            }

            SsrfProbeType::InternalIp => {
                // Check for internal network access indicators
                if self.has_internal_access_indicators(response_body) {
                    evidence_list.push(Evidence::new(
                        EvidenceType::InternalIpReachable {
                            ip: probe.target.clone(),
                            response_diff: "Internal service response detected".to_string(),
                        },
                        0.85,
                        "Internal IP address accessible".to_string(),
                    ));

                    let mut result = SsrfResult::new(
                        url.to_string(),
                        param_name.to_string(),
                        SsrfClassification::InternalNetworkSsrf,
                        probe.payload.clone(),
                    );

                    result.target_reached = Some(probe.target.clone());
                    result.request_control_confidence = 0.85;
                    result.impact_reachability_confidence = 0.80;
                    result.destination_control_score = 0.85;
                    result.protocol_control_score = 0.75;
                    
                    // Set capability boundaries
                    result.capability_boundaries.can_control_destination = true;
                    result.capability_boundaries.can_control_protocol = probe.payload.contains("://");
                    result.capability_boundaries.can_read_response = response_body.len() > 0;
                    result.capability_boundaries.can_control_method = false;
                    result.capability_boundaries.can_inject_headers = false;

                    for ev in evidence_list {
                        result.add_evidence(ev);
                    }

                    result.details = format!(
                        "Server successfully accessed internal IP: {}. \
                         This confirms network SSRF to internal network. {}",
                        probe.target,
                        result.capability_narrative()
                    );

                    return Ok(Some(result));
                }

                // Check timing differential (internal should be faster)
                if elapsed.as_millis() < 100 {
                    evidence_list.push(Evidence::new(
                        EvidenceType::TimingDifferential {
                            internal_time: elapsed,
                            external_time: Duration::from_millis(500),
                            delta_ms: -400,
                        },
                        0.70,
                        "Fast response suggests internal network access".to_string(),
                    ));
                }
            }

            SsrfProbeType::NonHttpScheme => {
                // Check for protocol-specific errors or file access
                if let Some(scheme_evidence) = self.detect_scheme_evidence(response_body, &probe.payload) {
                    evidence_list.push(scheme_evidence.clone());

                    // Determine if this is local resource access or network SSRF
                    let is_file_access = probe.payload.starts_with("file://") 
                        || probe.payload.contains("../") 
                        || probe.payload.contains("..\\");
                    
                    let classification = if is_file_access {
                        SsrfClassification::LocalResourceAccess
                    } else {
                        SsrfClassification::LimitedSsrf
                    };

                    let mut result = SsrfResult::new(
                        url.to_string(),
                        param_name.to_string(),
                        classification.clone(),
                        probe.payload.clone(),
                    );

                    if is_file_access {
                        result.request_control_confidence = 0.90;
                        result.impact_reachability_confidence = 0.90;
                        result.destination_control_score = 0.85;
                        result.protocol_control_score = 0.95;
                        
                        // Set capability boundaries for file access
                        result.capability_boundaries.can_control_destination = true;
                        result.capability_boundaries.can_control_protocol = true;
                        result.capability_boundaries.can_read_response = true;
                        result.capability_boundaries.can_control_method = false;
                        result.capability_boundaries.can_inject_headers = false;
                        
                        result.details = format!(
                            "Server accessed local file system via: {}. \
                             This is Internal Resource Access via Server-Side Fetch (SSRF-like impact). \
                             While not network SSRF, this allows reading arbitrary local files. {}",
                            probe.payload,
                            result.capability_narrative()
                        );
                    } else {
                        result.request_control_confidence = 0.75;
                        result.impact_reachability_confidence = 0.65;
                        result.destination_control_score = 0.70;
                        result.protocol_control_score = 0.85;
                        
                        // Set capability boundaries for non-HTTP schemes
                        result.capability_boundaries.can_control_destination = true;
                        result.capability_boundaries.can_control_protocol = true;
                        result.capability_boundaries.can_read_response = false; // Usually blind
                        result.capability_boundaries.can_control_method = false;
                        result.capability_boundaries.can_inject_headers = false;
                        
                        result.details = format!(
                            "Server attempted to process non-HTTP scheme: {}. \
                             This indicates network SSRF with protocol control. {}",
                            probe.payload,
                            result.capability_narrative()
                        );
                    }

                    for ev in evidence_list {
                        result.add_evidence(ev);
                    }

                    return Ok(Some(result));
                }
            }

            _ => {}
        }

        // If we have any evidence, create a result
        if !evidence_list.is_empty() {
            let classification = if evidence_list.iter().any(|e| e.confidence >= 0.85) {
                SsrfClassification::InternalNetworkSsrf
            } else {
                SsrfClassification::SsrfCandidate
            };

            let mut result = SsrfResult::new(
                url.to_string(),
                param_name.to_string(),
                classification,
                probe.payload.clone(),
            );

            result.request_control_confidence = 0.70;
            result.impact_reachability_confidence = 0.60;
            result.destination_control_score = 0.65;
            result.protocol_control_score = 0.60;
            
            // Set capability boundaries for limited/candidate SSRF
            result.capability_boundaries.can_control_destination = true;
            result.capability_boundaries.can_control_protocol = false;
            result.capability_boundaries.can_read_response = false;
            result.capability_boundaries.can_control_method = false;
            result.capability_boundaries.can_inject_headers = false;
            result.capability_boundaries.restrictions.push("Limited control observed".to_string());

            for ev in evidence_list {
                result.add_evidence(ev);
            }
            
            result.details = format!(
                "Parameter influences server-side request behavior. {}",
                result.capability_narrative()
            );

            return Ok(Some(result));
        }

        Ok(None)
    }

    /// Test for blind SSRF using OOB callbacks
    async fn test_oob(
        &self,
        client: &HttpClient,
        url: &Url,
        param_name: &str,
    ) -> anyhow::Result<Option<SsrfResult>> {
        let generator = match &self.oob_generator {
            Some(g) => g,
            None => return Ok(None),
        };

        let listener = match &self.oob_listener {
            Some(l) => l,
            None => return Ok(None),
        };

        tracing::debug!("Testing blind SSRF with OOB callbacks");

        let identifier = generate_identifier(&url.to_string(), param_name);
        let callback_url = generator.generate_callback_url(&identifier);

        // Inject the callback URL at the configured location (query or body).
        let request = self.build_injected(url, param_name, &callback_url, &[]);
        let _ = client.execute(request).await;

        // Wait for callback
        if listener.wait_for_callback(&identifier, 5).await {
            let mut result = SsrfResult::new(
                url.to_string(),
                param_name.to_string(),
                SsrfClassification::BlindSsrf,
                callback_url.clone(),
            );

            result.add_evidence(Evidence::new(
                EvidenceType::OobCallback {
                    callback_url: callback_url.clone(),
                    received_at: chrono::Utc::now().to_rfc3339(),
                },
                0.95,
                "Out-of-band callback received".to_string(),
            ));

            result.request_control_confidence = 0.95;
            result.impact_reachability_confidence = 0.90;
            result.destination_control_score = 0.95;
            result.protocol_control_score = 0.90;
            result.target_reached = Some(callback_url);
            
            // Set capability boundaries for blind SSRF
            result.capability_boundaries.can_control_destination = true;
            result.capability_boundaries.can_control_protocol = true;
            result.capability_boundaries.can_read_response = false; // Blind
            result.capability_boundaries.can_control_method = false;
            result.capability_boundaries.can_inject_headers = false;

            result.details = format!(
                "Server initiated outbound network request to attacker-controlled domain. \
                 Blind network SSRF confirmed through out-of-band callback. {}",
                result.capability_narrative()
            );

            return Ok(Some(result));
        }

        Ok(None)
    }

    /// Check if response has indicators of outbound request
    fn has_outbound_indicators(&self, body: &str) -> bool {
        // Look for common patterns that suggest server fetched external content
        let indicators = [
            "<!DOCTYPE html",
            "<html",
            "Example Domain",
            "This domain is for use in illustrative examples",
        ];

        indicators.iter().any(|pattern| body.contains(pattern))
    }

    /// Check for cloud metadata signatures
    fn has_metadata_signatures(&self, body: &str) -> bool {
        let signatures = [
            "ami-id",
            "instance-id",
            "instance-type",
            "local-hostname",
            "local-ipv4",
            "public-hostname",
            "public-ipv4",
            "security-groups",
            "iam/security-credentials",
            "computeMetadata",
            "metadata.google.internal",
            "azure",
            "digitalocean",
        ];

        signatures.iter().any(|sig| body.to_lowercase().contains(&sig.to_lowercase()))
    }

    /// Check for internal network access indicators
    fn has_internal_access_indicators(&self, body: &str) -> bool {
        let indicators = [
            "apache",
            "nginx",
            "iis",
            "tomcat",
            "jetty",
            "unauthorized",
            "forbidden",
            "authentication required",
            "login",
            "dashboard",
            "admin",
        ];

        indicators.iter().any(|ind| body.to_lowercase().contains(&ind.to_lowercase()))
    }

    /// Detect evidence of non-HTTP scheme processing
    fn detect_scheme_evidence(&self, body: &str, payload: &str) -> Option<Evidence> {
        let body_lower = body.to_lowercase();

        // file:// scheme or path traversal
        if payload.starts_with("file://") || payload.contains("../") || payload.contains("..\\") {
            // Check for /etc/passwd content
            if body.contains("root:") && body.contains("/bin/bash") {
                return Some(Evidence::new(
                    EvidenceType::ProtocolError {
                        scheme: "file".to_string(),
                        error_signature: "Local file access confirmed - /etc/passwd read".to_string(),
                    },
                    0.95,
                    "Server successfully read /etc/passwd via file access".to_string(),
                ));
            }

            // Check for Windows files
            if body.contains("[extensions]") || body.contains("[fonts]") || body.contains("for 16-bit app support") {
                return Some(Evidence::new(
                    EvidenceType::ProtocolError {
                        scheme: "file".to_string(),
                        error_signature: "Local file access confirmed - Windows system file read".to_string(),
                    },
                    0.95,
                    "Server successfully read Windows system file".to_string(),
                ));
            }

            // Check for /etc/hosts content
            if body.contains("127.0.0.1") && body.contains("localhost") {
                return Some(Evidence::new(
                    EvidenceType::ProtocolError {
                        scheme: "file".to_string(),
                        error_signature: "Local file access confirmed - /etc/hosts read".to_string(),
                    },
                    0.90,
                    "Server successfully read /etc/hosts".to_string(),
                ));
            }

            // Check for generic file access errors
            if body_lower.contains("file not found") || body_lower.contains("permission denied") || 
               body_lower.contains("no such file") || body_lower.contains("failed to open") {
                return Some(Evidence::new(
                    EvidenceType::ProtocolError {
                        scheme: "file".to_string(),
                        error_signature: "File protocol error - attempted access".to_string(),
                    },
                    0.75,
                    "Server attempted file:// access (error indicates processing)".to_string(),
                ));
            }
        }

        // gopher:// scheme
        if payload.starts_with("gopher://") && body_lower.contains("gopher") {
            return Some(Evidence::new(
                EvidenceType::ProtocolError {
                    scheme: "gopher".to_string(),
                    error_signature: "Gopher protocol reference".to_string(),
                },
                0.70,
                "Server processed gopher:// URL".to_string(),
            ));
        }

        // ftp:// scheme
        if payload.starts_with("ftp://") {
            if body_lower.contains("ftp") || body_lower.contains("220") {
                return Some(Evidence::new(
                    EvidenceType::ProtocolError {
                        scheme: "ftp".to_string(),
                        error_signature: "FTP protocol interaction".to_string(),
                    },
                    0.75,
                    "Server attempted FTP connection".to_string(),
                ));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_injected_uses_query_by_default() {
        let det = SsrfDetector::new(SsrfConfig::default());
        let url = Url::parse("http://t/a?url=x&q=1").unwrap();
        let req = det.build_injected(&url, "url", "http://169.254.169.254/", &[]);
        assert_eq!(req.method, Method::GET);
        assert!(req.url.query().unwrap().contains("url=http"));
        assert!(req.url.query().unwrap().contains("q=1"));
        assert!(req.body.is_none());
    }

    #[test]
    fn build_injected_uses_post_body_when_configured() {
        let mut cfg = SsrfConfig::default();
        cfg.post_body = Some("url=orig&x=1".to_string());
        let det = SsrfDetector::new(cfg);
        let url = Url::parse("http://t/a").unwrap();
        let req = det.build_injected(&url, "url", "http://169.254.169.254/", &[]);
        assert_eq!(req.method, Method::POST);
        let body = String::from_utf8_lossy(req.body.as_deref().unwrap_or_default()).to_string();
        assert!(body.contains("url=http")); // injected
        assert!(body.contains("x=1")); // other field preserved
    }

    #[test]
    fn build_injected_attaches_extra_headers() {
        let det = SsrfDetector::new(SsrfConfig::default());
        let url = Url::parse("http://t/a?url=x").unwrap();
        let headers = vec![("Metadata-Flavor".to_string(), "Google".to_string())];
        let req = det.build_injected(&url, "url", "http://metadata.google/", &headers);
        assert_eq!(
            req.headers.get("metadata-flavor").and_then(|v| v.to_str().ok()),
            Some("Google")
        );
    }
}

