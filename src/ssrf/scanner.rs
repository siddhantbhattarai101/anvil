//! SSRF scanner - High-level scanning orchestration

use crate::http::client::HttpClient;
use crate::scanner::sitemap::SiteMap;
use crate::ssrf::detector::SsrfDetector;
use crate::ssrf::evidence::SsrfResult;
use crate::ssrf::params::SsrfParamIdentifier;
use crate::ssrf::SsrfConfig;
use url::Url;

/// High-level SSRF scanner
pub struct SsrfScanner {
    config: SsrfConfig,
    detector: SsrfDetector,
    param_identifier: SsrfParamIdentifier,
}

impl SsrfScanner {
    pub fn new(config: SsrfConfig) -> Self {
        let detector = SsrfDetector::new(config.clone());
        let param_identifier = SsrfParamIdentifier::new();

        Self {
            config,
            detector,
            param_identifier,
        }
    }

    /// Scan a URL for SSRF vulnerabilities
    pub async fn scan(
        &self,
        client: &HttpClient,
        target_url: &Url,
        sitemap: &SiteMap,
    ) -> anyhow::Result<Vec<SsrfResult>> {
        let mut results = Vec::new();

        tracing::info!("Starting SSRF scan");

        // Iterate through all endpoints in the sitemap
        for (path, endpoint) in &sitemap.endpoints {
            if endpoint.parameters.is_empty() {
                continue;
            }

            let mut endpoint_url = match target_url.join(path) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!("Failed to join path '{}': {}", path, e);
                    continue;
                }
            };

            // `join(path)` drops the query string, leaving candidate
            // identification nothing to work with and dropping sibling params
            // that may gate the vulnerable code path. Rebuild the URL preserving
            // ALL of the target URL's query parameters plus this endpoint's
            // discovered parameters (so URL-like params are found and tested with
            // their real values).
            {
                use std::collections::HashSet;
                let mut pairs: Vec<(String, String)> = Vec::new();
                let mut seen = HashSet::new();
                for (k, v) in target_url.query_pairs() {
                    if seen.insert(k.to_string()) {
                        pairs.push((k.to_string(), v.to_string()));
                    }
                }
                for p in &endpoint.parameters {
                    if seen.insert(p.clone()) {
                        pairs.push((p.clone(), "1".to_string()));
                    }
                }
                let mut qp = endpoint_url.query_pairs_mut();
                qp.clear();
                for (k, v) in &pairs {
                    qp.append_pair(k, v);
                }
            }

            tracing::debug!("Scanning endpoint: {}", endpoint_url);

            // Identify SSRF candidate parameters. In POST-body mode the
            // candidates come from the body (and are injected there); otherwise
            // from the URL query string.
            let candidates = match &self.config.post_body {
                Some(body) => self.param_identifier.identify_from_post_data(body),
                None => self.param_identifier.identify_from_url(&endpoint_url),
            };

            if candidates.is_empty() {
                tracing::debug!("No SSRF candidate parameters found in {}", endpoint_url);
                continue;
            }

            tracing::info!(
                "Found {} SSRF candidate parameter(s) in {}",
                candidates.len(),
                endpoint_url
            );

            // Test each candidate parameter
            for candidate in candidates {
                tracing::info!(
                    "Testing parameter '{}' (score: {:.1}, reason: {})",
                    candidate.param_name,
                    candidate.score,
                    candidate.reason
                );

                match self
                    .detector
                    .detect(
                        client,
                        &endpoint_url,
                        &candidate.param_name,
                        &candidate.param_value,
                    )
                    .await
                {
                    Ok(Some(result)) => {
                        tracing::warn!(
                            "[SSRF DETECTED] {} - {} (confidence: {:.0}%)",
                            result.classification.severity(),
                            result.endpoint,
                            result.confidence * 100.0
                        );
                        results.push(result);
                    }
                    Ok(None) => {
                        tracing::debug!("No SSRF detected in parameter '{}'", candidate.param_name);
                    }
                    Err(e) => {
                        tracing::error!(
                            "Error testing parameter '{}': {}",
                            candidate.param_name,
                            e
                        );
                    }
                }
            }
        }

        if results.is_empty() {
            tracing::info!("No SSRF vulnerabilities found");
        } else {
            tracing::warn!("Found {} SSRF vulnerabilities", results.len());
        }

        Ok(results)
    }

    /// Scan a single parameter directly
    pub async fn scan_parameter(
        &self,
        client: &HttpClient,
        url: &Url,
        param_name: &str,
    ) -> anyhow::Result<Option<SsrfResult>> {
        tracing::info!("Scanning parameter '{}' for SSRF", param_name);

        // Get original value
        let original_value = url
            .query_pairs()
            .find(|(k, _)| k == param_name)
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();

        // Run detection
        self.detector
            .detect(client, url, param_name, &original_value)
            .await
    }
}

impl SsrfConfig {
    /// Set OOB callback domain
    pub fn with_oob_callback(mut self, callback: Option<String>) -> Self {
        self.oob_callback = callback;
        self
    }

    /// Set confidence threshold
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.confidence_threshold = threshold;
        self
    }

    /// Enable/disable internal network testing
    pub fn with_internal_testing(mut self, enabled: bool) -> Self {
        self.test_internal = enabled;
        self
    }

    /// Enable/disable metadata testing
    pub fn with_metadata_testing(mut self, enabled: bool) -> Self {
        self.test_metadata = enabled;
        self
    }

    /// Enable/disable scheme testing
    pub fn with_scheme_testing(mut self, enabled: bool) -> Self {
        self.test_schemes = enabled;
        self
    }
}

