// Stored/Persistent XSS Detection Module
// Tracks payloads across requests and correlates delayed execution

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::payload::injector::inject_query_param;
use crate::xss::context::{classify_context, ContextAnalysis};
use crate::xss::validate::validate_execution_likelihood;
use crate::reporting::model::{Finding, Severity};
use reqwest::Method;
use url::Url;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct StoredPayloadTracker {
    pub id: String,
    pub injection_url: String,
    pub injection_param: String,
    pub payload: String,
    pub timestamp: u64,
}

pub struct StoredXssEngine {
    pub crawl_depth: usize,
    pub payloads: HashMap<String, StoredPayloadTracker>,
    pub tested_urls: HashSet<String>,
}

impl Default for StoredXssEngine {
    fn default() -> Self {
        Self {
            crawl_depth: 3,
            payloads: HashMap::new(),
            tested_urls: HashSet::new(),
        }
    }
}

impl StoredXssEngine {
    pub fn new(crawl_depth: usize) -> Self {
        Self {
            crawl_depth,
            payloads: HashMap::new(),
            tested_urls: HashSet::new(),
        }
    }
    
    /// Phase 1: Inject storage test markers
    pub async fn inject_markers(
        &mut self,
        client: &HttpClient,
        injection_urls: &[(Url, Vec<String>)], // (URL, parameters)
    ) -> anyhow::Result<()> {
        tracing::info!("Stored XSS Phase 1: Injecting {} test markers", injection_urls.len());
        
        for (url, params) in injection_urls {
            for param in params {
                let tracker = self.inject_single_marker(client, url, param).await?;
                self.payloads.insert(tracker.id.clone(), tracker);
            }
        }
        
        tracing::info!("✓ Injected {} persistent markers", self.payloads.len());
        Ok(())
    }
    
    async fn inject_single_marker(
        &self,
        client: &HttpClient,
        url: &Url,
        param: &str,
    ) -> anyhow::Result<StoredPayloadTracker> {
        let tracker = StoredPayloadTracker {
            id: generate_unique_id(),
            injection_url: url.to_string(),
            injection_param: param.to_string(),
            payload: generate_stored_marker(),
            timestamp: current_timestamp(),
        };
        
        // Inject via GET
        let test_url = inject_query_param(url, param, &tracker.payload)?;
        let request = HttpRequest::new(Method::GET, test_url);
        client.execute(request).await?;
        
        // Small delay to allow persistence
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        Ok(tracker)
    }
    
    /// Phase 2: Crawl and check for marker resurfacing
    pub async fn check_persistence(
        &mut self,
        client: &HttpClient,
        base_url: &Url,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) -> anyhow::Result<()> {
        tracing::info!("Stored XSS Phase 2: Checking persistence across application");
        
        // Crawl the application
        let crawler = crate::scanner::crawler::Crawler::new(self.crawl_depth);
        // TODO: Get scope from context instead of client
        let scope = crate::core::scope::Scope::new(&base_url.to_string())?;
        let sitemap = crawler
            .crawl(client, base_url.clone(), &scope)
            .await?;
        
        let mut findings = 0;
        
        for (path, _ep) in sitemap.endpoints.iter() {
            if !self.tested_urls.insert(path.clone()) {
                continue; // Already tested
            }
            
            let url = match base_url.join(path) {
                Ok(u) => u,
                Err(_) => continue,
            };
            
            let request = HttpRequest::new(Method::GET, url.clone());
            let response = match client.execute(request).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            
            // Check if any of our markers resurfaced
            let body_str = String::from_utf8_lossy(&response.body).to_string();
            for (id, tracker) in &self.payloads {
                if body_str.contains(&tracker.payload) {
                    findings += 1;
                    
                    let context = classify_context(&body_str, &tracker.payload);
                    let validation = validate_execution_likelihood(
                        &body_str,
                        &tracker.payload,
                        &context.context,
                    );
                    
                    tracing::info!(
                        "✓ Stored XSS found: {} → {} (confidence: {:.0}%)",
                        tracker.injection_param,
                        path,
                        validation.confidence * 100.0
                    );
                    
                    reporter.add(Finding {
                        vuln_type: "XSS".to_string(),
                        technique: "Stored XSS".to_string(),
                        endpoint: path.to_string(),
                        parameter: Some(tracker.injection_param.clone()),
                        confidence: validation.confidence,
                        severity: match validation.severity {
                            crate::xss::validate::ExecutionSeverity::Critical => Severity::Critical,
                            crate::xss::validate::ExecutionSeverity::High => Severity::High,
                            crate::xss::validate::ExecutionSeverity::Medium => Severity::Medium,
                            _ => Severity::Low,
                        },
                        evidence: format!(
                            "Persistent XSS marker resurfaced on {}\nOriginal injection: {} parameter '{}'\nContext: {:?}\nExecution likelihood: {:.0}%\nDetails: {}",
                            path,
                            tracker.injection_url,
                            tracker.injection_param,
                            context.context,
                            validation.confidence * 100.0,
                            validation.technical_details
                        ),
                        http_method: "GET".to_string(),
                        database: None,
                        cwe: "CWE-79".to_string(),
                        cvss_score: Some(calculate_cvss_score(validation.confidence, &validation.severity)),
                        description: generate_stored_xss_description(&tracker, &context, &validation),
                        impact: generate_stored_xss_impact(),
                        remediation: generate_xss_remediation(),
                        references: vec![
                            "https://owasp.org/www-community/attacks/xss/".to_string(),
                            "https://cwe.mitre.org/data/definitions/79.html".to_string(),
                            "https://portswigger.net/web-security/cross-site-scripting/stored".to_string(),
                        ],
                        payload_sample: Some(tracker.payload.clone()),
                    });
                }
            }
        }
        
        tracing::info!("✓ Stored XSS scan complete: {} findings", findings);
        Ok(())
    }
    
    /// Run full stored XSS detection (inject + check)
    pub async fn run(
        &mut self,
        client: &HttpClient,
        injection_url: &Url,
        param: &str,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) -> anyhow::Result<()> {
        // Inject marker
        let tracker = self.inject_single_marker(client, injection_url, param).await?;
        self.payloads.insert(tracker.id.clone(), tracker.clone());
        
        // Wait for persistence
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        // Check for resurfacing
        self.check_persistence(client, injection_url, reporter).await
    }
}

fn generate_unique_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    // Monotonic counter guarantees uniqueness even within the same second; the
    // timestamp alone collided for IDs generated back-to-back.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let timestamp = current_timestamp();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("ANVIL_STORED_{}{:x}", timestamp, seq)
}

fn generate_stored_marker() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static MARKER_COUNTER: AtomicU64 = AtomicU64::new(0);
    let timestamp = current_timestamp();
    let seq = MARKER_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("<ANVIL_STORED_XSS_{}{:x}>", timestamp, seq)
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn calculate_cvss_score(
    confidence: f32,
    severity: &crate::xss::validate::ExecutionSeverity,
) -> f32 {
    let base_score = match severity {
        crate::xss::validate::ExecutionSeverity::Critical => 9.0,
        crate::xss::validate::ExecutionSeverity::High => 7.5,
        crate::xss::validate::ExecutionSeverity::Medium => 5.5,
        crate::xss::validate::ExecutionSeverity::Low => 3.5,
        crate::xss::validate::ExecutionSeverity::Info => 0.0,
    };
    
    // Adjust by confidence
    base_score * confidence
}

fn generate_stored_xss_description(
    tracker: &StoredPayloadTracker,
    context: &ContextAnalysis,
    validation: &crate::xss::validate::XssValidationResult,
) -> String {
    format!(
        "Stored/Persistent Cross-Site Scripting (XSS) vulnerability detected.\n\n\
        The application accepts and stores user-supplied input without proper sanitization, \
        then reflects it back to other users in a dangerous context. This allows an attacker \
        to inject malicious JavaScript that will execute in victims' browsers.\n\n\
        INJECTION POINT:\n\
        • URL: {}\n\
        • Parameter: {}\n\
        • Injection Context: {:?}\n\n\
        PERSISTENCE:\n\
        The injected payload is stored persistently and will execute for all users who \
        access pages where the data is displayed.\n\n\
        TECHNICAL ANALYSIS:\n\
        {}",
        tracker.injection_url,
        tracker.injection_param,
        context.context,
        validation.technical_details
    )
}

fn generate_stored_xss_impact() -> String {
    r#"CRITICAL RISK: Stored XSS is one of the most dangerous web vulnerabilities.

An attacker exploiting this stored XSS vulnerability can:

1. SESSION HIJACKING & ACCOUNT TAKEOVER
   • Steal session cookies of ALL users who view the injected content
   • Impersonate victims and gain full account access
   • Access sensitive data and perform actions as the victim

2. CREDENTIAL THEFT
   • Inject fake login forms to capture credentials
   • Steal authentication tokens and API keys
   • Harvest personally identifiable information (PII)

3. MALWARE DISTRIBUTION
   • Inject drive-by download exploits
   • Redirect users to malicious sites
   • Install keyloggers and browser-based malware

4. DATA EXFILTRATION
   • Extract all data visible to the victim
   • Send sensitive information to attacker-controlled servers
   • Capture user interactions and form submissions

5. PRIVILEGE ESCALATION
   • Target administrator accounts
   • Gain elevated access through admin victims
   • Modify application settings and configurations

6. WORM PROPAGATION
   • Create self-replicating XSS worms
   • Automatically inject payload into other users' profiles
   • Rapidly spread across the application

7. SOCIAL ENGINEERING
   • Display fake security warnings
   • Phish for sensitive information
   • Manipulate users into performing dangerous actions

8. APPLICATION DEFACEMENT
   • Modify page content for all users
   • Damage brand reputation
   • Display inappropriate or harmful content

PERSISTENT IMPACT:
Unlike reflected XSS, stored XSS affects multiple victims over time without
requiring attacker interaction. The payload remains active until removed."#.to_string()
}

fn generate_xss_remediation() -> String {
    r#"IMMEDIATE ACTIONS REQUIRED:

1. **INPUT VALIDATION (Defense in Depth)**
   ✅ Whitelist allowed characters and patterns
   • For names: Only allow [a-zA-Z0-9\s\-']
   • For emails: Use strict email regex
   • For URLs: Validate protocol and domain
   • For numbers: Type-check as integers/floats
   
   ✅ Reject or sanitize dangerous patterns
   • Block <script>, javascript:, onerror=, etc.
   • Remove or encode HTML special characters
   • Set maximum length limits

2. **OUTPUT ENCODING (Primary Defense)**
   ❌ NEVER output user data directly into HTML
   
   ✅ ALWAYS encode based on context:
   
   HTML Context:
   • Encode: < > " ' & / 
   • Use: HTML entity encoding
   • Library: Use framework's HTML escape function
   
   JavaScript Context:
   • Encode: \ " ' newline
   • Use: JavaScript escape function
   • Better: Use JSON.stringify() for data
   
   URL Context:
   • Use: URL encoding (percent-encoding)
   • Validate: Only allow safe protocols (http, https)
   
   CSS Context:
   • Avoid user input in CSS
   • If required: Use CSS escaping

3. **CONTENT SECURITY POLICY (CSP)**
   Implement strict CSP headers:
   
   Content-Security-Policy:
     default-src 'self';
     script-src 'self' 'nonce-{random}';
     object-src 'none';
     base-uri 'none';
     
   This prevents inline scripts and untrusted sources.

4. **HTTPONLY & SECURE COOKIES**
   Set-Cookie: sessionid=...; HttpOnly; Secure; SameSite=Strict
   
   • HttpOnly: Prevents JavaScript from accessing cookies
   • Secure: Only send over HTTPS
   • SameSite: Prevents CSRF attacks

5. **INPUT SANITIZATION LIBRARIES**
   Use battle-tested libraries:
   • DOMPurify (JavaScript)
   • Bleach (Python)
   • OWASP Java HTML Sanitizer
   • HtmlSanitizer (.NET)

6. **FRAMEWORK PROTECTIONS**
   Enable built-in XSS protection:
   • React: Use JSX (auto-escapes by default)
   • Angular: Use interpolation {{ }} (auto-escapes)
   • Vue: Use {{ }} and v-text (auto-escapes)
   • Django: Use {{ }} templates (auto-escapes)

7. **DATABASE STORAGE**
   • Store data in original form (don't encode for storage)
   • Encode ONLY when outputting to browser
   • Never trust data from database (assume compromised)

8. **WEB APPLICATION FIREWALL (WAF)**
   Deploy WAF as additional layer:
   • ModSecurity
   • Cloudflare WAF
   • AWS WAF
   • Imperva

9. **SECURITY HEADERS**
   Implement additional headers:
   • X-Content-Type-Options: nosniff
   • X-Frame-Options: DENY
   • X-XSS-Protection: 1; mode=block (legacy browsers)

10. **REGULAR SECURITY TESTING**
    • Automated scanning in CI/CD pipeline
    • Manual penetration testing
    • Bug bounty program
    • Security code reviews

TESTING YOUR FIX:
After implementing, verify the fix by:
1. Injecting test payloads (ensure they're encoded)
2. Checking page source (special chars should be entities)
3. Running automated XSS scanners
4. Validating CSP is active (browser dev tools)"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_marker_generation() {
        let marker = generate_stored_marker();
        assert!(marker.contains("ANVIL_STORED_XSS"));
        assert!(marker.starts_with('<'));
        assert!(marker.ends_with('>'));
    }
    
    #[test]
    fn test_unique_id_generation() {
        let id1 = generate_unique_id();
        let id2 = generate_unique_id();
        assert_ne!(id1, id2);
    }
}
