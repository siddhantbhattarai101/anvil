//! Passive security-header & cookie audit (OWASP A05, CWE-693 family).
//!
//! Unlike the active detectors this sends no payloads: it inspects the headers
//! of a normal response and reports missing or weak hardening controls
//! (HSTS, CSP, anti-clickjacking, MIME-sniffing, referrer policy, version
//! disclosure, and insecure cookie flags). The audit is a pure function over
//! the response headers so it is trivially testable; the engine supplies the
//! headers and HTTPS context.

use crate::reporting::model::Severity;
use std::collections::HashMap;

/// A single hardening gap found in a response.
#[derive(Debug, Clone)]
pub struct HeaderIssue {
    pub title: String,
    pub severity: Severity,
    pub cwe: &'static str,
    pub cvss: f32,
    /// What was observed.
    pub evidence: String,
    /// Concrete fix.
    pub remediation: String,
    /// Business impact.
    pub impact: String,
}

fn issue(
    title: &str,
    severity: Severity,
    cwe: &'static str,
    cvss: f32,
    evidence: &str,
    impact: &str,
    remediation: &str,
) -> HeaderIssue {
    HeaderIssue {
        title: title.to_string(),
        severity,
        cwe,
        cvss,
        evidence: evidence.to_string(),
        impact: impact.to_string(),
        remediation: remediation.to_string(),
    }
}

/// Audit response headers (keys expected lower-cased) for hardening gaps.
pub fn audit_headers(headers: &HashMap<String, String>, is_https: bool) -> Vec<HeaderIssue> {
    let has = |k: &str| headers.contains_key(k);
    let get = |k: &str| headers.get(k).map(|s| s.to_lowercase()).unwrap_or_default();
    let mut out = Vec::new();

    // --- Transport security (HTTPS only) ---
    if is_https && !has("strict-transport-security") {
        out.push(issue(
            "Missing Strict-Transport-Security (HSTS)",
            Severity::Medium,
            "CWE-319",
            5.3,
            "No Strict-Transport-Security header on an HTTPS response.",
            "Users can be downgraded to HTTP and have traffic intercepted (SSL stripping).",
            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS responses.",
        ));
    }

    // --- Content Security Policy ---
    if !has("content-security-policy") {
        out.push(issue(
            "Missing Content-Security-Policy",
            Severity::Low,
            "CWE-693",
            3.1,
            "No Content-Security-Policy header.",
            "No defence-in-depth against XSS and resource-injection.",
            "Define a Content-Security-Policy restricting script/style/object sources.",
        ));
    }

    // --- Clickjacking ---
    let csp = get("content-security-policy");
    if !has("x-frame-options") && !csp.contains("frame-ancestors") {
        out.push(issue(
            "Missing anti-clickjacking controls",
            Severity::Medium,
            "CWE-1021",
            4.3,
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is set.",
            "The page can be framed by a malicious site for clickjacking/UI-redress attacks.",
            "Set 'X-Frame-Options: DENY' (or SAMEORIGIN) or a CSP 'frame-ancestors' directive.",
        ));
    }

    // --- MIME sniffing ---
    if get("x-content-type-options") != "nosniff" {
        out.push(issue(
            "Missing X-Content-Type-Options: nosniff",
            Severity::Low,
            "CWE-693",
            3.1,
            "X-Content-Type-Options is absent or not set to 'nosniff'.",
            "Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
            "Send 'X-Content-Type-Options: nosniff' on all responses.",
        ));
    }

    // --- Referrer policy ---
    if !has("referrer-policy") {
        out.push(issue(
            "Missing Referrer-Policy",
            Severity::Info,
            "CWE-200",
            0.0,
            "No Referrer-Policy header.",
            "Full URLs (possibly with sensitive tokens) may leak to third parties via Referer.",
            "Set e.g. 'Referrer-Policy: strict-origin-when-cross-origin'.",
        ));
    }

    // --- Version / technology disclosure ---
    let server = get("server");
    if server.chars().any(|c| c.is_ascii_digit()) {
        out.push(issue(
            "Server version disclosure",
            Severity::Low,
            "CWE-200",
            3.1,
            &format!("Server header reveals software/version: '{}'.", headers.get("server").cloned().unwrap_or_default()),
            "Exposes the exact server software/version, easing targeted exploitation.",
            "Suppress or genericise the Server header.",
        ));
    }
    if has("x-powered-by") {
        out.push(issue(
            "Technology disclosure via X-Powered-By",
            Severity::Low,
            "CWE-200",
            3.1,
            &format!("X-Powered-By header present: '{}'.", headers.get("x-powered-by").cloned().unwrap_or_default()),
            "Reveals the backend technology stack, aiding fingerprinting.",
            "Remove the X-Powered-By header.",
        ));
    }

    // --- Cookie flags (single Set-Cookie observable via the headers map) ---
    if let Some(cookie) = headers.get("set-cookie") {
        let c = cookie.to_lowercase();
        if is_https && !c.contains("secure") {
            out.push(issue(
                "Cookie set without the Secure flag",
                Severity::Medium,
                "CWE-614",
                5.3,
                &format!("Set-Cookie lacks 'Secure': {cookie}"),
                "The cookie can be transmitted over plaintext HTTP and intercepted.",
                "Add the 'Secure' attribute to cookies on HTTPS sites.",
            ));
        }
        if !c.contains("httponly") {
            out.push(issue(
                "Cookie set without the HttpOnly flag",
                Severity::Low,
                "CWE-1004",
                3.1,
                &format!("Set-Cookie lacks 'HttpOnly': {cookie}"),
                "The cookie is readable from JavaScript, exposing it to theft via XSS.",
                "Add the 'HttpOnly' attribute to session cookies.",
            ));
        }
        if !c.contains("samesite") {
            out.push(issue(
                "Cookie set without a SameSite attribute",
                Severity::Low,
                "CWE-1275",
                3.1,
                &format!("Set-Cookie lacks 'SameSite': {cookie}"),
                "The cookie is sent on cross-site requests, enabling CSRF.",
                "Add 'SameSite=Lax' (or Strict) to cookies.",
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn bare_response_flags_the_core_headers() {
        let issues = audit_headers(&map(&[]), false);
        let titles: Vec<_> = issues.iter().map(|i| i.title.as_str()).collect();
        assert!(titles.iter().any(|t| t.contains("Content-Security-Policy")));
        assert!(titles.iter().any(|t| t.contains("clickjacking")));
        assert!(titles.iter().any(|t| t.contains("nosniff")));
        assert!(titles.iter().any(|t| t.contains("Referrer-Policy")));
    }

    #[test]
    fn fully_hardened_response_is_clean() {
        let h = map(&[
            ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
            ("x-frame-options", "DENY"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "strict-origin-when-cross-origin"),
        ]);
        assert!(audit_headers(&h, false).is_empty());
    }

    #[test]
    fn hsts_only_required_on_https() {
        let h = map(&[
            ("content-security-policy", "frame-ancestors 'none'"),
            ("x-frame-options", "DENY"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
        ]);
        assert!(audit_headers(&h, false).is_empty()); // http: no HSTS expected
        let on_https = audit_headers(&h, true);
        assert_eq!(on_https.len(), 1);
        assert!(on_https[0].title.contains("HSTS"));
    }

    #[test]
    fn server_version_disclosure_needs_a_digit() {
        let bare = map(&[("server", "nginx")]);
        assert!(!audit_headers(&bare, false).iter().any(|i| i.title.contains("version disclosure")));
        let versioned = map(&[("server", "nginx/1.25.3")]);
        assert!(audit_headers(&versioned, false).iter().any(|i| i.title.contains("version disclosure")));
    }
}
