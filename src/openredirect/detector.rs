//! Open redirect (CWE-601) detection.
//!
//! Evidence-driven: a unique canary host is injected via the common redirect
//! bypass forms (absolute, scheme-relative, missing-slash, backslash). A hit is
//! confirmed only when the *effective redirect target host* resolves to the
//! canary — read from the `Location` header of a 3xx, a `<meta http-equiv
//! refresh>`, or a `location.*` JavaScript assignment. Because we compare the
//! parsed host (not mere substring presence), a payload reflected as a query
//! parameter on a same-site redirect (`/go?next=//canary`) does not match.

use crate::sqli::request::Request;
use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;

/// A confirmed open-redirect vector.
#[derive(Debug, Clone)]
pub struct OpenRedirVector {
    /// How the redirect was delivered.
    pub technique: &'static str, // "Location header" | "meta refresh" | "javascript"
    pub payload: String,
    /// The observed redirect target.
    pub location: String,
}

/// Canary host under a reserved (`.example`) TLD — never actually contacted,
/// unmistakably not the target, and unlikely to appear in a real response.
const CANARY: &str = "anvil-redirect.example";

/// Redirect bypass payloads. Each should drive the victim to `CANARY` if the
/// destination parameter is used unvalidated.
fn payloads() -> Vec<String> {
    let c = CANARY;
    vec![
        format!("https://{c}/"),   // plain absolute
        format!("//{c}/"),         // scheme-relative (most common real bug)
        format!("https:/{c}/"),    // missing one slash
        format!("https:\\\\{c}\\"),// backslash variant
        format!("/\\{c}/"),        // leading-slash + backslash
        format!("https://{c}"),    // no trailing slash
        format!("////{c}/"),       // extra slashes
    ]
}

lazy_static! {
    // <meta http-equiv="refresh" content="0; url=https://canary/">
    static ref META: Regex =
        Regex::new(r#"(?i)<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=([^"'>\s]+)"#).unwrap();
    // location = "...", location.href=..., location.replace('...'), window.location=...
    static ref JS: Regex =
        Regex::new(r#"(?i)location(?:\.href|\.replace)?\s*(?:=|\()\s*["']([^"']+)["']"#).unwrap();
}

/// Parse a (possibly relative/obfuscated) redirect target and return its host.
fn redirect_host(location: &str) -> Option<String> {
    let loc = location.trim();
    // Servers/browsers treat backslashes in the authority like forward slashes.
    let norm = loc.replace('\\', "/");
    let parsed = if norm.starts_with("//") {
        url::Url::parse(&format!("https:{norm}")).ok()
    } else {
        url::Url::parse(&norm).ok()
    };
    parsed.and_then(|u| u.host_str().map(|h| h.to_lowercase()))
}

fn points_to_canary(location: &str) -> bool {
    redirect_host(location).as_deref() == Some(CANARY)
}

/// Check a parameter for open redirect.
pub async fn check_open_redirect(request: &Request<'_>) -> Result<Option<OpenRedirVector>> {
    for payload in payloads() {
        let resp = request.query_response(&payload).await?;

        // 1) Location header on a 3xx response (authoritative).
        if (300..400).contains(&resp.status) {
            if let Some(loc) = resp.headers.get("location") {
                if points_to_canary(loc) {
                    return Ok(Some(OpenRedirVector {
                        technique: "Location header",
                        payload,
                        location: loc.clone(),
                    }));
                }
            }
        }

        // 2) Client-side redirects in the body (also authoritative directives).
        let body = resp.body_text();
        if let Some(m) = META.captures(&body).and_then(|c| c.get(1)) {
            if points_to_canary(m.as_str()) {
                return Ok(Some(OpenRedirVector {
                    technique: "meta refresh",
                    payload,
                    location: m.as_str().to_string(),
                }));
            }
        }
        if let Some(m) = JS.captures(&body).and_then(|c| c.get(1)) {
            if points_to_canary(m.as_str()) {
                return Ok(Some(OpenRedirVector {
                    technique: "javascript",
                    payload,
                    location: m.as_str().to_string(),
                }));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_host_is_detected_across_forms() {
        assert!(points_to_canary("https://anvil-redirect.example/"));
        assert!(points_to_canary("//anvil-redirect.example/path"));
        assert!(points_to_canary("https:\\\\anvil-redirect.example\\"));
        assert!(points_to_canary("https://anvil-redirect.example"));
    }

    #[test]
    fn same_site_redirect_carrying_payload_does_not_match() {
        // The payload is reflected as a query param, but the redirect stays
        // on the target host — NOT an open redirect.
        assert!(!points_to_canary("https://target.com/go?next=//anvil-redirect.example"));
        assert!(!points_to_canary("/login?return=https://anvil-redirect.example"));
        assert!(!points_to_canary("https://target.com/home"));
    }

    #[test]
    fn meta_and_js_extraction() {
        let meta = r#"<meta http-equiv="refresh" content="0; url=https://anvil-redirect.example/">"#;
        let cap = META.captures(meta).and_then(|c| c.get(1)).unwrap();
        assert!(points_to_canary(cap.as_str()));

        let js = r#"<script>window.location.replace("https://anvil-redirect.example/")</script>"#;
        let cap = JS.captures(js).and_then(|c| c.get(1)).unwrap();
        assert!(points_to_canary(cap.as_str()));
    }

    #[test]
    fn payloads_all_carry_the_canary() {
        for p in payloads() {
            assert!(p.contains(CANARY), "payload missing canary: {p}");
        }
    }
}
