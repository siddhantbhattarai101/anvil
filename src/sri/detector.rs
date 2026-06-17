//! Missing Subresource Integrity (SRI) detection (OWASP A08, CWE-353).
//!
//! Passive: parses `<script src>` and `<link rel=stylesheet href>` tags in the
//! response and flags cross-origin resources that lack an `integrity` attribute.
//! Without SRI a compromised third-party/CDN host can serve malicious code that
//! the browser executes with the page's trust — a software-integrity failure.
//! Same-origin and already-protected (integrity-bearing) resources are ignored,
//! so a correctly configured page does not false-positive.

use crate::reporting::model::Severity;
use lazy_static::lazy_static;
use regex::Regex;

/// A resource loaded cross-origin without integrity protection.
#[derive(Debug, Clone)]
pub struct SriFinding {
    pub kind: &'static str, // "script" | "stylesheet"
    pub resource: String,
}

lazy_static! {
    static ref SCRIPT: Regex = Regex::new(r"(?is)<script\b([^>]*)>").unwrap();
    static ref LINK: Regex = Regex::new(r"(?is)<link\b([^>]*)>").unwrap();
    static ref ATTR_SRC: Regex = Regex::new(r#"(?i)\bsrc\s*=\s*["']([^"']+)["']"#).unwrap();
    static ref ATTR_HREF: Regex = Regex::new(r#"(?i)\bhref\s*=\s*["']([^"']+)["']"#).unwrap();
    static ref ATTR_REL: Regex = Regex::new(r#"(?i)\brel\s*=\s*["']([^"']+)["']"#).unwrap();
}

/// Extract the host (without scheme/port) from an absolute or protocol-relative
/// URL. Returns None for relative URLs (which are inherently same-origin).
fn host_of(url: &str) -> Option<String> {
    let rest = if let Some(r) = url.strip_prefix("https://") {
        r
    } else if let Some(r) = url.strip_prefix("http://") {
        r
    } else if let Some(r) = url.strip_prefix("//") {
        r
    } else {
        return None; // relative → same origin
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.split('@').last().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn has_integrity(attrs: &str) -> bool {
    attrs.to_ascii_lowercase().contains("integrity")
}

fn is_cross_origin(url: &str, page_host: &str) -> bool {
    match host_of(url) {
        Some(h) => h != page_host.to_ascii_lowercase(),
        None => false,
    }
}

/// Scan a response body for cross-origin resources missing SRI.
pub fn scan_sri(body: &str, page_host: &str) -> Vec<SriFinding> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for cap in SCRIPT.captures_iter(body) {
        let attrs = &cap[1];
        if let Some(src) = ATTR_SRC.captures(attrs).and_then(|c| c.get(1)) {
            let url = src.as_str();
            if is_cross_origin(url, page_host) && !has_integrity(attrs) && seen.insert(url.to_string()) {
                out.push(SriFinding { kind: "script", resource: url.to_string() });
            }
        }
    }

    for cap in LINK.captures_iter(body) {
        let attrs = &cap[1];
        let rel = ATTR_REL
            .captures(attrs)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        if !rel.contains("stylesheet") {
            continue; // only style/script resources execute or style the page
        }
        if let Some(href) = ATTR_HREF.captures(attrs).and_then(|c| c.get(1)) {
            let url = href.as_str();
            if is_cross_origin(url, page_host) && !has_integrity(attrs) && seen.insert(url.to_string()) {
                out.push(SriFinding { kind: "stylesheet", resource: url.to_string() });
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("https://cdn.example.com/a.js").as_deref(), Some("cdn.example.com"));
        assert_eq!(host_of("//cdn.example.com/a.js").as_deref(), Some("cdn.example.com"));
        assert_eq!(host_of("http://h:8080/a.js").as_deref(), Some("h"));
        assert_eq!(host_of("/local/a.js"), None);
        assert_eq!(host_of("a.js"), None);
    }

    #[test]
    fn flags_cross_origin_script_without_integrity() {
        let body = r#"<script src="https://cdn.example.com/lib.js"></script>"#;
        let f = scan_sri(body, "myapp.test");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "script");
    }

    #[test]
    fn script_with_integrity_is_clean() {
        let body = r#"<script src="https://cdn.example.com/lib.js" integrity="sha384-x" crossorigin></script>"#;
        assert!(scan_sri(body, "myapp.test").is_empty());
    }

    #[test]
    fn same_origin_and_relative_are_ignored() {
        let body = r#"<script src="/static/app.js"></script><script src="https://myapp.test/x.js"></script>"#;
        assert!(scan_sri(body, "myapp.test").is_empty());
    }

    #[test]
    fn flags_cross_origin_stylesheet_but_not_icon() {
        let body = r#"<link rel="stylesheet" href="https://cdn.example.com/a.css">
                      <link rel="icon" href="https://cdn.example.com/favicon.ico">"#;
        let f = scan_sri(body, "myapp.test");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "stylesheet");
    }
}
