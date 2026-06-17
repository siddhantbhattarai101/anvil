//! Server-Side Template Injection (CWE-1336) detection.
//!
//! Evidence-driven, mirroring ANVIL's other engines. A fixed arithmetic
//! expression (`7919*6841`) wrapped in a unique random marker is injected using
//! each common template syntax (`{{…}}`, `${…}`, `<%=…%>`, `{…}`, `@(…)`,
//! `#{…}`). A hit is confirmed only when the response contains
//! `{marker}{product}{marker}` — i.e. the engine actually evaluated the
//! multiplication. A merely reflected payload still contains the literal
//! `7919*6841`, never the product, so reflection alone cannot raise a finding.
//!
//! The matching syntax also fingerprints the likely template family, which is
//! reported as a hint for follow-up (SSTI frequently escalates to RCE).

use crate::sqli::request::Request;
use anyhow::Result;

/// A confirmed SSTI vector.
#[derive(Debug, Clone)]
pub struct SstiVector {
    /// Template family/families the matching delimiter targets.
    pub engine: &'static str,
    /// The payload that triggered evaluation.
    pub payload: String,
    /// The evaluated `{marker}{product}{marker}` string found in the response.
    pub evidence: String,
}

/// Two distinct primes; their product is unmistakable and never a substring of
/// the literal factors, so it can only appear if the engine did the arithmetic.
const A: u64 = 7919;
const B: u64 = 6841;

/// Template delimiters to probe: (engine family, open, close).
/// No inner spaces — keeps the expression valid across Smarty/Jinja/ERB alike.
const SYNTAXES: &[(&str, &str, &str)] = &[
    ("Jinja2/Twig/Nunjucks/Django/Liquid", "{{", "}}"),
    ("Freemarker/Mako/JSP-EL/Thymeleaf/Velocity", "${", "}"),
    ("ERB/EJS", "<%=", "%>"),
    ("Smarty", "{", "}"),
    ("Razor (.NET)", "@(", ")"),
    ("Pug/Jade", "#{", "}"),
];

/// A process-unique, low-collision marker tag for one probe.
fn marker_tag() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static C: AtomicU64 = AtomicU64::new(0);
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let s = C.fetch_add(1, Ordering::Relaxed);
    format!("st{n:x}{s:x}")
}

/// Build the probe for one syntax: returns (payload, expected evidence).
/// `payload`  = `{tag}{open}A*B{close}{tag}`  (engine renders the product)
/// `expected` = `{tag}{product}{tag}`         (present only after evaluation)
fn probe(open: &str, close: &str) -> (String, String) {
    let tag = marker_tag();
    let payload = format!("{tag}{open}{A}*{B}{close}{tag}");
    let expected = format!("{tag}{}{tag}", A * B);
    (payload, expected)
}

/// Check a parameter for server-side template injection.
pub async fn check_ssti(request: &Request<'_>) -> Result<Option<SstiVector>> {
    for (engine, open, close) in SYNTAXES {
        let (payload, expected) = probe(open, close);
        let page = request.query_page(&payload).await?;
        if page.contains(&expected) {
            return Ok(Some(SstiVector {
                engine,
                payload,
                evidence: expected,
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_is_correct() {
        assert_eq!(A * B, 54173879);
    }

    #[test]
    fn payload_never_contains_the_evaluated_evidence() {
        // Anti-false-positive invariant: the expected (post-evaluation) string
        // must never appear in the payload itself, or reflection would match.
        for (_, open, close) in SYNTAXES {
            let (payload, expected) = probe(open, close);
            assert!(
                !payload.contains(&expected),
                "evidence leaks into payload for {open}…{close}: {payload}"
            );
        }
    }

    #[test]
    fn evaluated_response_matches_evidence() {
        // Simulate an engine rendering `{{A*B}}` -> product; evidence must match.
        let tag = "stDEADBEEF";
        let payload = format!("{tag}{{{{{A}*{B}}}}}{tag}");
        let expected = format!("{tag}{}{tag}", A * B);
        // Engine replaces the delimited expression with its product.
        let rendered = payload.replace(&format!("{{{{{A}*{B}}}}}"), &(A * B).to_string());
        assert!(rendered.contains(&expected));
    }

    #[test]
    fn every_syntax_has_balanced_nonempty_delimiters() {
        for (engine, open, close) in SYNTAXES {
            assert!(!open.is_empty() && !close.is_empty(), "empty delim for {engine}");
        }
    }
}
