//! CORS misconfiguration (CWE-942 / CWE-346) detection.
//!
//! Evidence-driven: crafted `Origin` request headers are sent and the server's
//! `Access-Control-Allow-Origin` (ACAO) / `Access-Control-Allow-Credentials`
//! (ACAC) response headers are inspected. A finding is raised only when the
//! server *reflects* an attacker-controlled origin (or trusts `null`), which is
//! the misconfiguration itself — not merely the presence of CORS headers.
//! `ACAO: *` is reported separately at low severity (often intentional).

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use anyhow::Result;
use url::Url;

/// A confirmed CORS misconfiguration.
#[derive(Debug, Clone)]
pub struct CorsVector {
    /// What the server got wrong.
    pub issue: &'static str,
    /// The Origin we sent.
    pub origin: String,
    /// The ACAO value the server returned.
    pub acao: String,
    /// Whether ACAC: true accompanied it (credentialed cross-origin = worse).
    pub credentials: bool,
}

/// Attacker-controlled canary origin under a reserved TLD.
const ATTACKER: &str = "https://anvil-cors.example";

/// Probe the endpoint for reflected-origin / null-origin trust.
pub async fn check_cors(client: &HttpClient, url: &Url) -> Result<Option<CorsVector>> {
    let host = url.host_str().unwrap_or("");
    // (origin to send, issue if it is reflected). Most-severe first.
    let tests: Vec<(String, &'static str)> = vec![
        (ATTACKER.to_string(), "reflects an arbitrary external origin"),
        ("null".to_string(), "trusts the null origin"),
        (
            format!("https://{host}.anvil-cors.example"),
            "reflects an origin merely containing the trusted host",
        ),
    ];

    let mut wildcard: Option<CorsVector> = None;

    for (origin, issue) in tests {
        let mut req = HttpRequest::get(url.clone());
        req.set_header("Origin", &origin);
        let resp = client.execute(req).await?;

        let acao = resp
            .headers
            .get("access-control-allow-origin")
            .cloned()
            .unwrap_or_default();
        let credentials = resp
            .headers
            .get("access-control-allow-credentials")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if acao == "*" {
            // Wildcard: any origin can read, but browsers forbid credentials
            // with `*`. Note it, but keep probing for the stronger reflections.
            wildcard.get_or_insert(CorsVector {
                issue: "allows any origin via wildcard (ACAO: *)",
                origin: origin.clone(),
                acao: acao.clone(),
                credentials: false,
            });
            continue;
        }

        // Exact reflection of the attacker origin we sent = the vulnerability.
        if !acao.is_empty() && acao.eq_ignore_ascii_case(&origin) {
            return Ok(Some(CorsVector {
                issue,
                origin,
                acao,
                credentials,
            }));
        }
    }

    Ok(wildcard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attacker_origin_is_external_and_reserved() {
        // Sanity: the canary uses the reserved .example TLD so it is never a
        // real, routable origin a target would legitimately trust.
        assert!(ATTACKER.ends_with(".example"));
        assert!(ATTACKER.starts_with("https://"));
    }

    #[test]
    fn credentials_flag_parsing_is_case_insensitive() {
        assert!("TRUE".eq_ignore_ascii_case("true"));
        assert!(!"false".eq_ignore_ascii_case("true"));
    }
}
