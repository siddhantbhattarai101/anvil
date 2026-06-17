//! CRLF / HTTP response header injection (CWE-113) detection.
//!
//! Evidence-driven: a payload that closes the current header line and injects a
//! unique `X-Anvil-Crlf: <token>` header is sent through the parameter. A hit is
//! confirmed only when that header appears in the *response headers* — which can
//! happen only if the server reflected the value into a header and honored the
//! CRLF. Reflection into the body cannot create a response header, so it cannot
//! false-positive. The injected header name + random token are unique, ruling
//! out a coincidental pre-existing header.

use crate::sqli::request::Request;
use anyhow::Result;

/// A confirmed CRLF header-injection vector.
#[derive(Debug, Clone)]
pub struct CrlfVector {
    pub payload: String,
    /// The header we successfully injected (name + value).
    pub injected_header: String,
}

/// Lower-cased name of the header we attempt to inject (response headers are
/// stored lower-cased, so this is also the lookup key).
const HDR: &str = "x-anvil-crlf";

fn token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static C: AtomicU64 = AtomicU64::new(0);
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let s = C.fetch_add(1, Ordering::Relaxed);
    format!("crlf{n:x}{s:x}")
}

/// CRLF break variants. The client URL-encodes these values, so literal control
/// characters arrive as `%0D%0A` etc.; `%0d%0a` (literal text) probes servers
/// that decode the parameter twice.
fn payloads(tok: &str) -> Vec<String> {
    let inj = format!("X-Anvil-Crlf:{tok}");
    vec![
        format!("anvil\r\n{inj}"),   // canonical CRLF
        format!("anvil\n{inj}"),     // bare LF (lenient parsers)
        format!("anvil%0d%0a{inj}"), // double-decoding servers
    ]
}

/// Check a parameter for CRLF / response header injection.
pub async fn check_crlf(request: &Request<'_>) -> Result<Option<CrlfVector>> {
    let tok = token();
    for payload in payloads(&tok) {
        let resp = match request.query_response(&payload).await {
            Ok(r) => r,
            Err(_) => continue, // a malformed-response error on one variant must
                                // not abort the others
        };
        if let Some(v) = resp.headers.get(HDR) {
            if v.trim() == tok {
                return Ok(Some(CrlfVector {
                    payload,
                    injected_header: format!("X-Anvil-Crlf: {tok}"),
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
    fn each_payload_carries_the_injected_header_and_a_break() {
        let tok = "crlfTEST";
        for p in payloads(tok) {
            assert!(p.contains(&format!("X-Anvil-Crlf:{tok}")), "no injected header: {p}");
            assert!(
                p.contains('\n') || p.contains("%0d%0a"),
                "no line break in payload: {p}"
            );
        }
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(token(), token());
    }
}
