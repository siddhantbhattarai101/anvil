//! JSON Web Token weakness detection (CWE-347 / CWE-613).
//!
//! Passive + offline: candidate JWTs are harvested from request cookies/headers
//! and the response, then each is decoded and inspected. No requests are forged.
//! Findings are evidence-backed:
//!  - `alg: none` — the token is unsigned, so it can be trivially tampered.
//!  - weak HMAC secret — the HS256 signature verifies against a built-in list of
//!    common secrets, meaning the token can be forged (the secret is reported).
//!  - missing `exp` — the token never expires.
//!
//! base64url-decode and HMAC-SHA256 are implemented locally over the `sha2`
//! crate to avoid adding dependencies to the scanner.

use crate::reporting::model::Severity;
use lazy_static::lazy_static;
use regex::Regex;
use sha2::{Digest, Sha256};

/// A JWT weakness.
#[derive(Debug, Clone)]
pub struct JwtIssue {
    pub title: String,
    pub severity: Severity,
    pub cwe: &'static str,
    pub cvss: f32,
    pub evidence: String,
    pub impact: String,
    pub remediation: String,
    /// The token (truncated) the issue was found on.
    pub token: String,
}

/// Common/default HMAC secrets seen in tutorials, libraries and leaks.
const WEAK_SECRETS: &[&str] = &[
    "secret", "secretkey", "secret_key", "password", "changeme", "admin", "key",
    "jwt", "jwtsecret", "jwt_secret", "token", "test", "s3cr3t", "qwerty",
    "123456", "1234567890", "your-256-bit-secret", "your_jwt_secret",
    "supersecret", "default", "private", "mysecret", "secret123", "letmein",
];

lazy_static! {
    // JWT shape: base64url header (starts `eyJ`) . payload (`eyJ`) . signature
    static ref JWT_RE: Regex =
        Regex::new(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*").unwrap();
}

/// Extract unique JWT-shaped tokens from arbitrary text.
pub fn extract_jwts(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    JWT_RE
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .filter(|t| seen.insert(t.clone()))
        .collect()
}

/// URL-safe base64 decode without padding.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in s.as_bytes() {
        acc = (acc << 6) | val(c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// HMAC-SHA256(key, msg).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let mut res = [0u8; 32];
    res.copy_from_slice(&outer.finalize());
    res
}

fn short(token: &str) -> String {
    if token.len() > 32 {
        format!("{}…", &token[..32])
    } else {
        token.to_string()
    }
}

fn issue(
    title: String,
    severity: Severity,
    cwe: &'static str,
    cvss: f32,
    evidence: String,
    impact: &str,
    remediation: &str,
    token: &str,
) -> JwtIssue {
    JwtIssue {
        title,
        severity,
        cwe,
        cvss,
        evidence,
        impact: impact.to_string(),
        remediation: remediation.to_string(),
        token: short(token),
    }
}

/// Analyze one JWT. Returns the weaknesses found (empty if it looks sound).
pub fn analyze_jwt(token: &str) -> Vec<JwtIssue> {
    let mut out = Vec::new();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return out;
    }
    let header: serde_json::Value = match b64url_decode(parts[0])
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        Some(h) => h,
        None => return out, // not a real JWT after all
    };
    let payload: serde_json::Value = b64url_decode(parts[1])
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(serde_json::json!({}));
    let alg = header.get("alg").and_then(|a| a.as_str()).unwrap_or("");

    // 1) alg: none — unsigned token.
    if alg.eq_ignore_ascii_case("none") {
        out.push(issue(
            "JWT uses the 'none' algorithm (unsigned)".to_string(),
            Severity::Critical,
            "CWE-347",
            9.1,
            format!("Token header declares alg=\"{alg}\"; signature is not verified."),
            "An attacker can rewrite the token's claims (e.g. elevate roles) with no signature.",
            "Reject the 'none' algorithm; pin the expected algorithm server-side and always verify the signature.",
            token,
        ));
    }

    // 2) Weak HMAC secret (HS256) — token is forgeable if we can guess the key.
    if alg.eq_ignore_ascii_case("HS256") && parts.len() >= 3 && !parts[2].is_empty() {
        if let Some(sig) = b64url_decode(parts[2]) {
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            for secret in WEAK_SECRETS {
                if hmac_sha256(secret.as_bytes(), signing_input.as_bytes()).as_slice() == sig.as_slice() {
                    out.push(issue(
                        format!("JWT signed with a weak, guessable secret ('{secret}')"),
                        Severity::Critical,
                        "CWE-347",
                        9.1,
                        format!("HS256 signature verifies against the common secret \"{secret}\"."),
                        "Knowing the secret, an attacker can forge arbitrary valid tokens and impersonate any user.",
                        "Use a long, random, high-entropy signing key; rotate it; store it as a secret.",
                        token,
                    ));
                    break;
                }
            }
        }
    }

    // 3) No expiry.
    if payload.get("exp").is_none() {
        out.push(issue(
            "JWT has no expiry (exp) claim".to_string(),
            Severity::Medium,
            "CWE-613",
            5.3,
            "Decoded payload contains no 'exp' claim.".to_string(),
            "A leaked token remains valid forever, so it cannot be timed out or rotated.",
            "Set a short 'exp' on issuance and validate it on every request.",
            token,
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build an HS256 JWT for tests (mirrors a real issuer).
    fn b64url(b: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in b.chunks(3) {
            let n = (chunk[0] as u32) << 16
                | (*chunk.get(1).unwrap_or(&0) as u32) << 8
                | (*chunk.get(2).unwrap_or(&0) as u32);
            out.push(A[(n >> 18 & 63) as usize] as char);
            out.push(A[(n >> 12 & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(A[(n >> 6 & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(A[(n & 63) as usize] as char);
            }
        }
        out
    }
    fn make(header: &str, payload: &str, secret: &str) -> String {
        let h = b64url(header.as_bytes());
        let p = b64url(payload.as_bytes());
        let sig = b64url(&hmac_sha256(secret.as_bytes(), format!("{h}.{p}").as_bytes()));
        format!("{h}.{p}.{sig}")
    }

    #[test]
    fn b64url_roundtrip_known_vector() {
        // base64url("{") == "ew"
        assert_eq!(b64url_decode("eyJ").unwrap(), b"{\"");
    }

    #[test]
    fn weak_secret_is_cracked() {
        let t = make(r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"user":"admin","exp":9999999999}"#, "secret");
        let issues = analyze_jwt(&t);
        assert!(issues.iter().any(|i| i.title.contains("weak, guessable secret")));
    }

    #[test]
    fn strong_secret_with_exp_is_clean() {
        let t = make(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"user":"admin","exp":9999999999}"#,
            "f8Q3xK2pLm9Vr7Wz-this-is-a-long-random-key-not-in-any-list-0xAB",
        );
        assert!(analyze_jwt(&t).is_empty());
    }

    #[test]
    fn alg_none_is_flagged() {
        let h = b64url(br#"{"alg":"none","typ":"JWT"}"#);
        let p = b64url(br#"{"user":"admin","exp":9999999999}"#);
        let t = format!("{h}.{p}.");
        assert!(analyze_jwt(&t).iter().any(|i| i.title.contains("none")));
    }

    #[test]
    fn missing_exp_is_flagged() {
        let t = make(r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"user":"admin"}"#, "f8Q3xK2pLm9Vr7Wz-long-random-not-listed");
        assert!(analyze_jwt(&t).iter().any(|i| i.title.contains("expiry")));
    }

    #[test]
    fn extraction_finds_token_in_cookie() {
        let t = make(r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"u":1}"#, "secret");
        let found = extract_jwts(&format!("session={t}; Path=/"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], t);
    }
}
