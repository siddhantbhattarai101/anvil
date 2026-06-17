//! Sensitive data / secret exposure detection (OWASP A02, CWE-200/312/798).
//!
//! Passive: scans response bodies for high-confidence, structurally-distinct
//! secrets (fixed-prefix API keys, private-key blocks) and for verbose error /
//! stack-trace disclosure. Only patterns with a strong fixed signature are
//! included so reflected or benign content does not false-positive. The matched
//! secret is redacted in the finding.

use crate::reporting::model::Severity;
use lazy_static::lazy_static;
use regex::Regex;

/// A confirmed sensitive-data exposure.
#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub kind: &'static str,
    pub severity: Severity,
    pub cwe: &'static str,
    pub cvss: f32,
    /// Redacted snippet of what matched.
    pub matched: String,
    pub impact: String,
    pub remediation: String,
}

struct Pattern {
    kind: &'static str,
    re: Regex,
    severity: Severity,
    cwe: &'static str,
    cvss: f32,
    /// "credential" leaks need rotation; "disclosure" needs error suppression.
    category: &'static str,
}

lazy_static! {
    static ref PATTERNS: Vec<Pattern> = vec![
        Pattern {
            kind: "Private key block",
            re: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----").unwrap(),
            severity: Severity::Critical, cwe: "CWE-312", cvss: 9.1, category: "credential",
        },
        Pattern {
            kind: "AWS access key ID",
            re: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            severity: Severity::High, cwe: "CWE-798", cvss: 8.6, category: "credential",
        },
        Pattern {
            kind: "Google API key",
            re: Regex::new(r"\bAIza[0-9A-Za-z_\-]{35}\b").unwrap(),
            severity: Severity::High, cwe: "CWE-312", cvss: 7.5, category: "credential",
        },
        Pattern {
            kind: "GitHub token",
            re: Regex::new(r"\bgh[pousr]_[0-9A-Za-z]{36}\b").unwrap(),
            severity: Severity::High, cwe: "CWE-798", cvss: 8.6, category: "credential",
        },
        Pattern {
            kind: "Slack token",
            re: Regex::new(r"\bxox[baprs]-[0-9A-Za-z]{10,}\b").unwrap(),
            severity: Severity::High, cwe: "CWE-798", cvss: 7.5, category: "credential",
        },
        Pattern {
            kind: "Stripe secret key",
            re: Regex::new(r"\bsk_live_[0-9A-Za-z]{24,}\b").unwrap(),
            severity: Severity::Critical, cwe: "CWE-312", cvss: 9.1, category: "credential",
        },
        Pattern {
            kind: "Verbose error / stack trace disclosure",
            re: Regex::new(
                r"Traceback \(most recent call last\)|Exception in thread|Fatal error:|Warning: .+ on line \d+|at [a-z][a-zA-Z0-9_.]+\.[A-Za-z0-9_$]+\([A-Za-z0-9_.]+:\d+\)"
            ).unwrap(),
            severity: Severity::Low, cwe: "CWE-209", cvss: 3.7, category: "disclosure",
        },
    ];
}

/// Redact a matched secret, keeping just enough to prove the hit.
fn redact(s: &str) -> String {
    let s = s.lines().next().unwrap_or(s); // never spill a full multi-line key
    if s.len() <= 10 {
        return s.to_string();
    }
    format!("{}…{}", &s[..6], &s[s.len() - 2..])
}

fn describe(kind: &str, category: &str) -> (String, String) {
    if category == "credential" {
        (
            format!("{kind} is exposed in the HTTP response and can be used directly by anyone who reads it."),
            "Remove the secret from responses/source, rotate it immediately, and load credentials from a secrets manager.".to_string(),
        )
    } else {
        (
            "Verbose error output reveals stack traces, file paths, or framework internals that aid an attacker.".to_string(),
            "Disable debug mode in production and return generic error pages; log details server-side only.".to_string(),
        )
    }
}

/// Scan a response body for exposed secrets / sensitive data.
pub fn scan_secrets(text: &str) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for p in PATTERNS.iter() {
        if let Some(m) = p.re.find(text) {
            let matched = redact(m.as_str());
            if seen.insert((p.kind, matched.clone())) {
                let (impact, remediation) = describe(p.kind, p.category);
                out.push(SecretFinding {
                    kind: p.kind,
                    severity: p.severity.clone(),
                    cwe: p.cwe,
                    cvss: p.cvss,
                    matched,
                    impact,
                    remediation,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test fixtures are assembled from split literals so the source file never
    // contains a contiguous provider-key pattern (which would trip GitHub push
    // protection / secret scanning). They are not real credentials.
    const AWS: &str = concat!("AKIA", "IOSFODNN7EXAMPLE");
    const GH: &str = concat!("ghp", "_0123456789abcdefghijklmnopqrstuvwxyz");
    const STRIPE: &str = concat!("sk_", "live_", "0123456789abcdefghijklmno");

    #[test]
    fn detects_aws_key_and_private_key() {
        let body = format!("cfg = {{ id: {AWS} }}\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        let kinds: Vec<_> = scan_secrets(&body).iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&"AWS access key ID"));
        assert!(kinds.contains(&"Private key block"));
    }

    #[test]
    fn detects_provider_tokens() {
        assert!(scan_secrets(&format!("token={GH}"))
            .iter().any(|f| f.kind == "GitHub token"));
        assert!(scan_secrets(&format!("k: {STRIPE}"))
            .iter().any(|f| f.kind == "Stripe secret key"));
    }

    #[test]
    fn clean_body_yields_nothing() {
        assert!(scan_secrets("<html><body>Welcome back, user!</body></html>").is_empty());
    }

    #[test]
    fn redaction_does_not_spill_full_secret() {
        let f = &scan_secrets(&format!("id: {AWS} here"))[0];
        assert!(!f.matched.contains(AWS));
        assert!(f.matched.contains('…'));
    }

    #[test]
    fn stack_trace_is_flagged_as_disclosure() {
        let body = "Traceback (most recent call last):\n  File \"app.py\", line 7";
        let f = scan_secrets(body);
        assert!(f.iter().any(|x| x.cwe == "CWE-209"));
    }
}
