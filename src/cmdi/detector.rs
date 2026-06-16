//! OS command-injection (CWE-78) detection.
//!
//! Evidence-driven, mirroring ANVIL's other engines:
//!  - **Output-based**: a split-marker payload (`A$(echo B)C`) is reflected as
//!    the *joined* string (`ABC`) only if the shell executed the substitution —
//!    distinguishing real execution from mere reflection.
//!  - **Time-based (blind)**: a `sleep`/`ping` payload delays the response; a
//!    confirmatory second request rules out jitter.
//! Payloads are tried across the common shell separators so the injected command
//! breaks out of the original one.

use crate::sqli::request::Request;
use anyhow::Result;
use std::time::{Duration, Instant};

/// A confirmed command-injection vector.
#[derive(Debug, Clone)]
pub struct CmdiVector {
    pub technique: &'static str, // "output-based" | "time-based"
    pub payload: String,
    pub separator: String,
}

const TIME_DELAY: u64 = 5;

/// Separators for OUTPUT-based detection. These all keep the split marker
/// (`A$(echo B)C`) intact so the joined string `ABC` can never appear literally
/// in the payload — only the shell joining it on execution produces `ABC`.
/// (`$(` is excluded here: `$(echo ABC)` would contain `ABC` literally and
/// false-positive on simple reflection.)
const OUTPUT_SEPARATORS: &[&str] = &[";", "|", "||", "&&", "&", "\n", "`"];

/// Separators for TIME-based detection (delay measured, so no reflection
/// concern) — includes `$(` for the value-inside-substitution context.
const TIME_SEPARATORS: &[&str] = &[";", "|", "||", "&&", "&", "\n", "`", "$("];

fn token() -> (String, String, String) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static C: AtomicU64 = AtomicU64::new(0);
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let s = C.fetch_add(1, Ordering::Relaxed);
    let base = format!("{:x}{:x}", n, s);
    (format!("cmA{base}"), format!("cmB{base}"), format!("cmC{base}"))
}

/// Build an output-based payload for a separator. Returns (payload, expected
/// joined marker that only appears if the substitution executed).
fn output_payload(base: &str, sep: &str, t: &(String, String, String)) -> (String, String) {
    let (a, b, c) = t;
    let joined = format!("{a}{b}{c}");
    let payload = match sep {
        "`" => format!("{base};echo {a}`echo {b}`{c}"),
        "\n" => format!("{base}\necho {a}$(echo {b}){c}"),
        s => format!("{base}{s}echo {a}$(echo {b}){c}"),
    };
    (payload, joined)
}

/// Build a time-based payload for a separator.
fn time_payload(base: &str, sep: &str) -> String {
    match sep {
        "`" => format!("{base};`sleep {TIME_DELAY}`"),
        "$(" => format!("{base}$(sleep {TIME_DELAY})"),
        "\n" => format!("{base}\nsleep {TIME_DELAY}"),
        s => format!("{base}{s}sleep {TIME_DELAY}"),
    }
}

/// Check a parameter for OS command injection.
pub async fn check_cmdi(request: &Request<'_>) -> Result<Option<CmdiVector>> {
    let base = request.original_value();
    let base = if base.trim().is_empty() { "1".to_string() } else { base };

    // ---- Output-based (deterministic, fast) ----
    for sep in OUTPUT_SEPARATORS {
        let t = token();
        let (payload, joined) = output_payload(&base, sep, &t);
        let page = request.query_page(&payload).await?;
        // The joined marker (ABC) only appears if the shell ran `echo B` inside
        // the substitution; a reflected payload would still contain `$(echo B)`.
        if page.contains(&joined) {
            return Ok(Some(CmdiVector {
                technique: "output-based",
                payload,
                separator: sep.to_string(),
            }));
        }
    }

    // ---- Time-based (blind) ----
    // Baseline: median of a few quick samples.
    let mut samples = Vec::new();
    for _ in 0..3 {
        let start = Instant::now();
        let _ = request.query_page(&base).await?;
        samples.push(start.elapsed());
    }
    samples.sort();
    let normal = samples[samples.len() / 2];
    let threshold = Duration::from_secs(TIME_DELAY - 1).max(normal * 3);

    for sep in TIME_SEPARATORS {
        let payload = time_payload(&base, sep);
        let start = Instant::now();
        let _ = request.query_page(&payload).await?;
        if start.elapsed() < threshold {
            continue;
        }
        // Confirm to rule out a transient slow response.
        let start = Instant::now();
        let _ = request.query_page(&payload).await?;
        if start.elapsed() < threshold {
            continue;
        }
        return Ok(Some(CmdiVector {
            technique: "time-based",
            payload,
            separator: sep.to_string(),
        }));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_marker_never_appears_literally_in_payload() {
        // The core anti-false-positive invariant: the joined marker must only
        // appear if the shell executed the substitution, never via reflection.
        let t = (
            "cmAaaaa".to_string(),
            "cmBbbbb".to_string(),
            "cmCcccc".to_string(),
        );
        for sep in OUTPUT_SEPARATORS {
            let (payload, joined) = output_payload("x", sep, &t);
            assert!(
                !payload.contains(&joined),
                "joined marker leaks into payload for sep {sep:?}: {payload}"
            );
        }
    }

    #[test]
    fn time_payloads_carry_a_delay() {
        for sep in TIME_SEPARATORS {
            let p = time_payload("x", sep);
            assert!(p.contains("sleep"), "no delay in time payload for {sep:?}: {p}");
        }
    }
}
