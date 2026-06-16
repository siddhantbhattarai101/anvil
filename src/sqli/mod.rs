//! SQL Injection Module
//! 
//! This module provides SQL injection detection and exploitation capabilities.
//! Structure mirrors professional tools with separate modules for:
//! - core: settings, enums, agent, queries
//! - request: HTTP connection and page comparison
//! - techniques: union, blind, error, dns
//! - tamper: WAF bypass scripts
//! - shell: Interactive SQL shell
//! - file_access: Read/write files through SQLi
//! - os_shell: OS command execution

pub mod core;
pub mod request;
pub mod techniques;
pub mod tamper;
pub mod shell;
pub mod file_access;
pub mod os_shell;

// Re-export main types
pub use core::{DBMS, Agent, Queries, CHAR_START, CHAR_STOP, CHAR_DELIMITER, NULL};
pub use request::Request;
pub use techniques::{
    // UNION
    check_union, UnionVector, union_use, 
    get_databases, get_tables, get_columns, dump_table,
    get_current_db, get_current_user, get_version, get_users, get_passwords,
    // Blind
    check_boolean_blind, check_time_blind, BlindVector, extract_string, get_length,
    // Error
    check_error_based, ErrorVector, error_use, get_databases_error, get_tables_error,
    // DNS/OOB
    check_dns_exfiltration, DnsVector, dns_use,
};

use crate::http::client::HttpClient;
use anyhow::Result;
use url::Url;

// Compatibility aliases for existing code
pub type DatabaseType = DBMS;

/// SQL injection technique type (for compatibility)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliTechnique {
    Union,
    Boolean,
    Error,
    Time,
    TimeBased,  // Alias for Time
    Stacked,
    Inline,
}

impl std::fmt::Display for SqliTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SqliTechnique::Union => write!(f, "UNION query"),
            SqliTechnique::Boolean => write!(f, "Boolean-based blind"),
            SqliTechnique::Error => write!(f, "Error-based"),
            SqliTechnique::Time | SqliTechnique::TimeBased => write!(f, "Time-based blind"),
            SqliTechnique::Stacked => write!(f, "Stacked queries"),
            SqliTechnique::Inline => write!(f, "Inline query"),
        }
    }
}

/// SQL injection configuration (for compatibility)
#[derive(Debug, Clone, Default)]
pub struct SqliConfig {
    pub techniques: Vec<SqliTechnique>,
    pub level: u8,
    pub risk: u8,
}

/// SQL Injection result (compatible with engine.rs)
#[derive(Debug, Clone)]
pub struct SqliResult {
    pub endpoint: String,
    pub parameter: String,
    pub technique: SqliTechnique,
    pub confidence: f32,
    pub db_type: Option<DBMS>,
    pub details: String,
}

/// Main SQL injection engine
pub struct SqliEngine<'a> {
    client: &'a HttpClient,
    url: Option<Url>,
    parameter: Option<String>,
    /// Optional injection-point template. When set, every request injects at the
    /// configured location (form/JSON body, cookie, header) instead of the URL
    /// query string. When `None`, falls back to query-string GET injection.
    injection: Option<request::InjectionPoint>,
    /// Out-of-band callback domain for DNS-based exfiltration detection.
    oob_callback: Option<String>,
    pub vector: Option<UnionVector>,
    pub db_type: DBMS,
}

impl<'a> SqliEngine<'a> {
    pub fn new(client: &'a HttpClient) -> Self {
        Self {
            client,
            url: None,
            parameter: None,
            injection: None,
            oob_callback: None,
            vector: None,
            db_type: DBMS::Unknown,
        }
    }

    /// Construct an engine that injects at the given injection point (e.g. a
    /// POST form/JSON field) rather than the default URL query string.
    pub fn with_injection_point(client: &'a HttpClient, point: request::InjectionPoint) -> Self {
        Self {
            client,
            url: None,
            parameter: None,
            injection: Some(point),
            oob_callback: None,
            vector: None,
            db_type: DBMS::Unknown,
        }
    }

    /// Set the out-of-band callback domain used for DNS-exfiltration detection.
    pub fn with_oob_callback(mut self, callback: Option<String>) -> Self {
        self.oob_callback = callback;
        self
    }

    /// Build a `Request` for the given URL/param, honouring the injection-point
    /// template if one was configured.
    fn make_request(&self, url: &Url, param: &str) -> Request<'a> {
        match &self.injection {
            Some(point) => Request::with_point(self.client, point.clone()),
            None => Request::new(self.client, url.clone(), param.to_string()),
        }
    }

    /// Detect SQL injection vulnerability
    pub async fn detect(&mut self, url: &Url, param: &str) -> Result<bool> {
        self.url = Some(url.clone());
        self.parameter = Some(param.to_string());
        
        let request = self.make_request(url, param);

        // Try UNION-based first (most powerful)
        tracing::info!("Testing UNION-based SQL injection...");
        if let Some(union_vector) = check_union(&request).await? {
            self.db_type = union_vector.dbms;
            self.vector = Some(union_vector);
            return Ok(true);
        }

        // Try error-based
        tracing::info!("Testing error-based SQL injection...");
        if let Some(error_vector) = check_error_based(&request).await? {
            self.db_type = error_vector.dbms;
            // Convert to union-like vector for compatibility
            // Error-based doesn't have column info, so we can't use it for data extraction
            return Ok(false); // For now, only support UNION
        }

        // Try boolean-based blind
        tracing::info!("Testing boolean-based blind SQL injection...");
        if let Some(_blind_vector) = check_boolean_blind(&request).await? {
            // Blind is too slow for full enumeration
            return Ok(false);
        }

        // Out-of-band DNS exfiltration (last resort; needs the OOB DNS listener
        // running and the callback domain delegated to it).
        if let Some(ref domain) = self.oob_callback {
            tracing::info!("Testing DNS-based out-of-band SQL injection...");
            if let Some(dns_vector) = check_dns_exfiltration(&request, domain).await? {
                self.db_type = dns_vector.dbms;
                tracing::warn!(
                    "[SQLi OOB] DNS exfiltration confirmed (DBMS: {})",
                    dns_vector.dbms
                );
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get current database
    pub async fn get_current_db(&self, url: &Url, param: &str) -> Result<Option<String>> {
        let request = self.make_request(url, param);
        
        if let Some(ref v) = self.vector {
            let result = get_current_db(&request, v).await?;
            if !result.is_empty() {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }

    /// Get all databases
    pub async fn get_dbs(&self, url: &Url, param: &str) -> Result<Vec<String>> {
        let request = self.make_request(url, param);
        
        if let Some(ref v) = self.vector {
            return get_databases(&request, v).await;
        }
        Ok(vec![])
    }

    /// Get tables in a database
    pub async fn get_tables(&self, url: &Url, param: &str, database: &str) -> Result<Vec<String>> {
        let request = self.make_request(url, param);
        
        if let Some(ref v) = self.vector {
            return get_tables(&request, v, database).await;
        }
        Ok(vec![])
    }

    /// Get columns in a table
    pub async fn get_columns(&self, url: &Url, param: &str, database: &str, table: &str) -> Result<Vec<String>> {
        let request = self.make_request(url, param);
        
        if let Some(ref v) = self.vector {
            return get_columns(&request, v, database, table).await;
        }
        Ok(vec![])
    }

    /// Dump table data
    pub async fn dump_table(&self, url: &Url, param: &str, database: &str, table: &str, columns: &[String]) -> Result<Vec<Vec<String>>> {
        let request = self.make_request(url, param);
        
        if let Some(ref v) = self.vector {
            return dump_table(&request, v, database, table, columns).await;
        }
        Ok(vec![])
    }
}
