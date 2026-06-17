use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub vuln_type: String,        // SQL Injection, XSS, etc.
    pub technique: String,        // Time-based, Boolean, Reflected
    pub endpoint: String,         // /path
    pub parameter: Option<String>,
    pub confidence: f32,
    pub severity: Severity,
    pub evidence: String,
    pub http_method: String,      // GET, POST
    pub database: Option<String>, // MySQL, PostgreSQL, etc.
    pub cwe: String,              // CWE-89 for SQLi
    pub cvss_score: Option<f32>,  // 0.0-10.0
    pub description: String,      // What this vulnerability means
    pub impact: String,           // Business/technical impact
    pub remediation: String,      // How to fix it
    pub references: Vec<String>,  // URLs to documentation
    pub payload_sample: Option<String>, // Example payload used
}

impl Finding {
    /// Create a SQL Injection finding with comprehensive details
    pub fn sql_injection(
        technique: &str,
        endpoint: &str,
        parameter: &str,
        confidence: f32,
        evidence: &str,
        http_method: &str,
        database: Option<&str>,
        payload_sample: Option<String>,
    ) -> Self {
        let severity = if confidence >= 0.9 {
            Severity::Critical
        } else if confidence >= 0.7 {
            Severity::High
        } else if confidence >= 0.5 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let db_specific = database
            .map(|db| format!(" on {} database", db))
            .unwrap_or_default();

        Self {
            vuln_type: "SQL Injection".to_string(),
            technique: technique.to_string(),
            endpoint: endpoint.to_string(),
            parameter: Some(parameter.to_string()),
            confidence,
            severity: severity.clone(),
            evidence: evidence.to_string(),
            http_method: http_method.to_string(),
            database: database.map(|s| s.to_string()),
            cwe: "CWE-89".to_string(),
            cvss_score: Some(match severity {
                Severity::Critical => 9.8,
                Severity::High => 8.6,
                Severity::Medium => 6.5,
                Severity::Low => 4.3,
                _ => 0.0,
            }),
            description: format!(
                "SQL Injection vulnerability detected using {} technique{}. \
                 An attacker can inject malicious SQL commands into the '{}' parameter, \
                 potentially gaining unauthorized access to the database, modifying data, \
                 or executing administrative operations.",
                technique, db_specific, parameter
            ),
            impact: format!(
                "CRITICAL RISK: An attacker exploiting this vulnerability could:\n\
                 • Read sensitive data from the database (user credentials, PII, financial data)\n\
                 • Modify or delete database contents\n\
                 • Bypass authentication and authorization mechanisms\n\
                 • Execute administrative operations on the database\n\
                 • In some cases, execute operating system commands ({})\n\
                 • Gain access to other internal systems",
                if database == Some("MySQL") || database == Some("PostgreSQL") {
                    "possible with this database"
                } else {
                    "depending on configuration"
                }
            ),
            remediation: Self::get_remediation(database, http_method),
            references: vec![
                "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                "https://cwe.mitre.org/data/definitions/89.html".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
                "https://portswigger.net/web-security/sql-injection".to_string(),
            ],
            payload_sample,
        }
    }

    fn get_remediation(database: Option<&str>, http_method: &str) -> String {
        let db_specific = match database {
            Some("MySQL") => "
   -- MySQL/MariaDB parameterized query:
   SELECT * FROM users WHERE id = ? AND status = ?",
            Some("PostgreSQL") => "
   -- PostgreSQL parameterized query:
   SELECT * FROM users WHERE id = $1 AND status = $2",
            Some("MSSQL") => "
   -- MSSQL parameterized query:
   SELECT * FROM users WHERE id = @id AND status = @status",
            _ => "
   -- Generic parameterized query:
   SELECT * FROM users WHERE id = ? AND status = ?",
        };

        format!(
            "IMMEDIATE ACTIONS REQUIRED:\n\n\
            1. **USE PARAMETERIZED QUERIES (Primary Defense)**\n   \
               ❌ NEVER concatenate user input into SQL:\n   \
               query = \"SELECT * FROM users WHERE id = '\" + userId + \"'\"\n\n   \
               ✅ ALWAYS use parameterized queries:{}\n\n\
            2. **INPUT VALIDATION (Defense in Depth)**\n   \
               • Validate data type (e.g., numeric IDs should only contain digits)\n   \
               • Whitelist acceptable values where possible\n   \
               • Enforce strict length limits\n   \
               • Reject special characters if not needed: ' \" ; -- /* */ xp_ sp_\n\n\
            3. **LEAST PRIVILEGE PRINCIPLE**\n   \
               • Database user should have minimal permissions\n   \
               • READ-ONLY access for SELECT operations\n   \
               • No GRANT, DROP, CREATE permissions for application users\n   \
               • Disable xp_cmdshell, LOAD_FILE() and other dangerous functions\n\n\
            4. **WEB APPLICATION FIREWALL (WAF)**\n   \
               • Deploy ModSecurity or cloud WAF (Cloudflare, AWS WAF)\n   \
               • Enable SQL injection rule sets (OWASP Core Rule Set)\n   \
               • Log and alert on suspicious patterns\n\n\
            5. **SECURE CODING PRACTICES**\n   \
               • Use ORM frameworks (SQLAlchemy, Hibernate, Entity Framework)\n   \
               • Enable prepared statements by default\n   \
               • Escape output when displaying data\n   \
               • Implement CSRF tokens for {} requests\n\n\
            6. **MONITORING & DETECTION**\n   \
               • Log all database queries with user context\n   \
               • Alert on unusual query patterns (UNION, SLEEP, @@version)\n   \
               • Monitor for authentication bypasses\n   \
               • Implement rate limiting on endpoints\n\n\
            TESTING & VERIFICATION:\n   \
               • Re-scan with ANVIL after fixes: anvil -t <url> -p {} --sqli\n   \
               • Test with sqlmap for thorough validation\n   \
               • Perform manual penetration testing\n   \
               • Add security unit tests for input validation",
            db_specific,
            http_method,
            http_method
        )
    }
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Ordinal rank for threshold comparisons (Info=0 … Critical=4).
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Parse a severity name (case-insensitive). Accepts the five levels.
    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "ℹ️  INFO"),
            Severity::Low => write!(f, "🟢 LOW"),
            Severity::Medium => write!(f, "🟡 MEDIUM"),
            Severity::High => write!(f, "🟠 HIGH"),
            Severity::Critical => write!(f, "🔴 CRITICAL"),
        }
    }
}

impl Finding {
    /// Create an XSS finding with comprehensive evidence chain
    pub fn xss(
        technique: String,
        context: &str,
        endpoint: &str,
        parameter: Option<String>,
        confidence: f32,
        severity: Severity,
        description: String,
        impact: String,
        remediation: String,
    ) -> Self {
        Self {
            vuln_type: "Cross-Site Scripting (XSS)".to_string(),
            technique,
            endpoint: endpoint.to_string(),
            parameter,
            confidence,
            severity: severity.clone(),
            evidence: format!("Execution Context: {}\n\n{}", context, description),
            http_method: "GET".to_string(),
            database: None,
            cwe: "CWE-79".to_string(),
            cvss_score: Some(match severity {
                Severity::Critical => 9.6,
                Severity::High => 8.2,
                Severity::Medium => 6.8,
                Severity::Low => 5.3,
                Severity::Info => 0.0,
            }),
            description,
            impact,
            remediation,
            references: vec![
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html".to_string(),
                "https://cwe.mitre.org/data/definitions/79.html".to_string(),
                "https://portswigger.net/web-security/cross-site-scripting".to_string(),
            ],
            payload_sample: None,
        }
    }
}
