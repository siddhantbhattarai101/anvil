//! Scan capabilities and features

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    // Core modules
    Crawl,
    Fingerprint,
    
    // SQL Injection techniques
    SqlInjection,        // Boolean/Error-based
    TimeSqlInjection,    // Time-based blind
    StackedSqlInjection, // Stacked queries
    OobSqlInjection,     // Out-of-band
    SecondOrderSqli,     // Second-order
    
    // Exploitation modes
    ProofMode,           // Safe metadata extraction
    ExploitMode,         // Full data extraction
    HashDump,            // Password hash extraction
    
    // XSS scanners
    Xss,             // Reflected XSS
    StoredXss,       // Stored/Persistent XSS
    DomXss,          // DOM-based XSS
    BlindXss,        // Blind XSS with OOB
    
    // SSRF scanner
    Ssrf,            // Server-Side Request Forgery

    // Command injection
    Cmdi,            // OS command injection (CWE-78)
}

impl Capability {
    /// Check if this capability is SQL injection related
    pub fn is_sqli(&self) -> bool {
        matches!(
            self,
            Capability::SqlInjection
                | Capability::TimeSqlInjection
                | Capability::StackedSqlInjection
                | Capability::OobSqlInjection
                | Capability::SecondOrderSqli
        )
    }

    /// Check if this capability is exploitation related
    pub fn is_exploit(&self) -> bool {
        matches!(
            self,
            Capability::ProofMode | Capability::ExploitMode | Capability::HashDump
        )
    }
}
