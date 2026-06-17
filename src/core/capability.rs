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

    // Path traversal / LFI
    PathTraversal,   // Path traversal / Local File Inclusion (CWE-22)

    // Server-Side Template Injection
    Ssti,            // Server-Side Template Injection (CWE-1336)

    // Open redirect
    OpenRedirect,    // Open redirect / unvalidated forward (CWE-601)

    // CORS misconfiguration
    Cors,            // Cross-Origin Resource Sharing misconfiguration (CWE-942)

    // CRLF / HTTP header injection
    Crlf,            // CRLF / response header injection (CWE-113)

    // Passive security-header audit
    SecurityHeaders, // Missing/weak security headers & cookie flags (OWASP A05)

    // JWT weaknesses
    Jwt,             // JSON Web Token weaknesses (CWE-347)

    // Sensitive data exposure
    Secrets,         // Exposed secrets / sensitive data (OWASP A02)

    // NoSQL injection
    NoSqli,          // NoSQL (MongoDB operator) injection (CWE-943)

    // XML External Entity
    Xxe,             // XML External Entity injection (CWE-611)

    // Vulnerable/outdated components
    Components,      // Outdated front-end libraries with known CVEs (OWASP A06)

    // Subresource Integrity
    Sri,             // Missing Subresource Integrity on cross-origin assets (OWASP A08)
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
