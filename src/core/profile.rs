//! Scan profiles for different testing scenarios

use crate::core::capability::Capability;
use std::collections::HashSet;

#[derive(Debug)]
pub struct ScanProfile {
    pub enabled: HashSet<Capability>,
}

impl ScanProfile {
    /// Create an empty profile (no capabilities enabled)
    pub fn empty() -> Self {
        Self {
            enabled: HashSet::new(),
        }
    }

    /// Full OWASP-sweep profile (`--all` / `--owasp`): every detection class that
    /// runs reliably with no extra inputs. Deliberately excluded:
    ///  - OobSqlInjection / BlindXss — need an out-of-band callback (--callback)
    ///  - SecondOrderSqli — needs a trigger-URL workflow
    ///  - DomXss / StoredXss — need headless Chrome / a crawl workflow
    ///  - ProofMode / ExploitMode / HashDump — data-extraction, never automatic
    pub fn all() -> Self {
        use Capability::*;
        Self {
            enabled: [
                // recon
                Crawl,
                Fingerprint,
                // A03 injection
                SqlInjection,
                TimeSqlInjection,
                StackedSqlInjection,
                NoSqli,
                Xss,
                Cmdi,
                Ssti,
                Crlf,
                Xxe,
                // A10 / A01
                Ssrf,
                PathTraversal,
                OpenRedirect,
                Cors,
                // passive analyzers (A05 / A07 / A02 / A06)
                SecurityHeaders,
                Jwt,
                Secrets,
                Components,
                Sri,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Create a minimal profile (crawl + fingerprint only)
    pub fn minimal() -> Self {
        use Capability::*;
        Self {
            enabled: [Crawl, Fingerprint].into_iter().collect(),
        }
    }

    /// Create a SQLi-focused profile
    pub fn sqli_all() -> Self {
        use Capability::*;
        Self {
            enabled: [
                Crawl,
                Fingerprint,
                SqlInjection,
                TimeSqlInjection,
                StackedSqlInjection,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Create an exploitation profile (includes proof mode)
    pub fn exploit() -> Self {
        let mut profile = Self::sqli_all();
        profile.enable(Capability::ProofMode);
        profile.enable(Capability::ExploitMode);
        profile
    }

    /// Enable a specific capability
    pub fn enable(&mut self, cap: Capability) {
        self.enabled.insert(cap);
    }

    /// Disable a specific capability
    pub fn disable(&mut self, cap: Capability) {
        self.enabled.remove(&cap);
    }

    /// Check if a capability is enabled
    pub fn has(&self, cap: Capability) -> bool {
        self.enabled.contains(&cap)
    }

    /// Check if any SQLi capability is enabled
    pub fn has_sqli(&self) -> bool {
        self.enabled.iter().any(|c| c.is_sqli())
    }

    /// Check if any exploitation capability is enabled
    pub fn has_exploit(&self) -> bool {
        self.enabled.iter().any(|c| c.is_exploit())
    }
}
