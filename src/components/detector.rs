//! Vulnerable / outdated component detection (OWASP A06, CWE-1104).
//!
//! Passive: fingerprints well-known front-end libraries in response bodies and
//! flags versions below a known-safe threshold (each tied to a representative
//! advisory). Only libraries with a distinctive name+version signature are
//! included, and a finding is raised only when the detected version is provably
//! older than the fixed release — so up-to-date sites do not false-positive.

use crate::reporting::model::Severity;
use lazy_static::lazy_static;
use regex::Regex;

/// A detected outdated component.
#[derive(Debug, Clone)]
pub struct ComponentFinding {
    pub name: &'static str,
    pub version: String,
    pub min_safe: &'static str,
    pub advisory: &'static str,
    pub severity: Severity,
    pub cwe: &'static str,
    pub cvss: f32,
}

struct Lib {
    name: &'static str,
    re: Regex,
    min_safe: &'static str,
    advisory: &'static str,
    severity: Severity,
    cvss: f32,
}

lazy_static! {
    static ref LIBS: Vec<Lib> = vec![
        Lib {
            name: "jQuery",
            re: Regex::new(r"(?i)jquery[/-]?v?(\d+\.\d+\.\d+)").unwrap(),
            min_safe: "3.5.0",
            advisory: "jQuery < 3.5.0 is affected by XSS via htmlPrefilter (CVE-2020-11022/11023).",
            severity: Severity::Medium, cvss: 6.1,
        },
        Lib {
            name: "Bootstrap",
            re: Regex::new(r"(?i)bootstrap[/-]?v?(\d+\.\d+\.\d+)").unwrap(),
            min_safe: "4.3.1",
            advisory: "Bootstrap < 4.3.1 is affected by XSS in data-* attributes (CVE-2019-8331).",
            severity: Severity::Medium, cvss: 6.1,
        },
        Lib {
            name: "Lodash",
            re: Regex::new(r"(?i)lodash[/-]?v?(\d+\.\d+\.\d+)").unwrap(),
            min_safe: "4.17.21",
            advisory: "Lodash < 4.17.21 is affected by command injection / prototype pollution (CVE-2021-23337).",
            severity: Severity::High, cvss: 7.2,
        },
        Lib {
            name: "AngularJS",
            re: Regex::new(r"(?i)angular(?:js)?[/-]?v?(1\.\d+\.\d+)").unwrap(),
            min_safe: "2.0.0", // AngularJS 1.x is end-of-life
            advisory: "AngularJS 1.x is end-of-life and unmaintained; migrate to a supported framework.",
            severity: Severity::Medium, cvss: 5.3,
        },
        Lib {
            name: "Handlebars",
            re: Regex::new(r"(?i)handlebars[/-]?v?(\d+\.\d+\.\d+)").unwrap(),
            min_safe: "4.7.7",
            advisory: "Handlebars < 4.7.7 is affected by prototype pollution / RCE (CVE-2021-23369).",
            severity: Severity::High, cvss: 7.5,
        },
    ];
}

/// Parse a dotted version into numeric components.
fn parse(v: &str) -> Vec<u32> {
    v.split('.').filter_map(|p| p.parse().ok()).collect()
}

/// True if `a` is strictly older than `b`.
fn version_lt(a: &str, b: &str) -> bool {
    let (va, vb) = (parse(a), parse(b));
    for i in 0..va.len().max(vb.len()) {
        let (x, y) = (va.get(i).copied().unwrap_or(0), vb.get(i).copied().unwrap_or(0));
        if x != y {
            return x < y;
        }
    }
    false
}

/// Scan a response body for outdated component versions.
pub fn scan_components(body: &str) -> Vec<ComponentFinding> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for lib in LIBS.iter() {
        if let Some(c) = lib.re.captures(body).and_then(|c| c.get(1)) {
            let version = c.as_str().to_string();
            if version_lt(&version, lib.min_safe) && seen.insert((lib.name, version.clone())) {
                out.push(ComponentFinding {
                    name: lib.name,
                    version,
                    min_safe: lib.min_safe,
                    advisory: lib.advisory,
                    severity: lib.severity.clone(),
                    cwe: "CWE-1104",
                    cvss: lib.cvss,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering() {
        assert!(version_lt("1.8.0", "3.5.0"));
        assert!(version_lt("3.4.9", "3.5.0"));
        assert!(!version_lt("3.5.0", "3.5.0"));
        assert!(!version_lt("3.7.1", "3.5.0"));
        assert!(version_lt("4.17.20", "4.17.21"));
    }

    #[test]
    fn flags_outdated_jquery() {
        let body = r#"<script src="/static/jquery-1.8.0.min.js"></script>"#;
        let f = scan_components(body);
        assert!(f.iter().any(|c| c.name == "jQuery" && c.version == "1.8.0"));
    }

    #[test]
    fn current_jquery_is_clean() {
        let body = r#"<script src="/static/jquery-3.7.1.min.js"></script>"#;
        assert!(!scan_components(body).iter().any(|c| c.name == "jQuery"));
    }

    #[test]
    fn flags_angularjs_1x_as_eol() {
        let body = r#"<script src="//cdn/angular/1.6.9/angular.min.js"></script>"#;
        assert!(scan_components(body).iter().any(|c| c.name == "AngularJS"));
    }

    #[test]
    fn clean_page_yields_nothing() {
        assert!(scan_components("<html><body>hello</body></html>").is_empty());
    }
}
