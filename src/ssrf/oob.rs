//! Out-of-band (OOB) callback system for blind SSRF detection
//!
//! This module provides functionality for detecting blind SSRF through
//! out-of-band callbacks (DNS or HTTP).

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Process-global log of OOB interactions (one line per received request:
/// request-line + Host header). Shared by the built-in listener and every
/// blind-vuln check (SSRF, XSS, SQLi DNS/HTTP) so they can correlate by id.
static OOB_LOG: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();

/// Address the built-in listener bound to (set once, on first start).
static OOB_BOUND_ADDR: OnceLock<String> = OnceLock::new();

fn oob_log() -> &'static Arc<Mutex<Vec<String>>> {
    OOB_LOG.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

/// Whether any recorded interaction contains `identifier` (in its path or Host).
pub fn oob_was_hit(identifier: &str) -> bool {
    oob_log()
        .lock()
        .map(|g| g.iter().any(|line| line.contains(identifier)))
        .unwrap_or(false)
}

/// Record an interaction directly (used by tests and by other transports).
pub fn record_oob_interaction(line: impl Into<String>) {
    if let Ok(mut g) = oob_log().lock() {
        g.push(line.into());
    }
}

/// Start the built-in OOB HTTP interaction listener on `bind_addr`
/// (e.g. "0.0.0.0:8888"). Spawns a background accept loop that records every
/// incoming request so blind callbacks can be correlated. Returns the actual
/// bound address. The user's callback domain must route to this host/port.
pub async fn start_oob_server(bind_addr: &str) -> std::io::Result<String> {
    use tokio::net::TcpListener;

    // Idempotent: a single listener serves all blind-vuln checks (SSRF, XSS,
    // SQLi), so repeated calls return the already-bound address.
    if let Some(addr) = OOB_BOUND_ADDR.get() {
        return Ok(addr.clone());
    }

    let listener = TcpListener::bind(bind_addr).await?;
    let actual = listener.local_addr()?.to_string();
    if OOB_BOUND_ADDR.set(actual.clone()).is_err() {
        // Another caller won the race; defer to its address.
        return Ok(OOB_BOUND_ADDR.get().cloned().unwrap_or(actual));
    }
    let log = oob_log().clone();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let log = log.clone();
                    tokio::spawn(handle_oob_conn(stream, log));
                }
                Err(e) => {
                    tracing::warn!("OOB listener accept error: {}", e);
                    break;
                }
            }
        }
    });

    Ok(actual)
}

async fn handle_oob_conn(mut stream: tokio::net::TcpStream, log: Arc<Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = [0u8; 8192];
    if let Ok(n) = stream.read(&mut buf).await {
        if n > 0 {
            let req = String::from_utf8_lossy(&buf[..n]);
            let first_line = req.lines().next().unwrap_or("");
            let host = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                .unwrap_or("");
            if let Ok(mut g) = log.lock() {
                g.push(format!("{} | {}", first_line.trim(), host.trim()));
            }
            tracing::info!("OOB interaction: {} {}", first_line.trim(), host.trim());
        }
    }
    let _ = stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await;
}

/// Address the built-in DNS listener bound to (set once, on first start).
static OOB_DNS_ADDR: OnceLock<String> = OnceLock::new();

/// Start the built-in OOB DNS listener on `bind_addr` (e.g. "0.0.0.0:53", which
/// needs privileges; a high port can be used for testing). Records the queried
/// name for every inbound DNS question into the shared interaction log, so
/// DNS-based blind exfiltration (SQLi `LOAD_FILE`/`xp_dirtree`, SSRF DNS lookups)
/// is correlated by id just like HTTP callbacks. Idempotent.
pub async fn start_oob_dns_server(bind_addr: &str) -> std::io::Result<String> {
    use tokio::net::UdpSocket;

    if let Some(addr) = OOB_DNS_ADDR.get() {
        return Ok(addr.clone());
    }

    let socket = UdpSocket::bind(bind_addr).await?;
    let actual = socket.local_addr()?.to_string();
    if OOB_DNS_ADDR.set(actual.clone()).is_err() {
        return Ok(OOB_DNS_ADDR.get().cloned().unwrap_or(actual));
    }

    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let packet = &buf[..n];
                    if let Some((qname, q_end)) = parse_dns_question(packet) {
                        record_oob_interaction(format!("DNS {} | from {}", qname, peer));
                        tracing::info!("OOB DNS interaction: {} from {}", qname, peer);
                        if let Some(resp) = build_dns_response(packet, q_end) {
                            let _ = socket.send_to(&resp, peer).await;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("OOB DNS recv error: {}", e);
                    break;
                }
            }
        }
    });

    Ok(actual)
}

/// Parse the QNAME of the first question in a DNS query packet. Returns the
/// dotted name and the byte offset just past the question (QNAME+QTYPE+QCLASS).
fn parse_dns_question(packet: &[u8]) -> Option<(String, usize)> {
    if packet.len() < 12 {
        return None;
    }
    let mut pos = 12; // skip the 12-byte header
    let mut labels = Vec::new();
    loop {
        let len = *packet.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Compression pointers are not expected in a question's QNAME.
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        let end = pos.checked_add(len)?;
        if end > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[pos..end]).to_string());
        pos = end;
    }
    if labels.is_empty() {
        return None;
    }
    let q_end = pos + 4; // QTYPE(2) + QCLASS(2)
    Some((labels.join("."), q_end.min(packet.len())))
}

/// Build a minimal DNS response (A record -> 127.0.0.1) so the resolver is
/// satisfied and does not hammer us with retries. Best-effort.
fn build_dns_response(query: &[u8], q_end: usize) -> Option<Vec<u8>> {
    if query.len() < 12 || q_end < 12 || q_end > query.len() {
        return None;
    }
    let mut resp = Vec::with_capacity(q_end + 16);
    resp.extend_from_slice(&query[0..2]); // copy transaction ID
    resp.extend_from_slice(&[0x81, 0x80]); // flags: response, recursion available
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
    resp.extend_from_slice(&query[12..q_end]); // echo the question
    resp.extend_from_slice(&[0xC0, 0x0C]); // answer name -> pointer to offset 12
    resp.extend_from_slice(&[0x00, 0x01]); // TYPE A
    resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
    resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
    resp.extend_from_slice(&[127, 0, 0, 1]); // RDATA 127.0.0.1
    Some(resp)
}

/// OOB callback generator
#[derive(Debug, Clone)]
pub struct OobCallbackGenerator {
    /// Base callback domain (e.g., "attacker.com")
    pub callback_domain: String,
}

impl OobCallbackGenerator {
    pub fn new(callback_domain: String) -> Self {
        Self { callback_domain }
    }
    
    /// Generate a unique callback URL with identifier (sub-domain form, for
    /// wildcard-DNS callback servers).
    pub fn generate_callback_url(&self, identifier: &str) -> String {
        format!("http://{}.{}", identifier, self.callback_domain)
    }

    /// Path-based HTTP callback (`http://<domain>/<id>`). Works whenever the
    /// callback host:port is directly reachable (e.g. the built-in listener on
    /// an IP:port), without needing wildcard DNS.
    pub fn generate_http_callback(&self, identifier: &str) -> String {
        format!("http://{}/{}", self.callback_domain, identifier)
    }
    
    /// Generate a DNS callback hostname
    pub fn generate_dns_callback(&self, identifier: &str) -> String {
        format!("{}.{}", identifier, self.callback_domain)
    }
    
    /// Generate multiple callback variants for different protocols
    pub fn generate_callback_variants(&self, identifier: &str) -> Vec<String> {
        vec![
            // HTTP variants
            format!("http://{}.{}", identifier, self.callback_domain),
            format!("https://{}.{}", identifier, self.callback_domain),
            format!("http://{}.{}/", identifier, self.callback_domain),
            format!("http://{}.{}/callback", identifier, self.callback_domain),
            
            // DNS-only (for DNS exfiltration)
            format!("{}.{}", identifier, self.callback_domain),
            
            // With path encoding
            format!("http://{}.{}/ssrf-test", identifier, self.callback_domain),
        ]
    }
    
    /// Extract identifier from callback URL
    pub fn extract_identifier(&self, callback_url: &str) -> Option<String> {
        // Extract subdomain before callback_domain
        if let Some(pos) = callback_url.find(&self.callback_domain) {
            let before = &callback_url[..pos];
            // Remove protocol and extract subdomain
            let subdomain = before
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_end_matches('.');
            
            if !subdomain.is_empty() {
                return Some(subdomain.to_string());
            }
        }
        
        None
    }
}

/// OOB callback listener. Queries the process-global interaction log populated
/// by the built-in listener (see [`start_oob_server`]).
#[derive(Debug, Clone)]
pub struct OobCallbackListener {
    pub callback_domain: String,
}

impl OobCallbackListener {
    pub fn new(callback_domain: String) -> Self {
        Self { callback_domain }
    }

    /// Check whether a callback for `identifier` has been received.
    pub async fn check_callback(&self, identifier: &str) -> bool {
        let hit = oob_was_hit(identifier);
        tracing::debug!("Checking for OOB callback {}: {}", identifier, hit);
        hit
    }

    /// Wait up to `timeout_secs` for a callback, polling the interaction log.
    pub async fn wait_for_callback(&self, identifier: &str, timeout_secs: u64) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        loop {
            if oob_was_hit(identifier) {
                return true;
            }
            if start.elapsed() >= timeout {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}

/// Generate a unique identifier for tracking callbacks
pub fn generate_identifier(endpoint: &str, param: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    endpoint.hash(&mut hasher);
    param.hash(&mut hasher);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .hash(&mut hasher);
    
    format!("ssrf-{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_callback_url() {
        let generator = OobCallbackGenerator::new("attacker.com".to_string());
        let url = generator.generate_callback_url("test123");
        
        assert!(url.contains("test123"));
        assert!(url.contains("attacker.com"));
        assert!(url.starts_with("http://"));
    }
    
    #[test]
    fn test_extract_identifier() {
        let generator = OobCallbackGenerator::new("attacker.com".to_string());
        let url = "http://test123.attacker.com/callback";
        
        let identifier = generator.extract_identifier(url);
        assert_eq!(identifier, Some("test123".to_string()));
    }
    
    #[test]
    fn test_generate_variants() {
        let generator = OobCallbackGenerator::new("attacker.com".to_string());
        let variants = generator.generate_callback_variants("test");

        assert!(!variants.is_empty());
        assert!(variants.iter().any(|v| v.contains("http://")));
        assert!(variants.iter().any(|v| v.contains("https://")));
    }

    #[test]
    fn test_oob_log_correlation() {
        let id = "ssrf-deadbeef-unit";
        assert!(!oob_was_hit(id));
        // Simulate an inbound interaction carrying the identifier in the path.
        record_oob_interaction(format!("GET /{} HTTP/1.1 | Host: x.oast.test", id));
        assert!(oob_was_hit(id));
        // An unrelated identifier must not match.
        assert!(!oob_was_hit("ssrf-not-seen"));
    }

    #[tokio::test]
    async fn test_oob_server_records_real_request() {
        use tokio::io::AsyncWriteExt;

        // Bind on an ephemeral port and fire a real HTTP request at it.
        let addr = start_oob_server("127.0.0.1:0").await.expect("bind oob server");
        let id = "ssrf-livetest-9f8e7d";
        assert!(!oob_was_hit(id));

        let mut stream = tokio::net::TcpStream::connect(&addr).await.expect("connect");
        let req = format!(
            "GET /{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            id, addr
        );
        stream.write_all(req.as_bytes()).await.expect("send");

        // The accept/record happens on a spawned task; poll briefly.
        for _ in 0..40 {
            if oob_was_hit(id) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(oob_was_hit(id), "OOB listener did not record the interaction");
    }

    #[test]
    fn test_parse_dns_question() {
        // Query for "abc123.oast.test" A IN
        let mut pkt = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        for label in ["abc123", "oast", "test"] {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // end of name
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        let (qname, q_end) = parse_dns_question(&pkt).expect("parse");
        assert_eq!(qname, "abc123.oast.test");
        assert_eq!(q_end, pkt.len());
        assert!(build_dns_response(&pkt, q_end).is_some());
    }

    #[tokio::test]
    async fn test_oob_dns_server_records_query() {
        use tokio::net::UdpSocket;

        let addr = start_oob_dns_server("127.0.0.1:0").await.expect("bind dns");
        let id = "ssrf-dnslive-7c6b5a";
        assert!(!oob_was_hit(id));

        // Craft a DNS query for "<id>.oast.test".
        let mut pkt = vec![0x43, 0x21, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        for label in [id, "oast", "test"] {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&pkt, &addr).await.unwrap();

        for _ in 0..40 {
            if oob_was_hit(id) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(oob_was_hit(id), "DNS listener did not record the query");
    }
}

