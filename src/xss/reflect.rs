// Reflection Discovery Module
// Uses benign markers to discover reflection points before testing XSS payloads

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::payload::injector::inject_query_param;
use crate::xss::context::{classify_context, ContextAnalysis};
use reqwest::Method;
use url::Url;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ReflectionPoint {
    pub parameter: String,
    pub marker: String,
    pub context: ContextAnalysis,
    pub response_body: String,
    pub response_size: usize,
    pub response_time_ms: u128,
}

#[derive(Debug, Clone)]
pub struct ReflectionDiscovery {
    pub reflections: Vec<ReflectionPoint>,
    pub non_reflecting_params: Vec<String>,
}

/// Discover reflection points using benign markers
pub async fn discover_reflections(
    client: &HttpClient,
    url: &Url,
    parameters: &[String],
) -> anyhow::Result<ReflectionDiscovery> {
    let mut reflections = Vec::new();
    let mut non_reflecting = Vec::new();
    
    tracing::info!("Phase 1: Discovering reflection points for {} parameters", parameters.len());
    
    for param in parameters {
        match probe_parameter(client, url, param).await {
            Ok(Some(reflection)) => {
                tracing::info!(
                    "✓ Reflection found: {} → {:?} (confidence: {:.0}%)",
                    param,
                    reflection.context.context,
                    reflection.context.confidence * 100.0
                );
                reflections.push(reflection);
            }
            Ok(None) => {
                tracing::debug!("✗ No reflection: {}", param);
                non_reflecting.push(param.clone());
            }
            Err(e) => {
                tracing::warn!("Error probing {}: {}", param, e);
                non_reflecting.push(param.clone());
            }
        }
    }
    
    Ok(ReflectionDiscovery {
        reflections,
        non_reflecting_params: non_reflecting,
    })
}

async fn probe_parameter(
    client: &HttpClient,
    url: &Url,
    param: &str,
) -> anyhow::Result<Option<ReflectionPoint>> {
    // Use multiple benign markers to reduce false positives
    let markers = generate_markers();
    
    for marker in markers {
        let start = std::time::Instant::now();
        
        let test_url = inject_query_param(url, param, &marker)?;
        let request = HttpRequest::new(Method::GET, test_url);
        let response = client.execute(request).await?;
        
        let elapsed = start.elapsed().as_millis();
        
        // Check if marker is reflected
        let body_str = String::from_utf8_lossy(&response.body).to_string();
        if body_str.contains(&marker) {
            let context = classify_context(&body_str, &marker);
            
            // Require minimum confidence to avoid false positives
            if context.confidence >= 0.5 {
                return Ok(Some(ReflectionPoint {
                    parameter: param.to_string(),
                    marker,
                    context,
                    response_body: body_str.clone(),
                    response_size: response.body.len(),
                    response_time_ms: elapsed,
                }));
            }
        }
    }
    
    Ok(None)
}

fn generate_markers() -> Vec<String> {
    vec![
        "ANVILXSS".to_string(),
        "ANVIL_XSS_TEST".to_string(),
        "ANVIL_MARKER_12345".to_string(),
        format!("ANVIL_{}", random_string(8)),
    ]
}

fn random_string(len: usize) -> String {
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Monotonic per-process counter guarantees uniqueness even for markers
    // generated within the same nanosecond (the old timestamp-only scheme
    // collided and caused substring false positives).
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);

    // RandomState is seeded from the OS RNG, giving real per-process entropy
    // without adding the `rand` crate dependency.
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(nanos);
    hasher.write_u64(seq);
    let entropy = hasher.finish();

    let raw = format!("{:016x}{:016x}", nanos ^ entropy, seq);
    raw[..len.min(raw.len())].to_string()
}

/// Probe with POST data for forms
pub async fn discover_post_reflections(
    client: &HttpClient,
    url: &Url,
    form_data: &HashMap<String, String>,
) -> anyhow::Result<ReflectionDiscovery> {
    let mut reflections = Vec::new();
    let mut non_reflecting = Vec::new();
    
    for (param, _value) in form_data {
        match probe_post_parameter(client, url, param, form_data).await {
            Ok(Some(reflection)) => {
                tracing::info!(
                    "✓ POST reflection found: {} → {:?}",
                    param,
                    reflection.context.context
                );
                reflections.push(reflection);
            }
            Ok(None) => {
                non_reflecting.push(param.clone());
            }
            Err(e) => {
                tracing::warn!("Error probing POST {}: {}", param, e);
                non_reflecting.push(param.clone());
            }
        }
    }
    
    Ok(ReflectionDiscovery {
        reflections,
        non_reflecting_params: non_reflecting,
    })
}

async fn probe_post_parameter(
    client: &HttpClient,
    url: &Url,
    param: &str,
    form_data: &HashMap<String, String>,
) -> anyhow::Result<Option<ReflectionPoint>> {
    let markers = generate_markers();
    
    for marker in markers {
        let start = std::time::Instant::now();
        
        // Create modified form data with marker
        let mut test_data = form_data.clone();
        test_data.insert(param.to_string(), marker.clone());
        
        let mut request = HttpRequest::new(Method::POST, url.clone());
        
        // Set form data as body
        let form_body = serde_urlencoded::to_string(&test_data)?;
        request.body = Some(form_body.into_bytes());
        
        // Add Content-Type header
        request.headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        
        let response = client.execute(request).await?;
        let elapsed = start.elapsed().as_millis();
        
        let body_str = String::from_utf8_lossy(&response.body).to_string();
        if body_str.contains(&marker) {
            let context = classify_context(&body_str, &marker);
            
            if context.confidence >= 0.5 {
                return Ok(Some(ReflectionPoint {
                    parameter: param.to_string(),
                    marker,
                    context,
                    response_body: body_str.clone(),
                    response_size: response.body.len(),
                    response_time_ms: elapsed,
                }));
            }
        }
    }
    
    Ok(None)
}

/// Analyze reflection characteristics for exploitation planning
pub fn analyze_reflection_characteristics(reflection: &ReflectionPoint) -> ReflectionCharacteristics {
    let body_str = &reflection.response_body;
    let marker_count = body_str.matches(&reflection.marker).count();
    let encoding_level = detect_encoding_level(&body_str, &reflection.marker);
    let sanitization = detect_sanitization_patterns(&body_str, &reflection.marker);
    
    let is_injectable = marker_count > 0 && matches!(encoding_level, EncodingLevel::None);
    
    ReflectionCharacteristics {
        reflection_count: marker_count,
        encoding_level,
        sanitization_detected: !sanitization.is_empty(),
        sanitization_patterns: sanitization,
        injectable: is_injectable,
    }
}

#[derive(Debug, Clone)]
pub struct ReflectionCharacteristics {
    pub reflection_count: usize,
    pub encoding_level: EncodingLevel,
    pub sanitization_detected: bool,
    pub sanitization_patterns: Vec<String>,
    pub injectable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingLevel {
    None,
    Partial,      // Some characters encoded
    Full,         // All special characters encoded
    DoubleEncode, // Double HTML encoding detected
}

fn detect_encoding_level(body: &str, marker: &str) -> EncodingLevel {
    // Check for various encoding levels
    let encoded_lt = body.contains("&lt;") || body.contains("&#60;") || body.contains("&#x3c;");
    let encoded_gt = body.contains("&gt;") || body.contains("&#62;") || body.contains("&#x3e;");
    let encoded_quote = body.contains("&quot;") || body.contains("&#34;");
    let encoded_apos = body.contains("&#39;") || body.contains("&#x27;") || body.contains("&apos;");
    
    // Check for double encoding
    if body.contains("&amp;lt;") || body.contains("&amp;gt;") {
        return EncodingLevel::DoubleEncode;
    }
    
    // Angle brackets are the characters that enable HTML/tag injection. If BOTH
    // are encoded the payload cannot break out into markup, which is full
    // protection regardless of whether quotes happen to be encoded too. (The old
    // logic required 3+ of 4 char *types* encoded and so mislabelled a fully
    // bracket-encoded reflection as merely "Partial".)
    if encoded_lt && encoded_gt {
        return EncodingLevel::Full;
    }

    let encoding_count = [encoded_lt, encoded_gt, encoded_quote, encoded_apos]
        .iter()
        .filter(|&&x| x)
        .count();

    if encoding_count == 0 {
        EncodingLevel::None
    } else {
        EncodingLevel::Partial
    }
}

fn detect_sanitization_patterns(body: &str, marker: &str) -> Vec<String> {
    let mut patterns = Vec::new();

    // If the dangerous marker does not appear verbatim, its special characters
    // were stripped, encoded, or the payload was filtered out entirely — a
    // strong signal the input was neutralised. (Only meaningful because this is
    // called after a benign marker was confirmed to reflect.)
    if !body.contains(marker) {
        patterns.push("Marker altered or stripped (possible sanitization)".to_string());
    }

    // Check for common sanitization
    if body.contains(&marker.replace('<', ""))
        || body.contains(&marker.replace('>', ""))
    {
        patterns.push("Character stripping detected".to_string());
    }
    
    if body.contains(&marker.to_uppercase()) && marker.chars().any(|c| c.is_lowercase()) {
        patterns.push("Case transformation detected".to_string());
    }
    
    if body.contains(&marker.replace("script", "")) {
        patterns.push("Keyword filtering (script) detected".to_string());
    }
    
    if body.contains(&marker.replace("javascript:", "")) {
        patterns.push("Protocol filtering detected".to_string());
    }
    
    patterns
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_marker_generation() {
        let markers = generate_markers();
        assert!(!markers.is_empty());
        assert!(markers[0].contains("ANVIL"));
    }
    
    #[test]
    fn test_encoding_detection() {
        let body = "<div>&lt;MARKER&gt;</div>";
        let level = detect_encoding_level(body, "MARKER");
        assert_eq!(level, EncodingLevel::Full);
    }
    
    #[test]
    fn test_sanitization_detection() {
        let body = "<div>SAFE</div>";
        let patterns = detect_sanitization_patterns(body, "<MARKER>");
        assert!(!patterns.is_empty());
    }
}

