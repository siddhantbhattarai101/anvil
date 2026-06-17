//! HTTP connection handling for SQL injection.
//!
//! Injection is abstracted behind [`InjectionPoint`], which describes *where* a
//! payload is placed (query parameter, form field, JSON body field, cookie, or
//! header) and knows how to build the corresponding [`HttpRequest`]. The SQLi
//! techniques are agnostic to this — they call [`Request::query_page`] with a
//! payload and the injection point handles placement. This lets the exact same
//! detection logic test GET query params, POST bodies (form or JSON), cookies,
//! and headers without any change to the techniques.

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use anyhow::Result;
use reqwest::Method;
use url::Url;

/// Where in the request a payload is injected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionLocation {
    /// URL query-string parameter.
    Query,
    /// `application/x-www-form-urlencoded` body field.
    Form,
    /// JSON body field (the parameter name may be a dotted path, e.g. `a.b.c`).
    Json,
    /// A single cookie value within the `Cookie` header.
    Cookie,
    /// An arbitrary request header value.
    Header,
}

/// A fully-described injection point: the request context plus the location and
/// name of the parameter to inject into.
#[derive(Debug, Clone)]
pub struct InjectionPoint {
    pub location: InjectionLocation,
    pub method: Method,
    pub url: Url,
    /// Parameter / field / cookie / header name to inject into.
    pub param: String,
    /// Base request body (form string or JSON), if any.
    pub body: Option<String>,
    /// Base cookies carried on every request.
    pub cookies: Vec<(String, String)>,
    /// Base extra headers carried on every request.
    pub headers: Vec<(String, String)>,
}

impl InjectionPoint {
    /// Backward-compatible query-string GET injection point.
    pub fn query(url: Url, param: impl Into<String>) -> Self {
        Self {
            location: InjectionLocation::Query,
            method: Method::GET,
            url,
            param: param.into(),
            body: None,
            cookies: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Build an injection point from request context, auto-selecting the
    /// location: a POST with a JSON body injects into the JSON field, a POST
    /// with any other body injects into the form field, and everything else
    /// injects into the query string. (Cookie/header injection is reachable via
    /// the explicit struct form but not auto-selected here.)
    pub fn from_context(
        method: Method,
        url: Url,
        param: impl Into<String>,
        body: Option<String>,
        cookies: Vec<(String, String)>,
        headers: Vec<(String, String)>,
    ) -> Self {
        let location = if method == Method::POST {
            match body.as_deref().map(str::trim_start) {
                Some(b) if b.starts_with('{') || b.starts_with('[') => InjectionLocation::Json,
                Some(b) if !b.is_empty() => InjectionLocation::Form,
                _ => InjectionLocation::Query,
            }
        } else {
            InjectionLocation::Query
        };
        Self {
            location,
            method,
            url,
            param: param.into(),
            body,
            cookies,
            headers,
        }
    }

    /// The current (original) value of the target parameter at its location.
    /// Used to seed boundary payloads from the real value so injections in a
    /// string context (e.g. `WHERE name='admin'`) preserve the row match.
    pub fn original_value(&self) -> String {
        match self.location {
            InjectionLocation::Query => self
                .url
                .query_pairs()
                .find(|(k, _)| k == self.param.as_str())
                .map(|(_, v)| v.to_string())
                .unwrap_or_default(),
            InjectionLocation::Form => self
                .body
                .as_deref()
                .and_then(|b| {
                    url::form_urlencoded::parse(b.as_bytes())
                        .find(|(k, _)| k == self.param.as_str())
                        .map(|(_, v)| v.to_string())
                })
                .unwrap_or_default(),
            InjectionLocation::Json => self
                .body
                .as_deref()
                .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                .and_then(|v| {
                    let mut cur = &v;
                    for part in self.param.split('.') {
                        cur = cur.get(part)?;
                    }
                    cur.as_str().map(|s| s.to_string())
                })
                .unwrap_or_default(),
            InjectionLocation::Cookie => self
                .cookies
                .iter()
                .find(|(k, _)| k == &self.param)
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            InjectionLocation::Header => self
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&self.param))
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
        }
    }

    /// Build the HTTP request for this injection point with `payload` placed at
    /// the configured location.
    pub fn build_request(&self, payload: &str) -> HttpRequest {
        match self.location {
            InjectionLocation::Query => self.build_query(payload),
            InjectionLocation::Form => self.build_form(payload),
            InjectionLocation::Json => self.build_json(payload),
            InjectionLocation::Cookie => self.build_cookie(payload),
            InjectionLocation::Header => self.build_header(payload),
        }
    }

    fn build_query(&self, payload: &str) -> HttpRequest {
        let mut url = self.url.clone();
        let mut pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| {
                if k == self.param.as_str() {
                    (k.to_string(), payload.to_string())
                } else {
                    (k.to_string(), v.to_string())
                }
            })
            .collect();
        if !pairs.iter().any(|(k, _)| k == &self.param) {
            pairs.push((self.param.clone(), payload.to_string()));
        }
        url.query_pairs_mut().clear();
        for (k, v) in &pairs {
            url.query_pairs_mut().append_pair(k, v);
        }

        let mut req = HttpRequest::new(self.method.clone(), url);
        self.apply_body(&mut req);
        self.apply_headers_and_cookies(&mut req, None);
        req
    }

    fn build_form(&self, payload: &str) -> HttpRequest {
        let base = self.body.clone().unwrap_or_default();
        let mut pairs: Vec<(String, String)> =
            url::form_urlencoded::parse(base.as_bytes()).into_owned().collect();
        let mut found = false;
        for (k, v) in pairs.iter_mut() {
            if k == &self.param {
                *v = payload.to_string();
                found = true;
            }
        }
        if !found {
            pairs.push((self.param.clone(), payload.to_string()));
        }
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();

        let mut req = HttpRequest::new(self.method.clone(), self.url.clone());
        req.set_body(body);
        req.set_header("Content-Type", "application/x-www-form-urlencoded");
        self.apply_headers_and_cookies(&mut req, None);
        req
    }

    fn build_json(&self, payload: &str) -> HttpRequest {
        let base = self.body.clone().unwrap_or_else(|| "{}".to_string());
        let mut value: serde_json::Value =
            serde_json::from_str(&base).unwrap_or_else(|_| serde_json::json!({}));
        let parts: Vec<&str> = self.param.split('.').collect();
        set_json_path(&mut value, &parts, payload);
        let body = value.to_string();

        let mut req = HttpRequest::new(self.method.clone(), self.url.clone());
        req.set_body(body);
        req.set_header("Content-Type", "application/json");
        self.apply_headers_and_cookies(&mut req, None);
        req
    }

    fn build_cookie(&self, payload: &str) -> HttpRequest {
        let mut req = HttpRequest::new(self.method.clone(), self.url.clone());
        self.apply_body(&mut req);
        let cookie = self.render_cookies(Some(payload));
        self.apply_headers_and_cookies(&mut req, Some(cookie));
        req
    }

    fn build_header(&self, payload: &str) -> HttpRequest {
        let mut req = HttpRequest::new(self.method.clone(), self.url.clone());
        self.apply_body(&mut req);
        // Base headers, with the target header's value replaced by the payload.
        let mut injected = false;
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case(&self.param) {
                req.set_header(k, payload);
                injected = true;
            } else {
                req.set_header(k, v);
            }
        }
        if !injected {
            req.set_header(&self.param, payload);
        }
        let cookie = self.render_cookies(None);
        if !cookie.is_empty() {
            req.set_header("Cookie", &cookie);
        }
        req
    }

    fn apply_body(&self, req: &mut HttpRequest) {
        if let Some(b) = &self.body {
            req.set_body(b.clone());
        }
    }

    /// Attach base headers and the `Cookie` header. `cookie_override` lets the
    /// cookie-injection path supply an already-rendered cookie string.
    fn apply_headers_and_cookies(&self, req: &mut HttpRequest, cookie_override: Option<String>) {
        for (k, v) in &self.headers {
            req.set_header(k, v);
        }
        let cookie = cookie_override.unwrap_or_else(|| self.render_cookies(None));
        if !cookie.is_empty() {
            req.set_header("Cookie", &cookie);
        }
    }

    /// Render the `Cookie` header string. When `inject` is `Some`, the cookie
    /// named `self.param` carries the payload (appended if not already present).
    fn render_cookies(&self, inject: Option<&str>) -> String {
        let mut parts = Vec::new();
        let mut found = false;
        for (k, v) in &self.cookies {
            match inject {
                Some(p) if k == &self.param => {
                    parts.push(format!("{}={}", k, p));
                    found = true;
                }
                _ => parts.push(format!("{}={}", k, v)),
            }
        }
        if let Some(p) = inject {
            if !found {
                parts.push(format!("{}={}", self.param, p));
            }
        }
        parts.join("; ")
    }
}

/// Recursively set a (possibly nested) JSON object field to a string payload,
/// creating intermediate objects as needed.
fn set_json_path(value: &mut serde_json::Value, parts: &[&str], payload: &str) {
    match parts {
        [] => {}
        [last] => {
            if let Some(obj) = value.as_object_mut() {
                obj.insert((*last).to_string(), serde_json::Value::String(payload.to_string()));
            }
        }
        [head, rest @ ..] => {
            if let Some(obj) = value.as_object_mut() {
                let entry = obj
                    .entry((*head).to_string())
                    .or_insert_with(|| serde_json::json!({}));
                set_json_path(entry, rest, payload);
            }
        }
    }
}

/// Request handler for SQL injection testing. Wraps an [`InjectionPoint`] and an
/// HTTP client; techniques call [`query_page`](Self::query_page) with payloads.
pub struct Request<'a> {
    client: &'a HttpClient,
    point: InjectionPoint,
}

impl<'a> Request<'a> {
    /// Backward-compatible constructor: query-string GET injection on `parameter`.
    pub fn new(client: &'a HttpClient, base_url: Url, parameter: String) -> Self {
        Self {
            client,
            point: InjectionPoint::query(base_url, parameter),
        }
    }

    /// Construct from a fully-specified injection point (form/JSON/cookie/header).
    pub fn with_point(client: &'a HttpClient, point: InjectionPoint) -> Self {
        Self { client, point }
    }

    /// The injection point this request targets.
    pub fn injection_point(&self) -> &InjectionPoint {
        &self.point
    }

    /// The original value of the injected parameter (for boundary seeding).
    pub fn original_value(&self) -> String {
        self.point.original_value()
    }

    /// Send a payload and get the response body.
    pub async fn query_page(&self, payload: &str) -> Result<String> {
        let req = self.point.build_request(payload);
        let resp = self.client.execute(req).await?;
        Ok(resp.body_text())
    }

    /// Send a payload and get (body, status, length).
    pub async fn query_page_full(&self, payload: &str) -> Result<(String, u16, usize)> {
        let req = self.point.build_request(payload);
        let resp = self.client.execute(req).await?;
        let body = resp.body_text();
        let len = body.len();
        let status = resp.status;
        Ok((body, status, len))
    }

    /// Send a payload and get the full response (status, headers, body).
    /// Needed by detectors that inspect response headers — e.g. open redirect
    /// reads the `Location` header. Redirects are not followed by the client.
    pub async fn query_response(&self, payload: &str) -> Result<crate::http::response::HttpResponse> {
        let req = self.point.build_request(payload);
        self.client.execute(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(location: InjectionLocation, param: &str) -> InjectionPoint {
        InjectionPoint {
            location,
            method: Method::POST,
            url: Url::parse("http://t/app?id=1&q=x").unwrap(),
            param: param.to_string(),
            body: None,
            cookies: vec![("sid".into(), "abc".into()), ("role".into(), "user".into())],
            headers: vec![("X-Api".into(), "k".into())],
        }
    }

    fn body_str(req: &HttpRequest) -> String {
        String::from_utf8_lossy(req.body.as_deref().unwrap_or_default()).to_string()
    }

    fn header(req: &HttpRequest, name: &str) -> Option<String> {
        req.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    #[test]
    fn query_injection_replaces_target_param_only() {
        let p = InjectionPoint::query(Url::parse("http://t/a?id=1&q=x").unwrap(), "id");
        let req = p.build_request("1' OR '1'='1");
        let q = req.url.query().unwrap();
        assert!(q.contains("id=1%27+OR+%271%27%3D%271") || q.contains("id=1%27%20OR"));
        assert!(q.contains("q=x"));
    }

    #[test]
    fn form_injection_sets_body_and_content_type() {
        let mut p = point(InjectionLocation::Form, "user");
        p.body = Some("user=admin&page=2".into());
        let req = p.build_request("x' AND 1=1");
        let b = body_str(&req);
        assert!(b.contains("user=x%27+AND+1%3D1"));
        assert!(b.contains("page=2"));
        assert_eq!(header(&req, "content-type").as_deref(), Some("application/x-www-form-urlencoded"));
    }

    #[test]
    fn json_injection_handles_nested_path() {
        let mut p = point(InjectionLocation::Json, "filter.name");
        p.body = Some(r#"{"filter":{"name":"a","age":3},"k":1}"#.into());
        let req = p.build_request("z");
        let v: serde_json::Value = serde_json::from_str(&body_str(&req)).unwrap();
        assert_eq!(v["filter"]["name"], "z");
        assert_eq!(v["filter"]["age"], 3);
        assert_eq!(v["k"], 1);
        assert_eq!(header(&req, "content-type").as_deref(), Some("application/json"));
    }

    #[test]
    fn cookie_injection_replaces_target_cookie() {
        let p = point(InjectionLocation::Cookie, "sid");
        let req = p.build_request("payload123");
        let cookie = header(&req, "cookie").unwrap();
        assert!(cookie.contains("sid=payload123"));
        assert!(cookie.contains("role=user"));
    }

    #[test]
    fn original_value_extracted_per_location() {
        let qp = InjectionPoint::query(Url::parse("http://t/a?name=admin&x=1").unwrap(), "name");
        assert_eq!(qp.original_value(), "admin");

        let mut fp = point(InjectionLocation::Form, "user");
        fp.body = Some("user=bob&page=2".into());
        assert_eq!(fp.original_value(), "bob");

        let mut jp = point(InjectionLocation::Json, "filter.name");
        jp.body = Some(r#"{"filter":{"name":"alice"}}"#.into());
        assert_eq!(jp.original_value(), "alice");

        let cp = point(InjectionLocation::Cookie, "sid");
        assert_eq!(cp.original_value(), "abc");
    }

    #[test]
    fn header_injection_overrides_target_header() {
        let p = point(InjectionLocation::Header, "User-Agent");
        let req = p.build_request("sqli-ua");
        assert_eq!(header(&req, "user-agent").as_deref(), Some("sqli-ua"));
        // base cookies still travel along
        assert!(header(&req, "cookie").unwrap().contains("sid=abc"));
    }
}
