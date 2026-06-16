use crate::core::scope::Scope;
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::scanner::sitemap::SiteMap;
use reqwest::Method;
use scraper::{Html, Selector};
use std::collections::{HashSet, VecDeque};
use url::Url;

pub struct Crawler {
    pub max_depth: usize,
    /// When true (and a headless browser is available), pages are rendered with
    /// JavaScript executed, and the discovered DOM plus the page's XHR/fetch
    /// requests are harvested — capturing SPA attack surface a static fetch misses.
    pub js_render: bool,
}

impl Crawler {
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            js_render: false,
        }
    }

    /// Enable JavaScript-rendering crawl (headless Chrome).
    pub fn with_js_render(mut self, enabled: bool) -> Self {
        self.js_render = enabled;
        self
    }

    pub async fn crawl(
        &self,
        client: &HttpClient,
        start_url: Url,
        scope: &Scope,
    ) -> anyhow::Result<SiteMap> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut sitemap = SiteMap::new(start_url.as_str().to_string());

        queue.push_back((start_url.clone(), 0));

        // Launch a headless browser once if JS rendering is requested + available.
        let renderer = if self.js_render && crate::xss::headless::find_chrome().is_some() {
            match crate::xss::headless::HeadlessVerifier::launch().await {
                Ok(v) => {
                    tracing::info!("JS-rendering crawl enabled (headless Chrome)");
                    Some(v)
                }
                Err(e) => {
                    tracing::warn!("JS render unavailable ({}); falling back to static crawl", e);
                    None
                }
            }
        } else {
            None
        };

        while let Some((url, depth)) = queue.pop_front() {
            if depth > self.max_depth || visited.contains(url.as_str()) {
                continue;
            }
            visited.insert(url.as_str().to_string());

            // Register this endpoint.
            let path = url.path().to_string();
            let params: Vec<String> = url.query_pairs().map(|(k, _)| k.to_string()).collect();
            sitemap.add_endpoint(path.clone(), "GET", params);

            // Obtain the page HTML — JS-rendered or static.
            let body_html = if let Some(ref r) = renderer {
                match r.render(url.as_str()).await {
                    Ok(rendered) => {
                        // Harvest XHR/fetch/API requests the page made — the real
                        // SPA surface. Skip static assets and out-of-scope hosts.
                        for (method, req_url) in &rendered.requests {
                            if let Ok(u) = Url::parse(req_url) {
                                if scope.is_in_scope(&u) && !is_static_asset(u.path()) {
                                    let p: Vec<String> =
                                        u.query_pairs().map(|(k, _)| k.to_string()).collect();
                                    sitemap.add_endpoint(u.path().to_string(), method, p);
                                    if method == "GET"
                                        && u.query().map(|q| !q.is_empty()).unwrap_or(false)
                                        && !visited.contains(u.as_str())
                                    {
                                        queue.push_back((u, depth + 1));
                                    }
                                }
                            }
                        }
                        rendered.html
                    }
                    Err(_) => continue,
                }
            } else {
                let req = HttpRequest::new(Method::GET, url.clone());
                match client.execute(req).await {
                    Ok(r) => r.body_text(),
                    Err(_) => continue,
                }
            };

            if body_html.is_empty() {
                continue;
            }

            // Parse links and forms from the (rendered) DOM. Note: the scraper
            // Html value is not held across any await point.
            let document = Html::parse_document(&body_html);

            if let Ok(a_sel) = Selector::parse("a[href]") {
                for el in document.select(&a_sel) {
                    if let Some(href) = el.value().attr("href") {
                        if let Ok(next) = url.join(href) {
                            if scope.is_in_scope(&next) && !visited.contains(next.as_str()) {
                                queue.push_back((next, depth + 1));
                            }
                        }
                    }
                }
            }

            if let Ok(form_sel) = Selector::parse("form") {
                if let Ok(input_sel) = Selector::parse("input[name], textarea[name], select[name]") {
                    for form in document.select(&form_sel) {
                        let action = form.value().attr("action").unwrap_or(url.path());
                        let method =
                            form.value().attr("method").unwrap_or("GET").to_uppercase();

                        if let Ok(form_url) = url.join(action) {
                            let mut form_params = Vec::new();
                            for input in form.select(&input_sel) {
                                if let Some(name) = input.value().attr("name") {
                                    form_params.push(name.to_string());
                                }
                            }
                            sitemap.add_endpoint(form_url.path().to_string(), &method, form_params);
                        }
                    }
                }
            }
        }

        if let Some(r) = renderer {
            r.close().await;
        }

        Ok(sitemap)
    }
}

/// Whether a path looks like a static asset (skip when harvesting API surface).
fn is_static_asset(path: &str) -> bool {
    let p = path.to_lowercase();
    const EXT: &[&str] = &[
        ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm", ".mp3", ".pdf", ".wasm",
    ];
    EXT.iter().any(|e| p.ends_with(e))
}
