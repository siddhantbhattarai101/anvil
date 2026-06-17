//! Headless-browser XSS execution verification.
//!
//! Confirms that an injection point doesn't merely *reflect* a payload but
//! actually *executes* JavaScript, by driving system Chrome over the Chrome
//! DevTools Protocol. Canary payloads set `window.__ANVIL_XSS__='<token>'` only
//! if they execute; after navigation we read the variable back — if it equals
//! the token, script ran in the page context. This eliminates the false
//! positives inherent to string-match-only XSS detection and upgrades a finding
//! to "Confirmed (Active Test)".
//!
//! The verifier degrades gracefully: if no browser is present or it fails to
//! launch, callers fall back to the existing heuristic detection.

use crate::payload::injector::inject_query_param;
use anyhow::{anyhow, Result};
use chromiumoxide::{Browser, BrowserConfig};
use futures::StreamExt;
use std::time::Duration;
use url::Url;

const CHROME_CANDIDATES: &[&str] = &[
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
];

/// Locate a usable Chrome/Chromium binary, if any.
pub fn find_chrome() -> Option<String> {
    CHROME_CANDIDATES
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|s| s.to_string())
}

/// Proof that a parameter is XSS-executable (the canary payload that ran).
#[derive(Debug, Clone)]
pub struct XssProof {
    pub payload: String,
}

/// A launched headless browser used to verify XSS execution.
pub struct HeadlessVerifier {
    browser: Browser,
    handler_task: tokio::task::JoinHandle<()>,
}

impl HeadlessVerifier {
    /// Launch a headless Chrome. Returns `Err` if no browser is available or it
    /// fails to start; callers should fall back to heuristic detection.
    pub async fn launch() -> Result<Self> {
        let chrome = find_chrome().ok_or_else(|| anyhow!("no Chrome/Chromium binary found"))?;
        let config = BrowserConfig::builder()
            .chrome_executable(chrome)
            .arg("--no-sandbox")
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .build()
            .map_err(|e| anyhow!("browser config: {}", e))?;

        let (browser, mut handler) = Browser::launch(config).await?;
        let handler_task = tokio::spawn(async move {
            while let Some(h) = handler.next().await {
                if h.is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            browser,
            handler_task,
        })
    }

    /// Navigate to `url`, wait `settle_ms` for execution (and any navigation),
    /// and report whether the canary `token` ran in the resulting page.
    async fn run_canary(&self, url: &str, token: &str, settle_ms: u64) -> Result<bool> {
        let page = self.browser.new_page(url).await?;
        tokio::time::sleep(Duration::from_millis(settle_ms)).await;
        let script = format!("window.__ANVIL_XSS__ === '{}'", token);
        let executed = match page.evaluate(script).await {
            Ok(r) => r.into_value::<bool>().unwrap_or(false),
            Err(_) => false,
        };
        let _ = page.close().await;
        Ok(executed)
    }

    /// Navigate to `url` and report whether the canary `token` executed.
    async fn token_executed(&self, url: &str, token: &str) -> Result<bool> {
        // 350ms is enough for inline/event-handler (onerror/onload) payloads.
        self.run_canary(url, token, 350).await
    }

    /// Verify whether `param` on `base_url` is XSS-executable. Tries a set of
    /// context-aware canary payloads and returns the first that executes.
    pub async fn verify_param(&self, base_url: &Url, param: &str) -> Result<Option<XssProof>> {
        let token = unique_token();
        for canary in canary_payloads(&token) {
            let url = match inject_query_param(base_url, param, &canary) {
                Ok(u) => u,
                Err(_) => continue,
            };
            let executed = tokio::time::timeout(
                Duration::from_secs(15),
                self.token_executed(url.as_str(), &token),
            )
            .await
            .unwrap_or(Ok(false))
            .unwrap_or(false);
            if executed {
                return Ok(Some(XssProof { payload: canary }));
            }
        }
        Ok(None)
    }

    /// Verify whether `param` in a POST body to `action_url` is XSS-executable.
    /// Builds an auto-submitting form (carrying the canary in the body) as a
    /// `data:` URL, lets the headless browser POST it, and checks whether the
    /// canary executed in the response page. `body_params` are the other form
    /// fields to send alongside.
    pub async fn verify_param_post(
        &self,
        action_url: &str,
        param: &str,
        body_params: &[(String, String)],
    ) -> Result<Option<XssProof>> {
        let token = unique_token();
        for canary in canary_payloads(&token) {
            let mut inputs = String::new();
            let mut injected = false;
            for (k, v) in body_params {
                let val = if k == param {
                    injected = true;
                    canary.as_str()
                } else {
                    v.as_str()
                };
                inputs.push_str(&format!(
                    "<input name=\"{}\" value=\"{}\">",
                    attr_escape(k),
                    attr_escape(val)
                ));
            }
            if !injected {
                inputs.push_str(&format!(
                    "<input name=\"{}\" value=\"{}\">",
                    attr_escape(param),
                    attr_escape(&canary)
                ));
            }
            let form = format!(
                "<html><body><form id=\"f\" action=\"{}\" method=\"POST\">{}</form>\
                 <script>document.getElementById('f').submit()</script></body></html>",
                action_url, inputs
            );
            let data_url = format!("data:text/html,{}", urlencoding::encode(&form));
            // Longer settle: the form submits, the browser navigates to the
            // target response, and only then can the canary execute.
            let executed = tokio::time::timeout(
                Duration::from_secs(20),
                self.run_canary(&data_url, &token, 900),
            )
            .await
            .unwrap_or(Ok(false))
            .unwrap_or(false);
            if executed {
                return Ok(Some(XssProof { payload: canary }));
            }
        }
        Ok(None)
    }

    /// Render a URL in the headless browser (executing its JavaScript) and
    /// return the post-JS DOM HTML plus every network request the page issued
    /// (XHR/fetch/sub-resources) — i.e. the real attack surface of an SPA, which
    /// a static HTML fetch never sees.
    pub async fn render(&self, url: &str) -> Result<RenderedPage> {
        use chromiumoxide::cdp::browser_protocol::network::{
            EnableParams, EventRequestWillBeSent,
        };
        use std::sync::{Arc, Mutex};

        let page = self.browser.new_page("about:blank").await?;
        let _ = page.execute(EnableParams::default()).await;

        let requests: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let collector = if let Ok(mut events) =
            page.event_listener::<EventRequestWillBeSent>().await
        {
            let sink = requests.clone();
            Some(tokio::spawn(async move {
                while let Some(ev) = events.next().await {
                    if let Ok(mut g) = sink.lock() {
                        g.push((ev.request.method.clone(), ev.request.url.clone()));
                    }
                }
            }))
        } else {
            None
        };

        let _ = page.goto(url).await;
        let _ = page.wait_for_navigation().await;
        // Give SPA frameworks + their XHR/fetch calls time to run.
        tokio::time::sleep(Duration::from_millis(900)).await;

        let html = page.content().await.unwrap_or_default();
        if let Some(c) = collector {
            c.abort();
        }
        let captured = requests.lock().map(|g| g.clone()).unwrap_or_default();
        let _ = page.close().await;

        Ok(RenderedPage {
            html,
            requests: captured,
        })
    }

    /// Shut the browser down.
    pub async fn close(mut self) {
        let _ = self.browser.close().await;
        self.handler_task.abort();
    }
}

/// A rendered page: its post-JavaScript HTML and the requests it issued.
#[derive(Debug, Default)]
pub struct RenderedPage {
    pub html: String,
    /// (method, url) for every request the page made (XHR/fetch/sub-resources).
    pub requests: Vec<(String, String)>,
}

/// HTML-escape a string for safe inclusion in a form attribute value. The
/// browser decodes the entities on submit, so the server receives the raw value.
fn attr_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn unique_token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static C: AtomicU64 = AtomicU64::new(0);
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let s = C.fetch_add(1, Ordering::Relaxed);
    format!("ANVILX{:x}{:x}", n, s)
}

/// Context-aware canary payloads that set `window.__ANVIL_XSS__` on execution.
fn canary_payloads(token: &str) -> Vec<String> {
    let set = format!("window.__ANVIL_XSS__='{}'", token);
    vec![
        // HTML body context
        format!("<script>{}</script>", set),
        // Attribute breakouts
        format!("\"><script>{}</script>", set),
        format!("'><script>{}</script>", set),
        // Event-handler execution (no user interaction needed)
        format!("<img src=x onerror=\"{}\">", set),
        format!("\"><img src=x onerror=\"{}\">", set),
        format!("<svg onload=\"{}\">", set),
        // Single-quote attribute breakout into a tag
        format!("'><img src=x onerror='{}'>", set),
        // Attribute event-handler breakout with NO tags (survives <> filtering;
        // autofocus auto-fires onfocus on load, so no interaction needed)
        format!("\" autofocus onfocus=\"{}\"", set),
        format!("' autofocus onfocus='{}'", set),
        // HTML-comment escape
        format!("--><script>{}</script>", set),
        // Inside an existing script block
        format!("</script><script>{}</script>", set),
        // JS string breakouts
        format!("';{};//", set),
        format!("\";{};//", set),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn headless_detects_real_execution() {
        let verifier = match HeadlessVerifier::launch().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skipping headless test (no browser): {}", e);
                return;
            }
        };

        let token = "ANVILX_unit_token";
        // A data: URL whose inline script sets the canary variable.
        let exec_url =
            format!("data:text/html,<script>window.__ANVIL_XSS__='{}'</script>", token);
        assert!(
            verifier.token_executed(&exec_url, token).await.unwrap(),
            "execution should be detected"
        );

        // A benign page must NOT be flagged.
        let benign = "data:text/html,<h1>hello</h1>";
        assert!(
            !verifier.token_executed(benign, token).await.unwrap(),
            "benign page must not match"
        );

        verifier.close().await;
    }
}
