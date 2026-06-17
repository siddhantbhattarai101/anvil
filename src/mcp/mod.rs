//! Minimal Model Context Protocol (MCP) server over stdio.
//!
//! Lets any MCP-capable AI agent (e.g. Claude Code) drive ANVIL as a native
//! tool. The transport is newline-delimited JSON-RPC 2.0 on stdin/stdout;
//! stdout carries protocol messages only. Each `anvil_scan` tool call runs the
//! scanner as a child process that writes JSON findings to a temp file (so the
//! child's own stdout/stderr never touch the protocol stream), then returns the
//! parsed findings to the agent.

use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Run the stdio server loop until EOF.
pub async fn serve() -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = reader.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue, // ignore malformed frames
        };
        if let Some(resp) = handle(&req).await {
            let mut s = serde_json::to_string(&resp)?;
            s.push('\n');
            stdout.write_all(s.as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

/// Dispatch one JSON-RPC message. Returns None for notifications (no reply).
async fn handle(req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    // Notifications carry no id and expect no response.
    if id.is_none() {
        return None;
    }
    let id = id.unwrap();

    match method {
        "initialize" => Some(ok(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "anvil", "version": env!("CARGO_PKG_VERSION") }
            }),
        )),
        "ping" => Some(ok(id, json!({}))),
        "tools/list" => Some(ok(id, json!({ "tools": [tool_def()] }))),
        "tools/call" => Some(tools_call(id, req).await),
        _ => Some(err(id, -32601, &format!("method not found: {method}"))),
    }
}

/// The single scan tool exposed to agents.
fn tool_def() -> Value {
    json!({
        "name": "anvil_scan",
        "description":
            "Run the ANVIL web vulnerability scanner against a target URL and return JSON \
             findings. Covers the OWASP Top 10 (SQLi, NoSQLi, XSS, SSRF, command injection, \
             path traversal, SSTI, XXE, open redirect, CORS, CRLF) plus passive audits \
             (security headers, JWT, secrets, outdated components, SRI). Authorized testing only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": { "type": "string", "description": "Target URL, e.g. https://host/page?id=1" },
                "profile": {
                    "type": "string",
                    "description": "Which checks to run. 'owasp' (default) runs the full sweep; or a single class: sqli, nosqli, xss, ssrf, cmdi, path-traversal, ssti, xxe, open-redirect, cors, crlf, security-headers, jwt, secrets, components, sri.",
                    "default": "owasp"
                },
                "param": { "type": "string", "description": "Optional single parameter to test directly." },
                "fail_on": { "type": "string", "description": "Optional severity gate: info|low|medium|high|critical." }
            },
            "required": ["target"]
        }
    })
}

/// Map a profile name to the corresponding CLI flag(s).
fn profile_flags(profile: &str) -> Option<Vec<String>> {
    let single = [
        "sqli", "nosqli", "xss", "ssrf", "cmdi", "path-traversal", "ssti", "xxe",
        "open-redirect", "cors", "crlf", "security-headers", "jwt", "secrets",
        "components", "sri",
    ];
    match profile {
        "" | "owasp" | "all" => Some(vec!["--owasp".to_string()]),
        p if single.contains(&p) => Some(vec![format!("--{p}")]),
        _ => None,
    }
}

async fn tools_call(id: Value, req: &Value) -> Value {
    let args = req.get("params").and_then(|p| p.get("arguments")).cloned().unwrap_or(json!({}));
    let name = req
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("");
    if name != "anvil_scan" {
        return err(id, -32602, &format!("unknown tool: {name}"));
    }

    let target = match args.get("target").and_then(|t| t.as_str()) {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => return tool_error(id, "missing required argument: target"),
    };
    let profile = args.get("profile").and_then(|p| p.as_str()).unwrap_or("owasp");
    let flags = match profile_flags(profile) {
        Some(f) => f,
        None => return tool_error(id, &format!("unknown profile: {profile}")),
    };

    match run_scan(&target, &flags, &args).await {
        Ok(text) => ok(
            id,
            json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
        ),
        Err(e) => tool_error(id, &format!("scan failed: {e}")),
    }
}

/// Spawn ANVIL as a child process, capture JSON findings from a temp file.
async fn run_scan(target: &str, flags: &[String], args: &Value) -> Result<String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static C: AtomicU64 = AtomicU64::new(0);
    let uniq = format!(
        "{}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0),
        C.fetch_add(1, Ordering::Relaxed)
    );
    let out = std::env::temp_dir().join(format!("anvil-mcp-{uniq}.json"));

    let exe = std::env::current_exe()?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("-t").arg(target);
    for f in flags {
        cmd.arg(f);
    }
    if let Some(p) = args.get("param").and_then(|p| p.as_str()) {
        if !p.is_empty() {
            cmd.arg("-p").arg(p);
        }
    }
    if let Some(s) = args.get("fail_on").and_then(|s| s.as_str()) {
        if !s.is_empty() {
            cmd.arg("--fail-on").arg(s);
        }
    }
    cmd.arg("--format").arg("json").arg("-o").arg(&out).arg("--no-banner").arg("-q");
    // Keep the child's stdio off the protocol stream entirely.
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let status = cmd.status().await?;
    let body = tokio::fs::read_to_string(&out).await.unwrap_or_else(|_| "{\"findings\":[]}".to_string());
    let _ = tokio::fs::remove_file(&out).await;

    // Annotate with the gate exit code (2 = findings met --fail-on).
    let parsed: Value = serde_json::from_str(&body).unwrap_or(json!({"findings": []}));
    let count = parsed.get("findings").and_then(|f| f.as_array()).map(|a| a.len()).unwrap_or(0);
    let summary = json!({
        "target": target,
        "exit_code": status.code().unwrap_or(-1),
        "findings_count": count,
        "report": parsed,
    });
    Ok(serde_json::to_string_pretty(&summary)?)
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// A tool-level error is reported as a successful result with isError=true,
/// per MCP, so the agent can read the message rather than aborting.
fn tool_error(id: Value, message: &str) -> Value {
    ok(
        id,
        json!({ "content": [{ "type": "text", "text": message }], "isError": true }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_mapping() {
        assert_eq!(profile_flags("owasp"), Some(vec!["--owasp".to_string()]));
        assert_eq!(profile_flags(""), Some(vec!["--owasp".to_string()]));
        assert_eq!(profile_flags("sqli"), Some(vec!["--sqli".to_string()]));
        assert_eq!(profile_flags("path-traversal"), Some(vec!["--path-traversal".to_string()]));
        assert_eq!(profile_flags("bogus"), None);
    }

    #[tokio::test]
    async fn initialize_returns_server_info() {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let resp = handle(&req).await.unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "anvil");
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn tools_list_exposes_anvil_scan() {
        let req = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        let resp = handle(&req).await.unwrap();
        assert_eq!(resp["result"]["tools"][0]["name"], "anvil_scan");
    }

    #[tokio::test]
    async fn notification_has_no_response() {
        let req = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        assert!(handle(&req).await.is_none());
    }
}
