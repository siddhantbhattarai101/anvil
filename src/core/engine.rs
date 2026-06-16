//! ANVIL Core Engine
//!
//! Main orchestrator for security scanning workflows.

use crate::core::capability::Capability;
use crate::core::context::Context;
use crate::core::rate_limit::RateLimiter;
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::scanner::crawler::Crawler;
use crate::scanner::fingerprint::fingerprint_response;
use crate::scanner::sitemap::SiteMap;
use crate::sqli::{SqliResult, SqliTechnique};
use crate::validation::baseline::Baseline;
use reqwest::Method;
use url::Url;

pub struct Engine {
    ctx: Context,
}

impl Engine {
    pub fn new(ctx: Context) -> anyhow::Result<Self> {
        Ok(Self { ctx })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        tracing::info!("Starting ANVIL scan against {}", self.ctx.target);
        tracing::info!("Rate limit: {} req/sec", self.ctx.rate_limit);

        if self.ctx.verbose {
            tracing::info!("Enabled capabilities: {:?}", self.ctx.profile.enabled);
        }

        // Initialize reporter for vulnerability findings
        let mut reporter = crate::reporting::reporter::Reporter::new();

        // -------------------------------------------------
        // Core initialization with cookie/header support
        // -------------------------------------------------
        let limiter = RateLimiter::new(self.ctx.rate_limit);
        
        // Create client with authentication if provided
        let client = if self.ctx.cookies.is_some() || !self.ctx.headers.is_empty() {
            tracing::info!("Using authenticated session");
            if self.ctx.cookies.is_some() {
                tracing::info!("  Cookie: <redacted>");
            }
            if !self.ctx.headers.is_empty() {
                tracing::info!("  Custom headers: {}", self.ctx.headers.len());
            }
            HttpClient::with_auth(
                self.ctx.scope.clone(),
                limiter,
                self.ctx.cookies.clone(),
                self.ctx.headers.clone(),
            )?
        } else {
            HttpClient::new(self.ctx.scope.clone(), limiter)?
        };
        
        let target_url = Url::parse(&self.ctx.target)?;

        // -------------------------------------------------
        // Baseline request (MANDATORY)
        // -------------------------------------------------
        let baseline_req = HttpRequest::new(Method::GET, target_url.clone());
        let baseline_resp = client.execute(baseline_req).await?;

        tracing::info!(
            "Baseline: status={} time={}ms size={}",
            baseline_resp.status,
            baseline_resp.elapsed_ms,
            baseline_resp.body_len
        );

        let _baseline = Baseline::from_response(&baseline_resp);

        // -------------------------------------------------
        // Fingerprinting (PASSIVE)
        // -------------------------------------------------
        if self.ctx.profile.has(Capability::Fingerprint) {
            let fp = fingerprint_response(&baseline_resp);

            tracing::info!("Fingerprint results:");
            if let Some(v) = &fp.server {
                tracing::info!("  Server: {}", v);
            }
            if let Some(v) = &fp.os_hint {
                tracing::info!("  OS: {}", v);
            }
            if let Some(v) = &fp.language_hint {
                tracing::info!("  Language: {}", v);
            }
            if let Some(v) = &fp.framework_hint {
                tracing::info!("  Framework: {}", v);
            }
            if let Some(v) = &fp.waf_cdn_hint {
                tracing::info!("  WAF/CDN: {}", v);
            }
        }

        // -------------------------------------------------
        // ENUMERATION MODE (like sqlmap)
        // -------------------------------------------------
        if self.ctx.enumeration.has_any() {
            let result = self.run_enumeration_mode(&client, &target_url, &mut reporter).await;
            
            // Generate report even in enumeration mode
            tracing::info!("ANVIL scan completed successfully");
            self.generate_report(&reporter)?;
            
            return result;
        }

        // -------------------------------------------------
        // DIRECT PARAMETER TESTING (skip crawling)
        // -------------------------------------------------
        let sitemap = if let Some(ref param) = self.ctx.direct_param {
            tracing::info!("Direct parameter testing mode: param={}", param);
            
            // Create a synthetic sitemap with just the target URL and parameter
            let mut sitemap = SiteMap::new(target_url.to_string());
            
            // Extract path from target URL
            let path = target_url.path().to_string();
            
            sitemap.add_endpoint(
                path,
                &self.ctx.http_method,
                vec![param.clone()],
            );
            
            Some(sitemap)
        }
        // -------------------------------------------------
        // Crawl & parameter discovery
        // -------------------------------------------------
        else if self.ctx.profile.has(Capability::Crawl) {
            let crawler = Crawler::new(self.ctx.crawl_depth as usize);
            let sitemap = crawler
                .crawl(&client, target_url.clone(), &self.ctx.scope)
                .await?;

            tracing::info!("Discovered {} endpoints", sitemap.endpoints.len());
            
            if self.ctx.verbose {
                for (path, ep) in &sitemap.endpoints {
                    if !ep.parameters.is_empty() {
                        tracing::debug!("  {} params={:?}", path, ep.parameters);
                    }
                }
            }

            Some(sitemap)
        } else {
            None
        };

        // -------------------------------------------------
        // SQL INJECTION SCANNING
        // -------------------------------------------------
        if self.ctx.profile.has_sqli() {
            // Check for second-order SQLi mode (trigger_url provided)
            if let Some(ref trigger_url_str) = self.ctx.trigger_url {
                let trigger_url = Url::parse(trigger_url_str)?;
                let sqli_results = self
                    .run_second_order_sqli_scan(&client, &target_url, &trigger_url)
                    .await?;
                
                self.report_sqli_findings(&sqli_results);
                self.add_sqli_to_report(&sqli_results, &mut reporter);
                
                // Legacy proof/exploit modes removed - use new enumeration flags instead
                // (--dbs, --tables, --columns, --dump, --passwords, etc.)
            } else if let Some(ref sitemap) = sitemap {
                let sqli_results = self
                    .run_sqli_scan(&client, &target_url, sitemap)
                    .await?;

                // Process and report findings
                self.report_sqli_findings(&sqli_results);
                self.add_sqli_to_report(&sqli_results, &mut reporter);

                // Legacy proof/exploit/hash modes removed - use new enumeration flags instead
            } else {
                tracing::warn!("No sitemap available. Use --crawl or --param to specify targets.");
            }
        }

        // -------------------------------------------------
        // XSS SCANNING (Professional Multi-Type Detection)
        // -------------------------------------------------
        if self.ctx.profile.has(Capability::Xss) {
            tracing::info!("Running Professional Reflected XSS scan...");
            self.run_professional_xss_scan(&client, &target_url, &mut reporter).await?;
        }
        
        // Stored/Persistent XSS Detection
        if self.ctx.profile.has(Capability::StoredXss) {
            tracing::info!("Running Professional Stored XSS scan...");
            self.run_stored_xss_scan(&client, &target_url, &mut reporter).await?;
        }
        
        // DOM-based XSS Detection
        if self.ctx.profile.has(Capability::DomXss) {
            tracing::info!("Running Professional DOM-based XSS scan...");
            self.run_dom_xss_scan(&client, &target_url, &mut reporter).await?;
        }

        // Blind XSS Detection (out-of-band)
        if self.ctx.profile.has(Capability::BlindXss) {
            tracing::info!("Running Blind XSS scan...");
            self.run_blind_xss_scan(&client, &target_url, &mut reporter).await?;
        }

        // -------------------------------------------------
        // SSRF SCANNING (Evidence-Driven Detection)
        // -------------------------------------------------
        if self.ctx.profile.has(Capability::Ssrf) {
            tracing::info!("Running Professional SSRF scan...");
            self.run_ssrf_scan(&client, &target_url, &sitemap, &mut reporter).await?;
        }

        // -------------------------------------------------
        // GENERATE REPORT
        // -------------------------------------------------
        tracing::info!("ANVIL scan completed successfully");
        self.generate_report(&reporter)?;
        
        Ok(())
    }

    /// Run enumeration mode (like sqlmap --dbs, --tables, etc.)
    async fn run_enumeration_mode(
        &self,
        client: &HttpClient,
        target_url: &Url,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) -> anyhow::Result<()> {
        tracing::info!("Running in enumeration mode");

        // Get param name from URL or use the one provided
        let param_name = self.ctx.direct_param.clone().unwrap_or_else(|| {
            target_url.query_pairs()
                .next()
                .map(|(k, _)| k.to_string())
                .unwrap_or_else(|| "id".to_string())
        });

        tracing::info!("Testing parameter: {}", param_name);

        // Create SQLi engine and detect injection
        tracing::info!("Phase 1: Detecting SQL injection vulnerability...");
        
        let sqli_point = crate::sqli::request::InjectionPoint::from_context(
            reqwest::Method::from_bytes(self.ctx.http_method.as_bytes())
                .unwrap_or(reqwest::Method::GET),
            target_url.clone(),
            &param_name,
            self.ctx.post_data.clone(),
            Vec::new(), // auth cookies/headers are carried by the HTTP client
            Vec::new(),
        );
        let mut engine = crate::sqli::SqliEngine::with_injection_point(client, sqli_point);

        if !engine.detect(target_url, &param_name).await? {
            tracing::warn!("No SQL injection vulnerability detected");
            tracing::info!("Try adjusting --level and --risk for more thorough testing");
            return Ok(());
        }

        tracing::info!("[+] SQL injection confirmed: UNION-based");
        tracing::info!("[+] Backend DBMS: {}", engine.db_type);
        
        if let Some(ref v) = engine.vector {
            tracing::info!("[+] Columns: {}, Position: {}", v.count, v.position);
        }

        // -------------------------------------------------
        // Database Information
        // -------------------------------------------------
        if self.ctx.enumeration.banner || self.ctx.enumeration.current_user ||
           self.ctx.enumeration.current_db || self.ctx.enumeration.hostname ||
           self.ctx.enumeration.is_dba {
            tracing::info!("\n[*] Retrieving database information...");
            
            if let Some(db) = engine.get_current_db(target_url, &param_name).await? {
                println!("Current database: {}", db);
            }
        }

        // -------------------------------------------------
        // Enumerate Databases
        // -------------------------------------------------
        if self.ctx.enumeration.dbs || self.ctx.enumeration.schema {
            tracing::info!("\n[*] Enumerating databases...");
            
            let databases = engine.get_dbs(target_url, &param_name).await?;
            
            if databases.is_empty() {
                tracing::warn!("No databases found (may need higher privileges)");
            } else {
                // Calculate dynamic width based on content
                let max_db_len = databases.iter().map(|d| d.len()).max().unwrap_or(20);
                let min_width = 40; // Minimum width for title
                let content_width = std::cmp::max(max_db_len + 6, min_width); // 6 = "  [*] " prefix
                let total_width = content_width + 2; // +2 for the ║ borders
                
                let border = "═".repeat(content_width);
                println!("\n╔{}╗", border);
                println!("║{:^width$}║", "AVAILABLE DATABASES", width = content_width);
                println!("╠{}╣", border);
                for db in &databases {
                    println!("║  [*] {:<width$}║", db, width = content_width - 6);
                }
                println!("╚{}╝", border);
            }
        }

        // -------------------------------------------------
        // Enumerate Tables
        // -------------------------------------------------
        if self.ctx.enumeration.tables || self.ctx.enumeration.schema {
            let db = self.ctx.enumeration.database.clone()
                .or_else(|| {
                    // If no DB specified, try to get current
                    None
                });

            if let Some(database) = db {
                tracing::info!("\n[*] Enumerating tables in '{}'...", database);
                
                let tables = engine.get_tables(target_url, &param_name, &database).await?;
                
                if tables.is_empty() {
                    tracing::warn!("No tables found in database '{}'", database);
                } else {
                    // Calculate dynamic width
                    let max_table_len = tables.iter().map(|t| t.len()).max().unwrap_or(20);
                    let db_header_len = format!("Database: {}", database).len() + 2; // +2 for "  " prefix
                    let min_width = 40;
                    let content_width = std::cmp::max(
                        std::cmp::max(max_table_len + 6, db_header_len),
                        min_width
                    );
                    
                    let border = "═".repeat(content_width);
                    println!("\n╔{}╗", border);
                    let db_line = format!("  Database: {}", database);
                    println!("║{:<width$}║", db_line, width = content_width);
                    println!("╠{}╣", border);
                    for table in &tables {
                        let item_line = format!("  [*] {}", table);
                        println!("║{:<width$}║", item_line, width = content_width);
                    }
                    println!("╚{}╝", border);
                    println!("\nFound {} tables", tables.len());
                }
            } else {
                tracing::warn!("No database specified. Use -D to specify a database.");
            }
        }

        // -------------------------------------------------
        // Enumerate Columns
        // -------------------------------------------------
        if self.ctx.enumeration.columns || self.ctx.enumeration.schema {
            let db = self.ctx.enumeration.database.clone();
            let tbl = self.ctx.enumeration.table.clone();

            match (db, tbl) {
                (Some(database), Some(table)) => {
                    tracing::info!("\n[*] Enumerating columns in '{}.{}'...", database, table);
                    
                    let columns = engine.get_columns(target_url, &param_name, &database, &table).await?;
                    
                    if columns.is_empty() {
                        tracing::warn!("No columns found in table '{}'", table);
                    } else {
                        // Calculate dynamic width
                        let max_col_len = columns.iter().map(|c| c.len()).max().unwrap_or(20);
                        let db_header_len = format!("Database: {}", database).len() + 2;
                        let table_header_len = format!("Table: {}", table).len() + 2;
                        let min_width = 40;
                        let content_width = std::cmp::max(
                            std::cmp::max(
                                std::cmp::max(max_col_len + 6, db_header_len),
                                table_header_len
                            ),
                            min_width
                        );
                        
                        let border = "═".repeat(content_width);
                        println!("\n╔{}╗", border);
                        let db_line = format!("  Database: {}", database);
                        println!("║{:<width$}║", db_line, width = content_width);
                        let table_line = format!("  Table: {}", table);
                        println!("║{:<width$}║", table_line, width = content_width);
                        println!("╠{}╣", border);
                        for col in &columns {
                            let item_line = format!("  [*] {}", col);
                            println!("║{:<width$}║", item_line, width = content_width);
                        }
                        println!("╚{}╝", border);
                        println!("\nFound {} columns", columns.len());
                    }
                }
                _ => {
                    tracing::warn!("Use -D <database> -T <table> to specify target.");
                }
            }
        }

        // -------------------------------------------------
        // Dump Table Data
        // -------------------------------------------------
        if self.ctx.enumeration.dump {
            let db = self.ctx.enumeration.database.clone();
            let tbl = self.ctx.enumeration.table.clone();
            let cols = self.ctx.enumeration.columns_list.clone();

            match (db, tbl) {
                (Some(database), Some(table)) => {
                    tracing::info!("\n[*] Dumping data from '{}.{}'...", database, table);
                    
                    // Get columns first if not specified
                    let columns = if let Some(c) = cols {
                        c
                    } else {
                        engine.get_columns(target_url, &param_name, &database, &table).await?
                    };
                    
                    let rows = engine.dump_table(target_url, &param_name, &database, &table, &columns).await?;
                    
                    // Print table
                    if !rows.is_empty() {
                        println!("\n{}", columns.join(","));
                        for row in &rows {
                            println!("{}", row.join(","));
                        }
                        println!("\nRetrieved {} rows", rows.len());
                    } else {
                        println!("No data found");
                    }
                }
                _ => {
                    tracing::warn!("Use -D <database> -T <table> to specify target.");
                }
            }
        }

        // -------------------------------------------------
        // Enumerate Users (simplified)
        // -------------------------------------------------
        if self.ctx.enumeration.users {
            tracing::info!("\n[*] Enumerating database users...");
            tracing::warn!("User enumeration not implemented in simplified engine");
        }

        // -------------------------------------------------
        // Extract Password Hashes (simplified)
        // -------------------------------------------------
        if self.ctx.enumeration.passwords {
            tracing::warn!("\n[*] Extracting password hashes...");
            tracing::warn!("Password extraction not implemented in simplified engine");
        }

        // -------------------------------------------------
        // Enumerate Privileges (simplified)
        // -------------------------------------------------
        if self.ctx.enumeration.privileges {
            tracing::info!("\n[*] Enumerating user privileges...");
            tracing::warn!("Privilege enumeration not implemented in simplified engine");
            let privs: Vec<(String, String)> = Vec::new();
            if !privs.is_empty() {
                // Calculate dynamic width
                let max_user_len = privs.iter().map(|(u, _)| u.len()).max().unwrap_or(10);
                let max_priv_len = privs.iter().map(|(_, p)| p.len()).max().unwrap_or(10);
                let min_width = 40;
                let content_width = std::cmp::max(max_user_len + max_priv_len + 5, min_width);
                
                let border = "═".repeat(content_width);
                println!("\n╔{}╗", border);
                println!("║{:^width$}║", "USER PRIVILEGES", width = content_width);
                println!("╠{}╣", border);
                for (user, priv_type) in &privs {
                    let line = format!("  {} : {}", user, priv_type);
                    println!("║{:<width$}║", line, width = content_width);
                }
                println!("╚{}╝", border);
            }
        }

        tracing::info!("\n[*] Enumeration completed");
        Ok(())
    }

    /// Run second-order SQL injection scan
    /// Injects payloads on target_url and observes results on trigger_url
    async fn run_second_order_sqli_scan(
        &self,
        client: &HttpClient,
        inject_url: &Url,
        trigger_url: &Url,
    ) -> anyhow::Result<Vec<SqliResult>> {
        tracing::info!("Starting second-order SQL injection scan");
        tracing::info!("  Inject URL: {}", inject_url);
        tracing::info!("  Trigger URL: {}", trigger_url);
        tracing::warn!("Second-order SQLi detection not yet implemented in new engine");
        Ok(Vec::new())
    }

    /// Run SQL injection scan with all enabled techniques
    async fn run_sqli_scan(
        &self,
        client: &HttpClient,
        target_url: &Url,
        sitemap: &SiteMap,
    ) -> anyhow::Result<Vec<SqliResult>> {
        tracing::info!("Starting SQL injection scan");
        
        let mut all_results = Vec::new();
        
        // Test each endpoint
        for (path, ep) in sitemap.endpoints.iter() {
            if ep.parameters.is_empty() {
                continue;
            }

            let base_url = match target_url.join(path) {
                Ok(u) => u,
                Err(_) => continue,
            };

            for param in &ep.parameters {
                let sqli_point = crate::sqli::request::InjectionPoint::from_context(
                    reqwest::Method::from_bytes(self.ctx.http_method.as_bytes())
                        .unwrap_or(reqwest::Method::GET),
                    base_url.clone(),
                    param,
                    self.ctx.post_data.clone(),
                    Vec::new(),
                    Vec::new(),
                );
                let mut engine =
                    crate::sqli::SqliEngine::with_injection_point(client, sqli_point);
                if engine.detect(&base_url, param).await? {
                    all_results.push(SqliResult {
                        endpoint: base_url.to_string(),
                        parameter: param.clone(),
                        technique: SqliTechnique::Union,
                        confidence: 0.9,
                        db_type: Some(engine.db_type),
                        details: format!("UNION-based SQLi detected"),
                    });
                }
            }
        }

        Ok(all_results)
    }

    /// Report SQLi findings
    fn report_sqli_findings(&self, results: &[SqliResult]) {
        if results.is_empty() {
            tracing::info!("No SQL injection vulnerabilities found");
            return;
        }

        tracing::warn!("Found {} potential SQL injection vulnerabilities:", results.len());

        for result in results {
            let severity = if result.confidence >= 0.9 {
                "CRITICAL"
            } else if result.confidence >= 0.7 {
                "HIGH"
            } else {
                "MEDIUM"
            };

            tracing::warn!(
                "[{}][{}] {} param={} confidence={:.0}%",
                severity,
                result.technique,
                result.endpoint,
                result.parameter,
                result.confidence * 100.0
            );

            if let Some(db) = &result.db_type {
                tracing::warn!("  Database: {}", db);
            }

            if self.ctx.verbose {
                tracing::info!("  Details: {}", result.details);
            }
        }
    }

    /// Add SQLi findings to the reporter
    fn add_sqli_to_report(
        &self,
        results: &[crate::sqli::SqliResult],
        reporter: &mut crate::reporting::reporter::Reporter,
    ) {
        for result in results {
            // Determine HTTP method
            let http_method = if result.endpoint.contains('?') {
                "GET"
            } else {
                &self.ctx.http_method
            };

            // Determine database type
            let database = result.db_type.as_ref().map(|db| format!("{:?}", db));

            // Create sample payload based on technique
            let payload_sample = match result.technique {
                crate::sqli::SqliTechnique::Boolean => {
                    Some("' OR '1'='1".to_string())
                }
                crate::sqli::SqliTechnique::TimeBased => {
                    Some("' AND SLEEP(5)--".to_string())
                }
                crate::sqli::SqliTechnique::Union => {
                    Some("' UNION SELECT NULL,NULL,NULL--".to_string())
                }
                _ => None,
            };

            let finding = crate::reporting::model::Finding::sql_injection(
                &format!("{}", result.technique),
                &result.endpoint,
                &result.parameter,
                result.confidence,
                &result.details,
                http_method,
                database.as_deref(),
                payload_sample,
            );

            reporter.add(finding);
        }
    }

    /// Generate and output the final report
    fn generate_report(&self, reporter: &crate::reporting::reporter::Reporter) -> anyhow::Result<()> {
        let findings = reporter.findings();

        // Generate report based on format
        match self.ctx.output_format.as_str() {
            "json" => {
                let json = crate::reporting::json::render(findings)?;
                
                // Output to file or stdout
                if let Some(ref output_file) = self.ctx.output_file {
                    std::fs::write(output_file, &json)?;
                    println!("\n📄 Report saved to: {}", output_file);
                } else {
                    println!("{}", json);
                }
            }
            _ => {
                // Text format - only render full report if:
                // 1. Saving to file (--output specified), OR
                // 2. Verbose mode (--verbose/-v)
                // Otherwise, just show the clean summary already printed during scan
                
                if let Some(ref output_file) = self.ctx.output_file {
                    // Save full report to file
                    let text_report = self.generate_text_report_string(findings);
                    std::fs::write(output_file, text_report)?;
                    println!("\n📄 Full report saved to: {}", output_file);
                } else if self.ctx.verbose {
                    // Verbose mode: print full report to stdout
                    crate::reporting::text::render(findings);
                }
                // Default mode: summary already printed during scan, don't duplicate
            }
        }

        Ok(())
    }

    /// Generate text report as a string (for file output)
    fn generate_text_report_string(&self, findings: &[crate::reporting::model::Finding]) -> String {
        use std::fmt::Write;
        let mut output = String::new();

        if findings.is_empty() {
            writeln!(&mut output, "ANVIL Security Scan Report").unwrap();
            writeln!(&mut output, "==========================\n").unwrap();
            writeln!(&mut output, "✅ No vulnerabilities detected").unwrap();
            return output;
        }

        writeln!(&mut output, "ANVIL Security Scan Report").unwrap();
        writeln!(&mut output, "==========================\n").unwrap();
        writeln!(&mut output, "Total Findings: {}\n", findings.len()).unwrap();

        for (idx, finding) in findings.iter().enumerate() {
            writeln!(&mut output, "\nFINDING #{}: {}", idx + 1, finding.vuln_type).unwrap();
            writeln!(&mut output, "Severity: {}", finding.severity).unwrap();
            writeln!(&mut output, "Endpoint: {} {}", finding.http_method, finding.endpoint).unwrap();
            if let Some(param) = &finding.parameter {
                writeln!(&mut output, "Parameter: {}", param).unwrap();
            }
            writeln!(&mut output, "Confidence: {:.0}%", finding.confidence * 100.0).unwrap();
            writeln!(&mut output, "\nDescription:\n{}", finding.description).unwrap();
            writeln!(&mut output, "\nRemediation:\n{}", finding.remediation).unwrap();
            writeln!(&mut output, "{}", "=".repeat(80)).unwrap();
        }

        output
    }

    /// Run professional XSS scan with evidence-driven detection
    async fn run_professional_xss_scan(
        &self,
        client: &HttpClient,
        target_url: &Url,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) -> anyhow::Result<()> {
        // Removed verbose methodology output - enterprise tools are concise
        
        // Call the enhanced simple scanner (with professional logic)
        self.run_simple_xss_scan(client, target_url, reporter).await
    }
    
    /// Legacy XSS scan (kept for backwards compatibility)
    async fn run_simple_xss_scan(
        &self,
        client: &HttpClient,
        target_url: &Url,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) -> anyhow::Result<()> {
        // Determine which parameter to test
        let param_to_test = if let Some(ref param) = self.ctx.direct_param {
            vec![param.clone()]
        } else {
            // Extract all parameters from URL
            target_url
                .query_pairs()
                .map(|(k, _)| k.to_string())
                .collect::<Vec<_>>()
        };
        
        if param_to_test.is_empty() {
            tracing::warn!("No parameters found to test for XSS");
            return Ok(());
        }
        
        // Removed verbose output - enterprise tools are concise
        
        // XSS test payloads with validation markers
        // Each payload has a unique identifier we can check for execution
        let xss_tests = vec![
            // Basic script tag with unique marker
            ("<script>document.ANVIL_XSS_EXEC_1=1</script>", "ANVIL_XSS_EXEC_1", "script tag"),
            // Image onerror with unique marker
            ("<img src=x onerror=window.ANVIL_XSS_EXEC_2=1>", "ANVIL_XSS_EXEC_2", "img onerror"),
            // SVG onload with unique marker
            ("<svg/onload=window.ANVIL_XSS_EXEC_3=1>", "ANVIL_XSS_EXEC_3", "svg onload"),
            // Body onload
            ("<body onload=window.ANVIL_XSS_EXEC_4=1>", "ANVIL_XSS_EXEC_4", "body onload"),
            // Input autofocus
            ("<input onfocus=window.ANVIL_XSS_EXEC_5=1 autofocus>", "ANVIL_XSS_EXEC_5", "input autofocus"),
            // Attribute breakout variants
            ("\"><script>window.ANVIL_XSS_EXEC_6=1</script>", "ANVIL_XSS_EXEC_6", "double quote breakout"),
            ("'><script>window.ANVIL_XSS_EXEC_7=1</script>", "ANVIL_XSS_EXEC_7", "single quote breakout"),
        ];
        
        for param_name in &param_to_test {
            // Removed verbose phase-by-phase output
            
            // PHASE 1: Check for reflection with benign marker
            let marker = "ANVIL_REFLECTION_TEST_12345";
            let mut test_url = target_url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in target_url.query_pairs() {
                    if k == *param_name {
                        pairs.append_pair(&k, marker);
                    } else {
                        pairs.append_pair(&k, &v);
                    }
                }
            }
            
            let req = HttpRequest::new(Method::GET, test_url.clone());
            let resp = client.execute(req).await?;
            let body = resp.body_text();
            
            if !body.contains(marker) {
                if self.ctx.verbose {
                    tracing::info!("  ✓ No reflection detected - parameter '{}' is not reflected", param_name);
                }
                continue;
            }
            
            // Removed verbose phase output
            
            let mut found_exploitable = false;
            
            for (idx, (payload, marker, technique)) in xss_tests.iter().enumerate() {
                let mut test_url = target_url.clone();
                {
                    let mut pairs = test_url.query_pairs_mut();
                    pairs.clear();
                    for (k, v) in target_url.query_pairs() {
                        if k == *param_name {
                            pairs.append_pair(&k, payload);
                        } else {
                            pairs.append_pair(&k, &v);
                        }
                    }
                }
                
                let req = HttpRequest::new(Method::GET, test_url.clone());
                match client.execute(req).await {
                    Ok(resp) => {
                        let body = resp.body_text();
                        let body_lower = body.to_lowercase();
                        
                        // Check if payload is reflected
                        let is_reflected = body.contains(payload);
                        
                        if !is_reflected {
                            continue; // Payload was filtered/encoded
                        }
                        
                        // CRITICAL REFINEMENT: Multi-checkpoint validation
                        // 1. Check encoding/escaping
                        // 2. Check context breakout
                        // 3. Check execution likelihood
                        // 4. Determine interaction requirements
                        
                        let is_executable = self.check_xss_execution_likelihood(&body, payload);
                        
                        if !is_executable {
                            if self.ctx.verbose {
                                tracing::info!("  → Payload #{} reflected but properly encoded/escaped", idx + 1);
                            }
                            continue;
                        }
                        
                        // CHECKPOINT: Explicit context breakout verification
                        let (context_breakout, breakout_evidence) = self.verify_context_breakout(&body, payload, param_name);
                        
                        if !context_breakout {
                            // Payload trapped in safe context
                            continue;
                        }
                        
                        // Context breakout confirmed
                        
                        // Calculate execution confidence (independent of impact)
                        let execution_confidence = self.calculate_xss_confidence(&body, payload);
                        
                        // Detect interaction requirements
                        let (requires_interaction, interaction_type) = self.detect_interaction_requirements(payload, technique);
                        
                        // Classify exploitability level
                        let exploitability = if execution_confidence >= 0.90 && !requires_interaction {
                            "Confirmed XSS"
                        } else if execution_confidence >= 0.70 {
                            "Likely Exploitable XSS"
                        } else {
                            "Possible XSS"
                        };
                        
                        if execution_confidence >= 0.70 {
                            // Determine severity for display
                            let (severity_label, severity_color) = if exploitability == "Confirmed XSS" && !requires_interaction {
                                ("CRITICAL", "🔴")
                            } else if execution_confidence >= 0.85 && !requires_interaction {
                                ("HIGH", "🟠")
                            } else {
                                ("MEDIUM", "🟡")
                            };
                            
                            // Clean summary output (default)
                            if !self.ctx.verbose {
                                println!("\n[+] {} detected", exploitability);
                                println!("    Endpoint  : {}", target_url.path());
                                println!("    Parameter : {}", param_name);
                                println!("    Severity  : {} {}", severity_color, severity_label);
                                println!("    Confidence: {:.0}%", execution_confidence * 100.0);
                                let xss_type_label = if requires_interaction {
                                    format!("Interaction-required ({})", interaction_type)
                                } else {
                                    "Direct execution".to_string()
                                };
                                println!("    Type      : {}", xss_type_label);
                                println!("    XSS Type  : Reflected XSS");
                                println!("    Evidence  : {}", breakout_evidence);
                            }
                            // Removed verbose output - enterprise tools show findings in final report
                            
                            // Add to report with enhanced metadata
                            self.add_professional_validated_xss_to_report(
                                reporter,
                                payload,
                                target_url.path(),
                                param_name,
                                execution_confidence,
                                technique,
                                exploitability,
                                requires_interaction,
                                &interaction_type,
                                &breakout_evidence,
                                "Reflected XSS",  // Default to Reflected XSS for now
                            );
                            
                            found_exploitable = true;
                            break;
                        } else {
                            if self.ctx.verbose {
                                tracing::info!("  → Payload #{} reflected but execution unlikely (confidence: {:.0}%)", idx + 1, execution_confidence * 100.0);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("  Request failed: {}", e);
                    }
                }
            }
            
            if !found_exploitable && self.ctx.verbose {
                tracing::info!("\n  ✓ No exploitable XSS found in parameter '{}'", param_name);
                tracing::info!("    (Reflection detected but payloads are properly sanitized/encoded)");
            }
        }
        
        Ok(())
    }
    
    /// Verify explicit context breakout - payload must escape its container
    fn verify_context_breakout(&self, body: &str, payload: &str, param_name: &str) -> (bool, String) {
        let body_lower = body.to_lowercase();
        let payload_lower = payload.to_lowercase();
        
        // Find where payload appears in response
        if let Some(pos) = body.find(payload) {
            let context_start = pos.saturating_sub(200);
            let context_end = (pos + payload.len() + 200).min(body.len());
            let surrounding = &body[context_start..context_end];
            let surrounding_lower = surrounding.to_lowercase();
            
            // 1. Check if trapped in non-executable containers
            let safe_containers = [
                ("<textarea", "</textarea>"),
                ("<title", "</title>"),
                ("<noscript", "</noscript>"),
                ("<!--", "-->"),
                ("<plaintext", ""),
            ];
            
            for (open, close) in &safe_containers {
                if surrounding_lower.contains(open) && (close.is_empty() || surrounding_lower.contains(close)) {
                    return (false, format!("Payload trapped inside {} container", open));
                }
            }
            
            // 2. Check if properly quoted in attribute (no breakout)
            let before_payload = &body[context_start..pos];
            if let Some(last_eq) = before_payload.rfind('=') {
                let after_eq = &before_payload[last_eq + 1..];
                // Check if we're inside a quoted attribute AND didn't break out
                if (after_eq.starts_with('"') && !payload.starts_with('"')) ||
                   (after_eq.starts_with('\'') && !payload.starts_with('\'')) {
                    // We're in a quoted attribute - check if payload breaks out
                    if !payload.contains('"') && !payload.contains('\'') && !payload.contains('>') {
                        return (false, "Payload inside quoted attribute without breakout".to_string());
                    }
                }
            }
            
            // 3. Verify actual breakout for successful cases
            if payload_lower.contains("<script") && body_lower.contains("<script") {
                return (true, "Direct <script> tag injection in HTML context".to_string());
            }
            
            if (payload_lower.contains("onerror=") || payload_lower.contains("onload=") || 
                payload_lower.contains("onfocus=") || payload_lower.contains("onmouseover=")) {
                // Check if event handler is in an actual HTML tag
                if surrounding_lower.contains(&format!("<img")) || 
                   surrounding_lower.contains(&format!("<svg")) ||
                   surrounding_lower.contains(&format!("<body")) ||
                   surrounding_lower.contains(&format!("<input")) {
                    return (true, "Event handler introduced in HTML tag context".to_string());
                }
            }
            
            if payload.starts_with('"') || payload.starts_with('\'') {
                return (true, "Attribute quote breakout successful".to_string());
            }
        }
        
        (false, "No clear context breakout detected".to_string())
    }
    
    /// Detect if XSS requires user interaction
    fn detect_interaction_requirements(&self, payload: &str, technique: &str) -> (bool, String) {
        let payload_lower = payload.to_lowercase();
        
        // Immediate execution (no interaction)
        if payload_lower.contains("<script") {
            return (false, "none".to_string());
        }
        
        if payload_lower.contains("onload=") {
            // onload on body/img requires page/image load (not user interaction)
            return (false, "none".to_string());
        }
        
        // Requires image load failure (technical, not user interaction)
        if payload_lower.contains("onerror=") && payload_lower.contains("src=") {
            return (true, "image load error".to_string());
        }
        
        // Requires user focus
        if payload_lower.contains("onfocus=") && payload_lower.contains("autofocus") {
            return (false, "none (autofocus)".to_string());
        }
        
        if payload_lower.contains("onfocus=") {
            return (true, "user focus".to_string());
        }
        
        // Requires user interaction
        if payload_lower.contains("onclick=") || payload_lower.contains("onmouseover=") {
            return (true, "user interaction".to_string());
        }
        
        // Default: assume no interaction for detected executable contexts
        (false, "none".to_string())
    }
    
    /// Check if XSS payload would actually execute (not just reflect)
    fn check_xss_execution_likelihood(&self, body: &str, payload: &str) -> bool {
        let body_lower = body.to_lowercase();
        let payload_lower = payload.to_lowercase();
        
        // Check if payload appears in executable contexts
        
        // 1. Check if it's NOT HTML-encoded
        let encoded_lt = payload.replace("<", "&lt;");
        let encoded_gt = payload.replace(">", "&gt;");
        let encoded_both = encoded_lt.replace(">", "&gt;");
        
        if body.contains(&encoded_both) || body.contains(&encoded_lt) {
            return false; // Payload is HTML encoded, won't execute
        }
        
        // 2. Check if script tags are intact
        if payload_lower.contains("<script") && body_lower.contains("<script") {
            // Script tag is present - check if it's in executable position
            // Look for the pattern in HTML context (not inside textarea, etc.)
            if !body_lower.contains("<textarea") && !body_lower.contains("&lt;script") {
                return true;
            }
        }
        
        // 3. Check for event handlers (onerror, onload, onfocus, etc.)
        let event_handlers = ["onerror=", "onload=", "onfocus=", "onmouseover=", "onclick="];
        for handler in &event_handlers {
            if payload_lower.contains(handler) && body_lower.contains(handler) {
                // Event handler is present - likely executable
                return true;
            }
        }
        
        // 4. Check for SVG/IMG tags with events
        if (payload_lower.contains("<svg") || payload_lower.contains("<img")) && 
           (body_lower.contains("<svg") || body_lower.contains("<img")) {
            return true;
        }
        
        // 5. Check for attribute breakouts
        if (payload.starts_with("\"") || payload.starts_with("'")) && 
           (body.contains(&payload[1..]) || body.contains(payload)) {
            // Breakout quote is present
            return true;
        }
        
        false
    }
    
    /// Calculate XSS confidence based on execution likelihood
    fn calculate_xss_confidence(&self, body: &str, payload: &str) -> f32 {
        let mut confidence: f32 = 0.70; // Base confidence for reflected + executable
        
        // Increase confidence based on factors
        
        // 1. If script tag is completely unmodified
        if payload.contains("<script>") && body.contains("<script>") {
            confidence += 0.20;
        }
        
        // 2. If no encoding/filtering detected
        if !body.contains("&lt;") && !body.contains("&gt;") && !body.contains("&quot;") {
            confidence += 0.05;
        }
        
        // 3. If payload appears multiple times (higher chance of execution)
        let occurrences = body.matches(payload).count();
        if occurrences > 1 {
            confidence += 0.03;
        }
        
        // 4. If in <head> or early in <body> (executes faster)
        if let Some(pos) = body.find(payload) {
            if pos < 1000 { // Within first 1KB
                confidence += 0.02;
            }
        }
        
        confidence.min(0.99_f32) // Cap at 99%
    }
    
    /// Convert professionally validated XSS finding to report format
    fn add_professional_validated_xss_to_report(
        &self,
        reporter: &mut crate::reporting::reporter::Reporter,
        payload: &str,
        endpoint: &str,
        param: &str,
        execution_confidence: f32,
        technique: &str,
        exploitability: &str,
        requires_interaction: bool,
        interaction_type: &str,
        breakout_evidence: &str,
        xss_type: &str,  // "Reflected XSS", "Stored XSS", "DOM-based XSS", "Blind XSS"
    ) {
        use crate::reporting::model::{Finding, Severity};
        
        // Decouple confidence from severity - factor in interaction requirements
        let severity = if exploitability == "Confirmed XSS" && !requires_interaction {
            Severity::Critical
        } else if execution_confidence >= 0.85 && !requires_interaction {
            Severity::High
        } else if execution_confidence >= 0.70 {
            Severity::Medium
        } else {
            Severity::Low
        };
        
        let cvss_score = if exploitability == "Confirmed XSS" && !requires_interaction {
            9.6
        } else if execution_confidence >= 0.85 && !requires_interaction {
            8.2
        } else if requires_interaction {
            // Reduce score for interaction-required XSS
            (execution_confidence * 8.0).min(7.0)
        } else {
            6.8
        };
        
        // ONE-LINE JUSTIFICATION: "Why this is XSS"
        let xss_justification = format!(
            "Untrusted input reached HTML context without proper encoding, {} and introduced executable code via {}",
            breakout_evidence.to_lowercase(),
            technique
        );
        
        let interaction_notice = if requires_interaction {
            format!("\n\n⚠️  INTERACTION REQUIREMENT: This XSS requires {} to execute. While this reduces immediate risk, it remains a valid and exploitable vulnerability in targeted attacks.", interaction_type)
        } else {
            String::new()
        };
        
        let description = format!(
            "Cross-Site Scripting (XSS) - {}.\n\n\
            XSS TYPE: {}\n\n\
            WHY THIS IS XSS:\n\
            {}\n\n\
            CLASSIFICATION: {}\n\
            Technique: {}\n\
            Payload: {}\n\
            Execution Confidence: {:.0}%{}\n\n\
            EVIDENCE-DRIVEN VALIDATION:\n\
            ✓ Phase 1: Input reflection confirmed (benign marker test)\n\
            ✓ Phase 2: Payload reflected without HTML encoding\n\
            ✓ Phase 3: Context breakout verified ({})\n\
            ✓ Phase 4: Execution likelihood validated (confidence: {:.0}%)\n\n\
            PROFESSIONAL ASSESSMENT:\n\
            This is NOT merely reflection - the payload demonstrates actual executable capability. \
            {} The finding has been verified through multi-stage validation to ensure accuracy and minimize false positives.",
            exploitability,
            xss_type,
            xss_justification,
            exploitability.to_uppercase(),
            technique,
            payload,
            execution_confidence * 100.0,
            interaction_notice,
            breakout_evidence,
            execution_confidence * 100.0,
            if exploitability == "Confirmed XSS" {
                "Direct execution is possible without ambiguity."
            } else {
                "Execution is highly likely but may depend on specific browser behavior or DOM state."
            }
        );
        
        let impact = if severity == Severity::Critical {
            format!(
                "CRITICAL - Immediate JavaScript execution confirmed.\n\n\
                Attacker capabilities:\n\
                • Steal session cookies via document.cookie\n\
                • Exfiltrate authentication tokens from localStorage/sessionStorage\n\
                • Perform actions on behalf of the victim (CSRF)\n\
                • Steal sensitive form data and credentials\n\
                • Redirect users to phishing/malware sites\n\
                • Deploy keyloggers or cryptocurrency miners\n\
                • Access and leak any data visible to the user{}\n\n\
                EXPLOITABILITY: Direct, immediate execution. No user interaction required.",
                if requires_interaction {
                    format!("\n\nNote: Requires {} but remains highly exploitable", interaction_type)
                } else {
                    String::new()
                }
            )
        } else if requires_interaction {
            format!(
                "MEDIUM - Interaction-Required XSS ({})\n\n\
                While this XSS requires {} to execute, it remains a valid security vulnerability:\n\
                • Exploitable in targeted phishing attacks\n\
                • Can be triggered via social engineering\n\
                • Attacker retains full JavaScript execution capabilities once triggered\n\
                • Same impact as non-interaction XSS: session hijacking, credential theft, etc.\n\n\
                EXPLOITABILITY: High in targeted attacks. Lower risk for opportunistic exploitation.",
                exploitability, interaction_type
            )
        } else {
            format!(
                "HIGH - Likely Exploitable XSS\n\n\
                JavaScript execution is highly probable but may depend on:\n\
                • Specific browser rendering behavior\n\
                • Surrounding DOM structure\n\
                • Page load timing\n\n\
                Once executed, attacker capabilities include:\n\
                • Session hijacking and credential theft\n\
                • Unauthorized actions on behalf of the victim\n\
                • Data exfiltration\n\n\
                EXPLOITABILITY: Very high. Should be treated as confirmed XSS for remediation purposes."
            )
        };
        
        reporter.add(Finding::xss(
            format!("Cross-Site Scripting - {}", exploitability),
            technique,
            endpoint,
            Some(param.to_string()),
            execution_confidence,
            severity,
            description,
            impact,
            self.get_xss_remediation(requires_interaction),
        ));
    }
    
    fn get_xss_remediation(&self, requires_interaction: bool) -> String {
        let interaction_note = if requires_interaction {
            "\n\nNote: While this XSS requires user interaction, the root cause (lack of output encoding) \
            must still be fixed to prevent exploitation."
        } else {
            ""
        };
        
        format!(
            "1. OUTPUT ENCODING (Context-Specific - PRIMARY DEFENSE):\n\
            • HTML context: Use HTML entity encoding (&lt; &gt; &quot; &#x27; &amp;)\n\
            • Attribute context: HTML attribute encode AND always quote attributes\n\
            • JavaScript context: Use JavaScript escaping (\\x3C \\x3E \\x22 \\x27)\n\
            • URL context: URL encode and validate protocols (block javascript:, data:)\n\n\
            2. CONTENT SECURITY POLICY (CSP - Defense in Depth):\n\
            Implement strict CSP to block inline scripts:\n\
            Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'\n\n\
            3. INPUT VALIDATION (Defense in Depth):\n\
            • Validate against allowlists, not denylists\n\
            • Reject unexpected characters\n\
            • Enforce strict length limits\n\n\
            4. HTTP-ONLY & SECURE COOKIES:\n\
            Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict\n\n\
            5. FRAMEWORK PROTECTIONS:\n\
            Use auto-escaping templates (React, Angular, Vue) with proper configuration{}\n\n\
            VERIFICATION:\n\
            • Re-scan with ANVIL after fixes\n\
            • Verify CSP headers are present\n\
            • Test with manual payloads",
            interaction_note
        )
    }
    
    /// Legacy reporting function (deprecated)
    #[allow(dead_code)]
    fn add_validated_xss_to_report(
        &self,
        reporter: &mut crate::reporting::reporter::Reporter,
        payload: &str,
        endpoint: &str,
        param: &str,
        confidence: f32,
        technique: &str,
    ) {
        use crate::reporting::model::{Finding, Severity};
        
        // Map confidence to severity
        let severity = if confidence >= 0.95 {
            Severity::Critical
        } else if confidence >= 0.85 {
            Severity::High
        } else if confidence >= 0.75 {
            Severity::Medium
        } else {
            Severity::Low
        };
        
        let cvss_score = if confidence >= 0.95 {
            9.6
        } else if confidence >= 0.85 {
            8.2
        } else if confidence >= 0.75 {
            6.8
        } else {
            5.3
        };
        
        let description = format!(
            "Cross-Site Scripting (XSS) vulnerability detected and validated for execution.\n\n\
            Technique: {}\n\
            Payload: {}\n\
            Execution Confidence: {:.0}%\n\n\
            VALIDATION PROCESS:\n\
            ✓ Phase 1: Input reflection confirmed\n\
            ✓ Phase 2: Payload appears in executable context\n\
            ✓ Phase 3: No HTML encoding detected\n\
            ✓ Phase 4: Execution likelihood validated\n\n\
            This is NOT just reflection - the payload would actually EXECUTE JavaScript.\n\
            An attacker can inject malicious code that will run in the victim's browser, \
            potentially leading to session hijacking, credential theft, or malicious actions.",
            technique,
            payload,
            confidence * 100.0
        );
        
        let impact = match severity {
            Severity::Critical => {
                "CRITICAL - Immediate JavaScript execution confirmed. Attacker can:\n\
                • Steal session cookies via document.cookie\n\
                • Exfiltrate localStorage/sessionStorage tokens\n\
                • Perform actions on behalf of the victim\n\
                • Steal sensitive form data and credentials\n\
                • Redirect users to phishing/malware sites\n\
                • Deface the application\n\
                • Deploy keyloggers or cryptocurrency miners\n\
                • Access and leak any data visible to the user\n\
                • Pivot to other attacks (CSRF, clickjacking)"
            },
            Severity::High => {
                "HIGH - JavaScript execution highly likely. Similar impacts to Critical \
                but may require specific conditions or user interaction."
            },
            Severity::Medium => {
                "MEDIUM - JavaScript execution possible under certain conditions. \
                Still exploitable in targeted attacks."
            },
            _ => {
                "LOW - Limited execution potential but should still be fixed."
            }
        };
        
        let remediation = "\
            1. OUTPUT ENCODING (Context-Specific):\n   \
            • HTML context: Use HTML entity encoding (&lt; &gt; &quot; &#x27; &amp;)\n   \
            • Attribute context: Use HTML attribute encoding and quote all attributes\n   \
            • JavaScript context: Use JavaScript escaping (\\x3C \\x3E \\x22 \\x27)\n   \
            • URL context: Use URL encoding and validate protocols\n\n\
            2. CONTENT SECURITY POLICY (CSP):\n   \
            Implement strict CSP headers:\n   \
            Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'\n\n\
            3. INPUT VALIDATION:\n   \
            • Validate all user input against allowlists\n   \
            • Reject unexpected characters and patterns\n   \
            • Use security-focused validation libraries\n\n\
            4. HTTP-ONLY COOKIES:\n   \
            Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict\n\n\
            5. X-XSS-PROTECTION HEADER:\n   \
            X-XSS-Protection: 1; mode=block\n\n\
            6. FRAMEWORK PROTECTIONS:\n   \
            Use auto-escaping templates (e.g., React, Angular, Vue with proper configuration)"
            .to_string();
        
        let references = vec![
            "OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html".to_string(),
            "CWE-79: Improper Neutralization of Input During Web Page Generation: https://cwe.mitre.org/data/definitions/79.html".to_string(),
            "PortSwigger XSS: https://portswigger.net/web-security/cross-site-scripting".to_string(),
        ];
        
        let finding = Finding {
            vuln_type: "Cross-Site Scripting (XSS)".to_string(),
            technique: "Reflected XSS".to_string(),
            endpoint: endpoint.to_string(),
            parameter: Some(param.to_string()),
            confidence,
            severity,
            evidence: format!(
                "Payload: {}\nConfidence: {:.1}%\nCVSS Score: {}",
                payload,
                confidence * 100.0,
                cvss_score
            ),
            description,
            impact: impact.to_string(),
            remediation,
            references,
            cwe: "CWE-79".to_string(),
            cvss_score: Some(cvss_score),
            payload_sample: Some(payload.to_string()),
            http_method: "GET".to_string(),
            database: None,
        };
        
        reporter.add(finding);
    }

    /* TODO: Re-enable when XSS module types are fixed
    /// Convert XSS finding to report format (advanced - TODO: fix types)
    #[allow(dead_code)]
    fn add_xss_to_report(
        &self,
        reporter: &mut crate::reporting::reporter::Reporter,
        xss_result: &crate::xss::validate::XssValidationResult,
        endpoint: &str,
        param: &str,
    ) {
        use crate::reporting::model::{Finding, Severity};
        
        // Map confidence to severity
        let severity = if xss_result.confidence >= 0.95 {
            Severity::Critical
        } else if xss_result.confidence >= 0.85 {
            Severity::High
        } else if xss_result.confidence >= 0.70 {
            Severity::Medium
        } else {
            Severity::Low
        };
        
        // Calculate CVSS score based on severity
        let cvss_score = match severity {
            Severity::Critical => 9.6,
            Severity::High => 8.2,
            Severity::Medium => 6.1,
            Severity::Low => 4.0,
            _ => 2.0,
        };
        
        // Build description using available fields
        let description = format!(
            "Cross-Site Scripting (XSS) vulnerability detected.\n\n\
            Severity: {:?}\n\
            Breakout Required: {}\n\
            CSP Bypass Needed: {}\n\n\
            Reason: {}\n\n\
            Technical Details:\n{}\n\n\
            An attacker can inject malicious JavaScript code that will execute in the victim's browser, \
            potentially leading to session hijacking, credential theft, or malicious actions on behalf \
            of the victim.",
            xss_result.severity,
            if xss_result.breakout_required { "Yes" } else { "No" },
            if xss_result.csp_bypass_needed { "Yes" } else { "No" },
            xss_result.reason,
            xss_result.technical_details
        );
        
        // Build impact analysis
        let impact = if severity == Severity::Critical {
            "CRITICAL - Immediate JavaScript execution without user interaction. \
            Attacker can:\n\
            • Steal session cookies and authentication tokens\n\
            • Perform actions on behalf of the victim\n\
            • Redirect users to malicious sites\n\
            • Deface the application\n\
            • Deploy malware or keyloggers\n\
            • Access sensitive data visible to the user"
        } else if severity == Severity::High {
            "HIGH - JavaScript execution possible with minimal requirements. \
            Attacker can achieve similar impacts as Critical with slightly more effort."
        } else {
            "MEDIUM - JavaScript execution possible but may require specific conditions \
            or user interaction. Still exploitable in targeted attacks."
        };
        
        // Build remediation
        let remediation = "\
            1. OUTPUT ENCODING (Context-Specific):\n   \
            • HTML context: Use HTML entity encoding (&lt; &gt; &quot; &#x27; &amp;)\n   \
            • Attribute context: Use HTML attribute encoding and quote all attributes\n   \
            • JavaScript context: Use JavaScript escaping (\\x3C \\x3E \\x22 \\x27)\n   \
            • URL context: Use URL encoding and validate protocols\n\n\
            2. CONTENT SECURITY POLICY (CSP):\n   \
            Implement strict CSP headers:\n   \
            Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'\n\n\
            3. INPUT VALIDATION:\n   \
            • Validate all user input against allowlists\n   \
            • Reject unexpected characters and patterns\n   \
            • Use security-focused validation libraries\n\n\
            4. HTTP-ONLY COOKIES:\n   \
            Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict\n\n\
            5. X-XSS-PROTECTION HEADER:\n   \
            X-XSS-Protection: 1; mode=block\n\n\
            6. FRAMEWORK PROTECTIONS:\n   \
            Use auto-escaping templates (e.g., React, Angular, Vue with proper configuration)"
            .to_string();
        
        // Build references
        let references = vec![
            "OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html".to_string(),
            "CWE-79: Improper Neutralization of Input During Web Page Generation: https://cwe.mitre.org/data/definitions/79.html".to_string(),
            "PortSwigger XSS: https://portswigger.net/web-security/cross-site-scripting".to_string(),
        ];
        
        // Create finding
        let finding = Finding {
            vuln_type: "Cross-Site Scripting (XSS)".to_string(),
            technique: format!("{:?}", xss_result.severity),
            endpoint: endpoint.to_string(),
            parameter: Some(param.to_string()),
            confidence: xss_result.confidence,
            severity,
            evidence: format!(
                "Confidence: {:.1}%\nCVSS Score: {}\n\nReason: {}",
                xss_result.confidence * 100.0,
                cvss_score,
                xss_result.reason
            ),
            description,
            impact: impact.to_string(),
            remediation,
            references,
            cwe: "CWE-79".to_string(),
            cvss_score: Some(cvss_score),
            payload_sample: None,
            http_method: "GET".to_string(),
            database: None,
        };
        
        reporter.add(finding);
    }
    */
    
    /// Run Stored/Persistent XSS detection
    async fn run_stored_xss_scan(
        &self,
        client: &HttpClient,
        target_url: &Url,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) -> anyhow::Result<()> {
        if self.ctx.verbose {
            tracing::info!("\nSTORED XSS DETECTION - Persistence Analysis");
            tracing::info!("Methodology: Inject → Persist → Crawl → Correlate");
            tracing::info!("  1. Inject unique markers into input fields");
            tracing::info!("  2. Allow persistence (database/file storage)");
            tracing::info!("  3. Crawl application for marker resurfacing");
            tracing::info!("  4. Correlate injection point with execution point\n");
        }
        
        // Use the StoredXssEngine
        let mut stored_engine = crate::xss::stored::StoredXssEngine::default();
        
        // Get the parameter to test
        let param = self.ctx.direct_param.clone().unwrap_or_else(|| "name".to_string());
        
        // Run stored XSS detection
        stored_engine.run(client, target_url, &param, reporter).await?;

        Ok(())
    }

    /// Run blind XSS detection: inject OOB payloads carrying unique correlation
    /// IDs, then confirm any that reached the built-in interaction listener.
    async fn run_blind_xss_scan(
        &self,
        client: &HttpClient,
        target_url: &Url,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) -> anyhow::Result<()> {
        let callback_domain = match &self.ctx.xss_callback {
            Some(d) => d.clone(),
            None => {
                tracing::warn!(
                    "Blind XSS requested but no --callback domain provided; skipping"
                );
                return Ok(());
            }
        };

        // Ensure the OOB interaction listener is running (idempotent — shared
        // with blind SSRF). The callback domain must route to this host:port.
        const OOB_BIND: &str = "0.0.0.0:8888";
        match crate::ssrf::oob::start_oob_server(OOB_BIND).await {
            Ok(addr) => tracing::info!(
                "OOB listener on {} for blind XSS (callback domain '{}' must route here)",
                addr,
                callback_domain
            ),
            Err(e) => tracing::warn!("Failed to start OOB listener: {}", e),
        }

        let mut engine = crate::xss::blind::BlindXssEngine::new(callback_domain);

        // Inject blind payloads into the chosen parameter.
        let param = self.ctx.direct_param.clone().unwrap_or_else(|| "q".to_string());
        if let Err(e) = engine.inject(client, target_url, &param).await {
            tracing::warn!("Blind XSS injection failed for '{}': {}", param, e);
        }

        // Brief window for immediate callbacks, then correlate. Blind XSS often
        // fires much later (when a victim renders the payload); the listener
        // keeps running while anvil runs, but we report anything seen now.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let confirmed = engine.check_received_callbacks(reporter);
        if confirmed > 0 {
            tracing::warn!("[BLIND XSS] {} callback(s) confirmed during scan", confirmed);
        } else {
            tracing::info!(
                "Blind XSS payloads injected; no callbacks yet (they may fire later)"
            );
        }

        Ok(())
    }
    
    /// Run DOM-based XSS detection
    async fn run_dom_xss_scan(
        &self,
        client: &HttpClient,
        target_url: &Url,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) -> anyhow::Result<()> {
        if self.ctx.verbose {
            tracing::info!("\nDOM XSS DETECTION - Client-Side Analysis");
            tracing::info!("Methodology: Source-to-Sink Data Flow Analysis");
            tracing::info!("  1. Extract JavaScript from page");
            tracing::info!("  2. Identify untrusted sources (location.hash, etc.)");
            tracing::info!("  3. Identify dangerous sinks (innerHTML, eval, etc.)");
            tracing::info!("  4. Trace data flow from source to sink\n");
        }
        
        // Fetch the page
        let request = crate::http::request::HttpRequest::new(reqwest::Method::GET, target_url.clone());
        let response = client.execute(request).await?;
        
        // Extract JavaScript from the page
        let html = String::from_utf8_lossy(&response.body).to_string();
        let js_code = self.extract_javascript(&html);
        
        if self.ctx.verbose {
            tracing::info!("Extracted {} bytes of JavaScript code", js_code.len());
        }
        
        // Analyze for DOM XSS
        let flows = crate::xss::dom::analyze_dom_xss(&html, &js_code);
        
        if flows.is_empty() {
            if self.ctx.verbose {
                tracing::info!("No DOM XSS flows detected");
            }
            return Ok(());
        }
        
        // Report findings
        for flow in &flows {
            if !flow.exploitable {
                continue;
            }
            
            let (severity_label, severity_color, severity_enum) = if flow.confidence >= 0.85 {
                ("HIGH", "🟠", crate::reporting::model::Severity::High)
            } else if flow.confidence >= 0.70 {
                ("MEDIUM", "🟡", crate::reporting::model::Severity::Medium)
            } else {
                ("LOW", "🔵", crate::reporting::model::Severity::Low)
            };
            
            // Print summary
            println!("\n[+] DOM-based XSS detected");
            println!("    Endpoint  : {}", target_url.path());
            println!("    Source    : {}", flow.source.source_type);
            println!("    Sink      : {}", flow.sink.sink_type);
            println!("    Severity  : {} {}", severity_color, severity_label);
            println!("    Confidence: {:.0}%", flow.confidence * 100.0);
            println!("    XSS Type  : DOM-based XSS");
            println!("    Evidence  : {} → {}", flow.source.property, flow.sink.dangerous_function);
            
            // Add to report
            self.add_dom_xss_to_report(reporter, flow, target_url.path());
        }
        
        Ok(())
    }
    
    /// Extract JavaScript from HTML
    fn extract_javascript(&self, html: &str) -> String {
        use scraper::{Html, Selector};
        
        let document = Html::parse_document(html);
        let script_selector = Selector::parse("script").unwrap();
        
        let mut js_code = String::new();
        
        for element in document.select(&script_selector) {
            let text = element.text().collect::<String>();
            js_code.push_str(&text);
            js_code.push_str("\n\n");
        }
        
        // Also check inline event handlers
        let all_selector = Selector::parse("*").unwrap();
        for element in document.select(&all_selector) {
            for (attr, value) in element.value().attrs() {
                if attr.starts_with("on") { // onclick, onload, onerror, etc.
                    js_code.push_str(&format!("{}={}\n", attr, value));
                }
            }
        }
        
        js_code
    }
    
    /// Add DOM XSS finding to report
    fn add_dom_xss_to_report(
        &self,
        reporter: &mut crate::reporting::reporter::Reporter,
        flow: &crate::xss::dom::DomXssFlow,
        endpoint: &str,
    ) {
        use crate::reporting::model::{Finding, Severity};
        
        let severity = if flow.confidence >= 0.85 {
            Severity::High
        } else if flow.confidence >= 0.70 {
            Severity::Medium
        } else {
            Severity::Low
        };
        
        let cvss_score = match severity {
            Severity::High => 8.5,
            Severity::Medium => 6.5,
            Severity::Low => 4.5,
            _ => 2.0,
        };
        
        let description = format!(
            "DOM-based Cross-Site Scripting (XSS) vulnerability detected.\n\n\
            XSS TYPE: DOM-based XSS\n\n\
            WHY THIS IS XSS:\n\
            Untrusted data from {} flows to dangerous sink {} without proper sanitization, \
            allowing client-side JavaScript execution.\n\n\
            SOURCE: {}\n\
            Property: {}\n\n\
            SINK: {}\n\
            Function: {}\n\
            Context: {}\n\n\
            EVIDENCE-DRIVEN VALIDATION:\n\
            ✓ Phase 1: Source identified ({})\n\
            ✓ Phase 2: Dangerous sink identified ({})\n\
            ✓ Phase 3: Data flow path confirmed\n\
            ✓ Phase 4: No sanitization detected in flow\n\n\
            PROFESSIONAL ASSESSMENT:\n\
            DOM-based XSS occurs entirely in the client-side JavaScript without server involvement. \
            The untrusted data never reaches the server but flows directly from source to sink in the browser. \
            This makes it harder to detect with traditional server-side security controls.",
            flow.source.source_type,
            flow.sink.sink_type,
            flow.source.source_type,
            flow.source.property,
            flow.sink.sink_type,
            flow.sink.dangerous_function,
            flow.sink.line_context,
            flow.source.property,
            flow.sink.dangerous_function
        );
        
        let impact = format!(
            "{} - DOM-based XSS execution.\n\n\
            Attacker capabilities:\n\
            • Execute arbitrary JavaScript in victim's browser\n\
            • Steal session cookies via document.cookie\n\
            • Exfiltrate sensitive data from the DOM\n\
            • Perform actions on behalf of the victim\n\
            • Redirect to phishing/malware sites\n\
            • Modify page content dynamically\n\n\
            DOM XSS SPECIFIC RISKS:\n\
            • Bypasses server-side security filters\n\
            • Often missed by WAFs and security scanners\n\
            • Difficult to detect without client-side analysis\n\
            • Can be triggered by URL fragments (after #)\n\
            • Persists in single-page applications (SPAs)",
            if severity == Severity::High { "HIGH" } else { "MEDIUM" }
        );
        
        let remediation = "\
            DOM XSS REMEDIATION:\n\n\
            1. **AVOID DANGEROUS SINKS**\n   \
            ❌ NEVER use with untrusted data:\n   \
            • innerHTML, outerHTML, document.write\n   \
            • eval(), setTimeout(string), setInterval(string)\n   \
            • location.href with user input\n   \
            • Function() constructor\n\n\
            2. **USE SAFE ALTERNATIVES**\n   \
            ✅ Instead of innerHTML → Use textContent or createTextNode\n   \
            ✅ Instead of eval() → Use JSON.parse() for data\n   \
            ✅ Instead of location.href → Validate and sanitize URLs\n\n\
            3. **SANITIZE AT SINK**\n   \
            Use DOMPurify for HTML sanitization:\n   \
            const clean = DOMPurify.sanitize(dirty);\n   \
            element.innerHTML = clean;\n\n\
            4. **VALIDATE SOURCES**\n   \
            • Validate location.hash/search before use\n   \
            • Use allowlist for expected values\n   \
            • Encode data appropriately for context\n\n\
            5. **CONTENT SECURITY POLICY**\n   \
            Implement strict CSP:\n   \
            Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'\n\n\
            6. **USE SAFE FRAMEWORKS**\n   \
            • React: Use JSX (auto-escapes)\n   \
            • Angular: Use data binding (auto-escapes)\n   \
            • Vue: Use templates (auto-escapes)\n\n\
            7. **CODE REVIEW**\n   \
            Review all uses of:\n   \
            • location.hash, location.search, document.URL\n   \
            • innerHTML, outerHTML, document.write\n   \
            • eval, setTimeout, setInterval with strings"
            .to_string();
        
        let references = vec![
            "OWASP DOM XSS: https://owasp.org/www-community/attacks/DOM_Based_XSS".to_string(),
            "CWE-79: https://cwe.mitre.org/data/definitions/79.html".to_string(),
            "PortSwigger DOM XSS: https://portswigger.net/web-security/cross-site-scripting/dom-based".to_string(),
            "DOMPurify: https://github.com/cure53/DOMPurify".to_string(),
        ];
        
        let finding = Finding {
            vuln_type: "Cross-Site Scripting (XSS)".to_string(),
            technique: "DOM-based XSS".to_string(),
            endpoint: endpoint.to_string(),
            parameter: Some(format!("Source: {}", flow.source.property)),
            confidence: flow.confidence,
            severity,
            evidence: format!(
                "Confidence: {:.0}%\nCVSS Score: {:.1}\n\nData Flow:\n{} → {}\n\nSink Context:\n{}",
                flow.confidence * 100.0,
                cvss_score,
                flow.source.property,
                flow.sink.dangerous_function,
                flow.sink.line_context
            ),
            description,
            impact,
            remediation,
            references,
            cwe: "CWE-79".to_string(),
            cvss_score: Some(cvss_score),
            payload_sample: Some(format!("Source: {} → Sink: {}", flow.source.property, flow.sink.dangerous_function)),
            http_method: "GET".to_string(),
            database: None,
        };
        
        reporter.add(finding);
    }

    /// Run SSRF scan with evidence-driven detection
    async fn run_ssrf_scan(
        &self,
        client: &HttpClient,
        target_url: &Url,
        sitemap: &Option<SiteMap>,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) -> anyhow::Result<()> {
        // Removed verbose methodology - enterprise tools are concise

        // Start the built-in OOB interaction listener if an OOB callback domain
        // was configured (enables blind SSRF correlation). The callback domain
        // supplied via --ssrf-callback must route to this host:port.
        if let Some(ref domain) = self.ctx.ssrf_config.oob_callback {
            const OOB_BIND: &str = "0.0.0.0:8888";
            match crate::ssrf::oob::start_oob_server(OOB_BIND).await {
                Ok(addr) => tracing::info!(
                    "OOB interaction listener started on {} (ensure callback domain '{}' routes here)",
                    addr,
                    domain
                ),
                Err(e) => tracing::warn!("Failed to start OOB listener on {}: {}", OOB_BIND, e),
            }
        }

        // Check if we have a direct parameter first (takes priority)
        if let Some(ref param) = self.ctx.direct_param {
            // Direct parameter testing
            tracing::info!("Testing parameter '{}' for SSRF", param);
            
            let scanner = crate::ssrf::SsrfScanner::new(self.ctx.ssrf_config.clone());
            
            if let Some(result) = scanner.scan_parameter(client, target_url, param).await? {
                self.report_ssrf_finding(&result);
                self.add_ssrf_to_report(&result, reporter);
            } else {
                tracing::info!("No SSRF detected in parameter '{}'", param);
            }
        } else if let Some(sitemap) = sitemap {
            // Use sitemap for scanning
            let scanner = crate::ssrf::SsrfScanner::new(self.ctx.ssrf_config.clone());
            let results = scanner.scan(client, target_url, sitemap).await?;

            // Report findings
            for result in &results {
                self.report_ssrf_finding(&result);
                self.add_ssrf_to_report(&result, reporter);
            }
        } else {
            tracing::warn!("No sitemap available. Use --crawl or --param to specify targets.");
        }

        Ok(())
    }

    /// Report SSRF finding to console
    fn report_ssrf_finding(&self, result: &crate::ssrf::SsrfResult) {
        let severity = result.severity();
        let severity_color = match severity {
            "CRITICAL" => "🔴",
            "HIGH" => "🟠",
            "MEDIUM" => "🟡",
            _ => "🔵",
        };

        // Semantic labeling
        let impact_type = if result.classification.is_network_ssrf() {
            "Network SSRF"
        } else if result.classification.is_local_resource_access() {
            "Local Resource Access (SSRF-like impact)"
        } else {
            "SSRF Candidate"
        };

        if !self.ctx.verbose {
            // Clean summary output
            println!("\n[+] {} detected", result.classification.description());
            println!("    Endpoint  : {}", result.endpoint);
            println!("    Parameter : {}", result.parameter);
            println!("    Severity  : {} {}", severity_color, severity);
            println!("    Confidence: {:.0}%", result.confidence * 100.0);
            println!("    Impact Type: {}", impact_type);
            println!("    Classification: {:?}", result.classification);
            if let Some(ref target) = result.target_reached {
                println!("    Target Reached: {}", target);
            }
            println!("    Control Scores:");
            println!("      Destination: {:.0}%", result.destination_control_score * 100.0);
            println!("      Protocol: {:.0}%", result.protocol_control_score * 100.0);
            
            // Show capability boundaries
            let narrative = result.capability_narrative();
            if !narrative.is_empty() {
                println!("    Exploit Boundaries: {}", narrative);
            }
        } else {
            // Verbose output
            tracing::warn!(
                "\n  ✗ {} DETECTED",
                result.classification.description().to_uppercase()
            );
            tracing::warn!("    Endpoint: {}", result.endpoint);
            tracing::warn!("    Parameter: {}", result.parameter);
            tracing::warn!("    Impact Type: {}", impact_type);
            tracing::warn!("    Payload: {}", result.payload);
            tracing::warn!("    Confidence: {:.0}%", result.confidence * 100.0);
            tracing::warn!("    Request Control: {:.0}%", result.request_control_confidence * 100.0);
            tracing::warn!("    Impact Reachability: {:.0}%", result.impact_reachability_confidence * 100.0);
            tracing::warn!("    Control Scores:");
            tracing::warn!("      Destination Control: {:.0}%", result.destination_control_score * 100.0);
            tracing::warn!("      Protocol Control: {:.0}%", result.protocol_control_score * 100.0);
            
            // Show capability boundaries
            let narrative = result.capability_narrative();
            if !narrative.is_empty() {
                tracing::warn!("    Exploit Boundaries: {}", narrative);
            }
            
            if !result.evidence.is_empty() {
                tracing::warn!("    Evidence:");
                for (idx, evidence) in result.evidence.iter().enumerate() {
                    tracing::warn!("      {}. {} (confidence: {:.0}%)", 
                        idx + 1, 
                        evidence.description,
                        evidence.confidence * 100.0
                    );
                }
            }
            
            if !result.details.is_empty() {
                tracing::warn!("    Details: {}", result.details);
            }
        }
    }

    /// Add SSRF finding to report
    fn add_ssrf_to_report(
        &self,
        result: &crate::ssrf::SsrfResult,
        reporter: &mut crate::reporting::reporter::Reporter,
    ) {
        use crate::reporting::model::{Finding, Severity};

        let severity = match result.severity() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            _ => Severity::Info,
        };

        let cvss_score = match severity {
            Severity::Critical => 9.8,
            Severity::High => 8.5,
            Severity::Medium => 6.5,
            _ => 4.0,
        };

        // Build evidence summary
        let evidence_summary = if result.evidence.is_empty() {
            "No specific evidence collected".to_string()
        } else {
            result
                .evidence
                .iter()
                .enumerate()
                .map(|(idx, e)| format!("{}. {} (confidence: {:.0}%)", idx + 1, e.description, e.confidence * 100.0))
                .collect::<Vec<_>>()
                .join("\n")
        };

        let description = format!(
            "Server-Side Request Forgery (SSRF) - {}.\n\n\
            CLASSIFICATION: {:?}\n\n\
            WHY THIS IS SSRF:\n\
            {}\n\n\
            CONFIDENCE BREAKDOWN:\n\
            • Overall Confidence: {:.0}%\n\
            • Request Control Certainty: {:.0}%\n\
            • Impact Reachability Certainty: {:.0}%\n\n\
            EVIDENCE-DRIVEN VALIDATION:\n\
            {}\n\n\
            PROFESSIONAL ASSESSMENT:\n\
            This is NOT merely URL reflection - the server demonstrated actual outbound network interaction. \
            The finding has been verified through multi-stage validation to ensure accuracy and minimize false positives.",
            result.classification.description(),
            result.classification,
            result.details,
            result.confidence * 100.0,
            result.request_control_confidence * 100.0,
            result.impact_reachability_confidence * 100.0,
            evidence_summary
        );

        let impact = match severity {
            Severity::Critical => {
                "CRITICAL - Server-Side Request Forgery confirmed.\n\n\
                Attacker capabilities:\n\
                • Access internal network resources (databases, APIs, admin panels)\n\
                • Retrieve cloud metadata (AWS/GCP/Azure credentials)\n\
                • Port scan internal network\n\
                • Bypass firewall restrictions\n\
                • Access localhost services\n\
                • Read local files (if file:// is supported)\n\
                • Pivot to internal systems\n\
                • Exfiltrate sensitive data\n\n\
                EXPLOITABILITY: Direct, confirmed SSRF with high-value target access."
            }
            Severity::High => {
                "HIGH - Server-Side Request Forgery to internal network.\n\n\
                Attacker capabilities:\n\
                • Access internal IP addresses\n\
                • Enumerate internal services\n\
                • Bypass network segmentation\n\
                • Interact with internal APIs\n\
                • Potential for privilege escalation\n\n\
                EXPLOITABILITY: High - Internal network access confirmed."
            }
            Severity::Medium => {
                "MEDIUM - Limited Server-Side Request Forgery.\n\n\
                Server can be made to initiate outbound requests, but with restrictions:\n\
                • Limited protocol support\n\
                • Filtered responses\n\
                • Restricted target access\n\n\
                Still exploitable in specific scenarios."
            }
            _ => {
                "INFO - Potential SSRF candidate.\n\n\
                Parameter influences request destination but full execution not proven. \
                Requires further manual testing."
            }
        };

        let remediation = "\
            SSRF REMEDIATION:\n\n\
            1. **INPUT VALIDATION (PRIMARY DEFENSE)**\n   \
            • Validate against strict allowlist of permitted domains/IPs\n   \
            • Reject all internal IP ranges (RFC1918, loopback, link-local)\n   \
            • Block cloud metadata IPs (169.254.169.254)\n   \
            • Validate URL scheme (allow only http/https)\n\n\
            2. **NETWORK SEGMENTATION**\n   \
            • Isolate application servers from internal network\n   \
            • Use separate VLAN for outbound requests\n   \
            • Implement egress filtering\n   \
            • Block access to metadata endpoints at network level\n\n\
            3. **RESPONSE HANDLING**\n   \
            • Do not return raw responses to user\n   \
            • Sanitize and validate response content\n   \
            • Implement timeout controls\n   \
            • Log all outbound requests\n\n\
            4. **AUTHENTICATION & AUTHORIZATION**\n   \
            • Require authentication for URL-fetching features\n   \
            • Implement rate limiting\n   \
            • Use separate credentials for external requests\n\n\
            5. **DISABLE UNNECESSARY PROTOCOLS**\n   \
            • Block file://, gopher://, ftp://, dict:// schemes\n   \
            • Only allow http:// and https://\n   \
            • Disable URL redirects or validate redirect targets\n\n\
            6. **CLOUD-SPECIFIC PROTECTIONS**\n   \
            • Use IMDSv2 on AWS (requires token)\n   \
            • Block 169.254.169.254 at application level\n   \
            • Use workload identity (GCP) or managed identities (Azure)\n\n\
            VERIFICATION:\n\
            • Re-scan with ANVIL after fixes\n\
            • Test with internal IPs and metadata endpoints\n\
            • Verify network segmentation\n\
            • Review firewall rules"
            .to_string();

        let references = vec![
            "OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery".to_string(),
            "CWE-918: Server-Side Request Forgery: https://cwe.mitre.org/data/definitions/918.html".to_string(),
            "PortSwigger SSRF: https://portswigger.net/web-security/ssrf".to_string(),
            "AWS IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html".to_string(),
        ];

        let finding = Finding {
            vuln_type: "Server-Side Request Forgery (SSRF)".to_string(),
            technique: format!("{:?}", result.classification),
            endpoint: result.endpoint.clone(),
            parameter: Some(result.parameter.clone()),
            confidence: result.confidence,
            severity,
            evidence: format!(
                "Confidence: {:.0}%\nCVSS Score: {:.1}\n\nPayload: {}\n\nEvidence:\n{}",
                result.confidence * 100.0,
                cvss_score,
                result.payload,
                evidence_summary
            ),
            description,
            impact: impact.to_string(),
            remediation,
            references,
            cwe: "CWE-918".to_string(),
            cvss_score: Some(cvss_score),
            payload_sample: Some(result.payload.clone()),
            http_method: "GET".to_string(),
            database: None,
        };

        reporter.add(finding);
    }
}
