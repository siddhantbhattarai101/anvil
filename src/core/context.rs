//! Global context for scan execution

use crate::cli::args::Cli;
use crate::core::capability::Capability;
use crate::core::profile::ScanProfile;
use crate::core::scope::Scope;
use crate::reporting::model::Severity;
use crate::sqli::SqliConfig;
use crate::ssrf::SsrfConfig;
use std::collections::HashMap;

/// Enumeration options (like sqlmap)
#[derive(Debug, Clone, Default)]
pub struct EnumerationConfig {
    pub dbs: bool,
    pub tables: bool,
    pub columns: bool,
    pub schema: bool,
    pub count: bool,
    pub dump: bool,
    pub dump_all: bool,
    pub database: Option<String>,
    pub table: Option<String>,
    pub columns_list: Option<Vec<String>>,
    pub start: usize,
    pub stop: Option<usize>,
    // DB Info
    pub banner: bool,
    pub current_user: bool,
    pub current_db: bool,
    pub hostname: bool,
    pub is_dba: bool,
    // User enum
    pub users: bool,
    pub passwords: bool,
    pub privileges: bool,
    pub roles: bool,
}

impl EnumerationConfig {
    pub fn has_any(&self) -> bool {
        self.dbs || self.tables || self.columns || self.schema || 
        self.count || self.dump || self.dump_all ||
        self.banner || self.current_user || self.current_db ||
        self.hostname || self.is_dba ||
        self.users || self.passwords || self.privileges || self.roles
    }
}

pub struct Context {
    pub target: String,
    pub rate_limit: u32,
    pub crawl_depth: u32,
    /// Render JavaScript during crawl (headless Chrome) for SPA discovery.
    pub js_crawl: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub scope: Scope,
    pub profile: ScanProfile,
    pub sqli_config: SqliConfig,
    pub ssrf_config: SsrfConfig,
    pub output_format: String,
    pub output_file: Option<String>,
    // Authentication
    pub cookies: Option<String>,
    pub headers: HashMap<String, String>,
    // Direct testing
    pub direct_param: Option<String>,
    pub post_data: Option<String>,
    pub http_method: String,
    // Second-order SQLi
    pub trigger_url: Option<String>,
    pub extra_data: Option<String>,
    // Enumeration (like sqlmap)
    pub enumeration: EnumerationConfig,
    // Detection tuning
    pub threshold: f32,
    pub risk: u8,
    pub level: u8,
    pub technique: String,
    pub threads: usize,
    // Injection customization
    pub prefix: Option<String>,
    pub suffix: Option<String>,
    /// Callback domain for blind XSS (must route to the OOB listener).
    pub xss_callback: Option<String>,
    /// CI/agent gating: exit 2 if any finding at or above this severity exists.
    pub fail_on: Option<Severity>,
}

impl Context {
    pub fn from_cli(cli: Cli) -> anyhow::Result<Self> {
        let target = cli.target.clone().unwrap_or_default();
        let scope = Scope::new(&target)?;

        // Build scan profile from CLI flags
        let has_enumeration = cli.has_enumeration();
        
        let profile = if cli.all {
            ScanProfile::all()
        } else {
            let mut profile = ScanProfile::empty();

            // Determine if any specific module was requested
            let has_specific_module = cli.sqli
                || cli.time_sqli
                || cli.stacked
                || cli.oob
                || cli.second_order
                || cli.sqli_all
                || cli.xss
                || cli.xss_stored
                || cli.xss_dom
                || cli.xss_blind
                || cli.xss_all
                || cli.ssrf
                || cli.ssrf_all
                || cli.cmdi
                || cli.path_traversal
                || cli.ssti
                || cli.open_redirect
                || cli.cors
                || cli.crlf
                || cli.security_headers
                || cli.jwt
                || cli.secrets
                || cli.nosqli
                || cli.xxe
                || cli.components
                || cli.sri
                || has_enumeration;

            // Enable fingerprint and crawl by default if no specific module requested
            // BUT if direct param is specified, skip crawling
            if cli.fingerprint || (!has_specific_module && cli.param.is_none()) {
                profile.enable(Capability::Fingerprint);
            }
            if (cli.crawl || !has_specific_module) && cli.param.is_none() && !has_enumeration {
                profile.enable(Capability::Crawl);
            }

            // SQL Injection capabilities
            // Enable SQLi detection if any enumeration flag is set
            if cli.sqli_all || has_enumeration {
                profile.enable(Capability::SqlInjection);
                profile.enable(Capability::TimeSqlInjection);
                profile.enable(Capability::StackedSqlInjection);
                if cli.oob_callback.is_some() {
                    profile.enable(Capability::OobSqlInjection);
                }
            } else {
                if cli.sqli {
                    profile.enable(Capability::SqlInjection);
                }
                if cli.time_sqli {
                    profile.enable(Capability::TimeSqlInjection);
                }
                if cli.stacked {
                    profile.enable(Capability::StackedSqlInjection);
                }
                if cli.oob {
                    profile.enable(Capability::OobSqlInjection);
                }
                if cli.second_order {
                    profile.enable(Capability::SecondOrderSqli);
                }
            }

            // Exploitation modes
            if cli.proof || has_enumeration {
                profile.enable(Capability::ProofMode);
            }
            if cli.exploit || cli.dump || cli.dump_all {
                profile.enable(Capability::ExploitMode);
            }
            if cli.dump_hashes || cli.passwords {
                profile.enable(Capability::HashDump);
            }

            // XSS capabilities
            if cli.xss {
                profile.enable(Capability::Xss);
            }
            if cli.xss_stored {
                profile.enable(Capability::StoredXss);
            }
            if cli.xss_dom {
                profile.enable(Capability::DomXss);
            }
            if cli.xss_blind {
                profile.enable(Capability::BlindXss);
            }
            // Enable all XSS types if xss_all is set
            if cli.xss_all {
                profile.enable(Capability::Xss);
                profile.enable(Capability::StoredXss);
                profile.enable(Capability::DomXss);
                profile.enable(Capability::BlindXss);
            }

            // SSRF capabilities
            if cli.ssrf || cli.ssrf_all {
                profile.enable(Capability::Ssrf);
            }
            if cli.cmdi {
                profile.enable(Capability::Cmdi);
            }
            if cli.path_traversal {
                profile.enable(Capability::PathTraversal);
            }
            if cli.ssti {
                profile.enable(Capability::Ssti);
            }
            if cli.open_redirect {
                profile.enable(Capability::OpenRedirect);
            }
            if cli.cors {
                profile.enable(Capability::Cors);
            }
            if cli.crlf {
                profile.enable(Capability::Crlf);
            }
            if cli.security_headers {
                profile.enable(Capability::SecurityHeaders);
            }
            if cli.jwt {
                profile.enable(Capability::Jwt);
            }
            if cli.secrets {
                profile.enable(Capability::Secrets);
            }
            if cli.nosqli {
                profile.enable(Capability::NoSqli);
            }
            if cli.xxe {
                profile.enable(Capability::Xxe);
            }
            if cli.components {
                profile.enable(Capability::Components);
            }
            if cli.sri {
                profile.enable(Capability::Sri);
            }

            profile
        };

        // Build SQLi configuration (simplified)
        let sqli_config = SqliConfig {
            techniques: vec![
                crate::sqli::SqliTechnique::Union,
                crate::sqli::SqliTechnique::Boolean,
                crate::sqli::SqliTechnique::TimeBased,
            ],
            level: cli.level,
            risk: cli.risk,
        };

        // Build SSRF configuration
        let ssrf_config = SsrfConfig {
            oob_callback: cli.ssrf_callback,
            test_internal: cli.ssrf_all || cli.ssrf_internal,
            test_metadata: cli.ssrf_all || cli.ssrf_metadata,
            test_schemes: cli.ssrf_all || cli.ssrf_schemes,
            external_timeout: 5000,
            internal_timeout: 2000,
            confidence_threshold: cli.threshold,
            max_payloads: cli.ssrf_max_payloads,
            // When testing a POST request with a body, inject SSRF payloads into
            // the body rather than the query string.
            post_body: if cli.method.eq_ignore_ascii_case("POST") {
                cli.data.clone()
            } else {
                None
            },
        };

        // Parse custom headers
        let mut headers = HashMap::new();
        for header in &cli.headers {
            if let Some((key, value)) = header.split_once(':') {
                headers.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        // Build enumeration config
        let enumeration = EnumerationConfig {
            dbs: cli.dbs,
            tables: cli.tables,
            columns: cli.columns,
            schema: cli.schema,
            count: cli.count,
            dump: cli.dump,
            dump_all: cli.dump_all,
            database: cli.database,
            table: cli.table,
            columns_list: cli.columns_list.map(|s| s.split(',').map(|c| c.trim().to_string()).collect()),
            start: cli.start,
            stop: cli.stop,
            banner: cli.banner,
            current_user: cli.current_user,
            current_db: cli.current_db,
            hostname: cli.hostname,
            is_dba: cli.is_dba,
            users: cli.users,
            passwords: cli.passwords || cli.dump_hashes,
            privileges: cli.privileges,
            roles: cli.roles,
        };

        // Parse the CI/agent gating threshold, erroring (exit 1) on a bad value.
        let fail_on = match &cli.fail_on {
            Some(s) => Some(Severity::parse(s).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --fail-on value '{s}' (expected info|low|medium|high|critical)"
                )
            })?),
            None => None,
        };

        Ok(Self {
            target,
            rate_limit: cli.rate,
            crawl_depth: cli.depth,
            js_crawl: cli.js_crawl,
            quiet: cli.quiet,
            verbose: cli.verbose,
            scope,
            profile,
            sqli_config,
            ssrf_config,
            output_format: cli.format,
            output_file: cli.output,
            cookies: cli.cookie,
            headers,
            direct_param: cli.param,
            post_data: cli.data,
            http_method: cli.method.to_uppercase(),
            trigger_url: cli.trigger_url,
            extra_data: cli.extra_data,
            enumeration,
            threshold: cli.threshold,
            risk: cli.risk,
            level: cli.level,
            technique: cli.technique,
            threads: cli.threads,
            prefix: cli.prefix,
            suffix: cli.suffix,
            xss_callback: cli.xss_callback,
            fail_on,
        })
    }
}
