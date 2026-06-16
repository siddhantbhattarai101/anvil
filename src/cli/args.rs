use clap::Parser;

/// ANVIL – Enterprise-grade Adversarial Security Testing Framework
#[derive(Parser, Debug)]
#[command(
    name = "anvil",
    version = "0.6.0",
    author = "Siddhant Bhattarai",
    about = "ANVIL — adversarial web vulnerability scanner (SQLi · XSS · SSRF · Command Injection · Path Traversal)",
    long_about = "ANVIL is an enterprise-grade, evidence-driven web application security scanner.\n\
                  It detects and safely proves five vulnerability classes — SQL injection (CWE-89),\n\
                  cross-site scripting (CWE-79), server-side request forgery (CWE-918), OS command\n\
                  injection (CWE-78), and path traversal / LFI (CWE-22) — with low false positives,\n\
                  then emits machine-readable reports (text, JSON, CSV) for triage and CI gating.\n\n\
                  Run one targeted check with -t/--param plus a class flag (e.g. --sqli), or sweep\n\
                  everything with --all. Options are grouped by area below.",
    after_help = "EXAMPLES:\n  \
                  # Targeted single-class checks\n  \
                  anvil -t 'http://host/page?id=1'     -p id   --sqli\n  \
                  anvil -t 'http://host/search?q=t'    -p q    --xss --xss-all\n  \
                  anvil -t 'http://host/fetch?url=x'   -p url  --ssrf\n  \
                  anvil -t 'http://host/ping?host=x'   -p host --cmdi\n  \
                  anvil -t 'http://host/view?file=a'   -p file --path-traversal\n\n  \
                  # Full sweep with crawl + JSON report\n  \
                  anvil -t http://host --all --crawl -o report.json --format json\n\n\
                  DOCS:  man anvil   ·   https://github.com/siddhantbhattarai/anvil",
)]
pub struct Cli {
    /// Target URL (e.g. https://example.com/page.php?id=1)
    #[arg(short, long, required = true)]
    pub target: String,

    // ═══════════════════════════════════════════════════════════════════
    // CORE FEATURES
    // ═══════════════════════════════════════════════════════════════════

    /// Enable ALL vulnerability scans (SQLi + XSS + others)
    #[arg(long, help_heading = "CORE FEATURES")]
    pub all: bool,

    /// Enable fingerprinting (server, OS, framework detection)
    #[arg(long, help_heading = "CORE FEATURES")]
    pub fingerprint: bool,

    /// Enable application crawling & parameter discovery
    #[arg(long, help_heading = "CORE FEATURES")]
    pub crawl: bool,

    /// Render JavaScript (headless Chrome) while crawling — finds SPA routes, forms, and XHR APIs
    #[arg(long = "js-crawl", help_heading = "CORE FEATURES")]
    pub js_crawl: bool,

    /// Enable SQL Injection scanning (use --sqli for basic, see SQLI DETECTION for advanced)
    #[arg(long, help_heading = "CORE FEATURES")]
    pub sqli: bool,

    /// Enable Cross-Site Scripting scanning (use --xss for basic, see XSS DETECTION for advanced)
    #[arg(long, help_heading = "CORE FEATURES")]
    pub xss: bool,

    /// Enable Server-Side Request Forgery scanning
    #[arg(long, help_heading = "CORE FEATURES")]
    pub ssrf: bool,

    /// Enable OS command injection scanning (CWE-78)
    #[arg(long, help_heading = "CORE FEATURES")]
    pub cmdi: bool,

    /// Enable path traversal / LFI scanning (CWE-22)
    #[arg(long = "path-traversal", visible_alias = "lfi", help_heading = "CORE FEATURES")]
    pub path_traversal: bool,

    // ═══════════════════════════════════════════════════════════════════
    // XSS DETECTION OPTIONS
    // ═══════════════════════════════════════════════════════════════════

    /// Enable ALL XSS detection types (reflected, stored, DOM, blind)
    #[arg(long = "xss-all", help_heading = "XSS DETECTION")]
    pub xss_all: bool,

    /// Enable stored/persistent XSS detection
    #[arg(long = "xss-stored", help_heading = "XSS DETECTION")]
    pub xss_stored: bool,

    /// Enable DOM-based XSS detection (client-side analysis)
    #[arg(long = "xss-dom", help_heading = "XSS DETECTION")]
    pub xss_dom: bool,

    /// Enable blind XSS detection with out-of-band callbacks
    #[arg(long = "xss-blind", help_heading = "XSS DETECTION")]
    pub xss_blind: bool,

    /// Callback domain for blind XSS (e.g., attacker.com)
    #[arg(long = "callback", value_name = "DOMAIN", help_heading = "XSS DETECTION", requires = "xss_blind")]
    pub xss_callback: Option<String>,

    /// Maximum payloads to test per context
    #[arg(long = "max-payloads", value_name = "N", help_heading = "XSS DETECTION", default_value = "20")]
    pub max_payloads: usize,

    /// XSS context to target (html, attribute, js_string, js_code, url, polyglot)
    #[arg(long = "xss-context", value_name = "CONTEXT", help_heading = "XSS DETECTION")]
    pub xss_context: Option<String>,

    // ═══════════════════════════════════════════════════════════════════
    // SSRF DETECTION OPTIONS
    // ═══════════════════════════════════════════════════════════════════

    /// Enable ALL SSRF detection types (internal, metadata, schemes)
    #[arg(long = "ssrf-all", help_heading = "SSRF DETECTION")]
    pub ssrf_all: bool,

    /// Test internal network ranges (RFC1918, loopback, link-local)
    #[arg(long = "ssrf-internal", help_heading = "SSRF DETECTION")]
    pub ssrf_internal: bool,

    /// Test cloud metadata endpoints (AWS, GCP, Azure)
    #[arg(long = "ssrf-metadata", help_heading = "SSRF DETECTION")]
    pub ssrf_metadata: bool,

    /// Test non-HTTP schemes (file, gopher, ftp, dict)
    #[arg(long = "ssrf-schemes", help_heading = "SSRF DETECTION")]
    pub ssrf_schemes: bool,

    /// Callback domain for blind SSRF detection (e.g., attacker.com)
    #[arg(long = "ssrf-callback", value_name = "DOMAIN", help_heading = "SSRF DETECTION")]
    pub ssrf_callback: Option<String>,

    /// Maximum payloads to test per parameter for SSRF
    #[arg(long = "ssrf-max-payloads", value_name = "N", help_heading = "SSRF DETECTION", default_value = "20")]
    pub ssrf_max_payloads: usize,

    // ═══════════════════════════════════════════════════════════════════
    // SQL INJECTION DETECTION
    // ═══════════════════════════════════════════════════════════════════

    /// Enable ALL SQLi detection techniques
    #[arg(long = "sqli-all", help_heading = "SQLI DETECTION")]
    pub sqli_all: bool,


    /// Scan for time-based (blind) SQL Injection
    #[arg(long = "time-sqli", help_heading = "SQLI DETECTION")]
    pub time_sqli: bool,

    /// Scan for stacked queries SQL Injection
    #[arg(long, help_heading = "SQLI DETECTION")]
    pub stacked: bool,

    /// Scan for out-of-band (OOB) SQL Injection
    #[arg(long, help_heading = "SQLI DETECTION")]
    pub oob: bool,

    /// Callback domain for OOB detection
    #[arg(long = "oob-callback", help_heading = "SQLI DETECTION")]
    pub oob_callback: Option<String>,

    /// Scan for second-order SQL Injection
    #[arg(long = "second-order", help_heading = "SQLI DETECTION")]
    pub second_order: bool,

    /// SQLi technique to use: B=Boolean, E=Error, U=Union, T=Time, S=Stacked
    #[arg(long, default_value = "BEUTS", help_heading = "SQLI DETECTION")]
    pub technique: String,

    // ═══════════════════════════════════════════════════════════════════
    // ENUMERATION (like sqlmap)
    // ═══════════════════════════════════════════════════════════════════

    /// Enumerate DBMS databases
    #[arg(long, help_heading = "ENUMERATION")]
    pub dbs: bool,

    /// Enumerate tables (use -D to specify database)
    #[arg(long, help_heading = "ENUMERATION")]
    pub tables: bool,

    /// Enumerate columns (use -D and -T to specify)
    #[arg(long, help_heading = "ENUMERATION")]
    pub columns: bool,

    /// Enumerate database schema (all DBs, tables, columns)
    #[arg(long, help_heading = "ENUMERATION")]
    pub schema: bool,

    /// Count number of entries in table(s)
    #[arg(long, help_heading = "ENUMERATION")]
    pub count: bool,

    /// Dump table entries (use -D, -T, -C to specify)
    #[arg(long, help_heading = "ENUMERATION")]
    pub dump: bool,

    /// Dump all databases tables entries
    #[arg(long = "dump-all", help_heading = "ENUMERATION")]
    pub dump_all: bool,

    /// Database to enumerate (-D database_name)
    #[arg(short = 'D', long = "database", help_heading = "ENUMERATION")]
    pub database: Option<String>,

    /// Table to enumerate (-T table_name)
    #[arg(short = 'T', long = "table", help_heading = "ENUMERATION")]
    pub table: Option<String>,

    /// Column(s) to enumerate (-C "col1,col2")
    #[arg(short = 'C', long = "col", help_heading = "ENUMERATION")]
    pub columns_list: Option<String>,

    /// First row to retrieve (--start 0)
    #[arg(long, default_value_t = 0, help_heading = "ENUMERATION")]
    pub start: usize,

    /// Last row to retrieve (--stop 10)
    #[arg(long, help_heading = "ENUMERATION")]
    pub stop: Option<usize>,

    // ═══════════════════════════════════════════════════════════════════
    // DATABASE INFORMATION
    // ═══════════════════════════════════════════════════════════════════

    /// Retrieve DBMS banner/version
    #[arg(long, help_heading = "DB INFO")]
    pub banner: bool,

    /// Retrieve current user
    #[arg(long = "current-user", help_heading = "DB INFO")]
    pub current_user: bool,

    /// Retrieve current database
    #[arg(long = "current-db", help_heading = "DB INFO")]
    pub current_db: bool,

    /// Retrieve server hostname
    #[arg(long, help_heading = "DB INFO")]
    pub hostname: bool,

    /// Check if current user is DBA
    #[arg(long = "is-dba", help_heading = "DB INFO")]
    pub is_dba: bool,

    // ═══════════════════════════════════════════════════════════════════
    // USER ENUMERATION
    // ═══════════════════════════════════════════════════════════════════

    /// Enumerate DBMS users
    #[arg(long, help_heading = "USER ENUM")]
    pub users: bool,

    /// Enumerate DBMS users password hashes
    #[arg(long, help_heading = "USER ENUM")]
    pub passwords: bool,

    /// Enumerate DBMS users privileges
    #[arg(long, help_heading = "USER ENUM")]
    pub privileges: bool,

    /// Enumerate DBMS users roles
    #[arg(long, help_heading = "USER ENUM")]
    pub roles: bool,

    /// Crack password hashes using dictionary attack
    #[arg(long = "crack", help_heading = "USER ENUM")]
    pub crack_hashes: bool,

    /// Wordlist for hash cracking (default: built-in common passwords)
    #[arg(long = "wordlist", help_heading = "USER ENUM")]
    pub wordlist: Option<String>,

    // ═══════════════════════════════════════════════════════════════════
    // AUTHENTICATION
    // ═══════════════════════════════════════════════════════════════════

    /// Cookie string for authenticated scanning
    #[arg(long, help_heading = "AUTHENTICATION")]
    pub cookie: Option<String>,

    /// HTTP headers (can be used multiple times)
    #[arg(long = "header", short = 'H', help_heading = "AUTHENTICATION")]
    pub headers: Vec<String>,

    // ═══════════════════════════════════════════════════════════════════
    // INJECTION POINT
    // ═══════════════════════════════════════════════════════════════════

    /// Parameter to test directly
    #[arg(long, short = 'p', help_heading = "INJECTION")]
    pub param: Option<String>,

    /// POST data for testing
    #[arg(long, help_heading = "INJECTION")]
    pub data: Option<String>,

    /// HTTP method to use (GET, POST)
    #[arg(long, default_value = "GET", help_heading = "INJECTION")]
    pub method: String,

    /// Trigger URL for second-order SQLi
    #[arg(long = "trigger-url", help_heading = "INJECTION")]
    pub trigger_url: Option<String>,

    /// Extra POST data to include with payloads
    #[arg(long = "extra-data", help_heading = "INJECTION")]
    pub extra_data: Option<String>,

    /// Prefix string to inject before payload
    #[arg(long, help_heading = "INJECTION")]
    pub prefix: Option<String>,

    /// Suffix string to inject after payload
    #[arg(long, help_heading = "INJECTION")]
    pub suffix: Option<String>,

    // ═══════════════════════════════════════════════════════════════════
    // DETECTION TUNING
    // ═══════════════════════════════════════════════════════════════════

    /// Detection confidence threshold (0.0-1.0, default: 0.5)
    #[arg(long, default_value_t = 0.5, help_heading = "TUNING")]
    pub threshold: f32,

    /// Risk level (1=safe, 2=moderate, 3=aggressive)
    #[arg(long, default_value_t = 1, help_heading = "TUNING")]
    pub risk: u8,

    /// Test level (1=basic, 2=extended, 3=comprehensive)
    #[arg(long, default_value_t = 1, help_heading = "TUNING")]
    pub level: u8,

    // ═══════════════════════════════════════════════════════════════════
    // PERFORMANCE
    // ═══════════════════════════════════════════════════════════════════

    /// Maximum HTTP requests per second
    #[arg(long, default_value_t = 5, help_heading = "PERFORMANCE")]
    pub rate: u32,

    /// Crawl depth limit
    #[arg(long, default_value_t = 2, help_heading = "PERFORMANCE")]
    pub depth: u32,

    /// Time-based SQLi: samples per test
    #[arg(long = "time-samples", default_value_t = 6, help_heading = "PERFORMANCE")]
    pub time_samples: usize,

    /// Time-based SQLi: delay in seconds
    #[arg(long = "time-delay", default_value_t = 2, help_heading = "PERFORMANCE")]
    pub time_delay: u64,

    /// Number of threads for extraction
    #[arg(long, default_value_t = 1, help_heading = "PERFORMANCE")]
    pub threads: usize,

    // ═══════════════════════════════════════════════════════════════════
    // OUTPUT
    // ═══════════════════════════════════════════════════════════════════

    /// Skip the banner display
    #[arg(long, help_heading = "OUTPUT")]
    pub no_banner: bool,

    /// Quiet mode (minimal output)
    #[arg(short, long, help_heading = "OUTPUT")]
    pub quiet: bool,

    /// Verbose output (debug level)
    #[arg(short, long, help_heading = "OUTPUT")]
    pub verbose: bool,

    /// Output format (text, json, csv)
    #[arg(long, default_value = "text", help_heading = "OUTPUT")]
    pub format: String,

    /// Output file path
    #[arg(short, long, help_heading = "OUTPUT")]
    pub output: Option<String>,

    // ═══════════════════════════════════════════════════════════════════
    // LEGACY/COMPATIBILITY (like sqlmap)
    // ═══════════════════════════════════════════════════════════════════

    /// Enable proof mode (safe metadata extraction only)
    #[arg(long, hide = true, help_heading = "LEGACY")]
    pub proof: bool,

    /// Enable exploitation (same as enumeration flags)
    #[arg(long, hide = true, help_heading = "LEGACY")]
    pub exploit: bool,

    /// Extract database password hashes (same as --passwords)
    #[arg(long = "dump-hashes", hide = true, help_heading = "LEGACY")]
    pub dump_hashes: bool,
}

impl Cli {
    /// Check if any enumeration flag is set
    pub fn has_enumeration(&self) -> bool {
        self.dbs
            || self.tables
            || self.columns
            || self.schema
            || self.dump
            || self.dump_all
            || self.count
            || self.banner
            || self.current_user
            || self.current_db
            || self.hostname
            || self.is_dba
            || self.users
            || self.passwords
            || self.privileges
            || self.roles
    }
}
