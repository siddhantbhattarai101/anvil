//! DBMS error-message signatures for error-based SQLi fingerprinting.
//!
//! The signature set is a Rust port of sqlmap's `data/xml/errors.xml`
//! (https://github.com/sqlmapproject/sqlmap), used with permission — the logic
//! and regexes are reimplemented here in Rust rather than copied as Python/XML.
//! Covers 29 DBMS so error-based detection works far beyond the handful ANVIL
//! recognised before. Credit: sqlmap project (Bernardo Damele, Miroslav Stampar).

use crate::sqli::core::DBMS;
use lazy_static::lazy_static;
use regex::{Regex, RegexBuilder};

/// One DBMS's error signatures.
struct DbmsErrors {
    name: &'static str,
    dbms: DBMS,
    patterns: Vec<Regex>,
}

/// (display name, mapped DBMS enum, raw regexes). DBMS not in ANVIL's enum map
/// to `DBMS::Unknown` but keep their real display name.
fn raw_signatures() -> &'static [(&'static str, DBMS, &'static [&'static str])] {
    &[
        ("MySQL", DBMS::MySQL, &[
            r"SQL syntax.*?MySQL",
            r"Warning.*?\Wmysqli?_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that (corresponds to|fits) your MySQL server version",
            r"check the manual that (corresponds to|fits) your MariaDB server version",
            r"check the manual that (corresponds to|fits) your Drizzle server version",
            r"check the manual that (corresponds to|fits) your TiDB server version",
            r"Unknown column '[^ ]+' in 'field list'",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
            r"Pdo[./_\\]Mysql",
            r"MySqlException",
            r"MemSQL does not support this type of query",
            r"is not supported by MemSQL",
            r"unsupported nested scalar subselect",
        ]),
        ("PostgreSQL", DBMS::PostgreSQL, &[
            r"PostgreSQL.*?ERROR",
            r"Warning.*?\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"ERROR: parser: parse error at or near",
            r"PostgreSQL query failed",
            r"org\.postgresql\.jdbc",
            r"Pdo[./_\\]Pgsql",
            r"PSQLException",
        ]),
        ("Microsoft SQL Server", DBMS::MSSQL, &[
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"OLE DB.*? SQL Server",
            r#"\bSQL Server[^<"]+Driver"#,
            r"Warning.*?\W(mssql|sqlsrv)_",
            r#"\bSQL Server[^<"]+[0-9a-fA-F]{8}"#,
            r"System\.Data\.SqlClient\.(SqlException|SqlConnection\.OnError)",
            r"(?s)Exception.*?\bRoadhouse\.Cms\.",
            r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            r"\[SQL Server\]",
            r"ODBC SQL Server Driver",
            r"ODBC Driver \d+ for SQL Server",
            r"SQLServer JDBC Driver",
            r"com\.jnetdirect\.jsql",
            r"macromedia\.jdbc\.sqlserver",
            r"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
            r"com\.microsoft\.sqlserver\.jdbc",
            r"Pdo[./_\\](Mssql|SqlSrv)",
            r"SQL(Srv|Server)Exception",
            r"Unclosed quotation mark after the character string",
        ]),
        ("Microsoft Access", DBMS::Access, &[
            r"Microsoft Access (\d+ )?Driver",
            r"JET Database Engine",
            r"Access Database Engine",
            r"ODBC Microsoft Access",
            r"Syntax error \(missing operator\) in query expression",
        ]),
        ("Oracle", DBMS::Oracle, &[
            r"\bORA-\d{5}",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?\W(oci|ora)_",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
            r"macromedia\.jdbc\.oracle",
            r"oracle\.jdbc",
            r"Zend_Db_(Adapter|Statement)_Oracle_Exception",
            r"Pdo[./_\\](Oracle|OCI)",
            r"OracleException",
        ]),
        ("SQLite", DBMS::SQLite, &[
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"(Microsoft|System)\.Data\.SQLite\.SQLiteException",
            r"Warning.*?\W(sqlite_|SQLite3::)",
            r"\[SQLITE_ERROR\]",
            r"SQLite error \d+:",
            r"sqlite3.OperationalError:",
            r"SQLite3::SQLException",
            r"org\.sqlite\.JDBC",
            r"Pdo[./_\\]Sqlite",
            r"SQLiteException",
            r"SqliteError:",
        ]),
        ("IBM DB2", DBMS::Unknown, &[
            r"CLI Driver.*?DB2",
            r"DB2 SQL error",
            r"\bdb2_\w+\(",
            r"SQLCODE[=:\d, -]+SQLSTATE",
            r"com\.ibm\.db2\.jcc",
            r"Zend_Db_(Adapter|Statement)_Db2_Exception",
            r"Pdo[./_\\]Ibm",
            r"DB2Exception",
            r"ibm_db_dbi\.ProgrammingError",
        ]),
        ("Informix", DBMS::Unknown, &[
            r"Warning.*?\Wifx_",
            r"Exception.*?Informix",
            r"Informix ODBC Driver",
            r"ODBC Informix driver",
            r"com\.informix\.jdbc",
            r"weblogic\.jdbc\.informix",
            r"Pdo[./_\\]Informix",
            r"IfxException",
        ]),
        ("Firebird", DBMS::Unknown, &[
            r"Dynamic SQL Error.{1,10}SQL error code",
            r"Warning.*?\Wibase_",
            r"org\.firebirdsql\.jdbc",
            r"Pdo[./_\\]Firebird",
        ]),
        ("SAP MaxDB", DBMS::Unknown, &[
            r"SQL error.*?POS([0-9]+)",
            r"Warning.*?\Wmaxdb_",
            r"DriverSapDB",
            r"-3014.*?Invalid end of SQL statement",
            r"com\.sap\.db(tech)?\.jdbc",
            r"\[-3008\].*?: Invalid keyword or missing delimiter",
        ]),
        ("Sybase", DBMS::Unknown, &[
            r"Warning.*?\Wsybase_",
            r"Sybase message",
            r"Sybase.*?Server message",
            r"SybSQLException",
            r"Sybase\.Data\.AseClient",
            r"com\.sybase\.jdbc",
        ]),
        ("Ingres", DBMS::Unknown, &[
            r"Warning.*?\Wingres_",
            r"Ingres SQLSTATE",
            r"Ingres\W.*?Driver",
            r"com\.ingres\.gcf\.jdbc",
        ]),
        ("FrontBase", DBMS::Unknown, &[
            r"Exception (condition )?\d+\. Transaction rollback",
            r"com\.frontbase\.jdbc",
            r"Syntax error 1. Missing",
            r"(Semantic|Syntax) error [1-4]\d{2}\.",
        ]),
        ("HSQLDB", DBMS::Unknown, &[
            r"Unexpected end of command in statement \[",
            r"Unexpected token.*?in statement \[",
            r"org\.hsqldb\.jdbc",
        ]),
        ("H2", DBMS::Unknown, &[
            r"org\.h2\.jdbc",
            r"\[42000-\d+\]",
        ]),
        ("MonetDB", DBMS::Unknown, &[
            r"![0-9]{5}![^\n]+(failed|unexpected|error|syntax|expected|violation|exception)",
            r"\[MonetDB\]\[ODBC Driver",
            r"nl\.cwi\.monetdb\.jdbc",
        ]),
        ("Apache Derby", DBMS::Unknown, &[
            r"Syntax error: Encountered",
            r"org\.apache\.derby",
            r"ERROR 42X01",
        ]),
        ("Vertica", DBMS::Unknown, &[
            r", Sqlstate: (3F|42).{3}, (Routine|Hint|Position):",
            r"/vertica/Parser/scan",
            r"com\.vertica\.jdbc",
            r"org\.jkiss\.dbeaver\.ext\.vertica",
            r"com\.vertica\.dsi\.dataengine",
        ]),
        ("Mckoi", DBMS::Unknown, &[
            r"com\.mckoi\.JDBCDriver",
            r"com\.mckoi\.database\.jdbc",
            r"<REGEX_LITERAL>",
        ]),
        ("Presto", DBMS::Unknown, &[
            r"com\.facebook\.presto\.jdbc",
            r"io\.prestosql\.jdbc",
            r"com\.simba\.presto\.jdbc",
            r"UNION query has different number of fields: \d+, \d+",
            r"line \d+:\d+: mismatched input '[^']+'. Expecting:",
        ]),
        ("Altibase", DBMS::Unknown, &[r"Altibase\.jdbc\.driver"]),
        ("MimerSQL", DBMS::Unknown, &[
            r"com\.mimer\.jdbc",
            r"Syntax error,[^\n]+assumed to mean",
        ]),
        ("ClickHouse", DBMS::Unknown, &[
            r"Code: \d+[., ]+DB::Exception:",
            r"Syntax error: failed at position \d+",
        ]),
        ("CrateDB", DBMS::Unknown, &[r"io\.crate\.client\.jdbc"]),
        ("Cache", DBMS::Unknown, &[
            r"encountered after end of query",
            r"A comparison operator is required here",
        ]),
        ("Raima Database Manager", DBMS::Unknown, &[
            r"-10048: Syntax error",
            r"rdmStmtPrepare\(.+?\) returned",
        ]),
        ("Virtuoso", DBMS::Unknown, &[
            r"SQ074: Line \d+:",
            r"SR185: Undefined procedure",
            r"SQ200: No table ",
            r"Virtuoso S0002 Error",
            r"\[(Virtuoso Driver|Virtuoso iODBC Driver)\]\[Virtuoso Server\]",
        ]),
        ("Snowflake", DBMS::Unknown, &[
            r"001003 \(42000\):",
            r"100038 \(22018\):",
            r"000904 \(42000\):",
            r"SQL compilation error: (syntax )?error line \d+ at position \d+",
        ]),
        ("Spanner", DBMS::Unknown, &[
            r"type.googleapis.com/zetasql.ErrorMessageModeForPayload",
        ]),
    ]
}

lazy_static! {
    static ref SIGNATURES: Vec<DbmsErrors> = raw_signatures()
        .iter()
        .map(|(name, dbms, pats)| DbmsErrors {
            name,
            dbms: *dbms,
            patterns: pats
                .iter()
                .filter_map(|p| {
                    RegexBuilder::new(p)
                        .case_insensitive(true)
                        .build()
                        .ok()
                })
                .collect(),
        })
        .collect();
}

/// Scan a response body for a DBMS error signature. Returns the DBMS display
/// name and its mapped `DBMS` enum (Unknown for DBMS outside ANVIL's enum).
pub fn detect_dbms_error(body: &str) -> Option<(&'static str, DBMS)> {
    for set in SIGNATURES.iter() {
        if set.patterns.iter().any(|re| re.is_match(body)) {
            return Some((set.name, set.dbms));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_dbms_errors() {
        let cases = [
            ("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", "MySQL"),
            ("ERROR: syntax error at or near \"'\"", "PostgreSQL"),
            ("Unclosed quotation mark after the character string", "Microsoft SQL Server"),
            ("ORA-00933: SQL command not properly ended", "Oracle"),
            ("SQLite error 1: near \"'\"", "SQLite"),
            ("DB2 SQL error: SQLCODE=-104", "IBM DB2"),
            ("com.clickhouse: Code: 62. DB::Exception: Syntax error", "ClickHouse"),
        ];
        for (body, expected) in cases {
            let got = detect_dbms_error(body).map(|(n, _)| n);
            assert_eq!(got, Some(expected), "body: {body}");
        }
    }

    #[test]
    fn benign_response_has_no_signature() {
        assert!(detect_dbms_error("<html><body>Welcome back, member!</body></html>").is_none());
    }
}
