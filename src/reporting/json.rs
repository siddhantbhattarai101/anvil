use crate::reporting::model::{Finding, Severity};
use serde::Serialize;

#[derive(Serialize)]
struct Report {
    scan_metadata: ScanMetadata,
    summary: Summary,
    findings: Vec<Finding>,
}

#[derive(Serialize)]
struct ScanMetadata {
    tool: String,
    version: String,
    scan_date: String,
    report_format: String,
}

#[derive(Serialize)]
struct Summary {
    total_findings: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

pub fn render(findings: &[Finding]) -> anyhow::Result<String> {
    let summary = Summary {
        total_findings: findings.len(),
        critical: findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count(),
        high: findings.iter().filter(|f| matches!(f.severity, Severity::High)).count(),
        medium: findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count(),
        low: findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count(),
        info: findings.iter().filter(|f| matches!(f.severity, Severity::Info)).count(),
    };

    let report = Report {
        scan_metadata: ScanMetadata {
            tool: "ANVIL".to_string(),
            version: "0.2.0".to_string(),
            scan_date: chrono::Utc::now().to_rfc3339(),
            report_format: "application/json".to_string(),
        },
        summary,
        findings: findings.to_vec(),
    };

    let json = serde_json::to_string_pretty(&report)?;
    Ok(json)
}
