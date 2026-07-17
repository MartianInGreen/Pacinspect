use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

impl FromStr for Severity {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => bail!("expected one of: info, low, medium, high, critical"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    #[default]
    Safe,
    Caution,
    Dangerous,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Safe => "safe",
            Self::Caution => "caution",
            Self::Dangerous => "dangerous",
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub title: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<u32>,
    pub evidence: String,
    pub explanation: String,
    pub recommendation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AnalysisReport {
    pub verdict: Verdict,
    pub summary: String,
    #[serde(default)]
    pub findings: Vec<Finding>,
    pub source_changes: String,
    pub recommended_action: String,
}

impl AnalysisReport {
    pub fn maximum_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    pub fn should_block(&self, threshold: Severity) -> bool {
        self.verdict == Verdict::Dangerous || self.maximum_severity() >= threshold
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct HeuristicSignal {
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub pattern: String,
    pub excerpt: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(verdict: Verdict, severity: Severity) -> AnalysisReport {
        AnalysisReport {
            verdict,
            summary: String::new(),
            findings: vec![Finding {
                severity,
                category: "other".into(),
                title: String::new(),
                file: None,
                line: None,
                evidence: String::new(),
                explanation: String::new(),
                recommendation: String::new(),
            }],
            source_changes: String::new(),
            recommended_action: String::new(),
        }
    }

    #[test]
    fn blocks_at_threshold_or_for_dangerous_verdict() {
        assert!(report(Verdict::Caution, Severity::Medium).should_block(Severity::Medium));
        assert!(!report(Verdict::Caution, Severity::Low).should_block(Severity::Medium));
        assert!(report(Verdict::Dangerous, Severity::Info).should_block(Severity::Critical));
    }
}
