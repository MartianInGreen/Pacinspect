use std::env;
use std::io::{self, IsTerminal};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use console::{Style, Term};
use dialoguer::{Confirm, Input, Password, Select, theme::ColorfulTheme};

use crate::config::Config;
use crate::inspect;
use crate::openai::OpenAiClient;
use crate::report::{AnalysisReport, Finding, Severity, Verdict};

pub struct ReviewOptions {
    pub json: bool,
    pub non_interactive: bool,
    pub accept_risk: bool,
    pub quiet: bool,
}

pub struct ReviewOutcome {
    pub approved: bool,
    pub content_hash: String,
    pub report: AnalysisReport,
}

pub fn review_directory(
    root: &Path,
    config: &Config,
    options: &ReviewOptions,
) -> Result<ReviewOutcome> {
    loop {
        let bundle = inspect::collect(root, config.max_input_bytes)?;
        if !options.json && !options.quiet {
            eprintln!(
                "{} {} with model {}",
                Style::new().cyan().bold().apply_to("Inspecting"),
                root.display(),
                Style::new().bold().apply_to(&config.model)
            );
        }
        let report = OpenAiClient::new(config)?.analyze(&bundle)?;
        if !options.quiet {
            render_report(&report, options.json)?;
        }
        let blocked = report.should_block(config.block_threshold);
        if !blocked || options.accept_risk {
            return Ok(ReviewOutcome {
                approved: true,
                content_hash: bundle.content_hash,
                report,
            });
        }
        if options.json || options.non_interactive || !io::stdin().is_terminal() {
            return Ok(ReviewOutcome {
                approved: false,
                content_hash: bundle.content_hash,
                report,
            });
        }

        match prompt_action(&report)? {
            ReviewAction::Abort => {
                return Ok(ReviewOutcome {
                    approved: false,
                    content_hash: bundle.content_hash,
                    report,
                });
            }
            ReviewAction::EditAndRescan => open_relevant_file(root, &report)?,
            ReviewAction::Continue => {
                return Ok(ReviewOutcome {
                    approved: true,
                    content_hash: bundle.content_hash,
                    report,
                });
            }
        }
    }
}

pub fn interactive_config(defaults: &Config) -> Result<Config> {
    let theme = ColorfulTheme::default();
    let api_url = Input::<String>::with_theme(&theme)
        .with_prompt("OpenAI-compatible API base URL")
        .default(defaults.api_url.clone())
        .interact_text()?;
    let model = Input::<String>::with_theme(&theme)
        .with_prompt("Model")
        .default(defaults.model.clone())
        .interact_text()?;
    let prompt = if defaults.api_key.is_some() {
        "API key (leave empty to keep the saved key)"
    } else {
        "API key (may be empty for a local unauthenticated API)"
    };
    let entered_key = Password::with_theme(&theme)
        .with_prompt(prompt)
        .allow_empty_password(true)
        .interact()?;
    let fail_open = Confirm::with_theme(&theme)
        .with_prompt("Allow builds when the API cannot be reached")
        .default(defaults.fail_open)
        .interact()?;

    let mut configured = defaults.clone();
    configured.api_url = api_url;
    configured.model = model;
    if !entered_key.is_empty() {
        configured.api_key = Some(entered_key);
    }
    configured.fail_open = fail_open;
    configured.validate()?;
    Ok(configured)
}

pub fn prompt_api_key() -> Result<String> {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("API key")
        .interact()
        .context("failed to read API key")
}

fn render_report(report: &AnalysisReport, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    let verdict_style = match report.verdict {
        Verdict::Safe => Style::new().green().bold(),
        Verdict::Caution => Style::new().yellow().bold(),
        Verdict::Dangerous => Style::new().red().bold(),
    };
    println!();
    println!(
        "{} {} — {}",
        verdict_style.apply_to(report.verdict.to_string().to_uppercase()),
        severity_badge(report.maximum_severity()),
        report.summary
    );
    println!("Source review: {}", report.source_changes);

    if report.findings.is_empty() {
        println!(
            "{} No security findings.",
            Style::new().green().apply_to("✓")
        );
    } else {
        for (index, finding) in report.findings.iter().enumerate() {
            render_finding(index + 1, finding);
        }
    }
    println!();
    println!(
        "{} {}",
        Style::new().bold().apply_to("Recommended action:"),
        report.recommended_action
    );
    println!();
    Ok(())
}

fn render_finding(index: usize, finding: &Finding) {
    let location = match (&finding.file, finding.line) {
        (Some(file), Some(line)) => format!(" ({file}:{line})"),
        (Some(file), None) => format!(" ({file})"),
        _ => String::new(),
    };
    println!();
    println!(
        "{}. {} [{}] {}{}",
        index,
        severity_badge(finding.severity),
        finding.category,
        Style::new().bold().apply_to(&finding.title),
        Style::new().dim().apply_to(location)
    );
    println!("   Evidence: {}", finding.evidence);
    println!("   Why: {}", finding.explanation);
    println!("   Action: {}", finding.recommendation);
}

fn severity_badge(severity: Severity) -> console::StyledObject<String> {
    let style = match severity {
        Severity::Info => Style::new().dim(),
        Severity::Low => Style::new().blue(),
        Severity::Medium => Style::new().yellow(),
        Severity::High | Severity::Critical => Style::new().red().bold(),
    };
    style.apply_to(severity.to_string().to_uppercase())
}

enum ReviewAction {
    Abort,
    EditAndRescan,
    Continue,
}

fn prompt_action(report: &AnalysisReport) -> Result<ReviewAction> {
    let items = [
        "Abort this build",
        "Open the most relevant file, then rescan",
        "Continue once and accept the risk",
    ];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Review is {} (maximum severity {})",
            report.verdict,
            report.maximum_severity()
        ))
        .items(items)
        .default(0)
        .interact_on_opt(&Term::stderr())?
        .unwrap_or(0);
    Ok(match selection {
        0 => ReviewAction::Abort,
        1 => ReviewAction::EditAndRescan,
        2 => ReviewAction::Continue,
        _ => unreachable!(),
    })
}

fn open_relevant_file(root: &Path, report: &AnalysisReport) -> Result<()> {
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to resolve package directory {}", root.display()))?;
    let finding = report
        .findings
        .iter()
        .max_by_key(|finding| finding.severity);
    let relative = finding
        .and_then(|finding| finding.file.as_deref())
        .unwrap_or("PKGBUILD");
    let line = finding.and_then(|finding| finding.line).unwrap_or(1);
    let path = root
        .join(relative)
        .canonicalize()
        .with_context(|| format!("model referenced an unavailable package file: {relative}"))?;
    if !path.starts_with(root) || !path.is_file() {
        bail!("model referenced a file outside the package directory: {relative}");
    }
    let editor = env::var("VISUAL")
        .or_else(|_| env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".into());
    let words = shell_words::split(&editor).context("VISUAL/EDITOR contains invalid quoting")?;
    let (program, arguments) = words.split_first().context("VISUAL/EDITOR is empty")?;
    let status = Command::new(program)
        .args(arguments)
        .arg(format!("+{line}"))
        .arg(&path)
        .status()
        .with_context(|| format!("failed to launch editor {program}"))?;
    if !status.success() {
        bail!("editor exited with {status}");
    }
    Ok(())
}
