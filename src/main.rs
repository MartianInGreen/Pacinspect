mod config;
mod inspect;
mod integration;
mod openai;
mod report;
mod ui;

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use console::Style;

use config::Config;
use report::Severity;
use ui::{
    ReviewOptions, analyze_directories_parallel, interactive_config, prompt_api_key,
    review_completed, review_directory,
};

#[derive(Parser)]
#[command(
    name = "pacinspect",
    version,
    about = "Inspect AUR PKGBUILDs with an OpenAI-compatible model before makepkg runs",
    long_about = "Pacinspect reviews PKGBUILDs, related packaging files, and the previous Git revision. Its yay wrapper intercepts makepkg before the PKGBUILD is sourced or package sources are downloaded."
)]
struct Cli {
    /// Use a specific configuration file
    #[arg(long, global = true, env = "PACINSPECT_CONFIG")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create, display, or update configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    /// Inspect cached yay package directories, or one explicit PKGBUILD directory
    Scan {
        /// Package directory; omit to scan every PKGBUILD in yay's configured buildDir
        path: Option<PathBuf>,

        /// Emit only the model report as JSON and never prompt
        #[arg(long)]
        json: bool,

        /// Block at the configured threshold without prompting
        #[arg(long)]
        non_interactive: bool,

        /// Print findings but return success regardless of severity
        #[arg(long, conflicts_with = "non_interactive")]
        accept_risk: bool,
    },

    /// Run yay while intercepting every makepkg invocation
    #[command(trailing_var_arg = true)]
    Yay {
        /// Arguments passed verbatim to yay (a leading -- is optional)
        #[arg(allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Prompt for API settings and write a mode-0600 config file
    Init,
    /// Show the effective configuration with the API key redacted
    Show,
    /// Print the configuration file path
    Path,
    /// Set one configuration value
    Set {
        field: ConfigField,
        /// Omit this only for api-key, which is read without echo
        value: Option<String>,
    },
    /// Remove a saved API key (environment variables remain effective)
    UnsetApiKey,
}

#[derive(Clone, ValueEnum)]
enum ConfigField {
    ApiUrl,
    ApiKey,
    Model,
    TimeoutSeconds,
    MaxInputBytes,
    MaxParallelReviews,
    BlockThreshold,
    FailOpen,
    YayBinary,
    MakepkgBinary,
}

fn main() -> ExitCode {
    let result = if integration::is_yay_preflight() {
        run_yay_preflight()
    } else if integration::is_makepkg_shim() {
        run_shim()
    } else {
        run_cli()
    };
    match result {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(error) => {
            eprintln!(
                "{} {error:#}",
                Style::new().red().bold().apply_to("pacinspect: error:")
            );
            ExitCode::FAILURE
        }
    }
}

fn run_cli() -> Result<i32> {
    let cli = Cli::parse();
    let config_path = cli.config.map_or_else(config::default_path, Ok)?;

    match cli.command {
        Command::Config { command } => run_config(command, &config_path),
        Command::Scan {
            path,
            json,
            non_interactive,
            accept_risk,
        } => {
            let config = Config::load(&config_path)?;
            run_scan(
                &config,
                path,
                ReviewOptions {
                    json,
                    non_interactive,
                    accept_risk,
                    quiet: false,
                },
            )
        }
        Command::Yay { args } => {
            let config = Config::load(&config_path)?;
            integration::run_yay(&config, &config_path, args)
        }
    }
}

#[derive(serde::Serialize)]
struct BatchScanReport {
    package_directory: PathBuf,
    #[serde(flatten)]
    report: report::AnalysisReport,
}

fn run_scan(config: &Config, path: Option<PathBuf>, mut options: ReviewOptions) -> Result<i32> {
    let batch = path.is_none();
    let directories = match path {
        Some(path) => vec![path],
        None => {
            let build_dir = integration::yay_build_dir(&config.yay_binary).with_context(|| {
                format!("failed to read configuration from {}", config.yay_binary)
            })?;
            cached_package_directories(&build_dir)?
        }
    };

    if batch && !options.json {
        eprintln!(
            "Scanning {} cached package director{} with up to {} parallel request{}",
            directories.len(),
            if directories.len() == 1 { "y" } else { "ies" },
            config.max_parallel_reviews.min(directories.len()),
            if config.max_parallel_reviews.min(directories.len()) == 1 {
                ""
            } else {
                "s"
            }
        );
    }
    options.quiet = batch && options.json;

    if !batch {
        let outcome = review_directory(&directories[0], config, &options)?;
        return Ok(if outcome.approved { 0 } else { 2 });
    }

    let completed = analyze_directories_parallel(&directories, config);
    let mut blocked = false;
    let mut reports = Vec::with_capacity(if options.quiet { directories.len() } else { 0 });
    for (directory, completed) in directories.into_iter().zip(completed) {
        let completed =
            completed.with_context(|| format!("failed to inspect {}", directory.display()))?;
        let package_directory = completed.root.clone();
        if !options.json {
            eprintln!(
                "{} {}",
                Style::new().cyan().bold().apply_to("Reviewing"),
                package_directory.display()
            );
        }
        let outcome = review_completed(completed, config, &options)?;
        blocked |= !outcome.approved;
        if options.quiet {
            reports.push(BatchScanReport {
                package_directory,
                report: outcome.report,
            });
        }
    }
    if options.quiet {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    }
    Ok(if blocked { 2 } else { 0 })
}

fn cached_package_directories(build_dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    if build_dir.join("PKGBUILD").is_file() {
        return Ok(vec![build_dir.to_owned()]);
    }
    let entries = fs::read_dir(build_dir)
        .with_context(|| format!("failed to read yay build directory {}", build_dir.display()))?;
    let mut directories = Vec::new();
    for entry in entries {
        let path = entry
            .with_context(|| format!("failed to read an entry in {}", build_dir.display()))?
            .path();
        if path.join("PKGBUILD").is_file() {
            directories.push(path);
        }
    }
    directories.sort();
    if directories.is_empty() {
        bail!(
            "no PKGBUILDs found in yay build directory {}",
            build_dir.display()
        );
    }
    Ok(directories)
}

fn run_yay_preflight() -> Result<i32> {
    let config_path = integration::shim_config_path().map_or_else(config::default_path, Ok)?;
    let config = Config::load(&config_path)?;
    integration::run_yay_preflight(&config, std::env::args_os().skip(2).collect())
}

fn run_shim() -> Result<i32> {
    let config_path = integration::shim_config_path().map_or_else(config::default_path, Ok)?;
    let config = Config::load(&config_path)?;
    integration::run_makepkg_shim(&config, std::env::args_os().skip(1).collect())
}

fn run_config(command: ConfigCommand, path: &std::path::Path) -> Result<i32> {
    match command {
        ConfigCommand::Init => {
            let current = Config::load_file(path)?;
            let configured = interactive_config(&current)?;
            configured.save(path)?;
            println!("Saved configuration to {}", path.display());
        }
        ConfigCommand::Show => {
            let config = Config::load(path)?;
            println!("# {}", path.display());
            print!("{}", config.redacted_toml()?);
        }
        ConfigCommand::Path => println!("{}", path.display()),
        ConfigCommand::Set { field, value } => {
            let mut config = Config::load_file(path)?;
            set_config_value(&mut config, field, value)?;
            config.save(path)?;
            println!("Updated {}", path.display());
        }
        ConfigCommand::UnsetApiKey => {
            let mut config = Config::load_file(path)?;
            config.api_key = None;
            config.save(path)?;
            println!("Removed saved API key from {}", path.display());
        }
    }
    Ok(0)
}

fn set_config_value(config: &mut Config, field: ConfigField, value: Option<String>) -> Result<()> {
    if matches!(field, ConfigField::ApiKey) {
        config.api_key = Some(match value {
            Some(value) => value,
            None => prompt_api_key()?,
        });
        return config.validate();
    }
    let value = value.context("this field requires a value")?;
    match field {
        ConfigField::ApiUrl => config.api_url = value,
        ConfigField::ApiKey => unreachable!(),
        ConfigField::Model => config.model = value,
        ConfigField::TimeoutSeconds => {
            config.timeout_seconds = value
                .parse()
                .context("timeout-seconds must be an integer")?
        }
        ConfigField::MaxInputBytes => {
            config.max_input_bytes = value
                .parse()
                .context("max-input-bytes must be an integer")?
        }
        ConfigField::MaxParallelReviews => {
            config.max_parallel_reviews = value
                .parse()
                .context("max-parallel-reviews must be an integer")?
        }
        ConfigField::BlockThreshold => config.block_threshold = Severity::from_str(&value)?,
        ConfigField::FailOpen => {
            config.fail_open = match value.as_str() {
                "true" => true,
                "false" => false,
                _ => bail!("fail-open must be true or false"),
            }
        }
        ConfigField::YayBinary => config.yay_binary = value,
        ConfigField::MakepkgBinary => config.makepkg_binary = value,
    }
    config.validate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_path_is_optional() {
        let cli = Cli::try_parse_from(["pacinspect", "scan"]).unwrap();
        assert!(matches!(cli.command, Command::Scan { path: None, .. }));
    }

    #[test]
    fn discovers_sorted_cached_package_directories() {
        let build_dir = tempfile::tempdir().unwrap();
        for name in ["z-package", "a-package"] {
            let package_dir = build_dir.path().join(name);
            fs::create_dir(&package_dir).unwrap();
            fs::write(package_dir.join("PKGBUILD"), "pkgname=test\n").unwrap();
        }
        fs::create_dir(build_dir.path().join("not-a-package")).unwrap();

        let directories = cached_package_directories(build_dir.path()).unwrap();
        let names: Vec<_> = directories
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy())
            .collect();
        assert_eq!(names, ["a-package", "z-package"]);
    }
}
