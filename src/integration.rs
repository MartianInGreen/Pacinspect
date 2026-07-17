use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use serde::Deserialize;

use crate::config::Config;
use crate::ui::{ReviewOptions, review_directory};

pub const SHIM_ENV: &str = "PACINSPECT_MAKEPKG_SHIM";
const REAL_MAKEPKG_ENV: &str = "PACINSPECT_REAL_MAKEPKG";
const RUN_DIR_ENV: &str = "PACINSPECT_RUN_DIR";
const CONFIG_ENV: &str = "PACINSPECT_CONFIG";

pub fn is_makepkg_shim() -> bool {
    env::var_os(SHIM_ENV).is_some()
}

pub fn run_yay(config: &Config, config_path: &Path, args: Vec<OsString>) -> Result<i32> {
    let (forwarded, explicit_makepkg) = sanitize_yay_args(args)?;
    let makepkg = explicit_makepkg
        .or_else(|| query_yay_makepkg(&config.yay_binary))
        .unwrap_or_else(|| config.makepkg_binary.clone());
    let current_exe = env::current_exe().context("failed to locate the pacinspect executable")?;
    if same_executable(&current_exe, Path::new(&makepkg)) {
        bail!("the real makepkg command resolves to pacinspect; refusing recursive interception");
    }

    let run_directory = tempfile::Builder::new()
        .prefix("pacinspect-run-")
        .tempdir()
        .context("failed to create inspection run directory")?;
    let mut command = Command::new(&config.yay_binary);
    command
        .args(forwarded)
        .arg("--makepkg")
        .arg(&current_exe)
        .env(SHIM_ENV, "1")
        .env(REAL_MAKEPKG_ENV, &makepkg)
        .env(RUN_DIR_ENV, run_directory.path())
        .env(CONFIG_ENV, config_path);

    eprintln!(
        "pacinspect: intercepting makepkg calls from {} (real makepkg: {})",
        config.yay_binary, makepkg
    );
    let status = command
        .status()
        .with_context(|| format!("failed to launch {}", config.yay_binary))?;
    Ok(exit_code(status))
}

pub fn run_makepkg_shim(config: &Config, args: Vec<OsString>) -> Result<i32> {
    let makepkg = env::var(REAL_MAKEPKG_ENV).context("missing real makepkg command")?;
    let run_dir = env::var_os(RUN_DIR_ENV)
        .map(PathBuf::from)
        .context("missing inspection run directory")?;
    fs::create_dir_all(&run_dir)?;
    let lock_path = run_dir.join("review.lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    lock.lock_exclusive()
        .context("failed to serialize concurrent package reviews")?;

    let root = env::current_dir().context("failed to determine makepkg working directory")?;
    let bundle = crate::inspect::collect(&root, config.max_input_bytes)?;
    let marker = approval_marker(&run_dir, &bundle.content_hash);
    let approved = if marker.is_file() {
        true
    } else {
        let options = ReviewOptions {
            json: false,
            non_interactive: !std::io::stdin().is_terminal(),
            accept_risk: false,
            quiet: false,
        };
        match review_directory(&root, config, &options) {
            Ok(outcome) if outcome.approved => {
                fs::write(
                    approval_marker(&run_dir, &outcome.content_hash),
                    b"approved\n",
                )?;
                true
            }
            Ok(_) => false,
            Err(error) if config.fail_open => {
                eprintln!(
                    "pacinspect: WARNING: inspection failed but fail_open is enabled: {error:#}"
                );
                fs::write(&marker, b"fail-open\n")?;
                true
            }
            Err(error) => {
                eprintln!("pacinspect: blocked because inspection failed: {error:#}");
                false
            }
        }
    };
    FileExt::unlock(&lock)?;

    if !approved {
        eprintln!("pacinspect: build blocked; no PKGBUILD code was handed to makepkg");
        return Ok(125);
    }

    let current_exe = env::current_exe()?;
    if same_executable(&current_exe, Path::new(&makepkg)) {
        bail!("the real makepkg command resolves to pacinspect; refusing recursion");
    }
    let status = Command::new(&makepkg)
        .args(args)
        .env_remove(SHIM_ENV)
        .status()
        .with_context(|| format!("failed to launch real makepkg command {makepkg}"))?;
    Ok(exit_code(status))
}

pub fn shim_config_path() -> Option<PathBuf> {
    env::var_os(CONFIG_ENV).map(PathBuf::from)
}

fn sanitize_yay_args(args: Vec<OsString>) -> Result<(Vec<OsString>, Option<String>)> {
    let mut forwarded = Vec::with_capacity(args.len());
    let mut makepkg = None;
    let mut iter = args.into_iter();
    while let Some(argument) = iter.next() {
        let text = argument.to_string_lossy();
        if text == "--save" {
            bail!(
                "pacinspect yay cannot be used with --save because its temporary makepkg override must not be persisted"
            );
        }
        if text == "--makepkg" {
            let value = iter.next().context("--makepkg requires a command")?;
            makepkg = Some(value.to_string_lossy().into_owned());
            continue;
        }
        if let Some(value) = text.strip_prefix("--makepkg=") {
            makepkg = Some(value.to_owned());
            continue;
        }
        forwarded.push(argument);
    }
    Ok((forwarded, makepkg))
}

#[derive(Deserialize)]
struct YayConfig {
    #[serde(default)]
    makepkgbin: String,
    #[serde(rename = "buildDir", default)]
    build_dir: Option<PathBuf>,
}

pub fn yay_build_dir(yay: &str) -> Result<PathBuf> {
    query_yay_config(yay)
        .and_then(|config| config.build_dir)
        .context("yay did not return a buildDir in its current configuration")
}

fn query_yay_makepkg(yay: &str) -> Option<String> {
    query_yay_config(yay)
        .map(|config| config.makepkgbin)
        .filter(|command| !command.trim().is_empty())
}

fn query_yay_config(yay: &str) -> Option<YayConfig> {
    let output = Command::new(yay).args(["-P", "-g"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

fn approval_marker(run_dir: &Path, content_hash: &str) -> PathBuf {
    run_dir.join(format!("{content_hash}.approved"))
}

fn same_executable(current: &Path, candidate: &Path) -> bool {
    let Ok(current) = current.canonicalize() else {
        return false;
    };
    let candidate = if candidate.components().count() > 1 {
        candidate.canonicalize().ok()
    } else {
        executable_in_path(candidate).and_then(|path| path.canonicalize().ok())
    };
    candidate.is_some_and(|candidate| candidate == current)
}

fn executable_in_path(command: &Path) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(command))
        .find(|candidate| candidate.is_file())
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_makepkg_override_without_forwarding_it() {
        let arguments = vec![
            OsString::from("-S"),
            OsString::from("--makepkg=/opt/custom-makepkg"),
            OsString::from("example"),
        ];
        let (forwarded, makepkg) = sanitize_yay_args(arguments).unwrap();

        assert_eq!(makepkg.as_deref(), Some("/opt/custom-makepkg"));
        assert_eq!(
            forwarded,
            vec![OsString::from("-S"), OsString::from("example")]
        );
    }

    #[test]
    fn refuses_to_persist_temporary_yay_override() {
        let error = sanitize_yay_args(vec![OsString::from("--save")]).unwrap_err();
        assert!(error.to_string().contains("must not be persisted"));
    }
}
