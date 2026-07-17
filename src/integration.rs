use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use serde::Deserialize;

use crate::config::Config;
use crate::ui::{ReviewOptions, analyze_bundle, analyze_directories_parallel, review_completed};

pub const SHIM_ENV: &str = "PACINSPECT_MAKEPKG_SHIM";
pub const YAY_PREFLIGHT_MARKER: &str = "--pacinspect-yay-preflight";
const REAL_MAKEPKG_ENV: &str = "PACINSPECT_REAL_MAKEPKG";
const RUN_DIR_ENV: &str = "PACINSPECT_RUN_DIR";
const CONFIG_ENV: &str = "PACINSPECT_CONFIG";

pub fn is_makepkg_shim() -> bool {
    env::var_os(SHIM_ENV).is_some()
}

pub fn is_yay_preflight() -> bool {
    env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == OsStr::new(YAY_PREFLIGHT_MARKER))
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
        .arg("--editmenu")
        .arg("--answeredit")
        .arg("All")
        .arg("--editor")
        .arg(&current_exe)
        .arg("--editorflags")
        .arg(YAY_PREFLIGHT_MARKER)
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

pub fn run_yay_preflight(config: &Config, file_args: Vec<OsString>) -> Result<i32> {
    let run_dir = inspection_run_directory()?;
    fs::create_dir_all(&run_dir)?;
    let directories = preflight_directories(file_args)?;
    let completed = analyze_directories_parallel(&directories, config);
    let options = review_options();
    let mut blocked = false;

    for (directory, completed) in directories.iter().zip(completed) {
        match completed {
            Ok(completed) => {
                let attempted_hash = completed.content_hash.clone();
                let outcome = with_review_lock(&run_dir, || {
                    eprintln!("pacinspect: reviewing {}", directory.display());
                    review_completed(completed, config, &options)
                });
                match outcome {
                    Ok(outcome) if outcome.approved => {
                        write_approval(&run_dir, &outcome.content_hash, b"approved\n")?;
                    }
                    Ok(_) => blocked = true,
                    Err(error) if config.fail_open => {
                        print_serialized_warning(
                            &run_dir,
                            format!(
                                "inspection failed for {} but fail_open is enabled: {error:#}",
                                directory.display()
                            ),
                        )?;
                        write_approval(&run_dir, &attempted_hash, b"fail-open\n")?;
                    }
                    Err(error) => {
                        print_serialized_warning(
                            &run_dir,
                            format!(
                                "blocked because inspection failed for {}: {error:#}",
                                directory.display()
                            ),
                        )?;
                        blocked = true;
                    }
                }
            }
            Err(error) if config.fail_open => {
                print_serialized_warning(
                    &run_dir,
                    format!(
                        "inspection failed for {} but fail_open is enabled: {error:#}",
                        directory.display()
                    ),
                )?;
                if let Ok(bundle) = crate::inspect::collect(directory, config.max_input_bytes) {
                    write_approval(&run_dir, &bundle.content_hash, b"fail-open\n")?;
                }
            }
            Err(error) => {
                print_serialized_warning(
                    &run_dir,
                    format!(
                        "blocked because inspection failed for {}: {error:#}",
                        directory.display()
                    ),
                )?;
                blocked = true;
            }
        }
    }

    if blocked {
        with_review_lock(&run_dir, || {
            eprintln!("pacinspect: transaction blocked before yay handed code to makepkg");
            Ok(())
        })?;
        return Ok(125);
    }
    Ok(0)
}

pub fn run_makepkg_shim(config: &Config, args: Vec<OsString>) -> Result<i32> {
    let makepkg = env::var(REAL_MAKEPKG_ENV).context("missing real makepkg command")?;
    let run_dir = inspection_run_directory()?;
    fs::create_dir_all(&run_dir)?;

    let root = env::current_dir().context("failed to determine makepkg working directory")?;
    let bundle = crate::inspect::collect(&root, config.max_input_bytes)?;
    let content_hash = bundle.content_hash.clone();
    let hash_lock = open_lock(&run_dir.join(format!("{content_hash}.lock")))?;
    hash_lock
        .lock_exclusive()
        .context("failed to suppress a duplicate package review")?;

    let marker = approval_marker(&run_dir, &content_hash);
    let approved = if marker.is_file() {
        true
    } else {
        let review = analyze_bundle(root.clone(), bundle, config).and_then(|completed| {
            with_review_lock(&run_dir, || {
                review_completed(completed, config, &review_options())
            })
        });
        match review {
            Ok(outcome) if outcome.approved => {
                write_approval(&run_dir, &outcome.content_hash, b"approved\n")?;
                true
            }
            Ok(_) => false,
            Err(error) if config.fail_open => {
                print_serialized_warning(
                    &run_dir,
                    format!("inspection failed but fail_open is enabled: {error:#}"),
                )?;
                write_approval(&run_dir, &content_hash, b"fail-open\n")?;
                true
            }
            Err(error) => {
                print_serialized_warning(
                    &run_dir,
                    format!("blocked because inspection failed: {error:#}"),
                )?;
                false
            }
        }
    };
    FileExt::unlock(&hash_lock)?;

    if !approved {
        with_review_lock(&run_dir, || {
            eprintln!("pacinspect: build blocked; no PKGBUILD code was handed to makepkg");
            Ok(())
        })?;
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

fn inspection_run_directory() -> Result<PathBuf> {
    env::var_os(RUN_DIR_ENV)
        .map(PathBuf::from)
        .context("missing inspection run directory")
}

fn review_options() -> ReviewOptions {
    ReviewOptions {
        json: false,
        non_interactive: !std::io::stdin().is_terminal(),
        accept_risk: false,
        quiet: false,
    }
}

fn preflight_directories(file_args: Vec<OsString>) -> Result<Vec<PathBuf>> {
    if file_args.is_empty() {
        bail!("yay did not pass any packaging files to its editor hook");
    }
    let mut directories = BTreeSet::new();
    for argument in file_args {
        let file = PathBuf::from(argument);
        let parent = file
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let directory = parent
            .canonicalize()
            .with_context(|| format!("failed to resolve editor path {}", file.display()))?;
        if !directory.join("PKGBUILD").is_file() {
            bail!(
                "yay editor path {} belongs to {}, which has no PKGBUILD",
                file.display(),
                directory.display()
            );
        }
        directories.insert(directory);
    }
    Ok(directories.into_iter().collect())
}

fn open_lock(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open review lock {}", path.display()))
}

fn with_review_lock<T>(run_dir: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    let lock = open_lock(&run_dir.join("review.lock"))?;
    lock.lock_exclusive()
        .context("failed to serialize package review output")?;
    let result = action();
    FileExt::unlock(&lock).context("failed to release package review output lock")?;
    result
}

fn print_serialized_warning(run_dir: &Path, warning: String) -> Result<()> {
    with_review_lock(run_dir, || {
        eprintln!("pacinspect: WARNING: {warning}");
        Ok(())
    })
}

fn write_approval(run_dir: &Path, content_hash: &str, value: &[u8]) -> Result<()> {
    fs::write(approval_marker(run_dir, content_hash), value)
        .with_context(|| format!("failed to record approval for content hash {content_hash}"))
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
        if matches!(text.as_ref(), "--editor" | "--editorflags" | "--answeredit") {
            let option = text.into_owned();
            iter.next()
                .with_context(|| format!("{option} requires a value"))?;
            continue;
        }
        if matches!(text.as_ref(), "--editmenu" | "--noeditmenu")
            || text.starts_with("--editor=")
            || text.starts_with("--editorflags=")
            || text.starts_with("--answeredit=")
            || text.starts_with("--editmenu=")
            || text.starts_with("--noeditmenu=")
        {
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
    fn strips_arguments_that_conflict_with_the_reserved_editor_hook() {
        let arguments = vec![
            OsString::from("-S"),
            OsString::from("--editor"),
            OsString::from("vim"),
            OsString::from("--editorflags=--clean"),
            OsString::from("--editmenu"),
            OsString::from("--noeditmenu"),
            OsString::from("--answeredit"),
            OsString::from("None"),
            OsString::from("example"),
        ];

        let (forwarded, makepkg) = sanitize_yay_args(arguments).unwrap();

        assert_eq!(makepkg, None);
        assert_eq!(
            forwarded,
            vec![OsString::from("-S"), OsString::from("example")]
        );
    }

    #[test]
    fn deduplicates_and_sorts_preflight_package_directories() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("a-package");
        let second = temporary.path().join("b-package");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("PKGBUILD"), b"pkgname=a\n").unwrap();
        fs::write(first.join("a.install"), b"post_install() { :; }\n").unwrap();
        fs::write(second.join("PKGBUILD"), b"pkgname=b\n").unwrap();

        let directories = preflight_directories(vec![
            second.join("PKGBUILD").into_os_string(),
            first.join("a.install").into_os_string(),
            first.join("PKGBUILD").into_os_string(),
        ])
        .unwrap();

        assert_eq!(
            directories,
            vec![
                first.canonicalize().unwrap(),
                second.canonicalize().unwrap()
            ]
        );
    }

    #[test]
    fn refuses_to_persist_temporary_yay_override() {
        let error = sanitize_yay_args(vec![OsString::from("--save")]).unwrap_err();
        assert!(error.to_string().contains("must not be persisted"));
    }
}
