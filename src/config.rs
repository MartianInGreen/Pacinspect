use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::report::Severity;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub api_url: String,
    pub api_key: Option<String>,
    pub model: String,
    pub timeout_seconds: u64,
    pub max_input_bytes: usize,
    pub block_threshold: Severity,
    pub fail_open: bool,
    pub yay_binary: String,
    pub makepkg_binary: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_url: "https://api.openai.com/v1".into(),
            api_key: None,
            model: "gpt-4.1-mini".into(),
            timeout_seconds: 90,
            max_input_bytes: 300_000,
            block_threshold: Severity::Medium,
            fail_open: false,
            yay_binary: "yay".into(),
            makepkg_binary: "makepkg".into(),
        }
    }
}

impl Config {
    pub fn load_file(path: &Path) -> Result<Self> {
        let config = if path.exists() {
            let contents = fs::read_to_string(path)
                .with_context(|| format!("failed to read configuration {}", path.display()))?;
            toml::from_str(&contents)
                .with_context(|| format!("invalid configuration in {}", path.display()))?
        } else {
            Self::default()
        };
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let config_file_exists = path.exists();
        let mut config = Self::load_file(path)?;
        config.apply_environment(config_file_exists);
        config.validate()?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let parent = path
            .parent()
            .context("configuration path has no parent directory")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;

        let serialized =
            toml::to_string_pretty(self).context("failed to serialize configuration")?;
        let temporary = path.with_extension("toml.tmp");
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(serialized.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    pub fn redacted_toml(&self) -> Result<String> {
        let mut copy = self.clone();
        copy.api_key = copy.api_key.as_ref().map(|_| "<redacted>".into());
        toml::to_string_pretty(&copy).context("failed to render configuration")
    }

    pub fn endpoint(&self) -> String {
        let base = self.api_url.trim_end_matches('/');
        if base.ends_with("/chat/completions") {
            base.to_owned()
        } else {
            format!("{base}/chat/completions")
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !(self.api_url.starts_with("https://") || self.api_url.starts_with("http://")) {
            bail!("api_url must start with http:// or https://");
        }
        if self.model.trim().is_empty() {
            bail!("model must not be empty");
        }
        if self.timeout_seconds == 0 {
            bail!("timeout_seconds must be greater than zero");
        }
        if self.max_input_bytes < 16_384 {
            bail!("max_input_bytes must be at least 16384");
        }
        if self.yay_binary.trim().is_empty() || self.makepkg_binary.trim().is_empty() {
            bail!("yay_binary and makepkg_binary must not be empty");
        }
        Ok(())
    }

    fn apply_environment(&mut self, config_file_exists: bool) {
        self.api_url = resolve_api_url(
            std::mem::take(&mut self.api_url),
            config_file_exists,
            env::var("PACINSPECT_API_URL").ok(),
            env::var("OPENAI_BASE_URL").ok(),
        );
        self.api_key = resolve_api_key(
            self.api_key.take(),
            env::var("PACINSPECT_API_KEY").ok(),
            env::var("OPENAI_API_KEY").ok(),
        );
        if let Ok(value) = env::var("PACINSPECT_MODEL") {
            self.model = value;
        }
    }
}

fn resolve_api_url(
    saved: String,
    config_file_exists: bool,
    pacinspect_environment: Option<String>,
    openai_environment: Option<String>,
) -> String {
    pacinspect_environment
        .or_else(|| {
            (!config_file_exists)
                .then_some(openai_environment)
                .flatten()
        })
        .unwrap_or(saved)
}

fn resolve_api_key(
    saved: Option<String>,
    pacinspect_environment: Option<String>,
    openai_environment: Option<String>,
) -> Option<String> {
    pacinspect_environment.or(saved).or(openai_environment)
}

pub fn default_path() -> Result<PathBuf> {
    ProjectDirs::from("", "", "pacinspect")
        .map(|dirs| dirs.config_dir().join("config.toml"))
        .context("could not determine the user configuration directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_private_configuration_and_builds_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let config = Config {
            api_url: "http://127.0.0.1:8080/v1/".into(),
            api_key: Some("secret".into()),
            ..Config::default()
        };

        config.save(&path).unwrap();
        let loaded = Config::load_file(&path).unwrap();
        assert_eq!(
            loaded.endpoint(),
            "http://127.0.0.1:8080/v1/chat/completions"
        );
        assert_eq!(loaded.api_key.as_deref(), Some("secret"));
        assert!(!loaded.redacted_toml().unwrap().contains("secret"));

        #[cfg(unix)]
        {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn saved_key_beats_generic_openai_environment_fallback() {
        assert_eq!(
            resolve_api_key(
                Some("saved".into()),
                None,
                Some("generic-environment".into())
            )
            .as_deref(),
            Some("saved")
        );
        assert_eq!(
            resolve_api_key(
                Some("saved".into()),
                Some("pacinspect-environment".into()),
                Some("generic-environment".into())
            )
            .as_deref(),
            Some("pacinspect-environment")
        );
        assert_eq!(
            resolve_api_key(None, None, Some("generic-environment".into())).as_deref(),
            Some("generic-environment")
        );
    }

    #[test]
    fn saved_url_beats_generic_openai_environment_fallback() {
        assert_eq!(
            resolve_api_url(
                "https://saved.example/v1".into(),
                true,
                None,
                Some("https://generic.example/v1".into())
            ),
            "https://saved.example/v1"
        );
        assert_eq!(
            resolve_api_url(
                "https://saved.example/v1".into(),
                true,
                Some("https://pacinspect.example/v1".into()),
                Some("https://generic.example/v1".into())
            ),
            "https://pacinspect.example/v1"
        );
        assert_eq!(
            resolve_api_url(
                Config::default().api_url,
                false,
                None,
                Some("https://generic.example/v1".into())
            ),
            "https://generic.example/v1"
        );
    }
}
