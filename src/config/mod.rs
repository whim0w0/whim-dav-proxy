use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootConfig {
    #[serde(default)]
    pub log: LogSettings,
    pub backends: Vec<BackendConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSettings {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "json".into()
}

impl Default for LogSettings {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub name: String,
    pub listen: ListenConfig,
    pub webdav_host: WebdavHostConfig,
    #[serde(default)]
    pub encryption: Option<EncryptionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebdavHostConfig {
    pub url: String,
    #[serde(default)]
    pub insecure_skip_verify: bool,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub enable: bool,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_enc_type")]
    pub enc_type: String,
    #[serde(default)]
    pub enc_name: bool,
    #[serde(default)]
    pub enc_suffix: Option<String>,
}

fn default_enc_type() -> String {
    "aesctr".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    #[serde(default = "default_buffer_kb")]
    pub buffer_kb: usize,
    #[serde(default = "default_cb_threshold")]
    pub circuit_breaker_threshold: usize,
    #[serde(default = "default_cb_cooldown")]
    pub circuit_breaker_cooldown_secs: u64,
    #[serde(default = "default_retry")]
    pub retry_max_attempts: usize,
    #[serde(default = "default_max_streams")]
    pub max_active_streams: usize,
}

fn default_buffer_kb() -> usize {
    512
}
fn default_cb_threshold() -> usize {
    5
}
fn default_cb_cooldown() -> u64 {
    30
}
fn default_retry() -> usize {
    2
}
fn default_max_streams() -> usize {
    32
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            buffer_kb: default_buffer_kb(),
            circuit_breaker_threshold: default_cb_threshold(),
            circuit_breaker_cooldown_secs: default_cb_cooldown(),
            retry_max_attempts: default_retry(),
            max_active_streams: default_max_streams(),
        }
    }
}

impl WebdavHostConfig {
    pub fn basic_auth_header(&self) -> Option<String> {
        let username: &str = self.username.as_deref()?;
        let password: &str = self.password.as_deref()?;
        let auth: String = format!("{}:{}", username, password);
        let encoded: String =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, auth.as_bytes());
        Some(format!("Basic {}", encoded))
    }

    pub fn path_prefix(&self) -> String {
        let parsed: url::Url = match url::Url::parse(&self.url) {
            Ok(u) => u,
            Err(_) => return String::new(),
        };
        let path: &str = parsed.path();
        path.trim_end_matches('/').to_string()
    }
}

static VALID_ENC_TYPES: &[&str] = &[
    "aesctr",
    "chacha20",
    "aesgcm",
    "chacha20poly1305",
    "chacha20-poly1305",
    "aesgcmsiv",
    "aes-gcm-siv",
];

impl RootConfig {
    pub fn load(path: &str) -> Result<Self, String> {
        let data: Vec<u8> = std::fs::read(path)
            .map_err(|e: std::io::Error| format!("failed to read config {}: {}", path, e))?;
        let cfg: Self = serde_yaml::from_slice(&data)
            .map_err(|e: serde_yaml::Error| format!("failed to parse config {}: {}", path, e))?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut errs: Vec<String> = Vec::new();

        if self.backends.is_empty() {
            errs.push("at least one backend is required".into());
        }

        let mut seen_ports: std::collections::HashMap<u16, &str> = std::collections::HashMap::new();
        for be in &self.backends {
            if be.name.is_empty() {
                errs.push("backend name is required".into());
            }
            if be.listen.port == 0 {
                errs.push(format!(
                    "backend {:?}: listen.port must be between 1 and 65535",
                    be.name
                ));
            } else if let Some(other) = seen_ports.get(&be.listen.port) {
                errs.push(format!(
                    "backend {:?}: port {} conflicts with backend {:?}",
                    be.name, be.listen.port, other
                ));
            } else {
                seen_ports.insert(be.listen.port, &be.name);
            }

            if be.webdav_host.url.is_empty() {
                errs.push(format!(
                    "backend {:?}: webdav_host.url is required",
                    be.name
                ));
            }

            if let Some(ref enc) = be.encryption {
                if enc.enable {
                    if enc.password.is_empty() {
                        errs.push(format!(
                            "backend {:?}: encryption.password is required when enabled",
                            be.name
                        ));
                    }
                    if !enc.enc_type.is_empty() && !VALID_ENC_TYPES.contains(&enc.enc_type.as_str())
                    {
                        errs.push(format!(
                            "backend {:?}: encryption.enc_type must be one of aesctr, \
                             chacha20, aesgcm, chacha20poly1305, aesgcmsiv",
                            be.name
                        ));
                    }
                }
            }
        }

        if errs.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "configuration validation failed:\n  - {}",
                errs.join("\n  - ")
            ))
        }
    }
}