//! Daemon configuration — TOML format.
//!
//! Example config:
//! ```toml
//! [identity]
//! key_file = "~/.rsticulum/identity.key"
//!
//! [[interfaces]]
//! type = "udp"
//! bind = "0.0.0.0:4242"
//!
//! [icn]
//! cs_max_entries = 10000
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Full daemon configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Identity configuration.
    #[serde(default)]
    pub identity: IdentityConfig,

    /// Network interfaces.
    #[serde(default)]
    pub interfaces: Vec<InterfaceConfig>,

    /// ICN forwarder configuration.
    #[serde(default)]
    pub icn: IcnConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            identity: IdentityConfig::default(),
            interfaces: vec![InterfaceConfig::default()],
            icn: IcnConfig::default(),
        }
    }
}

/// Identity configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Path to the key file. If it doesn't exist, a new keypair is generated.
    #[serde(default = "default_key_file")]
    pub key_file: PathBuf,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        IdentityConfig {
            key_file: default_key_file(),
        }
    }
}

/// Network interface configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// Interface type: "udp", "tcp", "serial"
    #[serde(default = "default_iface_type")]
    pub r#type: String,

    /// Bind address (for UDP/TCP).
    #[serde(default = "default_bind")]
    pub bind: String,

    /// Interface name (for display).
    #[serde(default)]
    pub name: String,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        InterfaceConfig {
            r#type: default_iface_type(),
            bind: default_bind(),
            name: String::new(),
        }
    }
}

/// ICN forwarder configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IcnConfig {
    /// Maximum entries in ContentStore.
    #[serde(default = "default_cs_max")]
    pub cs_max_entries: usize,
}

impl Default for IcnConfig {
    fn default() -> Self {
        IcnConfig {
            cs_max_entries: default_cs_max(),
        }
    }
}

fn default_key_file() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".rsticulum")
        .join("identity.key")
}

fn default_iface_type() -> String {
    "udp".to_string()
}

fn default_bind() -> String {
    "0.0.0.0:4242".to_string()
}

fn default_cs_max() -> usize {
    10000
}

impl Config {
    /// Load config from a TOML file.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let config: Config =
            toml::from_str(&contents).map_err(|e| ConfigError::Parse(e.to_string()))?;
        Ok(config)
    }

    /// Save config to a TOML file.
    pub fn save(&self, path: &std::path::Path) -> Result<(), ConfigError> {
        let contents =
            toml::to_string_pretty(self).map_err(|e| ConfigError::Parse(e.to_string()))?;
        std::fs::write(path, contents).map_err(|e| ConfigError::Io(e.to_string()))?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(String),
    #[error("Parse error: {0}")]
    Parse(String),
}

/// Helper module for home directory.
mod dirs {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(PathBuf::from)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.interfaces.len(), 1);
        assert_eq!(config.interfaces[0].r#type, "udp");
        assert_eq!(config.interfaces[0].bind, "0.0.0.0:4242");
        assert_eq!(config.icn.cs_max_entries, 10000);
    }

    #[test]
    fn test_config_round_trip() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.icn.cs_max_entries, config.icn.cs_max_entries);
    }
}
