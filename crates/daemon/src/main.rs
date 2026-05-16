//! rsticulumd — rsticulum network daemon.
//!
//! Boots the mesh, runs the ICN forwarder, and listens for local API connections.
//!
//! Usage:
//!   rsticulumd                    # start with default config
//!   rsticulumd --config daemon.toml  # start with custom config

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rsticulum_daemon::{config::Config, Daemon};
use rsticulum_identity::Keys;
use rsticulum_mesh::UdpMedium;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load config
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".rsticulum")
                .join("daemon.toml")
        });

    let config = Config::load(&config_path).unwrap_or_else(|e| {
        tracing::warn!(
            "Could not load config from {}: {} — using defaults",
            config_path.display(),
            e
        );
        let default = Config::default();
        // Save default config for next time
        if let Some(parent) = config_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = default.save(&config_path);
        default
    });

    tracing::info!("Config loaded: {config_path:?}");
    tracing::info!(
        "Interfaces: {}",
        config
            .interfaces
            .iter()
            .map(|i| format!("{}:{}", i.r#type, i.bind))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Load or generate identity
    let keys = load_or_generate_keys(&config.identity.key_file);
    tracing::info!("Identity: {}", keys.rns_address());

    // Create daemon
    let mut daemon = Daemon::new(keys);

    // Bind interfaces
    for iface in &config.interfaces {
        match iface.r#type.as_str() {
            "udp" => {
                let bind_addr: SocketAddr = match iface.bind.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!("Invalid bind address '{}': {}", iface.bind, e);
                        continue;
                    }
                };

                let name = if iface.name.is_empty() {
                    format!("udp-{}", iface.bind)
                } else {
                    iface.name.clone()
                };

                match UdpMedium::bind(&name, bind_addr).await {
                    Ok(medium) => {
                        let addr = medium.local_addr().expect("bound socket has an address");
                        tracing::info!("Interface {} bound to {}", name, addr);
                        daemon.add_medium(Arc::new(medium));
                    }
                    Err(e) => {
                        tracing::error!("Failed to bind {}: {}", name, e);
                    }
                }
            }
            other => {
                tracing::warn!("Unknown interface type: {other} — skipping");
            }
        }
    }

    if daemon.media.is_empty() {
        tracing::error!("No interfaces bound — daemon has no network. Exiting.");
        std::process::exit(1);
    }

    // Set up local API socket if configured
    if let Some(api_cfg) = &config.api {
        let bind_addr: std::net::SocketAddr = match api_cfg.bind.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("Invalid API bind address '{}': {}", api_cfg.bind, e);
                std::process::exit(1);
            }
        };

        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        daemon.set_api_channel(cmd_rx);

        tokio::spawn(async move {
            if let Err(e) = rsticulum_daemon::api::run_api_server(bind_addr, cmd_tx).await {
                tracing::error!("API server error: {e}");
            }
        });

        tracing::info!("Local API socket listening on {bind_addr}");
    }

    // Run daemon
    tracing::info!("Daemon running. Press Ctrl+C to stop.");
    if let Err(e) = daemon.run().await {
        tracing::error!("Daemon error: {e}");
        std::process::exit(1);
    }
}

/// Load keys from file or generate new ones and save.
fn load_or_generate_keys(path: &PathBuf) -> Keys {
    if path.exists() {
        match std::fs::read_to_string(path) {
            Ok(hex_str) => {
                let hex_str = hex_str.trim();
                match hex::decode(hex_str) {
                    Ok(bytes) if bytes.len() == 64 => {
                        // 64 bytes = 32 signing + 32 encryption
                        let signing_bytes: [u8; 32] = bytes[..32].try_into().unwrap();
                        let encryption_bytes: [u8; 32] = bytes[32..64].try_into().unwrap();
                        let keys = Keys::from_secrets(signing_bytes, encryption_bytes);
                        tracing::info!("Loaded identity from {}", path.display());
                        return keys;
                    }
                    Ok(_) => {
                        tracing::warn!(
                            "Key file {} has wrong size — generating new identity",
                            path.display()
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to decode key file {}: {} — generating new identity",
                            path.display(),
                            e
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to read key file {}: {} — generating new identity",
                    path.display(),
                    e
                );
            }
        }
    }

    // Generate new keys
    let keys = Keys::generate();
    let signing = keys.signing_secret_bytes();
    let encryption = keys.encryption_secret_bytes();
    let hex_str = hex::encode(&[signing.as_slice(), encryption.as_slice()].concat());

    // Save
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(path, &hex_str) {
        tracing::error!("Failed to save identity to {}: {}", path.display(), e);
    } else {
        tracing::info!("Generated and saved new identity to {}", path.display());
    }

    keys
}

mod dirs {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(PathBuf::from)
            .ok()
    }
}
