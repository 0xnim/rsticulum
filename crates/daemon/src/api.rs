//! Local TCP API socket for rsticulum daemon.
//!
//! Listens on 127.0.0.1:37428 (configurable) and accepts JSON-line commands.
//! Each line is a JSON command, each response is a JSON line.

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;

use std::net::SocketAddr;

/// Commands that the API server can send to the daemon.
pub enum ApiCommand {
    /// Express (send) raw data to a destination address.
    Express {
        dest: [u8; 16],
        data: Vec<u8>,
        response: oneshot::Sender<Result<(), String>>,
    },
    /// Publish content to the ICN forwarder.
    Publish {
        name: String,
        data: Vec<u8>,
        response: oneshot::Sender<Result<(), String>>,
    },
    /// Return daemon status info.
    Status {
        response: oneshot::Sender<DaemonStatus>,
    },
    /// Initiate a link to a peer.
    Connect {
        dest: [u8; 16],
        response: oneshot::Sender<Result<(), String>>,
    },
    /// Send data over an established link.
    SendOverLink {
        dest: [u8; 16],
        data: Vec<u8>,
        response: oneshot::Sender<Result<(), String>>,
    },
    /// Send a large resource over an established link.
    SendResource {
        dest: [u8; 16],
        data: Vec<u8>,
        response: oneshot::Sender<Result<(), String>>,
    },
    /// Seed a peer's identity key and UDP endpoint.
    /// Used by tests to bootstrap peer discovery.
    SeedPeer {
        /// 32-hex-char RNS address
        dest: [u8; 16],
        /// 64-hex-char Ed25519 signing key (32 bytes)
        key_hex: String,
        /// UDP endpoint (ip:port) for direct communication
        udp_endpoint: String,
        response: oneshot::Sender<Result<(), String>>,
    },
}

/// Status information returned by the daemon.
#[derive(Clone, Debug, Serialize)]
pub struct DaemonStatus {
    pub address: String,
    pub link_count: usize,
    pub peer_count: usize,
    pub medium_count: usize,
}

/// Run the TCP API server on the given address.
///
/// Spawns a new task per connection. Each connection reads JSON lines
/// and dispatches them as `ApiCommand`s via the provided sender.
pub async fn run_api_server(
    addr: SocketAddr,
    cmd_tx: UnboundedSender<ApiCommand>,
) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("API server listening on {addr}");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("API accept error: {e}");
                continue;
            }
        };

        let cmd_tx = cmd_tx.clone();
        tokio::spawn(async move {
            tracing::debug!("API connection from {peer}");
            if let Err(e) = handle_connection(stream, cmd_tx).await {
                tracing::debug!("API connection {peer} error: {e}");
            }
            tracing::debug!("API connection {peer} closed");
        });
    }
}

/// Handle a single TCP connection: read JSON lines, dispatch commands, write JSON responses.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    cmd_tx: UnboundedSender<ApiCommand>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = buf_reader.read_line(&mut line).await?;
        if n == 0 {
            // Connection closed
            return Ok(());
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse the JSON command
        let request: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let resp = serde_json::json!({"ok": false, "error": format!("Invalid JSON: {e}")});
                let mut buf = serde_json::to_vec(&resp)?;
                buf.push(b'\n');
                writer.write_all(&buf).await?;
                continue;
            }
        };

        let cmd = match request.get("cmd").and_then(|c| c.as_str()) {
            Some(c) => c,
            None => {
                let resp = serde_json::json!({"ok": false, "error": "Missing 'cmd' field"});
                let mut buf = serde_json::to_vec(&resp)?;
                buf.push(b'\n');
                writer.write_all(&buf).await?;
                continue;
            }
        };

        let response = match cmd {
            "express" => handle_express(&request, &cmd_tx).await,
            "publish" => handle_publish(&request, &cmd_tx).await,
            "status" => handle_status(&cmd_tx).await,
            "connect" => handle_connect(&request, &cmd_tx).await,
            "send" => handle_send_over_link(&request, &cmd_tx).await,
            "send_resource" => handle_send_resource(&request, &cmd_tx).await,
            "seed_peer" => handle_seed_peer(&request, &cmd_tx).await,
            other => {
                serde_json::json!({"ok": false, "error": format!("Unknown command: {other}")})
            }
        };

        let mut buf = serde_json::to_vec(&response)?;
        buf.push(b'\n');
        writer.write_all(&buf).await?;
    }
}

async fn handle_express(
    request: &serde_json::Value,
    cmd_tx: &UnboundedSender<ApiCommand>,
) -> serde_json::Value {
    let dest_hex = match request.get("dest").and_then(|d| d.as_str()) {
        Some(h) => h,
        None => return serde_json::json!({"ok": false, "error": "Missing 'dest' field"}),
    };

    let data_hex = match request.get("data").and_then(|d| d.as_str()) {
        Some(h) => h,
        None => return serde_json::json!({"ok": false, "error": "Missing 'data' field"}),
    };

    let dest_bytes = match hex::decode(dest_hex) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::json!({"ok": false, "error": format!("Invalid dest hex: {e}")});
        }
    };

    let dest: [u8; 16] = match dest_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return serde_json::json!({"ok": false, "error": "dest must be 16 bytes (32 hex chars)"});
        }
    };

    let data = match hex::decode(data_hex) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::json!({"ok": false, "error": format!("Invalid data hex: {e}")});
        }
    };

    let (tx, rx) = oneshot::channel();
    if cmd_tx
        .send(ApiCommand::Express {
            dest,
            data,
            response: tx,
        })
        .is_err()
    {
        return serde_json::json!({"ok": false, "error": "Daemon not available"});
    }

    match rx.await {
        Ok(Ok(())) => serde_json::json!({"ok": true, "result": "sent"}),
        Ok(Err(e)) => serde_json::json!({"ok": false, "error": e}),
        Err(_) => serde_json::json!({"ok": false, "error": "Daemon response lost"}),
    }
}

async fn handle_publish(
    request: &serde_json::Value,
    cmd_tx: &UnboundedSender<ApiCommand>,
) -> serde_json::Value {
    let name = match request.get("name").and_then(|n| n.as_str()) {
        Some(n) => n.to_string(),
        None => return serde_json::json!({"ok": false, "error": "Missing 'name' field"}),
    };

    let data_hex = match request.get("data").and_then(|d| d.as_str()) {
        Some(h) => h,
        None => return serde_json::json!({"ok": false, "error": "Missing 'data' field"}),
    };

    let data = match hex::decode(data_hex) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::json!({"ok": false, "error": format!("Invalid data hex: {e}")});
        }
    };

    let (tx, rx) = oneshot::channel();
    if cmd_tx
        .send(ApiCommand::Publish {
            name,
            data,
            response: tx,
        })
        .is_err()
    {
        return serde_json::json!({"ok": false, "error": "Daemon not available"});
    }

    match rx.await {
        Ok(Ok(())) => serde_json::json!({"ok": true, "result": "published"}),
        Ok(Err(e)) => serde_json::json!({"ok": false, "error": e}),
        Err(_) => serde_json::json!({"ok": false, "error": "Daemon response lost"}),
    }
}

async fn handle_status(cmd_tx: &UnboundedSender<ApiCommand>) -> serde_json::Value {
    let (tx, rx) = oneshot::channel();
    if cmd_tx.send(ApiCommand::Status { response: tx }).is_err() {
        return serde_json::json!({"ok": false, "error": "Daemon not available"});
    }

    match rx.await {
        Ok(status) => serde_json::json!({
            "ok": true,
            "result": {
                "address": status.address,
                "link_count": status.link_count,
                "peer_count": status.peer_count,
                "medium_count": status.medium_count,
            }
        }),
        Err(_) => serde_json::json!({"ok": false, "error": "Daemon response lost"}),
    }
}

async fn handle_connect(
    request: &serde_json::Value,
    cmd_tx: &UnboundedSender<ApiCommand>,
) -> serde_json::Value {
    let dest_hex = match request.get("dest").and_then(|d| d.as_str()) {
        Some(h) => h,
        None => return serde_json::json!({"ok": false, "error": "Missing 'dest' field"}),
    };

    let dest_bytes = match hex::decode(dest_hex) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::json!({"ok": false, "error": format!("Invalid dest hex: {e}")});
        }
    };

    let dest: [u8; 16] = match dest_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return serde_json::json!({"ok": false, "error": "dest must be 16 bytes (32 hex chars)"});
        }
    };

    let (tx, rx) = oneshot::channel();
    if cmd_tx
        .send(ApiCommand::Connect {
            dest,
            response: tx,
        })
        .is_err()
    {
        return serde_json::json!({"ok": false, "error": "Daemon not available"});
    }

    match rx.await {
        Ok(Ok(())) => serde_json::json!({"ok": true, "result": "connecting"}),
        Ok(Err(e)) => serde_json::json!({"ok": false, "error": e}),
        Err(_) => serde_json::json!({"ok": false, "error": "Daemon response lost"}),
    }
}

async fn handle_send_over_link(
    request: &serde_json::Value,
    cmd_tx: &UnboundedSender<ApiCommand>,
) -> serde_json::Value {
    let dest_hex = match request.get("dest").and_then(|d| d.as_str()) {
        Some(h) => h,
        None => return serde_json::json!({"ok": false, "error": "Missing 'dest' field"}),
    };

    let data_hex = match request.get("data").and_then(|d| d.as_str()) {
        Some(h) => h,
        None => return serde_json::json!({"ok": false, "error": "Missing 'data' field"}),
    };

    let dest_bytes = match hex::decode(dest_hex) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::json!({"ok": false, "error": format!("Invalid dest hex: {e}")});
        }
    };

    let dest: [u8; 16] = match dest_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return serde_json::json!({"ok": false, "error": "dest must be 16 bytes (32 hex chars)"});
        }
    };

    let data = match hex::decode(data_hex) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::json!({"ok": false, "error": format!("Invalid data hex: {e}")});
        }
    };

    let (tx, rx) = oneshot::channel();
    if cmd_tx
        .send(ApiCommand::SendOverLink {
            dest,
            data,
            response: tx,
        })
        .is_err()
    {
        return serde_json::json!({"ok": false, "error": "Daemon not available"});
    }

    match rx.await {
        Ok(Ok(())) => serde_json::json!({"ok": true, "result": "sent"}),
        Ok(Err(e)) => serde_json::json!({"ok": false, "error": e}),
        Err(_) => serde_json::json!({"ok": false, "error": "Daemon response lost"}),
    }
}

async fn handle_send_resource(
    request: &serde_json::Value,
    cmd_tx: &UnboundedSender<ApiCommand>,
) -> serde_json::Value {
    let dest_hex = match request.get("dest").and_then(|d| d.as_str()) {
        Some(h) => h,
        None => return serde_json::json!({"ok": false, "error": "Missing 'dest' field"}),
    };

    let data_hex = match request.get("data").and_then(|d| d.as_str()) {
        Some(h) => h,
        None => return serde_json::json!({"ok": false, "error": "Missing 'data' field"}),
    };

    let dest_bytes = match hex::decode(dest_hex) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::json!({"ok": false, "error": format!("Invalid dest hex: {e}")});
        }
    };

    let dest: [u8; 16] = match dest_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return serde_json::json!({"ok": false, "error": "dest must be 16 bytes (32 hex chars)"});
        }
    };

    let data = match hex::decode(data_hex) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::json!({"ok": false, "error": format!("Invalid data hex: {e}")});
        }
    };

    let (tx, rx) = oneshot::channel();
    if cmd_tx
        .send(ApiCommand::SendResource {
            dest,
            data,
            response: tx,
        })
        .is_err()
    {
        return serde_json::json!({"ok": false, "error": "Daemon not available"});
    }

    match rx.await {
        Ok(Ok(())) => serde_json::json!({"ok": true, "result": "sent"}),
        Ok(Err(e)) => serde_json::json!({"ok": false, "error": e}),
        Err(_) => serde_json::json!({"ok": false, "error": "Daemon response lost"}),
    }
}

async fn handle_seed_peer(
    request: &serde_json::Value,
    cmd_tx: &UnboundedSender<ApiCommand>,
) -> serde_json::Value {
    let dest_hex = match request.get("dest").and_then(|d| d.as_str()) {
        Some(h) => h,
        None => return serde_json::json!({"ok": false, "error": "Missing 'dest' field"}),
    };
    let key_hex = match request.get("key").and_then(|d| d.as_str()) {
        Some(h) => h.to_string(),
        None => return serde_json::json!({"ok": false, "error": "Missing 'key' field"}),
    };
    let endpoint = match request.get("endpoint").and_then(|d| d.as_str()) {
        Some(h) => h.to_string(),
        None => return serde_json::json!({"ok": false, "error": "Missing 'endpoint' field"}),
    };

    let dest_bytes = match hex::decode(dest_hex) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::json!({"ok": false, "error": format!("Invalid dest hex: {e}")});
        }
    };
    let dest: [u8; 16] = match dest_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return serde_json::json!({"ok": false, "error": "dest must be 16 bytes (32 hex chars)"});
        }
    };

    let (tx, rx) = oneshot::channel();
    if cmd_tx
        .send(ApiCommand::SeedPeer {
            dest,
            key_hex,
            udp_endpoint: endpoint,
            response: tx,
        })
        .is_err()
    {
        return serde_json::json!({"ok": false, "error": "Daemon not available"});
    }

    match rx.await {
        Ok(Ok(())) => serde_json::json!({"ok": true, "result": "peer_seeded"}),
        Ok(Err(e)) => serde_json::json!({"ok": false, "error": e}),
        Err(_) => serde_json::json!({"ok": false, "error": "Daemon response lost"}),
    }
}
