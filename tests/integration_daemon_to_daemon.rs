//! Integration test: two rsticulumd processes communicating over loopback UDP.
//!
//! Tests:
//! 1. Both daemons start and expose their identities via the API
//! 2. Seed peers (register UDP endpoints + identity keys)
//! 3. Daemon A discovers daemon B via announce propagation
//! 4. Daemon A initiates a link to Daemon B, handshake completes
//! 5. Verified: both daemons report link_count >= 1
//! 6. Send data over the established link
//!
//! Self-contained — no external scripts required.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

// ── Port allocation ──

static NEXT_API_PORT: AtomicU16 = AtomicU16::new(19400);

fn allocate_ports() -> (u16, u16, u16) {
    let base = NEXT_API_PORT.fetch_add(3, Ordering::Relaxed);
    (base, base + 1, base + 2) // (api_a, api_b, udp_base)
}

// ── Config helpers ──

fn create_daemon_config(dir: &str, udp_port: u16, api_port: u16) -> String {
    std::fs::create_dir_all(dir).expect("create daemon config dir");
    let key_file = format!("{dir}/identity.key");
    let config = format!(
        "[identity]\n\
         key_file = \"{key_file}\"\n\n\
         [[interfaces]]\n\
         type = \"udp\"\n\
         bind = \"127.0.0.1:{udp_port}\"\n\
         name = \"d2d-test-udp\"\n\n\
         [api]\n\
         bind = \"127.0.0.1:{api_port}\"\n"
    );
    let config_path = format!("{dir}/daemon.toml");
    std::fs::write(&config_path, &config).expect("write daemon config");
    config_path
}

// ── Daemon process handle ──

struct DaemonHandle {
    child: Child,
    identity: String,
    key_file: String,
    udp_port: u16,
}

impl DaemonHandle {
    fn identity_from_stdout(child: &mut Child) -> String {
        let stdout = child.stdout.as_mut().expect("daemon stdout");
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);

        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => panic!("daemon stdout closed before Identity line"),
                Ok(_) => {
                    eprint!("[daemon] {line}");
                    if line.contains("Identity:") {
                        let parts: Vec<&str> = line.split("Identity:").collect();
                        if parts.len() >= 2 {
                            return parts[1].trim().trim_matches('"').to_string();
                        }
                    }
                }
                Err(_) => {
                    if std::time::Instant::now() > deadline {
                        panic!("timeout waiting for daemon Identity");
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            if std::time::Instant::now() > deadline {
                panic!("timeout waiting for daemon Identity (15s)");
            }
        }
    }

    fn spawn(config_path: &str, udp_port: u16, key_file: String) -> Self {
        let binary = std::env::current_dir()
            .expect("get cwd")
            .join("target")
            .join("debug")
            .join("rsticulumd");

        let mut child = Command::new(&binary)
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn rsticulumd");

        let identity = Self::identity_from_stdout(&mut child);
        eprintln!("Daemon spawned: udp={udp_port}, identity={identity}");
        Self { child, identity, key_file, udp_port }
    }
    /// Read the signing key file and return the hex-encoded Ed25519 public key (identity key).
    fn signing_key_hex(&self) -> String {
        let content = std::fs::read_to_string(&self.key_file)
            .expect("read identity key file");
        let trimmed = content.trim();
        assert_eq!(trimmed.len(), 128, "key file should be 128 hex chars (64 bytes)");
        let bytes = hex::decode(trimmed).expect("valid hex in key file");
        // bytes[..32] = signing_secret (Ed25519 seed)
        // bytes[32..64] = encryption_secret (X25519 static secret)
        // Derive the public verifying key from the seed
        use ed25519_dalek::{SigningKey, VerifyingKey};
        let secret = SigningKey::from_bytes(&bytes[..32].try_into().unwrap());
        let verifying = VerifyingKey::from(&secret);
        hex::encode(verifying.to_bytes())
    }
}

// ── API session helper — keeps a persistent TCP connection open ──

struct ApiSession {
    stream: TcpStream,
}

impl ApiSession {
    async fn connect(api_port: u16) -> Self {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            match TcpStream::connect(format!("127.0.0.1:{api_port}")).await {
                Ok(s) => {
                    s.set_nodelay(true).ok();
                    return Self { stream: s };
                }
                Err(_) if std::time::Instant::now() < deadline => {
                    sleep(Duration::from_millis(200)).await;
                }
                Err(e) => panic!("Could not connect to daemon API after 15s: {e}"),
            }
        }
    }

    async fn cmd(&mut self, cmd: &str) -> serde_json::Value {
        // Write command + newline
        let mut buf = cmd.as_bytes().to_vec();
        buf.push(b'\n');
        self.stream.writable().await.unwrap();
        self.stream.try_write(&buf).unwrap();

        // Read response: read until newline, up to 8KB
        let mut resp = Vec::new();
        let mut single = [0u8; 1];
        loop {
            self.stream.readable().await.unwrap();
            match self.stream.try_read(&mut single) {
                Ok(n) if n == 0 => break,
                Ok(_) => {
                    if single[0] == b'\n' {
                        break;
                    }
                    resp.push(single[0]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => panic!("read error: {e}"),
            }
        }
        let resp_str = String::from_utf8(resp).expect("valid UTF-8 from API");
        serde_json::from_str(&resp_str).unwrap_or_else(|e| {
            panic!("JSON parse error: {e} — raw: {resp_str}")
        })
    }
}

// ── The test ──

#[tokio::test(flavor = "multi_thread")]
async fn test_two_daemons_discover_and_link() {
    let (api_a, api_b, udp_base) = allocate_ports();
    let udp_a = udp_base;
    let udp_b = udp_base + 1;
    let tmpdir = format!("/tmp/rsticulum-d2d-{api_a}");
    let dir_a = format!("{tmpdir}/daemon_a");
    let dir_b = format!("{tmpdir}/daemon_b");
    let key_file_a = format!("{dir_a}/identity.key");
    let key_file_b = format!("{dir_b}/identity.key");

    // Build daemon binary
    eprintln!("=== Building rsticulumd ===");
    let build = Command::new("cargo")
        .args(["build", "--package", "rsticulum-daemon", "--bin", "rsticulumd", "-q"])
        .status()
        .expect("cargo build");
    assert!(build.success(), "rsticulumd must build");

    // Create configs
    eprintln!("=== Creating configs ===");
    let cfg_a = create_daemon_config(&dir_a, udp_a, api_a);
    let cfg_b = create_daemon_config(&dir_b, udp_b, api_b);

    // Spawn daemons
    eprintln!("=== Spawning Daemon A (UDP={udp_a}, API={api_a}) ===");
    let mut daemon_a = DaemonHandle::spawn(&cfg_a, udp_a, key_file_a);
    eprintln!("=== Spawning Daemon B (UDP={udp_b}, API={api_b}) ===");
    let mut daemon_b = DaemonHandle::spawn(&cfg_b, udp_b, key_file_b);
    eprintln!("=== Both daemons started ===");

    // Connect API sessions (one persistent TCP connection per daemon)
    eprintln!("=== Connecting to API sockets ===");
    // Brief pause to let daemons finish initializing their API sockets
    sleep(Duration::from_millis(500)).await;
    let mut api_a = ApiSession::connect(api_a).await;
    let mut api_b = ApiSession::connect(api_b).await;

    // Verify identities
    let status_a = api_a.cmd(r#"{"cmd": "status"}"#).await;
    let status_b = api_b.cmd(r#"{"cmd": "status"}"#).await;
    assert_eq!(status_a["result"]["address"], daemon_a.identity, "API address A mismatch");
    assert_eq!(status_b["result"]["address"], daemon_b.identity, "API address B mismatch");
    eprintln!("✓ Daemon A identity: {}", daemon_a.identity);
    eprintln!("✓ Daemon B identity: {}", daemon_b.identity);

    // Seed peers
    eprintln!("=== Seeding peers ===");
    let key_a = daemon_a.signing_key_hex();
    let key_b = daemon_b.signing_key_hex();
    let endpoint_a = format!("127.0.0.1:{udp_a}");
    let endpoint_b = format!("127.0.0.1:{udp_b}");

    let seed_a_cmd = format!(
        r#"{{"cmd": "seed_peer", "dest": "{}", "key": "{}", "endpoint": "{}"}}"#,
        daemon_b.identity, key_b, endpoint_b
    );
    let seed_resp = api_a.cmd(&seed_a_cmd).await;
    eprintln!("Seed A→B: {seed_resp}");
    assert!(seed_resp["ok"].as_bool().unwrap_or(false), "seed_peer A→B failed: {seed_resp}");

    let seed_b_cmd = format!(
        r#"{{"cmd": "seed_peer", "dest": "{}", "key": "{}", "endpoint": "{}"}}"#,
        daemon_a.identity, key_a, endpoint_a
    );
    let seed_resp = api_b.cmd(&seed_b_cmd).await;
    eprintln!("Seed B→A: {seed_resp}");
    assert!(seed_resp["ok"].as_bool().unwrap_or(false), "seed_peer B→A failed: {seed_resp}");
    eprintln!("✓ Peers seeded");

    // Wait for announce propagation
    eprintln!("=== Waiting for announce propagation (3s) ===");
    sleep(Duration::from_secs(3)).await;

    // Check peer discovery
    eprintln!("=== Checking peer discovery ===");
    let mut peer_a = 0u64;
    let mut peer_b = 0u64;
    for i in 0..30 {
        let s_a = api_a.cmd(r#"{"cmd": "status"}"#).await;
        let s_b = api_b.cmd(r#"{"cmd": "status"}"#).await;
        peer_a = s_a["result"]["peer_count"].as_u64().unwrap_or(0);
        peer_b = s_b["result"]["peer_count"].as_u64().unwrap_or(0);
        eprintln!("  check {i}: A peers={peer_a}, B peers={peer_b}");
        if peer_a >= 1 && peer_b >= 1 {
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }

    assert!(peer_a >= 1, "Daemon A should see >= 1 peer, got {peer_a}");
    assert!(peer_b >= 1, "Daemon B should see >= 1 peer, got {peer_b}");
    eprintln!("✓ Peer discovery confirmed: A={peer_a}, B={peer_b}");

    // Initiate link from A to B
    eprintln!("=== Initiating link: A → B ===");
    let connect_cmd = format!(r#"{{"cmd": "connect", "dest": "{}"}}"#, daemon_b.identity);
    let connect_resp = api_a.cmd(&connect_cmd).await;
    eprintln!("Connect: {connect_resp}");
    assert!(
        connect_resp["ok"].as_bool().unwrap_or(false)
            || connect_resp["result"].as_str() == Some("connecting"),
        "Connect failed: {connect_resp}"
    );

    // Wait for link handshake
    eprintln!("=== Waiting for link handshake (15s) ===");
    let mut link_a = 0u64;
    let mut link_b = 0u64;
    for i in 0..30 {
        sleep(Duration::from_millis(500)).await;
        let s_a = api_a.cmd(r#"{"cmd": "status"}"#).await;
        let s_b = api_b.cmd(r#"{"cmd": "status"}"#).await;
        link_a = s_a["result"]["link_count"].as_u64().unwrap_or(0);
        link_b = s_b["result"]["link_count"].as_u64().unwrap_or(0);
        eprintln!("  check {i}: A links={link_a}, B links={link_b}");
        if link_a >= 1 && link_b >= 1 {
            break;
        }
    }

    assert!(link_a >= 1, "Daemon A should have >= 1 link, got {link_a}");
    assert!(link_b >= 1, "Daemon B should have >= 1 link, got {link_b}");
    eprintln!("✓ Link established! A={link_a}, B={link_b}");

    // Send data over the link
    eprintln!("=== Sending data over link A → B ===");
    let send_cmd = format!(
        r#"{{"cmd": "send", "dest": "{}", "data": "{}"}}"#,
        daemon_b.identity,
        hex::encode(b"hello from rsticulum!")
    );
    let send_resp = api_a.cmd(&send_cmd).await;
    eprintln!("Send: {send_resp}");
    assert!(send_resp["ok"].as_bool().unwrap_or(false), "Send failed: {send_resp}");

    eprintln!("=== D2D TEST PASSED ===");

    // Cleanup
    let _ = daemon_a.child.kill();
    let _ = daemon_b.child.kill();
    let _ = daemon_a.child.wait();
    let _ = daemon_b.child.wait();
    let _ = std::fs::remove_dir_all(&tmpdir);
    eprintln!("Cleanup complete. Temp dir {tmpdir} removed.");
}
