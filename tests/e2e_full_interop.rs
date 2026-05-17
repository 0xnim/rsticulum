//! End-to-end cross-validation test: rsticulum ↔ Python RNS interop.
//!
//! Tests the full protocol stack:
//! 1. Start a Python RNS node
//! 2. Start an rsticulum daemon
//! 3. Seed peers (exchange identity keys)
//! 4. Initiate LINKREQUEST from Rust → Python
//! 5. Verify link established
//! 6. Send encrypted data over the link
//!
//! Requires: Python 3, RNS installed (pip install rns)

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::sleep;

static NEXT_PORT: AtomicU16 = AtomicU16::new(19500);

fn allocate_ports() -> (u16, u16, u16) {
    let base = NEXT_PORT.fetch_add(3, Ordering::Relaxed);
    (base, base + 1, base + 2)
}

/// Check if Python 3 with RNS is available on the system.
fn python_rns_available() -> bool {
    Command::new("python3")
        .args(["-c", "import RNS; print('ok')"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_rust_to_python_link() {
    if !python_rns_available() {
        eprintln!("SKIP: Python 3 + RNS not available on this system");
        return;
    }

    let base_port = allocate_ports();
    let api_port = base_port.0;
    let udp_port = base_port.1;
    let rust_port = base_port.2;
    let rust_api_port = api_port + 10;

    let configdir = format!("/tmp/rsticulum-interop-{api_port}");
    let _ = std::fs::remove_dir_all(&configdir);

    // ── Start Python RNS node ──
    let mut python = Command::new("python3")
        .args([
            "tests/python_rns_helper.py",
            &format!("{configdir}/python"),
            &udp_port.to_string(),
            &api_port.to_string(),
            &rust_port.to_string(),  // forward outbound packets to Rust daemon's port
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start Python RNS node");

    // Drain Python stderr in background
    let mut py_stderr = python.stderr.take().unwrap();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = [0u8; 4096];
        while let Ok(n) = py_stderr.read(&mut buf) {
            if n == 0 { break; }
            eprintln!("[python] {}", String::from_utf8_lossy(&buf[..n]).trim());
        }
    });

    // Read identity from Python stdout
    let python_info = read_python_identity(python.stdout.as_mut().unwrap());
    let python_identity = &python_info["identity_hash"];
    let python_pub_key = &python_info["identity_pub_key"];
    let python_dest_hash = &python_info["dest_hash"];
    eprintln!("Python RNS identity: {python_identity}");
    eprintln!("Python RNS pub key: {python_pub_key}");
    eprintln!("Python RNS dest hash: {python_dest_hash}");

    // Give Python time to initialize and announce
    sleep(Duration::from_secs(2)).await;

    // Build (quiet) and start rsticulum daemon
    let rust_dir = format!("{configdir}/rust");
    std::fs::create_dir_all(&rust_dir).unwrap();
    let key_file = format!("{rust_dir}/identity.key");

    // Pre-generate a known identity so we don't need to read it from the daemon
    let rust_keys = rsticulum_identity::Keys::generate();
    let signing_secret = rust_keys.signing_secret_bytes();
    let encryption_secret = rust_keys.encryption_secret_bytes();
    let key_hex = hex::encode(
        &[signing_secret.as_slice(), encryption_secret.as_slice()].concat()
    );
    std::fs::write(&key_file, &key_hex).unwrap();
    let rust_identity = rust_keys.rns_address();
    eprintln!("[test] Rust pre-generated identity: {rust_identity}");

    let config = format!(
        "[identity]\nkey_file = \"{key_file}\"\n\n\
         [[interfaces]]\ntype = \"udp\"\nbind = \"127.0.0.1:{rust_port}\"\nname = \"interop-udp\"\n\n\
         [api]\nbind = \"127.0.0.1:{rust_api_port}\"\n"
    );
    eprintln!("[test] API port: {api_port}, UDP port: {udp_port}, Rust port: {rust_port}, Rust API port: {rust_api_port}");
    eprintln!("[test] configfile: {rust_dir}/daemon.toml");
    eprintln!("[test] keyfile: {key_file}");
    std::fs::write(format!("{rust_dir}/daemon.toml"), &config).unwrap();

    eprintln!("[test] spawning rsticulumd...");
    // Ensure daemon binary is built
    let build = Command::new("cargo")
        .args(["build", "--package", "rsticulum-daemon", "--bin", "rsticulumd", "-q"])
        .status()
        .expect("cargo build failed");
    assert!(build.success(), "rsticulumd must build successfully");

    let mut rust_daemon = Command::new("target/debug/rsticulumd")
        .args([&format!("{rust_dir}/daemon.toml")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rsticulumd");
    eprintln!("[test] rsticulumd spawned, pid={}", rust_daemon.id());

    // Spawn background threads to drain daemon stdout and stderr
    let mut daemon_stdout = rust_daemon.stdout.take().unwrap();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = [0u8; 4096];
        while let Ok(n) = daemon_stdout.read(&mut buf) {
            if n == 0 { break; }
            eprintln!("[daemon:stdout] {}", String::from_utf8_lossy(&buf[..n]).trim());
        }
    });
    let mut daemon_stderr = rust_daemon.stderr.take().unwrap();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = [0u8; 4096];
        loop {
            match daemon_stderr.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    eprintln!("[daemon] {}", String::from_utf8_lossy(&buf[..n]).trim());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    eprintln!("[daemon-stderr-read-error] {e}");
                    break;
                }
            }
        }
    });

    eprintln!("Rust rsticulum identity: {rust_identity}");

    // Connect to Rust API
    sleep(Duration::from_millis(500)).await;
    let mut rust_api = ApiSession::connect(rust_api_port).await;

    // Check initial status
    let status = rust_api.cmd(r#"{"cmd": "status"}"#).await;
    eprintln!("Rust daemon status: {status}");

    // ── Seed Python peer into Rust daemon ──
    let seed_cmd = format!(
        r#"{{"cmd": "seed_peer", "dest": "{}", "key": "{}", "endpoint": "127.0.0.1:{}"}}"#,
        python_identity, python_pub_key, udp_port,
    );
    let seed_result = rust_api.cmd(&seed_cmd).await;
    eprintln!("Seed result: {seed_result}");
    assert_eq!(seed_result["ok"], true, "seed_peer should succeed");

    // ── Initiate link from Rust → Python ──
    let connect_cmd = format!(
        r#"{{"cmd": "connect", "dest": "{}", "dest_hash": "{}"}}"#,
        python_identity, python_dest_hash,
    );
    let connect_result = rust_api.cmd(&connect_cmd).await;
    eprintln!("Connect result: {connect_result}");

    // ── Wait for link establishment ──
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut link_established = false;
    loop {
        if std::time::Instant::now() > deadline {
            break;
        }
        let status = rust_api.cmd(r#"{"cmd": "status"}"#).await;
        let link_count = status["result"]["link_count"].as_u64().unwrap_or(0);
        eprintln!("  link_count={link_count} at {:?}", std::time::Instant::now());
        if link_count > 0 {
            link_established = true;
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }

    assert!(link_established, "Link should be established within 10s");

    // ── Send data over the link ──
    let send_cmd = format!(
        r#"{{"cmd": "send", "dest": "{}", "data": "{}"}}"#,
        python_identity,
        hex::encode(b"Hello from Rust!"),
    );
    let send_result = rust_api.cmd(&send_cmd).await;
    eprintln!("Send result: {send_result}");

    eprintln!("=== INTEROP TEST PASSED (link established + data sent) ===");

    // Cleanup
    let _ = rust_daemon.kill();
    let _ = rust_daemon.wait();
    let _ = python.kill();
    let _ = python.wait();
    let _ = std::fs::remove_dir_all(&configdir);
}

// ── Helpers ──

/// Read Python identity JSON from stdout. Returns a map of fields.
fn read_python_identity(stdout: &mut impl std::io::Read) -> std::collections::HashMap<String, String> {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => panic!("Python stdout closed"),
            Ok(_) => {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                    if val["status"] == "ready" {
                        let mut map = std::collections::HashMap::new();
                        if let Some(h) = val["identity_hash"].as_str() {
                            map.insert("identity_hash".to_string(), h.to_string());
                        }
                        if let Some(k) = val["identity_pub_key"].as_str() {
                            map.insert("identity_pub_key".to_string(), k.to_string());
                        }
                        if let Some(d) = val["dest_hash"].as_str() {
                            map.insert("dest_hash".to_string(), d.to_string());
                        }
                        return map;
                    }
                }
            }
            Err(_) => {
                if std::time::Instant::now() > deadline {
                    panic!("timeout reading Python identity");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

// ── Helpers (API) ──

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
        let mut buf = cmd.as_bytes().to_vec();
        buf.push(b'\n');
        self.stream.writable().await.unwrap();
        self.stream.try_write(&buf).unwrap();

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
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("read error: {e}"),
            }
        }
        let resp_str = String::from_utf8(resp).expect("valid UTF-8 from API");
        serde_json::from_str(&resp_str).unwrap_or_else(|e| {
            panic!("JSON parse error: {e} — raw: {resp_str}")
        })
    }
}