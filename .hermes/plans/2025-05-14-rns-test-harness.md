# RNS Multi-Node Test Harness — Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** A config-driven test harness that spins up N Python RNS nodes + 0..M Rust rsticulum nodes, wires them into a controlled topology, and verifies interop at packet, link, and resource layers.

**Architecture:** Python control plane (RNS imports needed to manipulate Python nodes). YAML topology definitions. Per-node isolated config dirs with TCP interfaces for deterministic peer wiring. Rust node connects via TCP medium. pytest scenarios exercise: announce propagation, path discovery, link establishment, resource transfer, and rsticulum interop.

**Tech Stack:** Python 3.12+ (RNS 1.2.6, pytest, PyYAML), Rust (rsticulum crates, tokio), macOS (Unix domain sockets for per-node shared instance isolation).

---

## Background: How RNS isolates multiple nodes on one machine

Each RNS node is a separate `RNS.Reticulum(configdir=…)` instance. Isolation comes from:

1. **Different configdir** → separate `config`, `storage/`, `interfaces/`
2. **Different `shared_instance_port` / `instance_control_port`** → no port collision
3. **TCP interfaces for topology** → TCPServerInterface listens on a unique port; TCPClientInterface connects to specific peers

Per-node config skeleton:
```ini
[reticulum]
enable_transport = yes
share_instance = yes
instance_name = node-<N>
shared_instance_port = <37428 + N>
instance_control_port = <37429 + N>

[interfaces]
  [[Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = <5000 + N>

  # One [[Client]] per peer
  [[Peer-X]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = <peer's server port>
```

The Rust `rsticulum-mesh` crate has `TcpMedium` (or uses `UdpMedium`). We'll extend it with TCP medium support for the harness.

---

## Phase 1: Harness Foundation

### Task 1.1: Create harness directory structure

**Files:**
- Create: `tests/rns_test_suite/__init__.py` (empty)
- Create: `tests/rns_test_suite/.gitignore` (ignore `nodes/`)
- Create: `tests/rns_test_suite/conftest.py` (pytest fixtures — initially empty)

### Task 1.2: Topology config format

**Files:**
- Create: `tests/rns_test_suite/configs/` directory
- Create: `tests/rns_test_suite/lib/__init__.py`
- Create: `tests/rns_test_suite/lib/topology.py`

**YAML schema:**
```yaml
# configs/mesh_3_python.yaml
nodes:
  - name: alpha
    type: python-rns
    transport: yes         # enable_transport
    server_port: 5001
    peers: [beta]          # client connections
    announce_interval: 60  # seconds

  - name: beta
    type: python-rns
    transport: yes
    server_port: 5002
    peers: [alpha, gamma]

  - name: gamma
    type: python-rns
    transport: yes
    server_port: 5003
    peers: [beta]
```

**Code (`lib/topology.py`):**
- `class TopologyNode` — dataclass holding parsed YAML
- `class Topology` — loads YAML, validates node names/ports don't collide
- `generate_configdir(node: TopologyNode, base_dir: Path, all_nodes: list[TopologyNode]) -> Path` — writes per-node `config` file and returns the configdir path

**Step 1: Write `test_topology_loads`** — verify YAML parsing produces correct TopologyNode objects
**Step 2: Write `test_generate_configdir`** — verify generated config file has correct ports, peers, interface stanzas
**Step 3: Commit**

### Task 1.3: Node orchestrator

**Files:**
- Create: `tests/rns_test_suite/lib/orchestrator.py`

**Code:**
```python
class RnsNode:
    """A running Python RNS node process."""
    def __init__(self, name: str, configdir: Path, transport: bool):
        self.name = name
        self.configdir = configdir
        self._reticulum = None
        self._identity = None
        self._hash = None

    def start(self):
        """Initialize RNS.Reticulum with this node's configdir."""
        self._reticulum = RNS.Reticulum(configdir=str(self.configdir), loglevel=RNS.LOG_WARNING)
        self._identity = RNS.Identity()
        self._hash = self._identity.hash
        return self

    def identity_hash(self) -> bytes:
        return self._hash

    def hexhash(self) -> str:
        return self._identity.hexhash

    def stop(self):
        """Tear down RNS gracefully."""
        RNS.Transport.detach_interfaces()  # or equivalent
        # RNS doesn't have a clean teardown API — just let GC handle it
```

```python
class Orchestrator:
    """Manages the lifecycle of all nodes in a topology."""
    def __init__(self, topology_path: str, work_dir: Path):
        self.topology = Topology.load(topology_path)
        self.work_dir = work_dir
        self.nodes: dict[str, RnsNode] = {}

    def setup(self):
        """Generate config dirs, instantiate all nodes."""
        for tn in self.topology.nodes:
            configdir = generate_configdir(tn, self.work_dir / "nodes", self.topology.nodes)
            node = RnsNode(tn.name, configdir, tn.transport)
            self.nodes[tn.name] = node

    def start_all(self):
        """Start all nodes."""
        for node in self.nodes.values():
            node.start()

    def wait_for_discovery(self, timeout: int = 30):
        """Poll until announces have propagated across the topology."""
        ...

    def stop_all(self):
        for node in self.nodes.values():
            node.stop()
```

**Step 1: Write `test_orchestrator_setup_creates_dirs`** — verify orchestrator.setup() creates config dirs for all nodes
**Step 2: Write `test_orchestrator_start_all`** — start nodes, verify each has an identity, no exceptions
**Step 3: Commit**

### Task 1.4: Message requester utility

**Files:**
- Create: `tests/rns_test_suite/lib/requester.py`

A helper Python RNS instance (separate configdir) that can reach into the mesh and:
- Announce a destination
- Send DATA packets to any node by hash
- Create links
- Receive packets on a destination

```python
class Requester:
    """Utility RNS instance for sending test traffic into the mesh."""
    def __init__(self, target_node: RnsNode):
        # Connect to target node's shared instance
        ...

    def announce(self, app_name: str = "test_harness"):
        ...

    def send_data(self, dest_hash: bytes, data: bytes):
        ...

    def send_link_request(self, dest_hash: bytes):
        ...

    def recv_data(self, timeout: float = 5.0) -> bytes | None:
        ...
```

**Step 1: Write `test_requester_send_recv`** — same-node send/receive via shared instance
**Step 2: Commit**

---

## Phase 2: Python-Only Mesh Scenarios

### Task 2.1: 3-node mesh announce propagation

**Files:**
- Create: `tests/rns_test_suite/scenarios/__init__.py`
- Create: `tests/rns_test_suite/scenarios/test_announce_propagation.py`

**Test:**
1. Spin up 3-node mesh (alpha—beta—gamma)
2. Alpha announces a destination
3. Wait for propagation timeout
4. Verify beta and gamma have the announce in their path table

**Step 1: Write the test function**
**Step 2: Run it, fix any transport/announce timing issues**
**Step 3: Commit**

### Task 2.2: 3-node mesh path discovery

**Files:**
- Modify: `tests/rns_test_suite/scenarios/test_announce_propagation.py` (or new file)

**Test:**
1. Alpha announces, beta and gamma have path
2. Alpha sends DATA to gamma
3. Verify gamma receives the packet
4. Verify the path was: alpha→beta→gamma (beta forwarded)

**Step 1: Write test**
**Step 2: Run, fix**
**Step 3: Commit**

### Task 2.3: Link establishment between two nodes

**Files:**
- Create: `tests/rns_test_suite/scenarios/test_link_establishment.py`

**Test:**
1. Alpha and beta with direct TCP connection
2. Alpha initiates link to beta
3. Handshake completes
4. Verify both sides show link established
5. Send encrypted data over the link, verify receipt

**Step 1: Write test**
**Step 2: Run, fix any link handshake issues**
**Step 3: Commit**

### Task 2.4: Resource transfer

**Files:**
- Create: `tests/rns_test_suite/scenarios/test_resource_transfer.py`

**Test:**
1. Alpha announces a resource destination
2. Beta fetches the resource (multi-segment)
3. Verify all segments received, checksums match

**Step 1: Write test**
**Step 2: Run, fix**
**Step 3: Commit**

---

## Phase 3: Rust (rsticulum) Interop

### Task 3.1: Add TcpMedium to rsticulum-mesh

**Files:**
- Modify: `crates/mesh/src/lib.rs` (or new file `tcp.rs`)

rsticulum already has `UdpMedium`. We need `TcpMedium` for interop with Python RNS `TCPInterface`.

```rust
pub struct TcpMedium {
    // Connect to a TCPServerInterface as client
    // or listen as server for Python TCPClientInterfaces
}
```

**Step 1: Add `tcp.rs` with TcpMedium that implements the `Medium` trait**
**Step 2: Write unit test `tcp_medium_roundtrip`** — two TcpMedium instances, send/receive
**Step 3: Run `cargo test -p rsticulum-mesh`**
**Step 4: Commit**

### Task 3.2: Hybrid topology YAML — 2 Python + 1 Rust

**Files:**
- Create: `tests/rns_test_suite/configs/hybrid_2_py_1_rs.yaml`

```yaml
nodes:
  - name: py-alpha
    type: python-rns
    transport: yes
    server_port: 5001
    peers: [py-beta]

  - name: py-beta
    type: python-rns
    transport: yes
    server_port: 5002
    peers: [py-alpha, rs-gamma]

  - name: rs-gamma
    type: rust-rsticulum
    transport: yes
    listen_port: 6001
    peers: [py-beta]
```

### Task 3.3: Rust node manager in orchestrator

**Files:**
- Modify: `tests/rns_test_suite/lib/orchestrator.py`

Add `RsticulumNode` class that:
1. Builds rsticulum test binary (or uses `cargo run` for a daemon binary)
2. Spawns it as a subprocess
3. Exposes identity hash for the topology

```python
class RsticulumNode(Node):
    def __init__(self, name: str, config: dict):
        ...
    def start(self):
        # Launch rsticulum daemon subprocess
        ...
    def identity_hash(self) -> bytes:
        # Read identity from rsticulum's output or a known file
        ...
```

**Step 1: Implement RsticulumNode**
**Step 2: Write `test_rust_node_starts_and_gets_hash`**
**Step 3: Commit**

### Task 3.4: Interop test — Rust packet send/receive

**Files:**
- Create: `tests/rns_test_suite/scenarios/test_rsticulum_interop.py`

**Test:**
1. Spin up hybrid topology: py-alpha — py-beta — rs-gamma
2. rs-gamma (Rust) sends a DATA packet to py-alpha
3. Verify py-alpha receives it, bytes match
4. py-alpha sends DATA packet to rs-gamma
5. Verify rs-gamma receives it

**Note:** This requires the rsticulum daemon to support basic send/receive, which may need to be stubbed or built as part of this task.

**Step 1: Write test**
**Step 2: Run, iterate on Rust daemon as needed**
**Step 3: Commit**

### Task 3.5: Interop test — Link establishment across Rust ↔ Python

**Files:**
- Extend: `tests/rns_test_suite/scenarios/test_rsticulum_interop.py`

**Test:**
1. Rust node announces, Python node discovers
2. Rust initiates link to Python (link request + proof handshake)
3. Verify both sides show link established
4. Exchange encrypted data

**Step 1: Write test**
**Step 2: Run, fix any proof format / handshake issues**
**Step 3: Commit**

---

## Phase 4: Config-Driven Parameter Sweeps (future)

### Task 4.1: Parameterized topology generator

**Files:**
- Modify: `tests/rns_test_suite/lib/topology.py`

Generate topologies programmatically:
- `ring(n)` — N-node ring
- `star(n)` — N-node star (central + leaves)
- `mesh(n)` — fully connected N-node mesh
- `line(n)` — N-node line (chain)

### Task 4.2: Scenario runner with matrix parameters

**Files:**
- Modify: `tests/rns_test_suite/conftest.py`

```python
@pytest.fixture(params=["mesh_3_python", "hybrid_2_py_1_rs", "ring_4_python"])
def topology_name(request):
    return request.param
```

Each scenario test parameterized over multiple topologies.

---

## File Summary

| File | Purpose |
|------|---------|
| `tests/rns_test_suite/__init__.py` | Package marker |
| `tests/rns_test_suite/.gitignore` | Ignore `nodes/` |
| `tests/rns_test_suite/conftest.py` | pytest fixtures |
| `tests/rns_test_suite/lib/__init__.py` | Package marker |
| `tests/rns_test_suite/lib/topology.py` | YAML loading, config dir generation |
| `tests/rns_test_suite/lib/orchestrator.py` | Node lifecycle management |
| `tests/rns_test_suite/lib/requester.py` | RNS test traffic utility |
| `tests/rns_test_suite/configs/mesh_3_python.yaml` | 3-node Python mesh topology |
| `tests/rns_test_suite/configs/hybrid_2_py_1_rs.yaml` | 2 Python + 1 Rust topology |
| `tests/rns_test_suite/scenarios/test_announce_propagation.py` | Announce propagation tests |
| `tests/rns_test_suite/scenarios/test_link_establishment.py` | Link handshake tests |
| `tests/rns_test_suite/scenarios/test_resource_transfer.py` | Resource transfer tests |
| `tests/rns_test_suite/scenarios/test_rsticulum_interop.py` | Rust ↔ Python interop tests |
| `crates/mesh/src/tcp.rs` | TcpMedium for interop with Python TCPInterface |

## Execution Order

```
Phase 1 → Phase 2 → Phase 3 → Phase 4

Phase 1:  tasks 1.1, 1.2, 1.3, 1.4  (serial)
Phase 2:  tasks 2.1, 2.2, 2.3, 2.4  (serial)
Phase 3:  tasks 3.1, 3.2, 3.3, 3.4, 3.5  (serial)
Phase 4:  tasks 4.1, 4.2  (serial, after everything works)
```

## Verification

After Phase 2: `pytest tests/rns_test_suite/scenarios/ -v` — all Python mesh scenarios pass
After Phase 3: `pytest tests/rns_test_suite/scenarios/ -v` — all tests including hybrid interop pass
After Phase 4: `pytest tests/rns_test_suite/scenarios/ -v --topology all` — all topologies pass

## Pitfalls

- **Port collisions**: Each node needs unique `shared_instance_port`, `instance_control_port`, and server port. The topology validator must catch collisions.
- **Announce timing**: RNS announce propagation is asynchronous. Tests need `wait_for_discovery()` with generous timeouts (30s+).
- **Clean teardown**: RNS has no `Reticulum.shutdown()` API. Each test must use fresh instances. Linux `SO_REUSEADDR` helps, but macOS may hold ports briefly.
- **Shared instance complexity**: On macOS with domain sockets, `instance_name` isolation works. On Linux without domain sockets, port-based isolation is needed.
- **Rust daemon**: Phase 3 requires the rsticulum daemon crate to have a minimal working binary. If it's still a stub, we may need to build a test-only binary first.
