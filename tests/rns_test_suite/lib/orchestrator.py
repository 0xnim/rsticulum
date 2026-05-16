"""Node lifecycle management: Python RNS multi-node test orchestration.

Each Python RNS node runs in a separate subprocess with a custom config
that uses TCP interfaces on loopback for deterministic peer wiring.

Rust rsticulum nodes run as daemon subprocesses.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from .topology import Topology, TopologyNode, generate_configdir


class RnsNode:
    """A Python RNS node running in a subprocess with custom loopback config."""

    def __init__(self, name: str, configdir: Optional[Path], transport: bool):
        self.name = name
        self.configdir = configdir
        self.transport = transport
        self._process: Optional[subprocess.Popen] = None
        self._hexhash: Optional[str] = None
        self._hash: Optional[bytes] = None
        self._lock = threading.Lock()

    def start(self) -> "RnsNode":
        runner = Path(__file__).parent / "node_runner.py"

        args = [sys.executable, str(runner)]
        if self.configdir is not None:
            args.append(str(self.configdir))

        self._process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        # Read the ready response
        resp = self._send_recv_raw(timeout=30)
        self._hexhash = resp["hexhash"]
        self._hash = bytes.fromhex(resp["hash_hex"])
        return self

    def identity_hash(self) -> bytes:
        assert self._hash is not None, "Node not started"
        return self._hash

    def hexhash(self) -> str:
        assert self._hexhash is not None, "Node not started"
        return self._hexhash

    def announce(self, app_name: str = "test_harness") -> dict:
        return self._send_recv({"op": "announce", "app_name": app_name})

    def has_path(self, target_hash: bytes) -> bool:
        resp = self._send_recv({"op": "has_path", "target": target_hash.hex()})
        return resp.get("result", False)

    def send_data(self, target_hash: bytes, data: bytes) -> dict:
        return self._send_recv({
            "op": "send_data",
            "target": target_hash.hex(),
            "data_hex": data.hex(),
        })

    def initiate_link(self, target_hash: bytes, link_name: str = "test_link") -> dict:
        return self._send_recv({
            "op": "initiate_link",
            "target": target_hash.hex(),
            "link_name": link_name,
        })

    def send_over_link(self, data: bytes) -> dict:
        return self._send_recv({"op": "send_over_link", "data_hex": data.hex()})

    def recv_poll(self) -> list[bytes]:
        resp = self._send_recv({"op": "recv_poll"})
        return [bytes.fromhex(h) for h in resp.get("messages", [])]

    def announce_table_size(self) -> int:
        resp = self._send_recv({"op": "announce_table_size"})
        return resp.get("count", 0)

    def stop(self) -> None:
        if self._process:
            try:
                self._send_recv({"op": "stop"}, timeout=3)
            except (BrokenPipeError, TimeoutError, OSError):
                pass
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

    def _send_recv(self, cmd: dict, timeout: float = 30.0) -> dict:
        return self._send_recv_raw(timeout, cmd)

    def _send_recv_raw(self, timeout: float = 30.0, cmd: dict | None = None) -> dict:
        assert self._process is not None, "Node not started"
        assert self._process.stdin is not None
        with self._lock:
            if cmd is not None:
                line = json.dumps(cmd) + "\n"
                try:
                    self._process.stdin.write(line)
                    self._process.stdin.flush()
                except (BrokenPipeError, OSError) as e:
                    rc = self._process.poll()
                    raise RuntimeError(
                        f"Node {self.name} process dead (rc={rc}) "
                        f"during send of {cmd.get('op', '?')}"
                    ) from e

            stdout = self._process.stdout
            assert stdout is not None
            deadline = time.time() + timeout
            while time.time() < deadline:
                resp_line = stdout.readline()
                if resp_line:
                    try:
                        return json.loads(resp_line.strip())
                    except json.JSONDecodeError:
                        continue
                if self._process.poll() is not None:
                    raise RuntimeError(f"Node {self.name} exited early (rc={self._process.returncode})")
                time.sleep(0.02)

            raise TimeoutError(f"Node {self.name}: no response in {timeout}s")

    def __repr__(self) -> str:
        h = self._hexhash[:16] if self._hexhash else "?"
        return f"RnsNode({self.name}, {h})"


class RsticulumNode:
    """A Rust rsticulum daemon subprocess."""

    def __init__(self, name: str, listen_port: int, peers: list[tuple[str, int]]):
        self.name = name
        self.listen_port = listen_port
        self.peers = peers
        self._process: Optional[subprocess.Popen] = None
        self._identity_hash: Optional[str] = None

    def start(self) -> "RsticulumNode":
        workspace = Path(__file__).parent.parent.parent.parent
        subprocess.run(
            ["cargo", "build", "--package", "rsticulum-daemon", "--bin", "rsticulumd"],
            cwd=workspace, check=True, capture_output=True,
        )

        binary = workspace / "target" / "debug" / "rsticulumd"
        configdir = Path("/tmp") / f"rsticulum-test-{self.name}"
        configdir.mkdir(parents=True, exist_ok=True)
        key_file = configdir / "identity.key"
        (configdir / "daemon.toml").write_text(
            "[identity]\n"
            f'key_file = "{key_file}"\n'
            "\n"
            "[[interfaces]]\n"
            'type = "udp"\n'
            f'bind = "127.0.0.1:{self.listen_port}"\n'
            'name = "test"\n'
        )

        self._process = subprocess.Popen(
            [str(binary), str(configdir / "daemon.toml")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

        deadline = time.time() + 15
        while time.time() < deadline:
            stdout = self._process.stdout
            if stdout is None:
                raise RuntimeError("stdout is None")
            line = stdout.readline()
            if not line:
                if self._process.poll() is not None:
                    stderr = self._process.stderr
                    err = stderr.read() if stderr else ""
                    raise RuntimeError(f"rsticulumd exited: {err[:500]}")
                time.sleep(0.1)
                continue
            if "Identity:" in line:
                self._identity_hash = line.split("Identity:")[-1].strip().strip('"')
                break
        if self._identity_hash is None:
            raise TimeoutError("rsticulumd did not print Identity: line")
        return self

    def identity_hash(self) -> str:
        assert self._identity_hash is not None, "Node not started"
        return self._identity_hash

    def stop(self) -> None:
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

    def __repr__(self) -> str:
        h = self._identity_hash[:16] if self._identity_hash else "?"
        return f"RsticulumNode({self.name}, {h})"


class Orchestrator:
    """Manages the lifecycle of all nodes in a topology."""

    def __init__(self, topology_path: str, work_dir: Path):
        self.topology = Topology.load(topology_path)
        self.work_dir = work_dir
        self.nodes: dict[str, RnsNode | RsticulumNode] = {}

    def setup(self) -> "Orchestrator":
        """Instantiate all nodes (does not start them).

        Python nodes use the default RNS config (connects to live relays).
        This is the production test path — nodes discover each other through
        the live Reticulum network.
        """
        for tn in self.topology.nodes:
            if tn.type == "python-rns":
                # Use default config — no custom configdir needed
                node = RnsNode(tn.name, None, tn.transport)
                self.nodes[tn.name] = node
            elif tn.type == "rust-rsticulum":
                listen_port = tn.listen_port or 6001
                peer_list = []
                for p_name in tn.peers:
                    p_node = next(n for n in self.topology.nodes if n.name == p_name)
                    p_port = p_node.listen_port or p_node.server_port or 0
                    peer_list.append((p_name, p_port))
                node = RsticulumNode(tn.name, listen_port, peer_list)
                self.nodes[tn.name] = node
        return self

    def start_all(self) -> "Orchestrator":
        """Start all nodes. Python first (start servers), then Rust."""
        for node in self.nodes.values():
            if isinstance(node, RnsNode):
                node.start()
        # Brief pause for TCP servers to start
        time.sleep(0.5)
        for node in self.nodes.values():
            if isinstance(node, RsticulumNode):
                node.start()
        return self

    def wait_for_discovery(self, timeout: float = 30.0) -> None:
        """Wait for announces to propagate across the topology."""
        python_nodes = [n for n in self.nodes.values() if isinstance(n, RnsNode)]
        if len(python_nodes) <= 1:
            return

        expected = len(self.nodes) - 1
        deadline = time.time() + timeout
        while time.time() < deadline:
            all_ready = True
            for node in python_nodes:
                if node.announce_table_size() < expected:
                    all_ready = False
                    break
            if all_ready:
                return
            time.sleep(0.5)

        for node in python_nodes:
            print(
                f"  {node.name}: {node.announce_table_size()}/{expected}",
                file=sys.stderr,
            )

    def stop_all(self) -> None:
        for node in self.nodes.values():
            node.stop()

    def get(self, name: str) -> RnsNode | RsticulumNode:
        return self.nodes[name]
