"""Topology definition: YAML loading, validation, and configdir generation."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Optional

import yaml


@dataclasses.dataclass
class TopologyNode:
    name: str
    type: str  # "python-rns" | "rust-rsticulum"
    transport: bool = True
    server_port: Optional[int] = None  # TCPServerInterface listen port (Python only)
    listen_port: Optional[int] = None  # TCP listen port (Rust only)
    peers: list[str] = dataclasses.field(default_factory=list)
    announce_interval: int = 60


@dataclasses.dataclass
class Topology:
    nodes: list[TopologyNode]

    @classmethod
    def load(cls, path: str | Path) -> Topology:
        raw = yaml.safe_load(Path(path).read_text())
        nodes = [TopologyNode(**n) for n in raw["nodes"]]
        topo = cls(nodes=nodes)
        topo.validate()
        return topo

    def validate(self) -> None:
        """Ensure no port collisions and all peer names exist."""
        names = {n.name for n in self.nodes}
        name_list = [n.name for n in self.nodes]
        duplicates = {n for n in names if name_list.count(n) > 1}
        assert not duplicates, f"Duplicate node names: {set(duplicates)}"

        ports: dict[int, str] = {}
        for n in self.nodes:
            p = n.server_port or n.listen_port
            if p and p in ports:
                raise ValueError(
                    f"Port {p} collision: {n.name} and {ports[p]}"
                )
            if p:
                ports[p] = n.name

        for n in self.nodes:
            for peer in n.peers:
                assert peer in names, f"Node {n.name} references unknown peer {peer}"

    def get_python_nodes(self) -> list[TopologyNode]:
        return [n for n in self.nodes if n.type == "python-rns"]

    def get_rust_nodes(self) -> list[TopologyNode]:
        return [n for n in self.nodes if n.type == "rust-rsticulum"]


def generate_configdir(
    node: TopologyNode,
    base_dir: Path,
    all_nodes: list[TopologyNode],
) -> Path:
    """Generate per-node isolated RNS config directory.

    Uses no explicit interfaces — RNS AutoInterface handles discovery
    via UDP broadcast on loopback. Each node gets unique shared_instance
    and instance_control ports for process isolation.
    """
    assert node.type == "python-rns", f"generate_configdir only for python-rns nodes, got {node.type}"

    python_nodes = [n for n in all_nodes if n.type == "python-rns"]
    idx = python_nodes.index(node)

    configdir = base_dir / node.name
    configdir.mkdir(parents=True, exist_ok=True)

    config_lines: list[str] = [
        "[reticulum]",
        f"enable_transport = {'yes' if node.transport else 'no'}",
        "share_instance = yes",
        f"instance_name = {node.name}",
        f"shared_instance_port = {37428 + idx * 10}",
        f"instance_control_port = {37429 + idx * 10}",
        "",
        "[logging]",
        "loglevel = 0",
        "",
    ]

    config_text = "\n".join(config_lines) + "\n"
    config_file = configdir / "config"
    config_file.write_text(config_text)

    return configdir
