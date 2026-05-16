#!/usr/bin/env python3
"""
Helper script to generate a minimal RNS config directory for testing.

Creates <config_dir>/.rns/config with a loopback UDP interface only.
"""

import os
import sys


def make_rns_config(config_dir: str, port: int = 4250) -> str:
    """
    Create a minimal RNS config directory at config_dir.

    Args:
        config_dir: Parent directory where .rns/ will be created.
        port: UDP listen/forward port. Default 4250.

    Returns:
        The port number used (as string, for caller convenience).
    """
    rns_dir = os.path.join(config_dir, ".rns")
    os.makedirs(rns_dir, exist_ok=True)

    config_path = os.path.join(rns_dir, "config")

    config_content = f"""[logging]
loglevel = 3

[reticulum]
shared_instance = no

[interfaces]
  [[UDPInterface]]
    type = UDPInterface
    enabled = yes
    listen_port = {port}
    forward_port = {port}
"""

    with open(config_path, "w") as f:
        f.write(config_content)

    return str(port)


def main():
    if len(sys.argv) < 2:
        print("Usage: make_rns_config.py <config_dir> [port]", file=sys.stderr)
        sys.exit(1)

    config_dir = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4250

    used_port = make_rns_config(config_dir, port)
    print(used_port)


if __name__ == "__main__":
    main()
