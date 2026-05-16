#!/usr/bin/env python3
"""
Helper for running Python RNS nodes for interop tests.

Usage:
    python3 tests/python_rns_helper.py <configdir> <udp_port> <api_port>
    
Starts an RNS node with:
- configdir = unique temp dir
- UDP interface on 127.0.0.1:<udp_port>
- Local API on 127.0.0.1:<api_port>
- Outputs JSON status line to stdout when ready

Expects RNS to be installed: pip install rns
"""

import sys
import os
import json
import time
import threading

def main():
    if len(sys.argv) < 4:
        print(json.dumps({"error": "Usage: python3 python_rns_helper.py <configdir> <udp_port> <api_port>"}))
        sys.exit(1)
    
    configdir = sys.argv[1]
    udp_port = int(sys.argv[2])
    api_port = int(sys.argv[3])
    
    # Configure RNS
    os.environ["RNS_CONFIGDIR"] = configdir
    os.makedirs(configdir, exist_ok=True)
    
    # Write RNS config file with UDP interface
    config_content = (
        "[logging]\n"
        "loglevel = 3\n"
        "\n"
        "[reticulum]\n"
        "shared_instance = no\n"
        "\n"
        "[interfaces]\n"
        "  [[UDPInterface]]\n"
        "    type = UDPInterface\n"
        "    enabled = yes\n"
        "    listen_port = {udp_port}\n"
        "    forward_port = {udp_port}\n"
        "    listen_ip = 127.0.0.1\n"
        "    forward_ip = 127.0.0.1\n"
    ).format(udp_port=udp_port)
    
    config_path = os.path.join(configdir, "config")
    with open(config_path, "w") as f:
        f.write(config_content)
    
    import RNS
    
    # Create RNS instance (will load interfaces from config)
    reticulum = RNS.Reticulum(configdir=configdir)
    
    # Get identity
    identity = RNS.Identity()
    identity_hex = identity.hexhash
    identity_hash = identity.hash.hex()
    
    # Signal readiness
    print(json.dumps({
        "status": "ready",
        "identity_hex": identity_hex,
        "identity_hash": identity_hash,
        "udp_port": udp_port,
        "api_port": api_port,
        "configdir": configdir,
    }))
    sys.stdout.flush()
    
    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
