#!/usr/bin/env python3
"""RNS test node — subprocess runner for multi-node test harness.

Each node:
  1. Loads Reticulum from the given configdir
  2. Creates an identity + destination
  3. Responds to JSON commands over stdin/stdout

Usage: node_runner.py [configdir]

If configdir is provided, uses that directory's config file.
Otherwise uses the default RNS config.
"""

import json
import os
import sys
import time

# Suppress RNS log messages on stdout
os.environ["RNS_LOGLEVEL"] = "3"

import RNS  # noqa: E402


def send_resp(data):
    """Write JSON response to stdout (flush ensures delivery)."""
    sys.stdout.write(json.dumps(data) + "\n")
    sys.stdout.flush()


# Start RNS — use provided configdir or default
configdir = sys.argv[1] if len(sys.argv) > 1 else None
if configdir:
    reticulum = RNS.Reticulum(configdir=configdir, loglevel=RNS.LOG_CRITICAL)
else:
    reticulum = RNS.Reticulum(loglevel=RNS.LOG_CRITICAL)
identity = RNS.Identity()

send_resp({"op": "ready", "hexhash": identity.hexhash, "hash_hex": identity.hash.hex()})

dest = None
received: list[bytes] = []
links: list[RNS.Link] = []


def _packet_cb(message, packet):
    received.append(bytes(message.data))


def _link_cb(link):
    links.append(link)


def main():
    global dest

    for line in sys.stdin:
        try:
            cmd = json.loads(line.strip())
        except (json.JSONDecodeError, ValueError):
            continue

        op = cmd.get("op")

        if op == "ping":
            send_resp({"op": "pong"})

        elif op == "identity":
            send_resp({
                "op": "identity",
                "hexhash": identity.hexhash,
                "hash_hex": identity.hash.hex(),
            })

        elif op == "announce":
            dest = RNS.Destination(
                identity,
                RNS.Destination.IN,
                RNS.Destination.SINGLE,
                cmd.get("app_name", "test_harness"),
            )
            dest.announce(app_data=cmd.get("app_data"))
            dest.set_packet_callback(_packet_cb)
            dest.set_link_established_callback(_link_cb)
            send_resp({"op": "announce", "status": "ok"})

        elif op == "has_path":
            target = bytes.fromhex(cmd["target"])
            result = RNS.Transport.has_path(target)
            send_resp({"op": "has_path", "target": cmd["target"], "result": result})

        elif op == "send_data":
            if dest is None:
                send_resp({"op": "send_data", "error": "not announced"})
                continue
            target = bytes.fromhex(cmd["target"])
            data = bytes.fromhex(cmd["data_hex"])
            pkt = RNS.Packet(dest, data)
            pkt.send()
            send_resp({"op": "send_data", "status": "sent"})

        elif op == "initiate_link":
            if dest is None:
                send_resp({"op": "initiate_link", "error": "not announced"})
                continue
            target = bytes.fromhex(cmd["target"])
            link = RNS.Link(dest, target)
            link.identify(cmd.get("link_name", "test_link"))
            deadline = time.time() + 15
            while link.status != RNS.Link.ACTIVE and time.time() < deadline:
                time.sleep(0.1)
            send_resp({
                "op": "initiate_link",
                "status": "ok",
                "link_active": link.status == RNS.Link.ACTIVE,
            })

        elif op == "send_over_link":
            data = bytes.fromhex(cmd["data_hex"])
            if not links:
                send_resp({"op": "send_over_link", "error": "no links"})
                continue
            link = links[-1]
            pkt = RNS.Packet(link, data)
            pkt.pack()
            pkt.send()
            send_resp({"op": "send_over_link", "status": "sent"})

        elif op == "recv_poll":
            msgs = list(received)
            received.clear()
            send_resp({"op": "recv_poll", "messages": [m.hex() for m in msgs]})

        elif op == "announce_table_size":
            send_resp({
                "op": "announce_table_size",
                "count": len(RNS.Transport.announce_table),
            })

        elif op == "stop":
            RNS.Transport.detach_interfaces()
            send_resp({"op": "stop", "status": "ok"})
            break


if __name__ == "__main__":
    main()
