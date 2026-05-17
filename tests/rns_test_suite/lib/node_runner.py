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
import select
import sys
import time

# Suppress RNS log messages on stdout
os.environ["RNS_LOGLEVEL"] = "3"

import RNS  # noqa: E402

# Read Rust daemon UDP port for direct LRPROOF delivery
RUST_UDP_PORT = os.environ.get("RSTICULUM_UDP_PORT")
if RUST_UDP_PORT:
    RUST_UDP_PORT = int(RUST_UDP_PORT)
    # Monkey-patch prove() to send LRPROOF directly to Rust daemon's UDP port
    # (bypasses RNS transport routing, which can't reach the daemon on a different port)
    _orig_prove = RNS.Link.prove
    def _patched_prove(self):
        import socket
        try:
            signalling_bytes = RNS.Link.signalling_bytes(self.mtu, self.mode)
            signed_data = self.link_id + self.pub_bytes + self.sig_pub_bytes + signalling_bytes
            signature = self.owner.identity.sign(signed_data)
            proof_data = signature + self.pub_bytes + signalling_bytes
            proof = RNS.Packet(self, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.LRPROOF)
            proof.pack()
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.sendto(proof.raw, ("127.0.0.1", RUST_UDP_PORT))
            udp_sock.close()
            self.establishment_cost += len(proof.raw)
            self.had_outbound()
        except Exception:
            pass
    RNS.Link.prove = _patched_prove


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
full_pub_key = identity.get_public_key()
ed25519_pub_key = full_pub_key[32:].hex()

send_resp({
    "op": "ready",
    "hexhash": identity.hexhash,
    "hash_hex": identity.hash.hex(),
    "identity_pub_key": ed25519_pub_key,
})

dest = None
received: list[bytes] = []
links: list[RNS.Link] = []


def _packet_cb(message, packet):
    received.append(bytes(message.data))


def _link_cb(link):
    links.append(link)


def process_cmd(cmd):
    global dest
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
        send_resp({"op": "announce", "status": "ok", "dest_hash": dest.hash.hex()})

    elif op == "has_path":
        target = bytes.fromhex(cmd["target"])
        result = RNS.Transport.has_path(target)
        send_resp({"op": "has_path", "target": cmd["target"], "result": result})

    elif op == "send_data":
        if dest is None:
            send_resp({"op": "send_data", "error": "not announced"})
            return
        target = bytes.fromhex(cmd["target"])
        data = bytes.fromhex(cmd["data_hex"])
        pkt = RNS.Packet(dest, data)
        pkt.send()
        send_resp({"op": "send_data", "status": "sent"})

    elif op == "initiate_link":
        if dest is None:
            send_resp({"op": "initiate_link", "error": "not announced"})
            return
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
            return
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
        return True
    return False


def main():
    global dest

    # Use select-based non-blocking stdin so RNS can process
    # incoming packets (LINKREQUEST, etc.) between commands.
    poll = select.poll()
    poll.register(sys.stdin, select.POLLIN)

    running = True
    while running:
        # 100ms timeout allows RNS background threads to process packets
        events = poll.poll(100)
        for fd, _event in events:
            if fd == sys.stdin.fileno():
                line = sys.stdin.readline()
                if not line:
                    running = False
                    break
                try:
                    cmd = json.loads(line.strip())
                    if process_cmd(cmd):
                        running = False
                except (json.JSONDecodeError, ValueError):
                    continue


if __name__ == "__main__":
    main()
