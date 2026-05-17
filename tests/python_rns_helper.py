#!/usr/bin/env python3
"""
Helper for running Python RNS nodes for interop tests.

Usage:
    python3 tests/python_rns_helper.py <configdir> <udp_port> <api_port> [rust_udp_port]

Starts an RNS node with:
- configdir = unique temp dir
- UDP interface on 127.0.0.1:<udp_port>
- Registers a destination and announces it
- Outputs JSON status line to stdout when ready

Optional 4th argument rust_udp_port: if provided, the helper forwards
outbound packets to 127.0.0.1:<rust_udp_port> so the Rust daemon can
receive link proofs and data back.
"""

import sys
import os
import json
import time
import threading

def main():
    import sys
    print("DEBUG: python helper starting", file=sys.stderr, flush=True)
    if len(sys.argv) < 4:
        print(json.dumps({"error": "Usage: python3 python_rns_helper.py <configdir> <udp_port> <api_port> [rust_udp_port]"}))
        sys.exit(1)
    
    configdir = sys.argv[1]
    udp_port = int(sys.argv[2])
    api_port = int(sys.argv[3])
    rust_udp_port = int(sys.argv[4]) if len(sys.argv) > 4 else None
    
    # Configure RNS
    os.environ["RNS_CONFIGDIR"] = configdir
    os.makedirs(configdir, exist_ok=True)
    
    # Write RNS config file with UDP interface
    if rust_udp_port:
        # Forward outbound packets to the Rust daemon's port
        config_content = (
            "[logging]\n"
            "loglevel = 5\n"
            "\n"
            "[reticulum]\n"
            "shared_instance = no\n"
            "enable_transport = Yes\n"
            "\n"
            "[interfaces]\n"
            "  [[UDPInterface]]\n"
            "    type = UDPInterface\n"
            "    enabled = yes\n"
            "    listen_port = {udp_port}\n"
            "    listen_ip = 127.0.0.1\n"
            "    forward_port = {rust_udp_port}\n"
            "    forward_ip = 127.0.0.1\n"
        ).format(udp_port=udp_port, rust_udp_port=rust_udp_port)
    else:
        # No forwarding — LRPROOF can't reach Rust daemon if ports differ
        config_content = (
            "[logging]\n"
            "loglevel = 5\n"
            "\n"
            "[reticulum]\n"
            "shared_instance = no\n"
            "enable_transport = Yes\n"
            "\n"
            "[interfaces]\n"
            "  [[UDPInterface]]\n"
            "    type = UDPInterface\n"
            "    enabled = yes\n"
            "    listen_port = {udp_port}\n"
            "    listen_ip = 127.0.0.1\n"
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
    # Ed25519 public key (32 bytes, hex) — second half of full 64-byte key
    full_pub_key = identity.get_public_key()
    ed25519_pub_key = full_pub_key[32:].hex()
    
    # Register a destination that accepts incoming link requests
    dest = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "rsticulum",
        "interop",
    )
    dest_hash = dest.hash.hex()

    dest.set_link_established_callback(lambda link: print(json.dumps({
        "event": "link_established",
        "remote": link.remote_identity.hash.hex(),
    })))
    
    dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
    
    # Add debug logging for received packets
    orig_receive = dest.receive
    def debug_receive(packet):
        import sys
        print(f"DEBUG: destination received packet type={packet.packet_type}", file=sys.stderr, flush=True)
        return orig_receive(packet)
    dest.receive = debug_receive
    
    # Monkey-patch validate_request for debug
    LinkClass = RNS.Link
    orig_validate = LinkClass.__dict__['validate_request']
    def debug_validate(owner, data, packet):
        import sys
        print(f"DEBUG: validate_request called len={len(data)} ECPUBSIZE={LinkClass.ECPUBSIZE} LINK_MTU_SIZE={LinkClass.LINK_MTU_SIZE}", file=sys.stderr, flush=True)
        try:
            result = orig_validate(owner, data, packet)
            if result:
                print(f"DEBUG: validate_request SUCCESS link_id={result.link_id.hex()}", file=sys.stderr, flush=True)
            else:
                print(f"DEBUG: validate_request returned None (orig caught exception)", file=sys.stderr, flush=True)
            return result
        except Exception as e:
            print(f"DEBUG: validate_request WRAPPER EXCEPTION: {e}", file=sys.stderr, flush=True)
            import traceback
            traceback.print_exc(file=sys.stderr)
            return None
    
    # Wrap the internal validate_request to catch exceptions
    import functools
    @functools.wraps(LinkClass.validate_request)
    def debug_validate_inner(owner, data, packet):
        import sys
        try:
            if len(data) != LinkClass.ECPUBSIZE and len(data) != LinkClass.ECPUBSIZE + LinkClass.LINK_MTU_SIZE:
                print(f"DEBUG: validate FAIL length check {len(data)} vs {LinkClass.ECPUBSIZE}+{LinkClass.LINK_MTU_SIZE}", file=sys.stderr, flush=True)
                return None
            
            link = LinkClass(owner=owner, peer_pub_bytes=data[:LinkClass.ECPUBSIZE//2], peer_sig_pub_bytes=data[LinkClass.ECPUBSIZE//2:LinkClass.ECPUBSIZE])
            link.set_link_id(packet)
            print(f"DEBUG: validate after set_link_id, link_id={link.link_id.hex() if link.link_id else 'None'}", file=sys.stderr, flush=True)
            
            if len(data) == LinkClass.ECPUBSIZE + LinkClass.LINK_MTU_SIZE:
                try:
                    link.mtu = LinkClass.mtu_from_lr_packet(packet) or RNS.Reticulum.MTU
                except Exception as e:
                    link.mtu = RNS.Reticulum.MTU

            link.mode = LinkClass.mode_from_lr_packet(packet)
            link.update_mdu()
            link.destination = packet.destination
            link.establishment_timeout = LinkClass.ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, packet.hops) + LinkClass.KEEPALIVE
            link.establishment_cost += len(packet.raw)
            
            print(f"DEBUG: validate calling handshake...", file=sys.stderr, flush=True)
            link.handshake()
            link.attached_interface = packet.receiving_interface
            
            print(f"DEBUG: validate calling prove...", file=sys.stderr, flush=True)
            link.prove()
            print(f"DEBUG: validate prove completed, calling register_link...", file=sys.stderr, flush=True)
            
            link.request_time = time.time()
            RNS.Transport.register_link(link)
            link.last_inbound = time.time()
            
            print(f"DEBUG: validate calling update_phy_stats...", file=sys.stderr, flush=True)
            try:
                link._Link__update_phy_stats(packet, force_update=True)
            except Exception as e:
                print(f"DEBUG: update_phy_stats failed (non-fatal): {e}", file=sys.stderr, flush=True)
            link.start_watchdog()
            
            print(f"DEBUG: validate SUCCESS returning link", file=sys.stderr, flush=True)
            RNS.log("Incoming link request "+str(link)+" accepted on "+str(link.attached_interface), RNS.LOG_DEBUG)
            return link
            
        except Exception as e:
            print(f"DEBUG: validate EXCEPTION at line: {e}", file=sys.stderr, flush=True)
            import traceback
            traceback.print_exc(file=sys.stderr)
            return None
    
    LinkClass.validate_request = staticmethod(debug_validate_inner)
    
    # Monkey-patch prove to send LRPROOF directly to Rust daemon's UDP port
    # Instead of relying on RNS Transport (which sends via UDPInterface forwarding
    # that may not work across different ports)
    orig_prove = LinkClass.prove
    def debug_prove(self):
        import sys, socket, struct
        print(f"DEBUG: prove() called link_id={self.link_id.hex() if self.link_id else 'None'}", file=sys.stderr, flush=True)
        try:
            # Generate the proof data as RNS normally would
            signalling_bytes = LinkClass.signalling_bytes(self.mtu, self.mode)
            signed_data = self.link_id + self.pub_bytes + self.sig_pub_bytes + signalling_bytes
            signature = self.owner.identity.sign(signed_data)
            proof_data = signature + self.pub_bytes + signalling_bytes
            
            # Create the packed packet manually
            proof = RNS.Packet(self, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.LRPROOF)
            proof.pack()
            
            # Send directly via UDP to Rust daemon
            if rust_udp_port:
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sock.sendto(proof.raw, ("127.0.0.1", rust_udp_port))
                udp_sock.close()
                print(f"DEBUG: LRPROOF sent directly to 127.0.0.1:{rust_udp_port} ({len(proof.raw)} bytes)", file=sys.stderr, flush=True)
            
            self.establishment_cost += len(proof.raw)
            self.had_outbound()
            print(f"DEBUG: prove() completed", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"DEBUG: prove() EXCEPTION: {e}", file=sys.stderr, flush=True)
            import traceback
            traceback.print_exc(file=sys.stderr)
            raise
    LinkClass.prove = debug_prove

    # Announce this destination periodically
    dest.announce()

    # Signal readiness (includes public key for peer seeding)
    print(json.dumps({
        "status": "ready",
        "identity_hex": identity_hex,
        "identity_hash": identity_hash,
        "identity_pub_key": ed25519_pub_key,
        "dest_hash": dest_hash,
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
