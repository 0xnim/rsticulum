#!/usr/bin/env python3
"""RNS ↔ rsticulum byte-compatibility validator."""

import sys, json, RNS

def log(msg): print(f"[PYTHON] {msg}", file=sys.stderr, flush=True)
def respond(obj): print(json.dumps(obj), flush=True)

def cmd_parse(hex_bytes):
    raw = bytes.fromhex(hex_bytes)
    try:
        pkt = RNS.Packet(None, raw); pkt.unpack()
        r = {"status":"ok","packet_type":pkt.packet_type,"hops":pkt.hops,
             "destination_hash":pkt.destination_hash.hex(),"context":pkt.context,
             "header_type":pkt.header_type,"transport_type":pkt.transport_type,
             "context_flag":pkt.context_flag,"destination_type":pkt.destination_type}
        if pkt.transport_id is not None: r["transport_id"] = pkt.transport_id.hex()
        if pkt.data is not None: r["data_hex"] = pkt.data.hex(); r["data_len"] = len(pkt.data)
        respond(r)
    except Exception as e: respond({"status":"error","error":str(e)})

def cmd_hkdf(length, ikm_hex):
    from RNS.Cryptography.HKDF import hkdf
    derived = hkdf(int(length), bytes.fromhex(ikm_hex), None, None)
    respond({"status":"ok","derived_hex":derived.hex()})

def cmd_token_encrypt(key_hex, plaintext_hex):
    from RNS.Cryptography.Token import Token
    t = Token(bytes.fromhex(key_hex))
    tok = t.encrypt(bytes.fromhex(plaintext_hex))
    respond({"status":"ok","token_hex":tok.hex(),"token_len":len(tok)})

def cmd_token_decrypt(token_hex, key_hex):
    from RNS.Cryptography.Token import Token
    try:
        t = Token(bytes.fromhex(key_hex))
        pt = t.decrypt(bytes.fromhex(token_hex))
        respond({"status":"ok","plaintext_hex":pt.hex()})
    except Exception as e: respond({"status":"error","error":str(e)})

def main():
    log("validator starting")
    RNS.Reticulum(configdir=None, loglevel=RNS.LOG_CRITICAL)
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        parts = line.split(" ", 1)
        cmd, rest = parts[0].upper(), parts[1] if len(parts) > 1 else ""
        if cmd == "PARSE": cmd_parse(rest)
        elif cmd == "ANNOUNCE_FLAGS": respond({"status":"ok","announce_flags":"0x21"})
        elif cmd == "HKDF_DERIVE" and rest:
            s = rest.split(" ", 1); cmd_hkdf(s[0], s[1])
        elif cmd == "TOKEN_ENCRYPT" and rest:
            s = rest.split(" ", 1); cmd_token_encrypt(s[0], s[1])
        elif cmd == "TOKEN_DECRYPT" and rest:
            s = rest.split(" ", 1); cmd_token_decrypt(s[0], s[1])
        elif cmd == "QUIT": break
        else: respond({"status":"error","error":f"unknown: {cmd}"})

if __name__ == "__main__": main()
