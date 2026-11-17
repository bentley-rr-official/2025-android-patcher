#!/usr/bin/env python3
"""Reference for com.p2025.DeviceIdentity (server side / tests).
    device_id_ref.py <ANDROID_ID>            -> prints platform id + proof
    verify(platform_id, proof)               -> True if the pair is self-consistent (format check only)
"""
import base64, hashlib, sys

def derive(android_id: str):
    d = hashlib.sha256(("2025-device-v1:" + (android_id or "unknown")).encode()).digest()
    pid = str(int.from_bytes(d[:8], "big") >> 4)
    proof = "2025-device-v1." + base64.urlsafe_b64encode(d).decode().rstrip("=")
    return pid, proof

def verify(pid: str, proof: str) -> bool:
    if not proof.startswith("2025-device-v1."): return False
    b = proof[len("2025-device-v1."):]
    try: d = base64.urlsafe_b64decode(b + "=" * (-len(b) % 4))
    except Exception: return False
    return len(d) == 32 and str(int.from_bytes(d[:8], "big") >> 4) == pid

if __name__ == "__main__":
    pid, proof = derive(sys.argv[1] if len(sys.argv) > 1 else "")
    print(pid); print(proof); print("self-consistent:", verify(pid, proof))
