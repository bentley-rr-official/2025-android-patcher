#!/usr/bin/env python3
"""Sanity-check the phone hook RVAs against a libil2cpp.so (arm64).

Usage: check_targets.py <libil2cpp.so> [--force]

Run this on any new phone build BEFORE compiling. It (1) refuses a libil2cpp.so whose md5
isn't the one the RVAs in src/2025_hook.cpp were resolved against, and (2) disassembles the
first 5 instructions at every hook target (A64HookFunction overwrites 20 bytes) and fails if
any of them is a return / unconditional jump -- i.e. the target is too short to hook, or the
RVA doesn't point at a function start at all. Needs: pip install capstone lief
"""
import hashlib, sys
import capstone, lief

lief.logging.disable()
EXPECT_MD5 = "ef682fb3e6b8d093d605b4f5e53e11e7"   # 20250718.01 / versionCode 23568923
TARGETS = {   # keep in sync with the RF_PHONE block in src/2025_hook.cpp
    "HTTPManager.SendRequest(HTTPRequest)":      0x153da57c,
    "HTTPRequest.CallCallback()":                0x153e3df8,
    "LegacyTlsAuthentication.NotifyServerCert":  0x153d11e4,
    "HPJKKCCECLH.BLDFMLMAFLH (image sig)":       0x15896568,
    "GLMGKKNCFGH.LOELLDBOINB (cheat suppress)":  0x0b79d634,
    "SessionManager.FatalApplicationQuit":       0x0b7c9af4,
    "SessionManager.TryApplicationQuit(int)":    0x0b7c99f8,
}

path = sys.argv[1]
force = "--force" in sys.argv
h = hashlib.md5()
with open(path, "rb") as f:
    for c in iter(lambda: f.read(1 << 20), b""):
        h.update(c)
print(f"md5 {h.hexdigest()}")
if h.hexdigest() != EXPECT_MD5 and not force:
    sys.exit(f"md5 mismatch (expected {EXPECT_MD5}): these RVAs are for a different build; "
             "re-resolve them (see PHONE-20250718.01-notes.md) or pass --force")

elf = lief.ELF.parse(path)
data = open(path, "rb").read()
def file_off(va):
    for s in elf.segments:
        if s.type == lief.ELF.Segment.TYPE.LOAD and s.virtual_address <= va < s.virtual_address + s.physical_size:
            return va - s.virtual_address + s.file_offset
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
bad = 0
for name, va in TARGETS.items():
    off = file_off(va)
    ins = list(md.disasm(data[off:off + 20], va)) if off is not None else []
    ok = len(ins) == 5 and not any(i.mnemonic in ("ret", "b", "br", "brk", "udf") for i in ins)
    print(f"  {'ok ' if ok else 'BAD'} {va:#012x} {name}: " + "; ".join(f"{i.mnemonic} {i.op_str}" for i in ins[:2]))
    bad += not ok
sys.exit(f"{bad} target(s) failed" if bad else 0)
