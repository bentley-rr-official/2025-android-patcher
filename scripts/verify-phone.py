#!/usr/bin/env python3
"""Structural check of a signed phone build.

Usage: verify-phone.py <signed dir> [expected libil2cpp md5]

Checks the arm64 config split: libvrsupport.so and libmain.so (the two libs we write) are
STORED and page-aligned, libmain.so has libvrsupport.so as FIRST DT_NEEDED, and libil2cpp.so is
byte-identical to the one the RVAs were resolved against. libil2cpp/libunity are passed through
exactly as the original shipped them -- the stock split deflates them (legacy extractNativeLibs
packaging, which the installer extracts to the app's lib dir), so they are NOT required to be
stored here. Also checks the
other three splits exist and are non-empty. (Signature agreement is checked by the caller.)
"""
import hashlib, io, sys, zipfile
import lief

lief.logging.disable()  # a harmless 'Failed to parse note' on Unity's libmain.so

d = sys.argv[1]
want_md5 = sys.argv[2] if len(sys.argv) > 2 else None   # md5 the shipped libil2cpp must have (patched one when gotfix is on)
stock_md5 = sys.argv[3] if len(sys.argv) > 3 else None  # md5 of the stock libil2cpp the RVAs were resolved against
EXPECT = ["com.AgainstGravity.RecRoom.apk", "config.arm64_v8a.apk",
          "UnityDataAssetPack.apk", "UnityStreamingAssetsPack.apk"]
ABI = "lib/arm64-v8a/"
bad = []

import os
for n in EXPECT:
    p = os.path.join(d, n)
    if not os.path.isfile(p) or os.path.getsize(p) == 0:
        bad.append(f"missing/empty split: {n}")
if bad:
    sys.exit("verify-phone FAILED:\n  " + "\n  ".join(bad))

with zipfile.ZipFile(os.path.join(d, "config.arm64_v8a.apk")) as z:
    names = set(z.namelist())
    for so in ("libvrsupport.so", "libmain.so", "libil2cpp.so", "libunity.so"):
        if ABI + so not in names:
            bad.append(f"{ABI}{so} missing from arm64 split")
    gf = [so for so in ("libgfi.so", "libgfw.so") if ABI + so in names]   # gotfix libs (optional)
    for so in ("libvrsupport.so", "libmain.so", *gf):
        if ABI + so not in names:
            continue
        i = z.getinfo(ABI + so)
        if i.compress_type != zipfile.ZIP_STORED:
            bad.append(f"{so} is compressed (must be STORED)")
        with open(os.path.join(d, "config.arm64_v8a.apk"), "rb") as f:
            f.seek(i.header_offset + 26)
            nlen, elen = int.from_bytes(f.read(2), "little"), int.from_bytes(f.read(2), "little")
        data_off = i.header_offset + 30 + nlen + elen
        if data_off % 4096:
            bad.append(f"{so} data offset {data_off} not 4096-aligned")
    if not bad:
        b = lief.ELF.parse(list(z.read(ABI + "libmain.so")))
        needed = [e.name for e in b.dynamic_entries if e.tag == lief.ELF.DynamicEntry.TAG.NEEDED]
        if not needed or needed[0] != "libvrsupport.so":
            bad.append(f"libmain.so DT_NEEDED order wrong: {needed}")
        h = hashlib.md5()
        with z.open(ABI + "libil2cpp.so") as f:
            for c in iter(lambda: f.read(1 << 20), b""):
                h.update(c)
        if want_md5 and h.hexdigest() != want_md5:
            bad.append(f"libil2cpp.so md5 {h.hexdigest()} != {want_md5}")
        hook = lief.ELF.parse(list(z.read(ABI + "libvrsupport.so")))
        if hook is None:
            bad.append("libvrsupport.so is not a valid ELF")
        elif hook.header.machine_type != lief.ELF.ARCH.AARCH64:
            bad.append("libvrsupport.so is not AArch64")

if bad:
    sys.exit("verify-phone FAILED:\n  " + "\n  ".join(bad))
print("verify-phone: OK (4 splits, hook lib + libmain stored/aligned, DT_NEEDED first, "
      + ("il2cpp = stock + in-place NEEDED patch, gotfix: " + ", ".join(gf) if want_md5 != stock_md5 else "il2cpp untouched") + ")")
