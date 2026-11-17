#!/usr/bin/env python3
"""Rewrite the arm64 config split: replace lib/arm64-v8a/libmain.so with the injected copy and
add lib/arm64-v8a/libvrsupport.so. Native libs we write are STORED (uncompressed); zipalign -p
page-aligns them afterwards. Everything else is copied through untouched.

Usage: phone_patch.py <in split.apk> <injected libmain.so> <libvrsupport.so> <out split.apk>
                      [--put <arcname>=<file> ...] [--drop <arcname> ...]
  --put  extra entries (gotfix): an arcname already in the split is REPLACED (keeps its original
         compression, e.g. libil2cpp.so stays deflated like the stock split); a new arcname is
         added STORED.
  --drop remove an entry from the split (used to leave lib_burst_generated.so out: its PairIP-encrypted
         code is not recoverable without a stock-process dump, so Burst is disabled instead).
"""
import sys, zipfile

args = sys.argv[1:]
puts = {}
while "--put" in args:
    i = args.index("--put"); arc, _, path = args[i + 1].partition("="); puts[arc] = path
    del args[i:i + 2]
drops = set()
while "--drop" in args:
    i = args.index("--drop"); drops.add(args[i + 1]); del args[i:i + 2]
src, main_so, hook_so, dst = args[:4]
MAIN, HOOK = "lib/arm64-v8a/libmain.so", "lib/arm64-v8a/libvrsupport.so"
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst, "w") as zo:
    names = set(zi.namelist())
    if MAIN not in names:
        sys.exit(f"{MAIN} not found in {src} -- is this the arm64 config split?")
    skip = {MAIN, HOOK} | set(puts) | drops
    for d in sorted(drops):
        print(f"  drop {d} ({'present' if d in names else 'NOT in split'})")
    for info in zi.infolist():
        n = info.filename
        if n.startswith("META-INF/") and n.upper().endswith((".SF", ".RSA", ".DSA", ".EC", ".MF")):
            continue                      # old signature; apksigner writes a new one
        if n in skip:
            continue
        zo.writestr(info, zi.read(n), compress_type=info.compress_type)
    for arc, path in ((MAIN, main_so), (HOOK, hook_so)):
        zi_info = zipfile.ZipInfo(arc, date_time=(2026, 1, 1, 0, 0, 0))
        zi_info.compress_type = zipfile.ZIP_STORED
        zi_info.external_attr = 0o100644 << 16
        zo.writestr(zi_info, open(path, "rb").read())
    for arc, path in puts.items():
        ct = zi.getinfo(arc).compress_type if arc in names else zipfile.ZIP_STORED
        zi_info = zipfile.ZipInfo(arc, date_time=(2026, 1, 1, 0, 0, 0))
        zi_info.compress_type = ct
        zi_info.external_attr = 0o100644 << 16
        zo.writestr(zi_info, open(path, "rb").read(), compresslevel=1)
        print(f"  put {arc} ({'replaced' if arc in names else 'added'}, "
              f"{'deflated' if ct == zipfile.ZIP_DEFLATED else 'stored'})")
print(f"wrote {dst}")
