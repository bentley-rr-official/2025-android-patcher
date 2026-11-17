#!/usr/bin/env python3
"""Probe an XAPK/APK-set for the files needed to resolve patch targets.

Usage:  python xapk_probe.py <file.xapk|file.apk> [--report-only]

Writes ./probe_out/report.txt (tiny -- upload this first), and unless --report-only,
extracts libil2cpp.so / libmain.so / global-metadata.dat (arm64 preferred) and bundles
them into ./probe_out/rr_upload.zip. Nothing is modified or sent anywhere.
"""
import hashlib, io, json, os, shutil, sys, tempfile, zipfile

TARGETS = ("libil2cpp.so", "libmain.so", "libunity.so", "global-metadata.dat")
args = [a for a in sys.argv[1:] if not a.startswith("--")]
report_only = "--report-only" in sys.argv
if not args:
    sys.exit(__doc__)
src = args[0]
out = os.path.abspath("probe_out")
shutil.rmtree(out, ignore_errors=True)
os.makedirs(out)
lines = []
def log(s=""):
    print(s); lines.append(s)

def md5_of(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def mb(n): return f"{n/1048576:.1f} MB"

tmp = tempfile.mkdtemp()
found = []   # (apk_label, entry_name, extracted_path)

def scan_apk(label, apk_path):
    with zipfile.ZipFile(apk_path) as z:
        for info in z.infolist():
            base = os.path.basename(info.filename)
            if base in TARGETS:
                dest = os.path.join(tmp, f"{len(found)}_{base}")
                with z.open(info) as fi, open(dest, "wb") as fo:
                    shutil.copyfileobj(fi, fo, 1 << 20)
                found.append((label, info.filename, dest))
        names = z.namelist()
        if "AndroidManifest.xml" in names:
            log(f"  [{label}] has AndroidManifest.xml ({mb(os.path.getsize(apk_path))})")

log(f"file: {src}  ({mb(os.path.getsize(src))})")
with zipfile.ZipFile(src) as z:
    infos = z.infolist()
    log(f"\n== top-level entries ({len(infos)}) ==")
    for i in infos[:60]:
        log(f"  {i.file_size:>12,}  {i.filename}")
    if len(infos) > 60:
        log(f"  ... {len(infos)-60} more")
    if "manifest.json" in z.namelist():
        try:
            m = json.loads(z.read("manifest.json"))
            log("\n== manifest.json ==")
            for k in ("package_name", "version_code", "version_name", "min_sdk_version",
                      "target_sdk_version", "native_code", "locales"):
                if k in m: log(f"  {k}: {m[k]}")
            if "split_apks" in m:
                log(f"  split_apks: {[s.get('file') for s in m['split_apks']]}")
            if "expansions" in m:
                log(f"  expansions (OBB): {m['expansions']}")
        except Exception as e:
            log(f"  manifest.json unreadable: {e}")
    obbs = [i.filename for i in infos if i.filename.lower().endswith(".obb")]
    log(f"\n== OBB files: {obbs if obbs else 'none'} ==")

    log("\n== scanning APKs ==")
    if src.lower().endswith(".apk"):
        scan_apk(os.path.basename(src), src)
    else:
        for i in infos:
            if i.filename.lower().endswith(".apk"):
                p = os.path.join(tmp, "nested_" + os.path.basename(i.filename))
                with z.open(i) as fi, open(p, "wb") as fo:
                    shutil.copyfileobj(fi, fo, 1 << 20)
                scan_apk(i.filename, p)
                os.remove(p)

log("\n== target files ==")
for label, name, path in found:
    log(f"  {name}   in {label}   {mb(os.path.getsize(path))}   md5 {md5_of(path)}")
    if name.endswith("global-metadata.dat"):
        with open(path, "rb") as f:
            head = f.read(32)
        log(f"      first 32 bytes: {head.hex()}")
        log(f"      standard magic (af1bb1fa): {head[:4].hex() == 'af1bb1fa'}"
            f"   -> {'unobfuscated header' if head[:4].hex() == 'af1bb1fa' else 'header modified/obfuscated'}")
if not any(n.endswith("libil2cpp.so") for _, n, _ in found):
    log("  !! no libil2cpp.so found (not IL2CPP, or in a split not present)")
if not any(n.endswith("global-metadata.dat") for _, n, _ in found):
    log("  !! no global-metadata.dat found")

open(os.path.join(out, "report.txt"), "w", encoding="utf-8").write("\n".join(lines))
print(f"\nwrote {out}\\report.txt  <- upload this first (tiny)")

if not report_only:
    keep = [(l, n, p) for l, n, p in found
            if "arm64" in n or n.endswith("global-metadata.dat") or "/lib/" not in "/" + n]
    zpath = os.path.join(out, "rr_upload.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zo:
        zo.write(os.path.join(out, "report.txt"), "report.txt")
        for i, (l, n, p) in enumerate(keep):
            arc = n.replace("/", "__")
            zo.write(p, arc)
    print(f"wrote {zpath}  ({mb(os.path.getsize(zpath))})")
shutil.rmtree(tmp, ignore_errors=True)
