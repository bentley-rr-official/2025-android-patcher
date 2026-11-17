#!/usr/bin/env python3
"""Search for the 1,404 OutfitsAssetPack bundles (20250718.01) on disk, inside archives, or at a URL you give it.

  Local scan (recurses folders; looks inside .apk/.zip/.obb/.xapk/.apks, one level of nesting):
    find_outfits_pack.py CustomAssetPacksData.json --scan "D:\\" "C:\\Users\\me\\Downloads" --copy-to out_pack

  Remote probe (YOU supply the base URL of a mirror/CDN; tries <base>/<hash>.bundle and <base>/Android/<hash>.bundle):
    find_outfits_pack.py CustomAssetPacksData.json --url https://example.com/bundles --copy-to out_pack

Matches by file name <32hex>.bundle. With --verify it also requires the UnityFS magic header, so empty
placeholder files are not counted. Exit 0 only if all 1,404 are found.
"""
import argparse, io, json, os, re, shutil, sys, urllib.request, zipfile

NAME = re.compile(r"(?i)^([0-9a-f]{32})\.bundle$")
ARCH = (".apk", ".zip", ".obb", ".xapk", ".apks")

def want_set(path):
    e = [x for x in json.load(open(path))["Entries"] if x["AssetPackName"] == "OutfitsAssetPack"][0]
    return set(e["AssetBundles"])

def scan_zip(zf, label, want, found, verify, copy_to, depth=0):
    for n in zf.namelist():
        base = os.path.basename(n)
        m = NAME.match(base)
        if m and m.group(1).lower() in want and m.group(1).lower() not in found:
            h = m.group(1).lower()
            if verify and zf.read(n)[:7] != b"UnityFS": continue
            found[h] = f"{label}!{n}"
            if copy_to:
                with open(os.path.join(copy_to, h + ".bundle"), "wb") as o: o.write(zf.read(n))
        elif depth == 0 and n.lower().endswith(ARCH) and zf.getinfo(n).file_size < 3_000_000_000:
            try:
                with zipfile.ZipFile(io.BytesIO(zf.read(n))) as inner:
                    scan_zip(inner, f"{label}!{n}", want, found, verify, copy_to, 1)
            except Exception: pass

def scan_local(roots, want, found, verify, copy_to):
    for root in roots:
        for r, _, fs in os.walk(root):
            for f in fs:
                p = os.path.join(r, f)
                m = NAME.match(f)
                if m and m.group(1).lower() in want and m.group(1).lower() not in found:
                    h = m.group(1).lower()
                    if verify:
                        try:
                            if open(p, "rb").read(7) != b"UnityFS": continue
                        except OSError: continue
                    found[h] = p
                    if copy_to: shutil.copyfile(p, os.path.join(copy_to, h + ".bundle"))
                elif f.lower().endswith(ARCH):
                    try:
                        with zipfile.ZipFile(p) as z: scan_zip(z, p, want, found, verify, copy_to)
                    except Exception: pass

def probe_url(base, want, found, verify, copy_to):
    base = base.rstrip("/")
    for h in sorted(want):
        if h in found: continue
        for u in (f"{base}/{h}.bundle", f"{base}/Android/{h}.bundle"):
            try:
                req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"})
                data = urllib.request.urlopen(req, timeout=20).read()
            except Exception: continue
            if verify and data[:7] != b"UnityFS": continue
            found[h] = u
            if copy_to: open(os.path.join(copy_to, h + ".bundle"), "wb").write(data)
            break

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("data_json"); ap.add_argument("--scan", nargs="*", default=[])
ap.add_argument("--url"); ap.add_argument("--copy-to"); ap.add_argument("--verify", action="store_true")
a = ap.parse_args()
want = want_set(a.data_json); found = {}
if a.copy_to: os.makedirs(a.copy_to, exist_ok=True)
if a.scan: scan_local(a.scan, want, found, a.verify, a.copy_to)
if a.url: probe_url(a.url, want, found, a.verify, a.copy_to)
print(f"expected {len(want)}, found {len(found)}, missing {len(want) - len(found)}")
for h, w in list(found.items())[:10]: print("  e.g.", h, "<-", w)
if found and a.copy_to: print(f"copied to {a.copy_to}")
sys.exit(0 if len(found) == len(want) else 1)
