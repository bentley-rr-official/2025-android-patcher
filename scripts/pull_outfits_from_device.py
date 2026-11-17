#!/usr/bin/env python3
"""Pull OutfitsAssetPack bundles off an ADB-connected phone that got them from the real Play Store.

Google Play serves fast-follow asset packs only to an authenticated Play client, and there is no public CDN path to
probe -- so let a real phone do the download, then collect the bundles here.

  1. On a phone/tablet signed into Google Play, install Rec Room from the Play Store and open it until the
     outfits pack has downloaded (it is fast-follow, DeliveryType 2).
  2. Enable USB debugging, connect, then:
       python pull_outfits_from_device.py CustomAssetPacksData.json --out out_pack
     Optional: --pkg com.AgainstGravity.RecRoom  --roots /sdcard/Android /data/local/tmp  --adb "C:\\platform-tools\\adb.exe"
  3. It finds <hash>.bundle files, keeps only those in the 1,404 list, pulls them, and prints coverage.

Caveats: Play serves the CURRENT build, not 20250718.01. Bundles whose content did not change keep the same hash, so
coverage may be partial -- the script says exactly how many of the 1,404 matched. Android 11+ hides other apps' data
dirs from file managers; `adb shell` can usually still list /sdcard/Android/data, but app-private /data/data needs root.
"""
import argparse, json, os, re, subprocess, sys

ap = argparse.ArgumentParser()
ap.add_argument("data_json"); ap.add_argument("--out", default="out_pack")
ap.add_argument("--adb", default="adb"); ap.add_argument("--serial")
ap.add_argument("--roots", nargs="*", default=["/sdcard/Android", "/storage/emulated/0/Android", "/data/data", "/data/local/tmp"])
a = ap.parse_args()
base = [a.adb] + (["-s", a.serial] if a.serial else [])
want = set([e for e in json.load(open(a.data_json))["Entries"] if e["AssetPackName"] == "OutfitsAssetPack"][0]["AssetBundles"])
os.makedirs(a.out, exist_ok=True)
pat = re.compile(r"/([0-9a-f]{32})\.bundle$")
found = {}
for root in a.roots:
    r = subprocess.run(base + ["shell", f"find {root} -name '*.bundle' 2>/dev/null"], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        m = pat.search(line.strip())
        if m and m.group(1) in want and m.group(1) not in found: found[m.group(1)] = line.strip()
print(f"on device: {len(found)} of {len(want)} expected bundles found")
ok = 0
for h, p in found.items():
    r = subprocess.run(base + ["pull", p, os.path.join(a.out, h + ".bundle")], capture_output=True, text=True)
    ok += r.returncode == 0
print(f"pulled {ok}/{len(found)} to {a.out}; missing {len(want) - ok} of {len(want)}")
sys.exit(0 if ok == len(want) else 1)
