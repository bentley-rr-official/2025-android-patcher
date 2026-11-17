#!/usr/bin/env python3
"""Check a candidate OutfitsAssetPack source against the 1,404 bundle hashes the 20250718.01 build expects.
    check_outfits_pack.py <CustomAssetPacksData.json> <dir | .apk | .zip | .obb> [...]
Matches files named <hash>.bundle (any folder depth / zip path). Prints found / missing counts and the missing list.
"""
import json, os, re, sys, zipfile

def names(src):
    if os.path.isdir(src):
        for r, _, fs in os.walk(src):
            for f in fs: yield f
    else:
        with zipfile.ZipFile(src) as z:
            for n in z.namelist(): yield os.path.basename(n)

if len(sys.argv) < 3: sys.exit(__doc__)
ent = [e for e in json.load(open(sys.argv[1]))["Entries"] if e["AssetPackName"] == "OutfitsAssetPack"][0]
want = set(ent["AssetBundles"]); have = set()
for src in sys.argv[2:]:
    for n in names(src):
        m = re.fullmatch(r"([0-9a-f]{32})\.bundle", n)
        if m: have.add(m.group(1))
found = want & have
print(f"expected {len(want)}, found {len(found)}, missing {len(want - found)}, unrelated bundles {len(have - want)}")
for h in sorted(want - found)[:50]: print("missing", h)
if len(want - found) > 50: print("... (truncated)")
sys.exit(0 if len(found) == len(want) else 1)
