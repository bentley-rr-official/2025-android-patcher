#!/usr/bin/env python3
"""got_map.json -> C include for gotfix.cpp.   usage:
   python3 gen_got_table.py --lib libil2cpp.so --so libil2cpp.so --map got_map.json --out got_libil2cpp.inc
Names come from the dump (device-independent); the raw addresses in the dump are NOT used.
Slots the dump could not name (ifunc impls like memcpy) use --unnamed (default: memmove,
which is a safe stand-in if the real import was memcpy or memmove -- VERIFY against call sites)."""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ap = argparse.ArgumentParser()
ap.add_argument("--lib", required=True); ap.add_argument("--so", required=True)
ap.add_argument("--map", default="got_map.json"); ap.add_argument("--out", required=True)
ap.add_argument("--unnamed", default=None, help="name for ALL unnamed slots (old behaviour)")
ap.add_argument("--override", action="append", default=[], metavar="LIBVADDR=NAME",
                help="unnamed slots whose dumped libc impl address (lib_vaddr) is LIBVADDR get NAME, e.g. 0x54940=memmove (shared memcpy/memmove impl)")
a = ap.parse_args()
from dump_got import hidden_slots           # from the project's dump_got.py (put it next to this file)
slots, plt0 = hidden_slots(a.so)
m = json.load(open(a.map)).get(a.lib)
if m is None: sys.exit(f"{a.lib} is not in {a.map}: that lib still needs a dump")
missing = [hex(v) for v in slots if hex(v) not in m]
if missing: sys.exit(f"{len(missing)} hidden slots absent from the map, e.g. {missing[:3]}")
rows, guessed = [], []
for va in sorted(slots):
    names = m[hex(va)].get("names") or []
    if not names:
        lv = m[hex(va)].get("lib_vaddr")
        ov = dict(o.split("=", 1) for o in a.override)
        pick = ov.get(lv) or a.unnamed
        guessed.append(f"{hex(va)}({lv}->{pick or 'LEFT UNFILLED'})")
        names = [pick] if pick else []
    rows.append(f'  {{{hex(va)}ULL, {{{", ".join(json.dumps(n) for n in names[:3])}}}}},')
with open(a.out, "w") as f:
    f.write(f'// generated from {os.path.basename(a.map)}\nstatic const char kTarget[] = "{a.lib}";\n'
            f'static const uint64_t kPlt0 = {hex(plt0)}ULL;\n'
            'struct Slot { uint64_t va; const char* names[4]; };\nstatic const Slot kSlots[] = {\n' + "\n".join(rows) + "\n};\n")
print(f"{a.out}: {len(rows)} slots; unnamed: {guessed}")
