#!/usr/bin/env python3
"""MEASURE what PairIP changes in a lib's writable data, from a STOCK process on the rootable emulator.

Compares each writable PT_LOAD segment's bytes on disk with the live process memory and classifies
every 8-byte word that differs:
  reloc   : file==0 and live points into a mapped region, or live == file+base  (normal linker relocation)
  cand    : file!=0, not a relocation, live differs   <-- scrambled-on-disk / descrambled-at-runtime candidates
  zero    : file!=0 and live==0
Writes <out>.summary.json (counts, per-64KB histogram, examples) and <out>.cand.bin (zlib: u64 vaddr,u64 live,
u64 file records; includes both "cand" and "zero") so we can decide what to ship. NOTHING is applied to the app by this script.

  python3 dump_state.py --so-dir <dir with ORIGINAL libs> --libs libil2cpp.so [libwebrtc.so] --out state
  python3 dump_state.py --selftest --so-dir <dir>      # no device: file vs itself, must give 0 diffs
Env ADB like dump_got.py. Stock app must be running past the Unity splash; adb root required.
Dump EARLY (right after launch): later the game mutates .data legitimately and that pollutes 'cand'.
"""
import argparse, json, os, struct, sys, zlib
import dump_got as G

def wsegs(path):
    e = G.Elf(path); d = e.raw; out = []
    for i in range(e.phnum):
        o = e.phoff + i * e.phentsize
        ty, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", d, o)
        if ty == 1 and fl & 2:
            out.append((va, off, fsz, msz))
    return e, out

def classify(fw, lw, base, regions):
    if fw == lw: return None
    if fw == 0 and any(a <= lw < b for a, b in regions): return "reloc"
    if lw == (fw + base) & (2**64 - 1): return "reloc"
    if lw == 0: return "zero"
    return "cand"

def analyse(so, base, regions, readmem, name):
    e, segs = wsegs(so)
    cnt = {"reloc": 0, "cand": 0, "zero": 0}; hist = {}; ex = []; recs = bytearray()
    for va, off, fsz, msz in segs:
        pg = va & ~0xfff; n = (va + fsz + 0xfff) & ~0xfff
        live = readmem(base + va, fsz)
        for k in range(0, fsz - 7, 8):
            fw = struct.unpack_from("<Q", e.raw, off + k)[0]; lw = struct.unpack_from("<Q", live, k)[0]
            c = classify(fw, lw, base, regions)
            if not c: continue
            cnt[c] += 1
            if c in ("cand", "zero"):          # 'zero' (file!=0, live==0) is kept too: scrambled words may decode to 0
                a = va + k
                if c == "cand": hist[hex(a & ~0xffff)] = hist.get(hex(a & ~0xffff), 0) + 1
                recs += struct.pack("<QQQ", a, lw, fw)
                if c == "cand" and len(ex) < 12: ex.append([hex(a), hex(fw), hex(lw)])
    return dict(lib=name, segments=[[hex(a), hex(b), hex(c), hex(d)] for a, b, c, d in segs], counts=cnt,
                cand_per_64k=dict(sorted(hist.items())), examples=ex), bytes(recs)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--so-dir", required=True); ap.add_argument("--libs", nargs="+", default=["libil2cpp.so"])
    ap.add_argument("--out", default="state"); ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        for lib in a.libs:
            so = os.path.join(a.so_dir, lib); e, segs = wsegs(so)
            fake = lambda addr, n, e=e, segs=segs: next(e.raw[o + addr - 0 - v: o + addr - v + n] for v, o, f, m in segs if v <= addr < v + f)
            s, r = analyse(so, 0, [], fake, lib); print(lib, s["counts"], "writable segs:", s["segments"])
        return
    G.adb("root"); G.adb("wait-for-device")
    if "uid=0" not in G.adb("shell", "id"): sys.exit("adb root failed")
    p = G.pid(); mp = G.maps(p); regions = [(x[0], x[1]) for x in mp]
    for lib in a.libs:
        b = [x for x in mp if x[4].endswith("/" + lib) and x[3] == 0]
        if not b:
            print(f"!! {lib} not mapped. lib-ish maps:", sorted({x[4] for x in mp if lib[:6] in x[4]})[:5]); continue
        s, r = analyse(os.path.join(a.so_dir, lib), b[0][0], regions, lambda ad, n: G.read_mem(p, ad, n), lib)
        json.dump(s, open(f"{a.out}.{lib}.summary.json", "w"), indent=1)
        open(f"{a.out}.{lib}.cand.bin", "wb").write(zlib.compress(r, 9))
        print(lib, s["counts"], "cand blob", len(zlib.compress(r, 9)), "bytes")
if __name__ == "__main__":
    main()
