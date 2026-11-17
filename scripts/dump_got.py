#!/usr/bin/env python3
"""Dump PairIP's hidden-import GOT slots from a STOCK Rec Room process on a ROOTABLE emulator.

Why: in libil2cpp.so / libwebrtc.so / lib_burst_generated.so, PairIP removes ~200 imports'
relocations and fills their .got/.got.plt slots at startup from its native program. Without that
program the slots keep their raw link-time value (== address of .plt) and the first call
through one crashes. A stock, Play-signed process has them filled; this script reads them back
and names each one.

Needs on the PC:  python3 (Windows PowerShell/cmd or WSL, nothing else), adb that can see the emulator.
Needs on the AVD: a "Google APIs" image (NOT "Google Play") so `adb root` works; the STOCK,
                  unmodified XAPK installed and already past the Unity splash start (libil2cpp loaded).

  python3 dump_got.py --so-dir <dir with the ORIGINAL lib*.so from config.arm64_v8a.apk> \
                      --out got_map.json [--libs libil2cpp.so libwebrtc.so lib_burst_generated.so]
  --static-only   just list the hidden slots per lib (no device needed)
Env: ADB=<adb command>, default "adb" (PowerShell: $env:ADB='"C:\\path with spaces\\adb.exe" -s emulator-5554').
"""
import argparse, json, os, re, shlex, subprocess, sys, struct, tempfile

def _split(cmd):
    parts = shlex.split(cmd, posix=(os.name != "nt"))
    return [p[1:-1] if len(p) > 1 and p[0] == p[-1] and p[0] in "\"'" else p for p in parts]
ADB = _split(os.environ.get("ADB", "adb"))
PKG = "com.AgainstGravity.RecRoom"

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw).stdout

def adb(*a, binary=False):
    r = subprocess.run(ADB + list(a), capture_output=True)
    return r.stdout if binary else r.stdout.decode("utf-8", "replace")

# ---------------------------------------------------------------- static (host) ELF helpers
# Pure-Python ELF64 reader: no readelf needed, so this runs in plain Windows PowerShell/cmd too.
class Elf:
    def __init__(self, path):
        self.raw = d = open(path, "rb").read()
        if d[:4] != b"\x7fELF" or d[4] != 2:
            raise ValueError(f"{path}: not an ELF64 file")
        (self.phoff, self.shoff) = struct.unpack_from("<QQ", d, 0x20)
        (self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx) = struct.unpack_from("<HHHHH", d, 0x36)
        secs = []
        for i in range(self.shnum):
            o = self.shoff + i * self.shentsize
            nm, ty, fl, ad, off, sz, lk, inf, al, es = struct.unpack_from("<IIQQQQIIQQ", d, o)
            secs.append(dict(nameoff=nm, type=ty, addr=ad, off=off, size=sz, link=lk, entsize=es))
        if secs:
            st = secs[self.shstrndx]
            for sc in secs:
                a = st["off"] + sc["nameoff"]
                sc["name"] = d[a:d.index(b"\0", a)].decode()
        self.secs = secs

    def sec(self, name):
        return next((s for s in self.secs if s["name"] == name), None)

    def reloc_offsets(self):
        out = set()
        for s in self.secs:
            if s["type"] == 4:  # SHT_RELA
                for o in range(s["off"], s["off"] + s["size"], 24):
                    out.add(struct.unpack_from("<Q", self.raw, o)[0])
        return out

    def load_segments(self):
        segs = []
        for i in range(self.phnum):
            o = self.phoff + i * self.phentsize
            ty, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", self.raw, o)
            if ty == 1:
                segs.append(dict(off=off, vaddr=va, filesz=fsz))
        return segs

    def dynsyms(self):
        """vaddr -> [names] for defined symbols."""
        d, out = self.raw, {}
        ds = next((s for s in self.secs if s["type"] == 11), None)  # SHT_DYNSYM
        if not ds:
            return out
        st = self.secs[ds["link"]]
        for o in range(ds["off"], ds["off"] + ds["size"], 24):
            nm, info, other, shndx, val, sz = struct.unpack_from("<IBBHQQ", d, o)
            if shndx != 0 and val:
                a = st["off"] + nm
                out.setdefault(val, []).append(d[a:d.index(b"\0", a)].decode())
        return out

def hidden_slots(so):
    """slots in .got.plt / .got with no relocation whose file value is the start of .plt (unfilled)."""
    e = Elf(so)
    plt = e.sec(".plt")
    if not plt:
        return [], 0
    plt0 = plt["addr"]
    rel = e.reloc_offsets()
    out = []
    for name in (".got.plt", ".got"):
        g = e.sec(name)
        if not g:
            continue
        for k in range(g["size"] // 8):
            va = g["addr"] + 8 * k
            if va not in rel and struct.unpack_from("<Q", e.raw, g["off"] + 8 * k)[0] == plt0:
                out.append(va)
    return out, plt0

# ---------------------------------------------------------------- runtime (device) helpers
def pid():
    out = adb("shell", "pidof", PKG).split()
    if not out:
        sys.exit(f"{PKG} is not running. Start the STOCK app and wait ~20 s, then rerun.")
    return out[0]

def maps(p):
    ents = []
    for l in adb("shell", "cat", f"/proc/{p}/maps").splitlines():
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\S+\s*(.*)", l)
        if m:
            ents.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3), int(m.group(4), 16), m.group(5).strip()))
    return ents

def read_mem(p, addr, n):
    page = 4096
    start = addr & ~(page - 1)
    end = (addr + n + page - 1) & ~(page - 1)
    raw = adb("exec-out", f"dd if=/proc/{p}/mem bs={page} skip={start // page} count={(end - start) // page} 2>/dev/null", binary=True)
    if len(raw) != end - start:
        sys.exit(f"short read at {hex(addr)}: got {len(raw)} of {end - start} bytes (is this a rooted `adb root` shell?)")
    return raw[addr - start: addr - start + n]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--so-dir", required=True)
    ap.add_argument("--libs", nargs="+", default=["libil2cpp.so", "libwebrtc.so", "lib_burst_generated.so"])
    ap.add_argument("--out", default="got_map.json")
    ap.add_argument("--static-only", action="store_true")
    a = ap.parse_args()

    plan, plt0s = {}, {}
    for lib in a.libs:
        so = os.path.join(a.so_dir, lib)
        if not os.path.isfile(so):
            print(f"!! {so} missing, skipping"); continue
        plan[lib], plt0s[lib] = hidden_slots(so)
        print(f"{lib}: {len(plan[lib])} hidden (unrelocated) .got/.got.plt slots")
    if a.static_only:
        return

    adb("root"); adb("wait-for-device")
    if "uid=0" not in adb("shell", "id"):
        sys.exit("adb root failed: use a 'Google APIs' (non-Play) system image.")
    p = pid(); mp = maps(p)
    cache = tempfile.mkdtemp(prefix="gotsyms_")
    symcache = {}

    def lib_info(path):
        if path not in symcache:
            local = os.path.join(cache, path.replace("/", "_"))
            # exec-out cat instead of `adb pull`: works with adb.exe called from WSL (no path translation)
            open(local, "wb").write(adb("exec-out", "cat", path, binary=True))
            try:
                e = Elf(local); symcache[path] = (e.dynsyms(), e.load_segments())
            except (OSError, ValueError):
                symcache[path] = ({}, [])
        return symcache[path]

    result = {}
    for lib, slots in plan.items():
        bases = [e for e in mp if e[4].endswith("/" + lib) and e[3] == 0]
        if not bases:
            print(f"!! {lib} is not mapped in the process (not loaded yet?) -- skipping"); continue
        base = bases[0][0]
        res, unfilled, unknown = {}, 0, 0
        for va in slots:
            val = struct.unpack("<Q", read_mem(p, base + va, 8))[0]
            if val == 0 or val == plt0s[lib]:
                unfilled += 1; continue
            hit = next((e for e in mp if e[0] <= val < e[1]), None)
            rec = {"value": hex(val)}
            if hit and hit[4].startswith("/"):
                syms, segs = lib_info(hit[4])
                foff = val - hit[0] + hit[3]
                seg = next((s for s in segs if s["off"] <= foff < s["off"] + s["filesz"]), None)
                if seg:
                    lv = foff - seg["off"] + seg["vaddr"]
                    rec.update(lib=hit[4], lib_vaddr=hex(lv), names=syms.get(lv, []))
            if not rec.get("names"):
                unknown += 1
                rec["map"] = hit[4] if hit else "unmapped"
            res[hex(va)] = rec
        print(f"{lib}: {len(res)} slots read, {unfilled} still unfilled, {unknown} with no symbol name")
        result[lib] = res
    json.dump(result, open(a.out, "w"), indent=1)
    print("wrote", a.out)

if __name__ == "__main__":
    main()
