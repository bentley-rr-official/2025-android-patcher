#!/usr/bin/env python3
"""Make <newname> a DT_NEEDED of an ELF64 lib WITHOUT rewriting it: the existing NEEDED entry
"liblog.so" (9 chars) has its .dynstr string overwritten in place by <newname> (<= 9 chars,
e.g. libgfi.so). The gotfix lib itself links liblog.so (-llog), so liblog stays in the lib's
dependency group and its imports still resolve. Only those string bytes change: no LIEF, no
layout change, every RVA / file offset identical. Refuses if anything else could reference the
string (version-needs, dynsym names, tail-merged strings).

usage: gotfix_inject.py <in.so> <out.so> <newname>"""
import shutil, struct, sys

VICTIM = b"liblog.so"

def main():
    src, dst, new = sys.argv[1], sys.argv[2], sys.argv[3].encode()
    if len(new) > len(VICTIM): sys.exit(f"name too long (max {len(VICTIM)} chars): {new!r}")
    shutil.copyfile(src, dst)
    with open(dst, "r+b") as f:
        hdr = f.read(64)
        if hdr[:4] != b"\x7fELF" or hdr[4] != 2: sys.exit("not ELF64")
        shoff, = struct.unpack_from("<Q", hdr, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", hdr, 0x3a)
        f.seek(shoff); sh = f.read(shentsize * shnum)
        secs = [struct.unpack_from("<IIQQQQIIQQ", sh, i * shentsize) for i in range(shnum)]
        # (name,type,flags,addr,off,size,link,info,align,entsize)
        dyn = next(s for s in secs if s[1] == 6)            # SHT_DYNAMIC
        strsec = secs[dyn[6]]
        f.seek(dyn[4]); d = f.read(dyn[5])
        needed = []
        for o in range(0, len(d), 16):
            tag, val = struct.unpack_from("<qQ", d, o)
            if tag == 1: needed.append(val)
            if tag == 0: break
        f.seek(strsec[4]); strtab = f.read(strsec[5])
        hits = [v for v in needed if strtab[v:v + len(VICTIM) + 1] == VICTIM + b"\0"]
        if len(hits) != 1: sys.exit(f"expected exactly one NEEDED {VICTIM.decode()}, found {len(hits)}")
        off = hits[0]
        if off and strtab[off - 1] != 0: sys.exit("string is a suffix of another string; refusing")
        inside = lambda v: off <= v <= off + len(VICTIM)
        dsym = next(s for s in secs if s[1] == 11)           # no dynsym name may point into it
        f.seek(dsym[4]); ds = f.read(dsym[5])
        for o in range(0, len(ds), 24):
            if inside(struct.unpack_from("<I", ds, o)[0]): sys.exit("a dynsym name points into the string; refusing")
        for vn in (s for s in secs if s[1] == 0x6ffffffe):   # SHT_GNU_verneed
            f.seek(vn[4]); vd = f.read(vn[5]); p = 0
            while True:
                _, cnt, vfile, vaux, vnext = struct.unpack_from("<HHIII", vd, p)
                if inside(vfile): sys.exit("version-needs references the string; refusing")
                a = p + vaux
                for _i in range(cnt):
                    _h, _fl, _oth, vname, anext = struct.unpack_from("<IHHII", vd, a)
                    if inside(vname): sys.exit("a version name points into the string; refusing")
                    a += anext
                if not vnext: break
                p += vnext
        f.seek(strsec[4] + off); f.write(new + b"\0" * (len(VICTIM) - len(new)))
    print(f"NEEDED {VICTIM.decode()} -> {new.decode()} (in place, {len(VICTIM)} bytes at .dynstr+{off:#x})")

if __name__ == "__main__":
    main()
