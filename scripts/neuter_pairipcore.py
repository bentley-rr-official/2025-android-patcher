#!/usr/bin/env python3
"""Turn Google's libpairipcore.so into an inert stub (same file, same exports, no behaviour).

Why: on the phone the REAL libpairipcore crashes inside System.loadLibrary("pairipcore")
(SIGSEGV SEGV_ACCERR, pc = libpairipcore+0x5b820, `ldr q0,[x21]` with x21 = base + (uint16 idx << 4),
main thread, ~35 ms after the load). PairIP's VM state is bound to the Play-signed original package, so in a
re-signed / patched APK it walks off a table instead of failing cleanly. Nothing we ship needs its program any
more: libgfi.so / libgfw.so already restore the hidden GOT slots, the scrambled .data words and libwebrtc's code.
libil2cpp / libwebrtc / lib_burst_generated still DT_NEED this lib and their DT_INIT stub still calls
ExecuteProgram(); with the stub that call just returns.

What is patched (everything else byte-identical, file size unchanged, no relocation/layout change):
  ExecuteProgram  -> mov x0,#0 ; ret
  JNI_OnLoad      -> mov w0,#0x10006 (JNI_VERSION_1_6) ; ret
  JNI_OnUnload    -> ret
  DT_INIT_ARRAYSZ / DT_FINI_ARRAYSZ -> 0   (its 7 static constructors never run either)
The lib carries no BTI/PAC property note, so no landing-pad instruction is required at the entry points.

usage: neuter_pairipcore.py <in libpairipcore.so> <out libpairipcore.so>
"""
import struct, sys

MOV_X0_0, RET = 0xD2800000, 0xD65F03C0
MOVZ_W0_6, MOVK_W0_1_LSL16 = 0x528000C0, 0x72A00020      # w0 = 0x10006

src, dst = sys.argv[1:3]
d = bytearray(open(src, "rb").read())
if d[:4] != b"\x7fELF" or d[4] != 2 or struct.unpack_from("<H", d, 0x12)[0] != 183:
    sys.exit("not an AArch64 ELF64")

phoff, = struct.unpack_from("<Q", d, 0x20); phn, = struct.unpack_from("<H", d, 0x38)
# --- program headers: vaddr -> file offset, DYNAMIC
loads, dyn = [], None
for i in range(phn):
    ty, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", d, phoff + 56 * i)
    if ty == 1: loads.append((va, off, fsz))
    if ty == 2: dyn = (off, fsz)
def foff(va):
    for v, o, f in loads:
        if v <= va < v + f: return o + va - v
    sys.exit("vaddr %#x not in a PT_LOAD" % va)

# --- dynamic table
tags = {}
o, n = dyn
for k in range(0, n, 16):
    t, v = struct.unpack_from("<qQ", d, o + k)
    if t == 0: break
    tags.setdefault(t, []).append((o + k, v))
symtab, strtab = tags[6][0][1], tags[5][0][1]
# --- find the three exports by name (DT_HASH gives the symbol count)
nsym = struct.unpack_from("<I", d, foff(tags[4][0][1]) + 4)[0]
want, found = {"ExecuteProgram", "JNI_OnLoad", "JNI_OnUnload"}, {}
for i in range(nsym):
    nm, info, oth, shn_, val, sz = struct.unpack_from("<IBBHQQ", d, foff(symtab) + 24 * i)
    a = foff(strtab) + nm; name = bytes(d[a:d.index(b"\0", a)]).decode()
    if name in want and shn_: found[name] = (val, sz)
if set(found) != want: sys.exit("missing exports: %s" % (want - set(found)))

def put(va, words):
    o = foff(va); assert len(words) * 4 <= found_sz[va]
    for k, w in enumerate(words): struct.pack_into("<I", d, o + 4 * k, w)
found_sz = {v: s for v, s in found.values()}
put(found["ExecuteProgram"][0], [MOV_X0_0, RET])
put(found["JNI_OnLoad"][0],     [MOVZ_W0_6, MOVK_W0_1_LSL16, RET])
put(found["JNI_OnUnload"][0],   [RET])
for tag in (0x1B, 0x1C):                       # DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ
    for off, _ in tags.get(tag, []): struct.pack_into("<Q", d, off + 8, 0)
for tag in (0xC, 0xD):                         # DT_INIT / DT_FINI (this lib has none; guard anyway)
    if tag in tags: sys.exit("unexpected DT_INIT/DT_FINI in libpairipcore -- stub not written")
open(dst, "wb").write(d)
print("neuter_pairipcore: ExecuteProgram@%#x JNI_OnLoad@%#x JNI_OnUnload@%#x patched, init/fini arrays disabled -> %s"
      % (found["ExecuteProgram"][0], found["JNI_OnLoad"][0], found["JNI_OnUnload"][0], dst))
