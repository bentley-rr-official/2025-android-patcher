#!/usr/bin/env python3
"""Run from the project root AFTER patch_assetpack_fallback.py:
    python3 patch_assetpack_rva.py
Makes the asset-pack stub hook AndroidAssetPacks.GetAssetPackPath by fixed RVA
(0x171d2f5c on the 20250718.01 phone build, libil2cpp md5 ef682fb3...) when the
name-based MethodInfo pointer comes back null.
"""
import pathlib, sys

p = pathlib.Path("src/2025_hook.cpp")
s = p.read_text(encoding="utf-8")
if "kGetAssetPackPathRVA" in s:
    sys.exit("already patched")

anchor = "// Diagnostic: log every method of a class (name, argc, native pointer)."
if anchor not in s:
    sys.exit("run patch_assetpack_fallback.py first (anchor not found)")
s = s.replace(anchor,
    "// UnityEngine.Android.AndroidAssetPacks.GetAssetPackPath(string) -- phone build 20250718.01,\n"
    "// resolved from the metadata (scripts/rebase-phone/resolve.py). The MethodInfo pointer from\n"
    "// il2cpp_class_get_method_from_name() read back null on this runtime, so use the RVA.\n"
    "static const uintptr_t kGetAssetPackPathRVA = 0x171d2f5cUL;\n\n" + anchor, 1)

log = '    LOGI("assetpack: AndroidAssetPacks.GetAssetPackPath mi=%p native=%p", mi, fn);\n'
if log not in s:
    sys.exit("expected log line not found")
s = s.replace(log, log +
    "#ifdef RF_PHONE\n"
    "    if (!fn && g_il2cpp_base) {\n"
    "        fn = (void *)(g_il2cpp_base + kGetAssetPackPathRVA);\n"
    "        LOGI(\"assetpack: using RVA 0x%lx -> %p\", (unsigned long)kGetAssetPackPathRVA, fn);\n"
    "    }\n"
    "#endif\n", 1)
p.write_text(s, encoding="utf-8")
print("patched", p)
