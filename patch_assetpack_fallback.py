#!/usr/bin/env python3
"""Run from the project root:  python3 patch_assetpack_fallback.py
Rewrites arm_assetpack_hook() in src/2025_hook.cpp so that when
AndroidAssetPacks.GetAssetPackPath has no native body (stripped), it
  1. logs every method of AndroidAssetPacks / AndroidAssetPacksInternal, and
  2. falls back to hooking the engine icall behind the wrapper.
"""
import re, sys, pathlib

p = pathlib.Path("src/2025_hook.cpp")
s = p.read_text(encoding="utf-8")
if "rf_dump_class_methods" in s:
    sys.exit("already patched")

start = s.index("static void arm_assetpack_hook() {")
end = s.index("    init_stub_root();\n    A64HookFunction(fn, (void *)hk_GetAssetPackPath")
# keep the guard variable line that precedes start
new_fn = r'''// Diagnostic: log every method of a class (name, argc, native pointer).
static void rf_dump_class_methods(void *h, void *klass, const char *label) {
    typedef void *(*get_methods_t)(void *, void **);
    typedef const char *(*mname_t)(void *);
    typedef uint32_t (*mpc_t)(void *);
    get_methods_t gm = (get_methods_t)dlsym(h, "il2cpp_class_get_methods");
    mname_t mn = (mname_t)dlsym(h, "il2cpp_method_get_name");
    mpc_t pc = (mpc_t)dlsym(h, "il2cpp_method_get_param_count");
    if (!gm || !mn || !pc || !klass) { LOGE("assetpack: cannot dump %s", label); return; }
    void *iter = nullptr, *m;
    int n = 0;
    while ((m = gm(klass, &iter)) && n++ < 60)
        LOGI("assetpack: %s.%s(%u) ptr=%p", label, mn(m), pc(m), *(void **)m);
}

static void arm_assetpack_hook() {
    if (!__sync_bool_compare_and_swap(&g_assetpack_armed, 0, 1)) return;
    if (!il2cpp_domain_get_assemblies || !il2cpp_assembly_get_image || !il2cpp_image_get_name ||
        !il2cpp_class_from_name) {
        LOGE("assetpack: il2cpp reflection exports missing; not armed");
        return;
    }
    void *h = dlopen("libil2cpp.so", RTLD_NOW | RTLD_NOLOAD);
    void *dom = il2cpp_domain_get();
    size_t cnt = 0;
    void **asms = dom ? il2cpp_domain_get_assemblies(dom, &cnt) : nullptr;
    void *klass = nullptr, *iklass = nullptr;
    for (size_t i = 0; asms && i < cnt && !klass; i++) {
        void *img = il2cpp_assembly_get_image(asms[i]);
        const char *nm = img ? il2cpp_image_get_name(img) : nullptr;
        if (nm && strncmp(nm, "UnityEngine.AndroidJNIModule", 28) == 0) {
            klass = il2cpp_class_from_name(img, "UnityEngine.Android", "AndroidAssetPacks");
            iklass = il2cpp_class_from_name(img, "UnityEngine.Android", "AndroidAssetPacksInternal");
        }
    }
    if (!klass) { LOGE("assetpack: AndroidAssetPacks class not found (%zu assemblies)", cnt); return; }
    void *mi = il2cpp_class_get_method_from_name(klass, "GetAssetPackPath", 1);
    void *fn = mi ? *(void **)mi : nullptr;  // MethodInfo::methodPointer is the first field
    LOGI("assetpack: AndroidAssetPacks.GetAssetPackPath mi=%p native=%p", mi, fn);
    if (!fn) {
        // Wrapper has no native body (stripped, or never called). Dump what does exist,
        // then try the engine icall the wrapper would have used.
        rf_dump_class_methods(h, klass, "AndroidAssetPacks");
        rf_dump_class_methods(h, iklass, "AndroidAssetPacksInternal");
        typedef void *(*resolve_icall_t)(const char *);
        resolve_icall_t ri = h ? (resolve_icall_t)dlsym(h, "il2cpp_resolve_icall") : nullptr;
        static const char *names[] = {
            "UnityEngine.Android.AndroidAssetPacksInternal::GetAssetPackPath",
            "UnityEngine.Android.AndroidAssetPacksInternal::GetAssetPackPath_Injected",
            "UnityEngine.Android.AndroidAssetPacks::GetAssetPackPath",
        };
        for (size_t i = 0; ri && i < sizeof(names) / sizeof(names[0]) && !fn; i++) {
            fn = ri(names[i]);
            LOGI("assetpack: icall %s -> %p", names[i], fn);
        }
        if (!fn) { LOGE("assetpack: GetAssetPackPath not found (no native body, no icall)"); return; }
    }
    // A64HookFunction overwrites 20 bytes; refuse a body that returns inside that window.
    const uint32_t *w = (const uint32_t *)fn;
    for (int i = 0; i < 5; i++)
        if (w[i] == 0xd65f03c0u) { LOGE("assetpack: target %p too short to hook; not armed", fn); return; }
'''
s = s[:start] + new_fn + s[end:]
p.write_text(s, encoding="utf-8")
print("patched", p)
