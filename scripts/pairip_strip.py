#!/usr/bin/env python3
"""Neutralise Google Play's PairIP protection in the BASE apk (dex-only patch).

Usage: pairip_strip.py <in base.apk> <out base.apk>
Env:   BAKSMALI / SMALI  -- command (or "java -jar x.jar") for baksmali / smali
                            (default: tools/baksmali.jar + tools/smali.jar if present, else PATH)

Why: Rec Room ships PairIP. At class-init time com.pairip.application.Application runs an
encrypted program inside the native libpairipcore.so, which verifies the APK/signature and
deliberately SEGVs (about 1 s after launch) when it isn't the Play-signed original -- before
Unity or our hook library ever load. This patches ONLY classes.dex:

  Application            no StartupLauncher.launch(), no SignatureCheck.verifyIntegrity()
  VMRunner               never System.loadLibrary("pairipcore"); invoke() returns null
  SignatureCheck         verifyIntegrity() -> no-op
  LicenseContentProvider onCreate() -> no license check / no "get it from Play" activity
  CombineContinuationsWorker.doWork()  -> Result.success()   (was a VM stub)

PairIP also moved ~21 methods into its VM (androidx.work, media3, firebase/gms, Play Core
assetpacks, webrtc, singular). Void handlers become harmless no-ops, but VALUE-RETURNING ones
would now return null: Firebase's FirebaseCommonRegistrar.safeValue() did, and Firebase init
crashed the process on every launch. restore_virtualized() puts known bodies back
(KNOWN_RESTORES) and reports/stubs the rest (PAIRIP_STRICT=1 makes unknown ones fatal). Resources/manifest are untouched, so the
manifest still names the (now inert) pairip classes. By default libpairipcore.so is never loaded from Java,
BUT libil2cpp.so / libwebrtc.so / lib_burst_generated.so DT_NEED it and run its ExecuteProgram from an
injected DT_INIT, which needs JNI_OnLoad to have run first: set PAIRIP_KEEP_PAIRIPCORE=1 (see below).

String holders: PairIP also moved ~1500 string literals (incl. Firebase's "kotlin" library name,
which is what actually made FirebaseCommonRegistrar.getComponents NPE) into static fields of ~32
empty holder classes that only the startup program fills. Dropping the program leaves them all
null, so materialize_holders.py adds a static initialiser to each holder class with the real
values from scripts/holders/holders.json (made once by scripts/dump_holders.py from a stock run).
In fallback mode WorkManager's startup initialiser is also skipped (its SQL is placeholders);
PAIRIP_KEEP_WORKMANAGER=1 keeps it.
Env: HOLDERS_JSON (path), PAIRIP_REQUIRE_HOLDERS=1 (fail if no dump), PAIRIP_ALLOW_MISSING_HOLDERS=1,
PAIRIP_HOLDER_FALLBACK=placeholder (no dump needed: seed values where certain, "~field" elsewhere --
a boot-test stopgap, not a fix; see HOLDERS-README.md).
"""
import os, re, shlex, shutil, subprocess, sys, tempfile, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.environ.get("TOOLS", os.path.join(HERE, "..", "tools"))
sys.path.insert(0, HERE)
import materialize_holders as mh
import signin_fallback as sf

def tool(env, name):
    if os.environ.get(env):
        return shlex.split(os.environ[env])
    jar = os.path.join(TOOLS, name + ".jar")
    if os.path.isfile(jar):
        return ["java", "-jar", jar]
    p = shutil.which(name)
    if p:
        return [p]
    sys.exit(f"{name} not found: put {name}.jar in tools/, install it (apt install smali), or set {env}")

def method_re(sig):
    return re.compile(r"\.method [^\n]*?" + re.escape(sig) + r"[^\n]*\n.*?\.end method\n", re.S)

def replace_method(text, sig, new_body, path):
    pat = method_re(sig)
    if not pat.search(text):
        sys.exit(f"pairip_strip: method '{sig}' not found in {path} -- different build?")
    return pat.sub(lambda m: new_body, text, count=1)

def drop_line(text, line_re, path):
    new, n = re.subn(r"[ \t]*" + line_re + r"[ \t]*\n(\s*\n)?", "", text, count=1)
    if n != 1:
        sys.exit(f"pairip_strip: expected line /{line_re}/ not found in {path} -- different build?")
    return new

# ---- PairIP-virtualised methods -------------------------------------------------------------
# PairIP moves some method bodies into its VM: the method becomes a stub that calls
# VMRunner.invoke("<id>", args) and returns whatever that gives back. With the VM gone
# invoke() returns null, so every such method that RETURNS A VALUE now returns null/0/false.
# Firebase's FirebaseCommonRegistrar.safeValue(String) is one of them: it came back null and
# FirebaseInitProvider died on every launch with
#   NPE at AutoValue_LibraryVersion.<init> <- FirebaseCommonRegistrar.getComponents:106
# (the whole app is killed before Unity or the hook library load). Void handlers are harmless
# as no-ops; value-returning ones need their real body back.
KNOWN_RESTORES = {
    # firebase-common: value.replace(' ', '_').replace('/', '_')
    ("com.google.firebase.FirebaseCommonRegistrar",
     "safeValue(Ljava/lang/String;)Ljava/lang/String;"):
        "    .registers 3\n\n"
        "    const/16 v0, 0x20\n    const/16 v1, 0x5f\n"
        "    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->replace(CC)Ljava/lang/String;\n"
        "    move-result-object p0\n"
        "    const/16 v0, 0x2f\n"
        "    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->replace(CC)Ljava/lang/String;\n"
        "    move-result-object p0\n"
        "    return-object p0\n",
}

VM_CALL = "Lcom/pairip/VMRunner;->invoke"

def _dump(cls, header, body):
    """Append the stubbed method to $PAIRIP_DUMP so its real body can be rebuilt by hand."""
    path = os.environ.get("PAIRIP_DUMP")
    if not path:
        return
    lines = [l for l in body.splitlines() if l.strip()]
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"### {cls} :: {header.strip()}\n" + "\n".join(lines[:40]) + "\n\n")
_METHOD_RE = re.compile(r"^\.method ([^\n]*)\n(.*?)^\.end method\n", re.S | re.M)
_SIG_RE = re.compile(r"(\S+)\((.*?)\)(\S+)$")

def _param_words(params, static):
    n = 0 if static else 1
    i = 0
    while i < len(params):
        c = params[i]
        if c in "JD":
            n += 2; i += 1
        elif c == "[":
            while params[i] == "[": i += 1
            if params[i] == "L": i = params.index(";", i)
            n += 1; i += 1
        elif c == "L":
            i = params.index(";", i) + 1; n += 1
        else:
            n += 1; i += 1
    return n

def _default_return(ret):
    """smali body returning the zero value of `ret`."""
    if ret == "V":
        return "    .locals 0\n\n    return-void\n"
    if ret in ("J", "D"):
        return "    .locals 2\n\n    const-wide/16 v0, 0x0\n\n    return-wide v0\n"
    if ret[0] in "L[":
        return "    .locals 1\n\n    const/4 v0, 0x0\n\n    return-object v0\n"
    return "    .locals 1\n\n    const/4 v0, 0x0\n\n    return v0\n"

def restore_virtualized(smali_dir):
    """Give every PairIP-virtualised, value-returning method a sane body.
    Returns (restored, defaulted) lists of 'Class.method' strings."""
    restored, defaulted, voids = [], [], 0
    for root, _, files in os.walk(smali_dir):
        for f in files:
            if not f.endswith(".smali"):
                continue
            path = os.path.join(root, f)
            text = open(path, encoding="utf-8").read()
            if VM_CALL not in text:
                continue
            cls = os.path.relpath(path, smali_dir)[:-len(".smali")].replace(os.sep, ".")
            if cls.startswith("com.pairip."):
                continue                       # handled explicitly in main()
            def fix(m):
                nonlocal voids
                header, body = m.group(1), m.group(2)
                if VM_CALL not in body:
                    return m.group(0)
                _dump(cls, header, body)
                sm = _SIG_RE.search(header.strip())
                if not sm:
                    return m.group(0)
                name, params, ret = sm.groups()
                key = (cls, f"{name}({params}){ret}")
                if key in KNOWN_RESTORES:
                    restored.append(f"{cls}.{name}")
                    return f".method {header}\n{KNOWN_RESTORES[key]}.end method\n"
                if ret == "V":
                    voids += 1                 # no-op already (invoke() result unused)
                    return m.group(0)
                defaulted.append(f"{cls}.{name}({params}){ret}")
                return f".method {header}\n{_default_return(ret)}.end method\n"
            new = _METHOD_RE.sub(fix, text)
            if new != text:
                open(path, "w", encoding="utf-8").write(new)
    print(f"pairip_strip: virtualised methods: {len(restored)} restored, "
          f"{len(defaulted)} value-returning stubbed to null/0, {voids} void (no-op)")
    for r in restored:
        print(f"   restored  {r}")
    for d in defaulted:
        print(f"   WARNING stubbed to default (original body is gone): {d}")
    if defaulted and os.environ.get("PAIRIP_STRICT") == "1":
        sys.exit("pairip_strip: PAIRIP_STRICT=1 and unknown value-returning methods remain -- "
                 "add them to KNOWN_RESTORES")
    return restored, defaulted

WM_INIT = "androidx/work/WorkManagerInitializer.smali"
WM_CREATE_RE = re.compile(
    r"\.method public create\(Landroid/content/Context;\)Landroidx/work/WorkManager;.*?\.end method", re.S)
WM_CREATE_NEW = (".method public create(Landroid/content/Context;)Landroidx/work/WorkManager;\n"
                 "    .locals 1\n\n    const/4 p1, 0x0\n\n    return-object p1\n.end method")


def disable_workmanager_init(sm):
    """Fallback mode only: WorkManager's Room/SQL strings are placeholders, so its first database
    access throws on a background thread and kills the process. Nothing in this app uses WorkManager
    (only media3's optional offline-download scheduler references it), so skip its startup initialiser.
    """
    p = os.path.join(sm, WM_INIT)
    if not os.path.isfile(p):
        return False
    t = open(p, encoding="utf-8").read()
    new, n = WM_CREATE_RE.subn(lambda m: WM_CREATE_NEW, t, count=1)
    if n != 1:
        sys.exit("pairip_strip: WorkManagerInitializer.create not in the expected form")
    open(p, "w", encoding="utf-8").write(new)
    return True


def harden_firebase_libversion(smali_dir):
    """Safety net: whichever virtualised value feeds LibraryVersion.create(name, version) came
    back null, make create() substitute "unknown" instead of letting AutoValue throw NPE."""
    path = os.path.join(smali_dir, "com/google/firebase/platforminfo/LibraryVersion.smali")
    if not os.path.isfile(path):
        return False
    t = open(path, encoding="utf-8").read()
    pat = re.compile(r"^\.method ([^\n]*?)create\(Ljava/lang/String;Ljava/lang/String;\)"
                     r"Lcom/google/firebase/platforminfo/LibraryVersion;\n.*?^\.end method\n", re.S | re.M)
    m = pat.search(t)
    if not m:
        print("pairip_strip: WARNING LibraryVersion.create(String,String) not found -- skipped")
        return False
    new = (f".method {m.group(1)}create(Ljava/lang/String;Ljava/lang/String;)"
           "Lcom/google/firebase/platforminfo/LibraryVersion;\n"
           "    .registers 4\n\n"
           "    if-nez p0, :n0\n    const-string p0, \"unknown\"\n    :n0\n"
           "    if-nez p1, :n1\n    const-string p1, \"unknown\"\n    :n1\n"
           "    new-instance v0, Lcom/google/firebase/platforminfo/AutoValue_LibraryVersion;\n"
           "    invoke-direct {v0, p0, p1}, Lcom/google/firebase/platforminfo/AutoValue_LibraryVersion;"
           "-><init>(Ljava/lang/String;Ljava/lang/String;)V\n"
           "    return-object v0\n.end method\n")
    open(path, "w", encoding="utf-8").write(t[:m.start()] + new + t[m.end():])
    print("pairip_strip: hardened Firebase LibraryVersion.create against null name/version")
    return True

def main():
    src, dst = sys.argv[1], sys.argv[2]
    baksmali, smali = tool("BAKSMALI", "baksmali"), tool("SMALI", "smali")
    work = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(src) as z:
            dexes = sorted((n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)),
                           key=lambda n: int(n[7:-4] or 1))
            if not dexes:
                sys.exit("no classes*.dex in base apk")
            blobs = {n: z.read(n) for n in dexes}
        if not any(b"Lcom/pairip/VMRunner;" in d for d in blobs.values()):
            print("pairip_strip: no PairIP in any dex -- copying unchanged")
            shutil.copyfile(src, dst); return
        print(f"pairip_strip: dex files: {', '.join(dexes)}")
        if os.environ.get("PAIRIP_DUMP"):
            open(os.environ["PAIRIP_DUMP"], "w").close()

        # Explicit PairIP edits: (class, fn). Each is applied in whichever dex defines the class.
        # PAIRIP_KEEP_STARTUP=1: let PairIP's own startup program run (StartupLauncher.launch() ->
        # VMRunner.invoke -> native executeVM) and keep the real VMRunner.invoke/loadLibrary. Only the
        # Java-side SignatureCheck.verifyIntegrity stays neutralised. Diagnostic for the native
        # DT_INIT stubs in libil2cpp/libwebrtc/lib_burst_generated (see PHONE notes).
        keep_startup = os.environ.get("PAIRIP_KEEP_STARTUP", "").lower() not in ("", "0", "no", "false")
        def drop_launch(t, p):
            if not keep_startup:
                t = drop_line(t, r"invoke-static \{\}, Lcom/pairip/StartupLauncher;->launch\(\)V", p)
            return drop_line(t, r"invoke-static \{p1\}, Lcom/pairip/SignatureCheck;->verifyIntegrity\(Landroid/content/Context;\)V", p)
        def vmrunner(t, p):
            # PAIRIP_KEEP_PAIRIPCORE=1: keep System.loadLibrary("pairipcore") so its JNI_OnLoad runs.
            # libil2cpp/libwebrtc/lib_burst_generated carry a PairIP DT_INIT stub that calls
            # ExecuteProgram(); that refuses to run (leaving 200 GOT slots unfilled -> SIGSEGV in
            # libil2cpp's ctors) unless JNI_OnLoad initialised the library first.
            if keep_startup:
                print("pairip_strip: PAIRIP_KEEP_STARTUP on -- VMRunner left completely untouched")
                return t
            if os.environ.get("PAIRIP_KEEP_PAIRIPCORE", "").lower() in ("", "0", "no", "false"):
                t = drop_line(t, r'const-string v0, "pairipcore"', p)
                t = drop_line(t, r"invoke-static \{v0\}, Ljava/lang/System;->loadLibrary\(Ljava/lang/String;\)V", p)
            else:
                print("pairip_strip: PAIRIP_KEEP_PAIRIPCORE on -- VMRunner keeps System.loadLibrary(\"pairipcore\")")
            return replace_method(t, "invoke(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;",
                ".method public static invoke(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;\n"
                "    .registers 3\n\n    const/4 v0, 0x0\n\n    return-object v0\n.end method\n", p)
        edits = {
            "com.pairip.application.Application": drop_launch,
            "com.pairip.VMRunner": vmrunner,
            "com.pairip.SignatureCheck": lambda t, p: replace_method(t,
                "verifyIntegrity(Landroid/content/Context;)V",
                ".method public static verifyIntegrity(Landroid/content/Context;)V\n"
                "    .registers 1\n\n    return-void\n.end method\n", p),
            "com.pairip.licensecheck.LicenseContentProvider": lambda t, p: replace_method(t,
                "onCreate()Z",
                ".method public onCreate()Z\n    .registers 2\n\n    const/4 v0, 0x1\n\n    return v0\n.end method\n", p),
            "androidx.work.impl.workers.CombineContinuationsWorker": lambda t, p: replace_method(t,
                "doWork()Landroidx/work/ListenableWorker$Result;",
                ".method public doWork()Landroidx/work/ListenableWorker$Result;\n    .registers 2\n\n"
                "    invoke-static {}, Landroidx/work/ListenableWorker$Result;->success()Landroidx/work/ListenableWorker$Result;\n\n"
                "    move-result-object v0\n\n    return-object v0\n.end method\n", p),
        }
        done_edits, hardened, wm_off = set(), False, False
        signin_done = False
        new_dexes = {}

        holders_path = os.environ.get("HOLDERS_JSON", os.path.join(HERE, "holders", "holders.json"))
        holders, done_holders = None, set()
        fallback = os.environ.get("PAIRIP_HOLDER_FALLBACK", "").lower() not in ("", "0", "no", "false")
        seed_path = os.environ.get("HOLDERS_SEED", os.path.join(HERE, "holders", "holders_seed.json"))
        seed = mh.load(seed_path) if fallback and os.path.isfile(seed_path) else {}
        if os.path.isfile(holders_path):
            holders = mh.load(holders_path)
            print(f"pairip_strip: holder strings: {sum(len(v) for v in holders.values())} values for "
                  f"{len(holders)} classes from {holders_path}")
        elif os.environ.get("PAIRIP_REQUIRE_HOLDERS"):
            sys.exit(f"pairip_strip: PAIRIP_REQUIRE_HOLDERS=1 but {holders_path} not found "
                     f"(run scripts/dump_holders.py)")
        elif fallback:
            holders = {}
            print(f"pairip_strip: no {holders_path}: PAIRIP_HOLDER_FALLBACK is on, ALL holder strings will "
                  f"come from the seed file or be placeholders (boot-test stopgap)")
        else:
            print(f"pairip_strip: WARNING {holders_path} not found -- PairIP's ~1500 string fields stay "
                  f"NULL, expect NullPointerExceptions (run scripts/dump_holders.py)")
        marks = list(holders or [])
        if holders is not None and not marks:          # fallback with no dump: use the shipped class list
            lst = os.path.join(HERE, "holders", "holder_classes.txt")
            if os.path.isfile(lst):
                marks = [l.split("#", 1)[0].strip() for l in open(lst, encoding="utf-8")]
                marks = [m for m in marks if m]
        holder_marks = [mh.to_desc(c).encode() for c in marks]
        for name in dexes:
            dex = blobs[name]
            has_vm = b"Lcom/pairip/VMRunner;" in dex
            has_fb = b"Lcom/google/firebase/platforminfo/LibraryVersion;" in dex
            has_cls = any(c.replace(".", "/").encode() in dex for c in edits)
            has_holder = any(m in dex for m in holder_marks)
            has_signin = sf.enabled() and b"Lcom/recroom/googleplaynative/SignInActivity;" in dex
            if not (has_vm or has_fb or has_cls or has_holder or has_signin):
                continue
            print(f"pairip_strip: processing {name}")
            sm = f"{work}/sm_{name}"
            open(f"{work}/{name}", "wb").write(dex)
            subprocess.check_call(baksmali + ["d", f"{work}/{name}", "-o", sm])
            for cls, fn in edits.items():
                p = os.path.join(sm, cls.replace(".", "/") + ".smali")
                if os.path.isfile(p):
                    t = open(p).read(); open(p, "w").write(fn(t, p)); done_edits.add(cls)
            restore_virtualized(sm)
            hardened |= harden_firebase_libversion(sm)
            if sf.enabled():
                _sf_hit = sf.patch(sm)
                signin_done |= _sf_hit
                if _sf_hit and sf.device_mode():
                    print("pairip_strip: DEVICE-BOUND platform id mode ON (no Google popup)")
            if holders is not None:
                done_holders |= mh.materialize(
                    sm, holders, allow_missing=bool(os.environ.get("PAIRIP_ALLOW_MISSING_HOLDERS")),
                    fallback=fallback, seed=seed)
            if fallback and not os.environ.get("PAIRIP_KEEP_WORKMANAGER"):
                wm_off |= disable_workmanager_init(sm)
            out = f"{work}/new_{name}"
            subprocess.check_call(smali + ["a", "-a", "26", sm, "-o", out])
            new_dexes[name] = open(out, "rb").read()
            if sf.enabled() and sf.device_mode() and os.path.isfile(os.path.join(sm, sf.CLS)) \
                    and b"2025-device-v1" not in new_dexes[name]:
                sys.exit("pairip_strip: device-bound sign-in was NOT compiled into the dex -- aborting (would ship id 1)")
            print(f"pairip_strip: {name}: {len(dex)} -> {len(new_dexes[name])} bytes")
        missing = set(edits) - done_edits
        if missing:
            sys.exit(f"pairip_strip: classes not found in any dex: {sorted(missing)} -- different build?")
        if sf.enabled() and not signin_done:
            sys.exit("pairip_strip: SignInActivity not found in any dex -- different build? "
                     "(SIGNIN_FALLBACK=0 skips the Google sign-in fallback)")
        if not hardened:
            print("pairip_strip: WARNING Firebase LibraryVersion.create not found in any dex -- hardening skipped")
        if fallback and not os.environ.get("PAIRIP_KEEP_WORKMANAGER"):
            print("pairip_strip: WorkManager initializer " + ("disabled (fallback mode)" if wm_off
                  else "NOT FOUND -- not disabled"))
        if holders is not None:
            lost = set(holders) - done_holders
            if lost:
                sys.exit(f"pairip_strip: {len(lost)} holder class(es) from {holders_path} not found in any "
                         f"dex (dump is from a different build?): "
                         f"{', '.join(mh.to_dotted(d) for d in sorted(lost)[:5])}")
            print(f"pairip_strip: materialised {len(done_holders)} holder classes")

        with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst, "w") as zo:
            for info in zi.infolist():
                n = info.filename
                if n.startswith("META-INF/") and n.upper().endswith((".SF", ".RSA", ".DSA", ".EC", ".MF")):
                    continue           # old signature; apksigner writes a new one
                if n in new_dexes:
                    zo.writestr(zipfile.ZipInfo(n, date_time=(2026, 1, 1, 0, 0, 0)),
                                new_dexes[n], compress_type=zipfile.ZIP_STORED)   # stock apk stores dex
                else:
                    zo.writestr(info, zi.read(n), compress_type=info.compress_type)
        print(f"pairip_strip: patched {', '.join(new_dexes)}; wrote {dst}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

if __name__ == "__main__":
    main()
