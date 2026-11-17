#!/usr/bin/env bash
#
# Android phone/tablet build (Rec Room 20250718.01, versionCode 23568923, arm64).
# Takes the XAPK and produces re-signed split APKs + install scripts. Does NOT rename the
# package, so the huge asset packs are only re-signed, never decoded (all splits of one app
# must share the base's signing cert).
#
# Usage:  build-phone.sh <RecRoom.xapk>        -> build/phone/signed/*.apk + install.sh/.ps1
#
# Env (all optional):
#   ANDROID_NDK  NDK root (r27c)                         default ~/x/ndk/android-ndk-r27c
#   TOOLS        dir with zipalign, lib/apksigner.jar, debug.keystore   default <repo>/tools
#                (zipalign / apksigner found on PATH are used if not in TOOLS)
#   CONFIG       2025.cfg to bake in                   default <repo>/2025.cfg
#   HOOK_SO      use this prebuilt libvrsupport.so instead of compiling (CI / no NDK)
#   NOHOOK=1     DIAGNOSTIC: re-sign the untouched XAPK (no hook lib, no injection) to test whether a crash
#                comes from re-signing alone (e.g. PairIP) or from the hook
#   NOCRASHLOG=1 leave src/crashlog.cpp (native crash logger, tag CRASHLOG) out of the hook lib
#   KEEPBURST=1  keep lib_burst_generated.so in the split (default: dropped, see the Burst block below)
#   NOGOTFIX=1   skip the PairIP GOT fill (libgf*.so + in-place NEEDED patch of libil2cpp/libwebrtc)
#   FORCE=1      continue even if versionCode / libil2cpp md5 don't match (RVAs WILL be wrong)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
XAPK="${1:?usage: build-phone.sh <RecRoom.xapk>}"
ANDROID_NDK="${ANDROID_NDK:-$HOME/x/ndk/android-ndk-r27c}"
TOOLS="${TOOLS:-$REPO/tools}"; CONFIG="${CONFIG:-$REPO/2025.cfg}"
OUT="$REPO/build/phone"; GEN="$REPO/build/gen"
FORCE="${FORCE:-0}"; HOOK_SO="${HOOK_SO:-}"; NOHOOK="${NOHOOK:-0}"

EXPECT_VC=23568923
EXPECT_IL2CPP_MD5=ef682fb3e6b8d093d605b4f5e53e11e7
ABI_DIR="lib/arm64-v8a"

die() { echo "ERROR: $*" >&2; exit 1; }
warn_or_die() { if [ "$FORCE" = 1 ]; then echo "!! $* (FORCE=1, continuing)"; else die "$* (set FORCE=1 to override -- hooks will land on wrong code)"; fi; }

# ---- tools --------------------------------------------------------------------------------
[ -f "$XAPK" ] || [ -d "$XAPK" ] || die "XAPK not found (need the .xapk file or its unzipped folder): $XAPK"
ZIPALIGN="$TOOLS/zipalign"; [ -x "$ZIPALIGN" ] || ZIPALIGN="$(command -v zipalign || true)"
[ -n "$ZIPALIGN" ] || die "zipalign not found (put it in $TOOLS or install build-tools)"
if [ -f "$TOOLS/lib/apksigner.jar" ]; then APKSIGNER=(java -jar "$TOOLS/lib/apksigner.jar")
elif command -v apksigner >/dev/null; then APKSIGNER=(apksigner)
else die "apksigner not found (put lib/apksigner.jar in $TOOLS or install it)"; fi
KS="$TOOLS/debug.keystore"
[ -f "$KS" ] || die "missing $KS (run scripts/make-keystore.sh)"
python3 -c "import lief" 2>/dev/null || die "python 'lief' missing: pip install lief"
command -v java >/dev/null || die "java not found"

CLANG="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++"
if [ -z "$HOOK_SO" ] && [ ! -x "$CLANG" ]; then die "NDK clang not found: $CLANG (set ANDROID_NDK, or HOOK_SO=<prebuilt libvrsupport.so>)"; fi
[ -z "$HOOK_SO" ] || [ -f "$HOOK_SO" ] || die "HOOK_SO not found: $HOOK_SO"

rm -rf "$OUT"; mkdir -p "$OUT/in" "$OUT/tmp" "$GEN"

# ---- unpack + identify --------------------------------------------------------------------
echo ">> unpack XAPK"
if [ -d "$XAPK" ]; then   # already-unzipped XAPK folder
  XAPK="${XAPK%/}"
  ls "$XAPK"/*.apk >/dev/null 2>&1 \
    || die "$XAPK has no *.apk at its top level (point at the folder that contains them): $(ls "$XAPK" | head -8 | tr '\n' ' ')"
  cp "$XAPK"/*.apk "$OUT/in/" 2>/dev/null || true
  [ -f "$XAPK/manifest.json" ] && cp "$XAPK/manifest.json" "$OUT/in/"
else
  unzip -q -o "$XAPK" '*.apk' -d "$OUT/in"
  unzip -q -o "$XAPK" 'manifest.json' -d "$OUT/in" 2>/dev/null || true
fi
SPLIT="$OUT/in/config.arm64_v8a.apk"
[ -f "$SPLIT" ] || die "no config.arm64_v8a.apk in XAPK (this build is arm64-only)"
if [ -f "$OUT/in/manifest.json" ]; then
  VC="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['version_code'])" "$OUT/in/manifest.json")"
else
  echo "   no manifest.json in XAPK; assuming target versionCode $EXPECT_VC (use FORCE=1 for mismatches)"
  VC="$EXPECT_VC"
fi
[ "$VC" = "$EXPECT_VC" ] || warn_or_die "versionCode $VC != $EXPECT_VC"
IL_MD5="$(unzip -p "$SPLIT" "$ABI_DIR/libil2cpp.so" | md5sum | cut -d' ' -f1)"
[ "$IL_MD5" = "$EXPECT_IL2CPP_MD5" ] || warn_or_die "libil2cpp.so md5 $IL_MD5 != $EXPECT_IL2CPP_MD5"
echo "   versionCode $VC, libil2cpp md5 $IL_MD5"

# ---- PairIP strip on the BASE apk (our copy in $OUT/in; the source XAPK folder is never touched) ----
# NOSTRIP=1 skips it. Defaults match the working phone flow; override any of them in the environment.
if [ "${NOSTRIP:-0}" != 1 ]; then
  export PAIRIP_HOLDER_FALLBACK="${PAIRIP_HOLDER_FALLBACK:-placeholder}"
  export PAIRIP_KEEP_PAIRIPCORE="${PAIRIP_KEEP_PAIRIPCORE:-1}"
  export PAIRIP_KEEP_STARTUP="${PAIRIP_KEEP_STARTUP:-0}"
  if [ -f "$OUT/in/manifest.json" ]; then
    BASE_APK="$(python3 -c 'import json,sys;print(next(s["file"] for s in json.load(open(sys.argv[1]))["split_apks"] if s["id"]=="base"))' "$OUT/in/manifest.json")"
  else
    BASE_APK="$(python3 - "$OUT/in" <<'PY'
import glob, os, sys
d = sys.argv[1]
apks = sorted(glob.glob(os.path.join(d, '*.apk')))
cands = [os.path.basename(p) for p in apks if not os.path.basename(p).startswith('config.') and not os.path.basename(p).startswith('Unity')]
if not cands:
    cands = [os.path.basename(p) for p in apks]
print(cands[0] if cands else '')
PY
)"
  fi
  [ -n "$BASE_APK" ] && [ -f "$OUT/in/$BASE_APK" ] || die "base apk not found in $OUT/in (looked for $BASE_APK)"
  echo ">> pairip_strip: $BASE_APK"
  python3 "$HERE/pairip_strip.py" "$OUT/in/$BASE_APK" "$OUT/tmp/base.stripped.apk" || die "pairip_strip failed (see messages above)"
  mv -f "$OUT/tmp/base.stripped.apk" "$OUT/in/$BASE_APK"
fi

if [ "$NOHOOK" = 1 ]; then
  echo ">> NOHOOK=1: re-signing the original splits only (no libvrsupport.so, no libmain injection)"
  cp "$SPLIT" "$OUT/tmp/config.arm64_v8a.apk"
else
# ---- hook library -------------------------------------------------------------------------
if [ -n "$HOOK_SO" ]; then
  echo ">> using prebuilt hook library $HOOK_SO"; cp "$HOOK_SO" "$OUT/libvrsupport.so"
else
  INC=()
  if [ -f "$CONFIG" ]; then
    python3 "$HERE/gen-config.py" "$CONFIG" "$GEN/config_generated.h"
    # The phone build keeps the ORIGINAL package (no rename), but 2025.cfg's "Package Name"
    # is the Quest build's renamed package. Baking it would point the optional on-device config
    # override at the wrong /sdcard/Android/data/<pkg>/ dir -> drop it, use the phone default.
    sed -i '/RF_PACKAGE/d' "$GEN/config_generated.h"
    INC=(-I "$GEN")
  else
    echo "   no $CONFIG -- using built-in defaults (copy 2025.cfg.example -> 2025.cfg)"
  fi
  CRASH_SRC=()   # src/crashlog.cpp logs pc/lr/module+RVA of a native crash to logcat tag CRASHLOG. NOCRASHLOG=1 skips it.
  if [ "${NOCRASHLOG:-0}" != 1 ] && [ -f "$REPO/src/crashlog.cpp" ]; then CRASH_SRC=("$REPO/src/crashlog.cpp"); echo ">> + crashlog.cpp"; fi
  echo ">> compile libvrsupport.so (RF_PHONE)"
  "$CLANG" -shared -fPIC -O2 -fno-exceptions -fno-rtti -static-libstdc++ -DRF_PHONE=1 \
    -Wl,-z,max-page-size=16384 "${INC[@]}" \
    -o "$OUT/libvrsupport.so" "$REPO/src/2025_hook.cpp" "$REPO/src/And64InlineHook.cpp" ${CRASH_SRC[@]+"${CRASH_SRC[@]}"} -llog
fi

# ---- inject DT_NEEDED + rewrite split -----------------------------------------------------
echo ">> inject DT_NEEDED into libmain.so"
unzip -q -o -j "$SPLIT" "$ABI_DIR/libmain.so" -d "$OUT/tmp"
python3 "$HERE/inject.py" "$OUT/tmp/libmain.so" "$OUT/tmp/libmain.injected.so" 2>&1 \
  | grep -v -E 'Note name size|Failed to parse note' || true
[ -s "$OUT/tmp/libmain.injected.so" ] || die "LIEF injection produced no output"
python3 - "$OUT/tmp/libmain.injected.so" <<'PY'
import sys, lief
b = lief.ELF.parse(sys.argv[1])
n = [e.name for e in b.dynamic_entries if e.tag == lief.ELF.DynamicEntry.TAG.NEEDED]
sys.exit(0 if n and n[0] == "libvrsupport.so" else "libvrsupport.so is not the first DT_NEEDED: %s" % n)
PY

# ---- gotfix: fill PairIP's hidden GOT slots before libil2cpp/libwebrtc constructors run ----
# PairIP removed ~200 imports' relocations per lib; without its native program those slots keep
# their raw .plt address and the first call through one SEGVs (pc == .plt) inside the lib's
# constructors. libgf*.so fills them by name (dlsym) and is made a DT_NEEDED of the target by
# overwriting its "liblog.so" NEEDED string in place (3 bytes; no LIEF rewrite of a 422 MB lib).
GOTFIX_PUT=(); export VERIFY_IL2CPP_MD5=""
if [ "${NOGOTFIX:-0}" != 1 ]; then
  [ -x "$CLANG" ] || die "gotfix needs the NDK (set ANDROID_NDK) -- or NOGOTFIX=1"
  for spec in "libil2cpp.so:libgfi.so:got_libil2cpp.inc" "libwebrtc.so:libgfw.so:got_libwebrtc.inc"; do
    IFS=: read -r TGT GNAME GINC <<<"$spec"
    if [ ! -f "$HERE/gotfix/$GINC" ]; then
      echo "!! gotfix: no scripts/gotfix/$GINC -- $TGT keeps its unfilled PairIP slots (needs a dump: see GOTFIX-README.md)"; continue
    fi
    DATA_FLAGS=()
    DINC="data_${TGT%.so}.inc"   # optional: PairIP-scrambled .data words (scripts/gen_data_blob.py)
    if [ -f "$HERE/gotfix/$DINC" ]; then DATA_FLAGS=(-DDATA_INC="\"$DINC\""); echo ">> gotfix: + data fix $DINC"; fi
    CINC="code_${TGT%.so}.inc"   # optional: PairIP-encrypted CODE words (scripts/gen_code_blob.py)
    if [ -f "$HERE/gotfix/$CINC" ]; then DATA_FLAGS+=(-DCODE_INC="\"$CINC\""); echo ">> gotfix: + code fix $CINC"; fi
    echo ">> gotfix: $GNAME for $TGT"
    "$CLANG" -shared -fPIC -O2 -fno-exceptions -fno-rtti -static-libstdc++ -Wl,-z,max-page-size=16384 \
      -DGOT_INC="\"$GINC\"" ${DATA_FLAGS[@]+"${DATA_FLAGS[@]}"} -I "$HERE/gotfix" -o "$OUT/$GNAME" "$REPO/src/gotfix.cpp" -llog -ldl
    unzip -p "$SPLIT" "$ABI_DIR/$TGT" > "$OUT/tmp/$TGT"
    python3 "$HERE/gotfix_inject.py" "$OUT/tmp/$TGT" "$OUT/tmp/$TGT.gf" "$GNAME"
    rm -f "$OUT/tmp/$TGT"
    GOTFIX_PUT+=(--put "$ABI_DIR/$TGT=$OUT/tmp/$TGT.gf" --put "$ABI_DIR/$GNAME=$OUT/$GNAME")
    [ "$TGT" != libil2cpp.so ] || VERIFY_IL2CPP_MD5="$(md5sum "$OUT/tmp/$TGT.gf" | cut -d' ' -f1)"
  done
fi

# ---- neuter libpairipcore.so ------------------------------------------------------------------
# The real one SEGVs in its own JNI_OnLoad on a re-signed APK (pc=libpairipcore+0x5b820). libil2cpp/libwebrtc/
# lib_burst_generated still DT_NEED it and call ExecuteProgram() from DT_INIT, so the lib must exist -- but it
# can be inert: libgfi/libgfw already do PairIP's job. NOPAIRIPSTUB=1 ships the stock lib instead.
if [ "${NOPAIRIPSTUB:-0}" != 1 ]; then
  echo ">> neuter libpairipcore.so (inert JNI_OnLoad / ExecuteProgram)"
  unzip -p "$SPLIT" "$ABI_DIR/libpairipcore.so" > "$OUT/tmp/libpairipcore.so" || die "no $ABI_DIR/libpairipcore.so in the arm64 split"
  python3 "$HERE/neuter_pairipcore.py" "$OUT/tmp/libpairipcore.so" "$OUT/tmp/libpairipcore.stub.so" || die "neuter_pairipcore failed"
  rm -f "$OUT/tmp/libpairipcore.so"
  GOTFIX_PUT+=(--put "$ABI_DIR/libpairipcore.so=$OUT/tmp/libpairipcore.stub.so")
fi

# ---- Burst: leave lib_burst_generated.so out ------------------------------------------------------------
# run6: SIGILL inside lib_burst_generated.so (burst.initialize.externals.*): ~51 KB of its code is PairIP-encrypted
# and, unlike libwebrtc, there is no stock-process dump of it. Without the lib Unity's Burst stays uninitialised and
# the Entities/Jobs code is expected to run on the managed (IL2CPP) fallback -- slower but bootable. UNTESTED.
# KEEPBURST=1 ships the stock lib again (needed once a Burst code/data dump exists).
if [ "${KEEPBURST:-0}" != 1 ]; then
  echo ">> drop lib_burst_generated.so (Burst off; KEEPBURST=1 keeps it)"
  GOTFIX_PUT+=(--drop "$ABI_DIR/lib_burst_generated.so")
fi

echo ">> rewrite arm64 split"
python3 "$HERE/phone_patch.py" "$SPLIT" "$OUT/tmp/libmain.injected.so" "$OUT/libvrsupport.so" "$OUT/tmp/config.arm64_v8a.apk" ${GOTFIX_PUT[@]+"${GOTFIX_PUT[@]}"}

fi

# ---- align + sign ---------------------------------------------------------------------------
echo ">> align + sign every split with ONE key (splits must share a signer)"
mkdir -p "$OUT/signed"
for apk in "$OUT/in/"*.apk; do
  b="$(basename "$apk")"; src="$apk"
  [ "$b" = "config.arm64_v8a.apk" ] && src="$OUT/tmp/config.arm64_v8a.apk"
  echo "   $b"
  "$ZIPALIGN" -p -f 4 "$src" "$OUT/tmp/al_$b"
  "${APKSIGNER[@]}" sign --ks "$KS" --ks-key-alias 2025 \
    --ks-pass pass:android --key-pass pass:android --out "$OUT/signed/$b" "$OUT/tmp/al_$b"
  rm -f "$OUT/tmp/al_$b" "$OUT/signed/$b.idsig"
done

# ---- verify ---------------------------------------------------------------------------------
echo ">> verify"
CERTS=""
for apk in "$OUT/signed/"*.apk; do
  CERTS+="$("${APKSIGNER[@]}" verify --print-certs "$apk" | grep -i 'certificate SHA-256 digest' | head -1)"$'\n'
done
[ "$(printf '%s' "$CERTS" | sort -u | grep -c .)" = 1 ] || die "splits are not all signed by the same certificate"
if [ "$NOHOOK" = 1 ]; then echo "   (NOHOOK: skipping verify-phone)"; else python3 "$HERE/verify-phone.py" "$OUT/signed" "${VERIFY_IL2CPP_MD5:-$EXPECT_IL2CPP_MD5}" "$EXPECT_IL2CPP_MD5"; fi
rm -rf "$OUT/tmp" "$OUT/in"

# ---- install helpers --------------------------------------------------------------------------
cat > "$OUT/signed/install.sh" <<'EOS'
#!/usr/bin/env bash
# The patched splits are signed with a different key than the Play/original copy, so the
# original must be uninstalled first (this DELETES its local data). Skip with KEEP=1 if you
# already removed it or only updating a previous patched install.
set -e
cd "$(dirname "$0")"
adb get-state >/dev/null || { echo "no device: enable USB debugging and authorise this PC"; exit 1; }
[ "${KEEP:-0}" = 1 ] || adb uninstall com.AgainstGravity.RecRoom || true
# Install as if from Play (-i). A plain `adb install-multiple` leaves the app with NO installer
# package, and the game's bundled Firebase then crashes in FirebaseInitProvider (NPE in
# AutoValue_LibraryVersion, via FirebaseCommonRegistrar) before any native code runs.
# Override with INSTALLER=<pkg>; INSTALLER=none restores the plain install.
INSTALLER="${INSTALLER:-com.android.vending}"
if [ "$INSTALLER" = none ]; then adb install-multiple -r *.apk
else adb install-multiple -r -i "$INSTALLER" *.apk; fi
adb shell pm list packages -i com.AgainstGravity.RecRoom   # expect installer=$INSTALLER
echo "logs:  adb logcat -c; adb logcat -s 2025"
EOS
cat > "$OUT/signed/install.ps1" <<'EOS'
# Windows twin of install.sh (needs adb on PATH). $env:KEEP=1 skips the uninstall.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if ($env:KEEP -ne "1") { adb uninstall com.AgainstGravity.RecRoom }
# Install as if from Play (-i): a plain install leaves no installer package and the bundled
# Firebase crashes in FirebaseInitProvider before any native code runs. $env:INSTALLER overrides;
# $env:INSTALLER="none" restores the plain install.
$installer = if ($env:INSTALLER) { $env:INSTALLER } else { "com.android.vending" }
if ($installer -eq "none") { adb install-multiple -r (Get-ChildItem *.apk).Name }
else { adb install-multiple -r -i $installer (Get-ChildItem *.apk).Name }
if ($LASTEXITCODE -ne 0) { throw "install failed" }
adb shell pm list packages -i com.AgainstGravity.RecRoom   # expect installer=$installer
Write-Host "logs:  adb logcat -c; adb logcat -s 2025"
EOS
chmod +x "$OUT/signed/install.sh"
echo ">> done: $OUT/signed  (run install.sh / install.ps1 from that folder with the phone connected)"
