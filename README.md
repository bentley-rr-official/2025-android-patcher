# 2025 Android Patcher

Tooling and native hooks for patching Rec Room Android (arm64) builds. This repo contains the scripts, hook source, and fix data used to take a stock game package, apply patches/strips/injections, and produce re-signed APKs for testing on device.

## Target build

The phone build scripts are configured for:

- **Rec Room 20250718.01** (arm64)
- **`versionCode`: 23568923**
- **`libil2cpp.so` md5:** `ef682fb3e6b8d093d605b4f5e53e11e7`

`scripts/build-phone.sh` verifies the input package and will refuse mismatched builds unless `FORCE=1` is set (using `FORCE=1` on a different build will likely produce incorrect offsets/RVAs).

> Note: the phone/XAPK build for this target uses split APKs and Play asset packs (no OBB). Some Quest/device workflows still involve OBB files and local bundles; see **OBB & bundles** below.

## Repository layout

- `scripts/build-phone.sh` – main phone/tablet build (XAPK in, patched & re-signed splits out)
- `build-phone.ps1` – Windows wrapper that runs the phone build in WSL
- `scripts/prepare-project.sh` – decode/prepare an APK project with apktool (package/manifest/sdk adjustments)
- `scripts/` – patch/build helpers (PairIP strip/stub, GOT/code/data fixes, injection, verification, metadata/signin/asset-pack utilities, etc.)
- `src/` – native hook/fix sources (`2025_hook.cpp`, `And64InlineHook.*`, `crashlog.cpp`, `gotfix.cpp`)
- `bundles/` – local asset bundle storage (gitignored; you populate this yourself when needed)
- `CustomAssetPacksData.json` – bundle/asset-pack metadata used by bundle helper scripts
- `2025.cfg.example` – example runtime/build config template

## Requirements

Requirements depend on the workflow, but for the phone build you typically need:

- Linux (or WSL on Windows)
- `bash`, `python3`, `java`
- Python package: `lief` (`pip install lief`)
- Android build tools: `zipalign`, `apksigner` (or `tools/lib/apksigner.jar`)
- `apktool.jar` in `tools/` for APK decode/prepare workflows
- Android NDK **r27c** (default: `~/x/ndk/android-ndk-r27c`) unless using a prebuilt hook (`HOOK_SO`)
- A signing keystore at `tools/debug.keystore` (see `scripts/make-keystore.sh`)

## Configuration

1. Copy the example config:
   ```bash
   cp 2025.cfg.example 2025.cfg
   ```
2. Edit `2025.cfg` for your environment (at minimum set `RecNet NameServer Host` under `[Server]` if required by your setup).
3. Keep `2025.cfg` local (it is gitignored).

### `2025.cfg` notes

- **`[Server] RecNet NameServer Host`**: nameserver host used by the hook/config for redirection.
- **`[Advanced] Log HTTP`**: basic HTTP logging.
- **`[Advanced] Debug`**: full request/response body tracing (**may log passwords/tokens**; do not share logs).
- **`[Advanced] Log HTTP Body Max`**: body log truncation limit.
- **`[Advanced] Log Noisy Endpoints`**: include noisy telemetry/heartbeat endpoints.

## Building (phone/XAPK)

Basic usage:

```bash
scripts/build-phone.sh /path/to/RecRoom.xapk
```

- Input can be a `.xapk` file or an unzipped XAPK folder containing split APKs + `manifest.json`.
- Output is written to `build/phone/signed/` (re-signed split APKs and install scripts).

Windows (via WSL):

```powershell
.\build-phone.ps1 C:\path\to\RecRoom.xapk
```

### Common build environment/options

Set as needed when running `scripts/build-phone.sh`:

- `ANDROID_NDK` – NDK root (default: `~/x/ndk/android-ndk-r27c`)
- `TOOLS` – tools/keystore directory (default: `<repo>/tools`)
- `CONFIG` – config file to bake in (default: `<repo>/2025.cfg`)
- `HOOK_SO` – use a prebuilt `libvrsupport.so` instead of compiling
- `NOHOOK=1` – re-sign original splits only (diagnostic)
- `NOSTRIP=1` – skip PairIP strip step on the base APK copy
- `NOGOTFIX=1` – skip GOT/code/data fix injection
- `NOPAIRIPSTUB=1` – skip neutering `libpairipcore.so`
- `KEEPBURST=1` – keep `lib_burst_generated.so` in the split (dropped by default in this flow)
- `NOCRASHLOG=1` – omit native crash logger from the hook library
- `FORCE=1` – continue on version/hash mismatch (**unsafe for patched RVAs**)

(See the header/comments in `scripts/build-phone.sh` and related scripts for additional toggles such as PairIP holder/signin behavior.)

## Install notes (device)

- The generated output in `build/phone/signed/` includes install scripts for ADB installs.
- If an install script supports `KEEP=1`, prefer it when updating in place to avoid wiping app data (e.g. `/sdcard/Android/data/<pkg>/`), which may remove manually placed files/stubs.
- View runtime logs with `adb logcat` (useful tags include `2025`, `GOTFIX`, `CRASHLOG` depending on what you’re debugging).

## OBB & bundles

This repo does **not** include copyrighted game assets. If your workflow requires the Quest OBB and/or extracted bundles, obtain them from a device/build you own and keep them local (`bundles/` and `*.obb` are gitignored).

### 1. Get the OBB (from your Quest/device)

1. Install the matching Rec Room build on the device.
2. Find the OBB path via ADB (commonly under `/sdcard/Android/obb/<package>/`):
   ```bash
   adb shell ls /sdcard/Android/obb/
   adb shell ls /sdcard/Android/obb/com.AgainstGravity.RecRoom/
   ```
3. Pull the OBB to your PC:
   ```bash
   adb pull /sdcard/Android/obb/com.AgainstGravity.RecRoom/main.<versionCode>.com.AgainstGravity.RecRoom.obb .
   ```
   Use the actual package name and version code from the installed build. For the target build this repo is configured around, the version code is **23568923** (game version **20250718.01**).

> If you change package name/version code in a rebuilt APK, the OBB filename the app expects must match (e.g. `main.<versionCode>.<package>.obb`).

### 2. Unzip the OBB and put bundles in the right folder

OBB files are zip-compatible archives. To extract bundles into this repo’s `bundles/` folder:

```bash
mkdir -p bundles
unzip -o main.<versionCode>.<package>.obb '*.bundle' -d /tmp/obb-extract

# Copy extracted bundle files into the repo
find /tmp/obb-extract -type f -name '*.bundle' -exec cp -n {} bundles/ \;
```

- **Right folder:** `bundles/` in the repo root (e.g. `bundles/<hash>.bundle`)
- Keep bundles local; do not commit them.

You can also extract the full OBB and manually copy/move only the `*.bundle` files you need into `bundles/`.

### 3. Check bundle coverage (optional, when using `CustomAssetPacksData.json`)

If you are working with the outfit/asset-pack bundle lists in this repo, you can inspect or collect matching bundles:

```bash
# Check how many expected bundles are present in a directory/archive/OBB
python3 scripts/check_outfits_pack.py CustomAssetPacksData.json main.<versionCode>.<package>.obb
python3 scripts/check_outfits_pack.py CustomAssetPacksData.json bundles/

# Find/copy matching bundles from local folders/archives into bundles/
python3 scripts/find_outfits_pack.py CustomAssetPacksData.json --scan /path/to/search --copy-to bundles
```

`scripts/pull_outfits_from_device.py` can collect matching bundles from an ADB-connected device that already downloaded them, but the preferred/manual flow here is to **unzip the OBB (or other archive/source you have) and copy `*.bundle` files into `bundles/`**.

## Runtime/patch notes (important)

- **PairIP handling**: the build flow can strip/neuter PairIP-related components and apply fixups (configurable via env flags). Some fixes depend on generated/inc data in `scripts/gotfix/`.
- **GOT/code/data fixes**: `libgfi`/`libgfw` fixups may be injected for specific libs; `NOGOTFIX=1` disables this step.
- **Crash logging**: `src/crashlog.cpp` can emit native crash details to logcat tag `CRASHLOG` (disable with `NOCRASHLOG=1`).
- **Asset pack stubs / DNS logging**: behavior may be toggled via on-device config/runtime options depending on the hook build (see hook source and scripts for current defaults/keys).
- **Sign-in fallback**: Java-side fallback patching is applied by the PairIP/base-dex patching flow when enabled (see `scripts/pairip_strip.py` / `scripts/signin_fallback.py`).

This repo is build-specific and operates on binaries you provide locally. Always verify outputs on-device and review script headers before changing flags or rebasing to another game version.
