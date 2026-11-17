#!/usr/bin/env bash
# One-time: create tools/debug.keystore (alias 2025, pass android). BACK IT UP --
# the same key must sign every build or Oculus/Meta entitlement and updates break.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$REPO/tools"
[ -f "$REPO/tools/debug.keystore" ] && { echo "tools/debug.keystore already exists; not overwriting"; exit 0; }
keytool -genkeypair -keystore "$REPO/tools/debug.keystore" -alias 2025 \
  -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 36500 \
  -dname "CN=Rec-Uni, O=Rec-Uni"
echo "created tools/debug.keystore"
