#!/usr/bin/env python3
"""Google Sign-In fallback, Java side (called from pairip_strip.py; can also run standalone on a smali dir).

Why: a re-signed Rec Room gets DEVELOPER_ERROR (status 10) from Google Play Games sign-in, so
com.recroom.googleplaynative.SignInActivity reports JNICallback_OnSignInComplete(false, "", "") and
Platform.BootSequence never continues (run19.log). The first attempt hooked
UnityEngine.AndroidJavaProxy.Invoke natively, but IL2CPP stripped that method (run21: "has no native
body"), so this does the same job in the dex instead, where nothing can be stripped.

What: in SignInActivity, every *failed* report
        new String(); new String(); const/4 vC, 0x0; callback.JNICallback_OnSignInComplete(vC, a, b)
becomes
        const-string a, "1"; const-string b, "2025-no-platform-account"; const/4 vC, 0x1; (same call)
That is the two error paths (handleSignInResult, lambda$invokeSignIn$0). The success path
(ReportSignInSuccess) and the SIGN_IN_REQUIRED (status 4) retry are untouched, so a build that really
signs in still reports the real account.

Nothing is authenticated. The sentinel pair is unusable on purpose: the server must REFUSE it
(expect 400 on /connect/token) so the client falls through to its own username/password login.
Never make the sentinel plausible.

Device-bound mode (DEFAULT; DEVICE_PLATFORM_ID=0 at build time restores the sentinel). Instead of the shared sentinel, the two failure
reports send a per-device pair from com.p2025.DeviceIdentity (injected into the same dex): a decimal platform id
and a proof, both derived from SHA-256("2025-device-v1:" + ANDROID_ID). In this mode invokeSignIn() is also
replaced outright: it never builds a Google sign-in client, so there is NO Google account popup at all. See DEVICE-PLATFORM-ID-README.md.
The server must then ACCEPT it (trust-on-first-use), which is the opposite of the sentinel contract.

Off: SIGNIN_FALLBACK=0 in the build environment (the on-device 2025.cfg cannot reach Java).
Standalone: signin_fallback.py <smali dir>   (exit 1 if the pattern is not found)
"""
import os, re, sys

CLS = "com/recroom/googleplaynative/SignInActivity.smali"
SENTINEL_ID = "1"
SENTINEL_TOKEN = "2025-no-platform-account"

_NEW_EMPTY = (r"new-instance (?P<{r}>[vp]\d+), Ljava/lang/String;\s+"
              r"invoke-direct \{{(?P={r})\}}, Ljava/lang/String;-><init>\(\)V")
# The failure report: two empty Strings (registers a, b), a constant-false (register c), then the
# interface call with (c, a, b). Blank lines and ".line N" markers may sit between the statements.
_FAIL = re.compile(
    r"(?P<ws>[ \t]*)" + _NEW_EMPTY.format(r="a") + r"(?:\s+\.line \d+)?\s+" +
    _NEW_EMPTY.format(r="b") + r"(?:\s+\.line \d+)?\s+"
    r"const/4 (?P<c>[vp]\d+), 0x0\s+"
    r"(?P<call>invoke-interface \{[vp]\d+, (?P=c), (?P=a), (?P=b)\}, "
    r"Lcom/recroom/googleplaynative/SignInCallback;->JNICallback_OnSignInComplete"
    r"\(ZLjava/lang/String;Ljava/lang/String;\)V)")


DEVICE_MARK = "Lcom/p2025/DeviceIdentity;"
DEVICE_CLS = "com/p2025/DeviceIdentity.smali"

DEVICE_SMALI = """.class public final Lcom/p2025/DeviceIdentity;
.super Ljava/lang/Object;
.source "DeviceIdentity.java"

# sha256("2025-device-v1:" + ANDROID_ID)
.method private static hash(Landroid/content/Context;)[B
    .locals 3

    invoke-virtual {p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v0

    const-string v1, "android_id"

    invoke-static {v0, v1}, Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    const-string v0, "unknown"

    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "2025-device-v1:"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "UTF-8"

    invoke-virtual {v0, v1}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    move-result-object v0

    const-string v1, "SHA-256"

    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/security/MessageDigest;->digest([B)[B

    move-result-object v0

    return-object v0
.end method

# decimal string of (first 8 digest bytes, big-endian) >>> 4  -> 60-bit, never negative, <= 19 digits
.method public static platformId(Landroid/content/Context;)Ljava/lang/String;
    .locals 3

    invoke-static {p0}, Lcom/p2025/DeviceIdentity;->hash(Landroid/content/Context;)[B

    move-result-object v0

    invoke-static {v0}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    move-result-object v0

    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->getLong()J

    move-result-wide v0

    const/4 v2, 0x4

    ushr-long/2addr v0, v2

    invoke-static {v0, v1}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

# "2025-device-v1." + base64url(digest), no padding, no wrap
.method public static proof(Landroid/content/Context;)Ljava/lang/String;
    .locals 3

    invoke-static {p0}, Lcom/p2025/DeviceIdentity;->hash(Landroid/content/Context;)[B

    move-result-object v0

    const/16 v1, 0xb

    invoke-static {v0, v1}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "2025-device-v1."

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
"""


INVOKE_NEW = """.method public invokeSignIn()V
    .locals 5

    iget-object v0, p0, Lcom/recroom/googleplaynative/SignInActivity;->callback:Lcom/recroom/googleplaynative/SignInCallback;

    if-nez v0, :cond_0

    const-string v0, "RecRoom"

    const-string v1, "No callback object was present, device sign-in will not be reported"

    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    return-void

    :cond_0
    invoke-static {p0}, Lcom/p2025/DeviceIdentity;->platformId(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v1

    invoke-static {p0}, Lcom/p2025/DeviceIdentity;->proof(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v2

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "device platform id "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    const-string v4, "2025"

    invoke-static {v4, v3}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    const/4 v3, 0x1

    invoke-interface {v0, v3, v1, v2}, Lcom/recroom/googleplaynative/SignInCallback;->JNICallback_OnSignInComplete(ZLjava/lang/String;Ljava/lang/String;)V

    return-void
.end method"""
_INVOKE = re.compile(r"\.method public invokeSignIn\(\)V.*?\.end method", re.S)


def device_mode():
    """Device-bound ids + no Google popup. DEFAULT ON; DEVICE_PLATFORM_ID=0 restores the old sentinel mode."""
    return os.environ.get("DEVICE_PLATFORM_ID", "1").lower() not in ("0", "no", "false", "off")


def enabled():
    return os.environ.get("SIGNIN_FALLBACK", "1").lower() not in ("0", "no", "false", "off")


def patch_text(t, device=False):
    """Return (new_text, number_of_sites_patched)."""
    def sub(m):
        ws = m.group("ws")
        if device:
            # p0 is `this` (a Context) in both failure-report methods (non-static instance methods).
            return (f'{ws}invoke-static {{p0}}, {DEVICE_MARK}->platformId(Landroid/content/Context;)Ljava/lang/String;\n\n'
                    f'{ws}move-result-object {m.group("a")}\n\n'
                    f'{ws}invoke-static {{p0}}, {DEVICE_MARK}->proof(Landroid/content/Context;)Ljava/lang/String;\n\n'
                    f'{ws}move-result-object {m.group("b")}\n\n'
                    f'{ws}const/4 {m.group("c")}, 0x1\n\n'
                    f'{ws}{m.group("call")}')
        return (f'{ws}const-string {m.group("a")}, "{SENTINEL_ID}"\n\n'
                f'{ws}const-string {m.group("b")}, "{SENTINEL_TOKEN}"\n\n'
                f'{ws}const/4 {m.group("c")}, 0x1\n\n'
                f'{ws}{m.group("call")}')
    return _FAIL.subn(sub, t)


def patch(smali_dir):
    """Patch SignInActivity under smali_dir. Returns True if the class was found in this dex."""
    p = os.path.join(smali_dir, CLS)
    if not os.path.isfile(p):
        return False
    t = open(p, encoding="utf-8").read()
    if f'"{SENTINEL_TOKEN}"' in t or DEVICE_MARK in t:
        print("signin_fallback: already patched"); return True
    device = device_mode()
    new, n = patch_text(t, device)
    if device:
        new, k = _INVOKE.subn(lambda m: INVOKE_NEW, new, count=1)
        if k != 1:
            sys.exit(f"signin_fallback: invokeSignIn() not found in {p} -- different build?")
    if n != 2:
        sys.exit(f"signin_fallback: expected 2 failure-report sites in {p}, found {n} -- different build?")
    open(p, "w", encoding="utf-8").write(new)
    if device:
        hp = os.path.join(smali_dir, DEVICE_CLS)
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        open(hp, "w", encoding="utf-8").write(DEVICE_SMALI)
        print(f"signin_fallback: SignInActivity: {n} failure reports + invokeSignIn() now report a DEVICE-BOUND id/proof "
              f"(com.p2025.DeviceIdentity), Google popup removed; the server must accept it on first use")
    else:
        print(f"signin_fallback: SignInActivity: {n} failure reports now report sentinel success "
              f"(id={SENTINEL_ID!r}); the server must refuse it")
    return True


if __name__ == "__main__":
    sys.exit(0 if patch(sys.argv[1]) else 1)
