#!/usr/bin/env python3
"""One-time dump of PairIP's string-holder fields from a STOCK Rec Room run (needs Frida).

  python scripts/dump_holders.py                       # USB device, app already installed from Play
  python scripts/dump_holders.py --spawn               # let Frida start the app instead
  python scripts/dump_holders.py --host 192.168.1.50:27042   # frida-server over TCP

Writes scripts/holders/holders.json, which pairip_strip.py then bakes into the patched dex.

Requirements (see HOLDERS-README.md): rooted phone/emulator with frida-server running, the
UNMODIFIED Play build (same versionCode as the one you patch), and on the PC
    pip install frida==16.7.19 frida-tools==13.7.1      (Frida 17 dropped the bundled Java bridge)
"""
import argparse, json, os, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = "com.AgainstGravity.RecRoom"


def read_classes(path):
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def get_device(frida, args):
    if args.host:
        return frida.get_device_manager().add_remote_device(args.host)
    if args.device:
        return frida.get_device(args.device)
    return frida.get_usb_device(timeout=15)


def find_pid(dev, pkg):
    for p in dev.enumerate_processes():
        if p.name == pkg:
            return p.pid
    return None


def launch_with_adb(pkg, serial):
    adb = os.environ.get("ADB") or shutil.which("adb")
    if not adb:
        return False
    cmd = [adb] + (["-s", serial] if serial else []) + ["shell", "monkey", "-p", pkg,
           "-c", "android.intent.category.LAUNCHER", "1"]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--package", default=PKG)
    ap.add_argument("--classes", default=os.path.join(HERE, "holders", "holder_classes.txt"))
    ap.add_argument("--out", default=os.path.join(HERE, "holders", "holders.json"))
    ap.add_argument("--js", default=os.path.join(HERE, "frida", "dump_holders.js"))
    ap.add_argument("--delay", type=float, default=15,
                    help="seconds to wait after the app starts before dumping (default 15)")
    ap.add_argument("--spawn", action="store_true", help="spawn the app via Frida instead of attaching")
    ap.add_argument("--device", help="device id (adb serial) if several are attached")
    ap.add_argument("--host", help="host:port of a remote frida-server")
    args = ap.parse_args()

    try:
        import frida
    except ImportError:
        sys.exit("frida python module missing: pip install frida==16.7.19 frida-tools==13.7.1")
    if int(frida.__version__.split(".")[0]) >= 17:
        print(f"WARNING: frida {frida.__version__}: Frida 17+ does not bundle the Java bridge in plain "
              f"scripts; if the dump fails with 'No Java bridge', install frida==16.7.19.", file=sys.stderr)

    classes = read_classes(args.classes)
    js = open(args.js, encoding="utf-8").read()
    dev = get_device(frida, args)
    print(f"device: {dev.name}  frida {frida.__version__}  classes to read: {len(classes)}")

    if args.spawn:
        pid = dev.spawn([args.package])
        session = dev.attach(pid)
        dev.resume(pid)
        print(f"spawned {args.package} (pid {pid}); waiting {args.delay:.0f}s for PairIP startup ...")
        time.sleep(args.delay)
    else:
        pid = find_pid(dev, args.package)
        if pid is None:
            print(f"{args.package} is not running; launching it ...")
            if not launch_with_adb(args.package, args.device):
                print("adb not found -- start Rec Room on the phone yourself now.")
            for _ in range(60):
                time.sleep(1)
                pid = find_pid(dev, args.package)
                if pid:
                    break
            if pid is None:
                sys.exit("process never appeared (is frida-server running? is the stock app installed?)")
        print(f"attached to pid {pid}; waiting {args.delay:.0f}s so startup has finished ...")
        time.sleep(args.delay)
        session = dev.attach(pid)

    script = session.create_script(js)
    script.load()
    res = script.exports_sync.dump(classes)
    session.detach()

    meta, errors = res.get("meta", {}), res.get("errors", {})
    holders = {}
    nulls = []
    for cls, fields in res["holders"].items():
        holders[cls] = {}
        for name, raw in fields.items():
            if raw is None:
                holders[cls][name] = None
                nulls.append(f"{cls}.{name}")
            else:
                holders[cls][name] = json.loads('"' + raw + '"')   # raw is an ASCII JSON-string body

    n_fields = sum(len(v) for v in holders.values())
    print(f"meta: {meta}")
    print(f"classes read: {len(holders)}/{len(classes)}   fields: {n_fields}   null fields: {len(nulls)}")
    for c, e in errors.items():
        print(f"  ERROR {c}: {e}")
    for n in nulls[:10]:
        print(f"  null: {n}")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"_meta": dict(meta, dumped_at=time.strftime("%Y-%m-%d %H:%M:%S")), "holders": holders},
                  f, ensure_ascii=True, indent=1, sort_keys=True)
    print(f"wrote {args.out}")

    if errors or nulls or len(holders) != len(classes):
        print("\nDump is incomplete. Most likely the app hadn't finished PairIP startup (raise --delay) "
              "or a class failed to load. pairip_strip.py will refuse to use an incomplete dump unless "
              "PAIRIP_ALLOW_MISSING_HOLDERS=1.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
