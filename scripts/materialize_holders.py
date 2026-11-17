#!/usr/bin/env python3
"""Give PairIP's string-holder classes their real values (so the startup program isn't needed).

Background: PairIP replaced ~1500 string literals with `sget-object` reads of public static
String fields in ~32 empty "holder" classes. Nothing in the Java/smali writes those fields; the
encrypted startup program (StartupLauncher.launch() -> VMRunner.invoke) fills them natively.
pairip_strip.py removes that program, so every field is null and the first reader NPEs
(Firebase's "kotlin" library name was just the first one hit).

This module adds a static initialiser to each holder class that assigns the real values, taken
from a JSON file produced by scripts/dump_holders.py (a one-time dump from a stock, Play-
installed run of the SAME build).

Use as a library (pairip_strip.py does) or standalone:
  materialize_holders.py <smali_dir> <holders.json> [--allow-missing] [--dry-run]
  materialize_holders.py <smali_dir> --fallback [<holders.json>] [--seed <seed.json>]   # no dump needed
  materialize_holders.py --list <smali_dir> [<smali_dir> ...]     # print holder classes found

holders.json format:
  {"_meta": {...}, "holders": {"a.b.Holder": {"fieldName": "value", ...}, ...}}
(a bare {"a.b.Holder": {...}} mapping is accepted too).
"""
import json, os, re, struct, sys

FIELD_RE = re.compile(r"^\.field ((?:[a-z\-]+ )*)(\w+):Ljava/lang/String;( = .*)?$", re.M)
ANY_FIELD_RE = re.compile(r"^\.field ", re.M)
CLASS_RE = re.compile(r"^\.class [^\n]*?(L[^;\n]+;)", re.M)


def to_desc(name):
    """'a.b.C' or 'La/b/C;' -> 'La/b/C;'"""
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"


def to_dotted(desc):
    return desc[1:-1].replace("/", ".")


def load(path):
    """-> {descriptor: {field: str|None}}"""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    data = data.get("holders", data)
    out = {}
    for cls, fields in data.items():
        if cls.startswith("_") or not isinstance(fields, dict):
            continue
        out[to_desc(cls)] = {k: v for k, v in fields.items() if not k.startswith("__")}
    if not out:
        sys.exit(f"materialize_holders: {path} contains no holder classes")
    return out


def smali_escape(s):
    """Escape a Python str as the body of a smali string literal (UTF-16 code units, lone
    surrogates preserved)."""
    raw = s.encode("utf-16-le", "surrogatepass")
    units = struct.unpack("<%dH" % (len(raw) // 2), raw)
    out = []
    for u in units:
        if u == 0x22:
            out.append('\\"')
        elif u == 0x5C:
            out.append("\\\\")
        elif u == 0x0A:
            out.append("\\n")
        elif u == 0x0D:
            out.append("\\r")
        elif u == 0x09:
            out.append("\\t")
        elif 0x20 <= u < 0x7F:
            out.append(chr(u))
        else:
            out.append("\\u%04x" % u)
    return "".join(out)


def holder_fields(text):
    """Field names if `text` is a pure holder class (no methods; only public static
    non-final String fields without initial values), else None."""
    if ".method" in text:
        return None
    names = []
    for m in FIELD_RE.finditer(text):
        mods = m.group(1).split()
        if "static" not in mods or "final" in mods or m.group(3):
            return None
        names.append(m.group(2))
    if not names or len(names) != len(ANY_FIELD_RE.findall(text)):
        return None
    return names


def _walk_small(smali_dir):
    for dp, _, fs in os.walk(smali_dir):
        for f in fs:
            if f.endswith(".smali"):
                p = os.path.join(dp, f)
                if os.path.getsize(p) <= 40000:
                    yield p


def find_holders(smali_dir):
    """-> {descriptor: (path, [fields])} for every holder-like class under smali_dir."""
    found = {}
    for p in _walk_small(smali_dir):
        with open(p, encoding="utf-8", errors="replace") as f:
            t = f.read()
        names = holder_fields(t)
        if names:
            m = CLASS_RE.search(t)
            if m:
                found[m.group(1)] = (p, names)
    return found


def build_clinit(desc, fields, values):
    """Return (smali text, n_assigned, [missing field names])."""
    body, missing, n = [], [], 0
    for name in fields:
        v = values.get(name)
        if v is None:
            missing.append(name)
            continue
        body.append(f'    const-string v0, "{smali_escape(v)}"\n')
        body.append(f"    sput-object v0, {desc}->{name}:Ljava/lang/String;\n\n")
        n += 1
    text = ("\n# direct methods\n.method static constructor <clinit>()V\n    .locals 1\n\n"
            + "".join(body) + "    return-void\n.end method\n")
    return text, n, missing


def materialize(smali_dir, holders, allow_missing=False, dry_run=False, log=print,
                fallback=False, seed=None):
    """Add <clinit> to the holder classes in `smali_dir`.

    Value precedence per field: real dump value > seed value (fallback only) > "~<field>"
    placeholder (fallback only). Without `fallback`, fields missing from the dump are a problem
    (exit unless allow_missing). With `fallback`, EVERY holder class found in the dex is patched,
    even with no dump at all, so nothing is left null (see HOLDERS-README.md for the caveats).

    Returns the set of descriptors patched in this dex.
    """
    present = find_holders(smali_dir)
    seed = seed or {}
    done, problems = set(), []
    counts = {"dump": 0, "seed": 0, "placeholder": 0}

    targets = sorted(present) if fallback else sorted(d for d in holders if d in present)
    for desc in targets:
        path, fields = present[desc]
        real, sd = holders.get(desc, {}), seed.get(desc, {})
        values, missing = {}, []
        for name in fields:
            if real.get(name) is not None:
                values[name] = real[name]; counts["dump"] += 1
            elif fallback and sd.get(name) is not None:
                values[name] = sd[name]; counts["seed"] += 1
            elif fallback:
                values[name] = "~" + name; counts["placeholder"] += 1
            else:
                missing.append(name)
        extra = sorted(set(real) - set(fields))
        if missing:
            problems.append(f"{to_dotted(desc)}: {len(missing)} field(s) have no value in the dump: "
                            + ", ".join(missing[:5]) + (" ..." if len(missing) > 5 else ""))
        if extra:
            log(f"materialize_holders: note: {to_dotted(desc)}: {len(extra)} dumped field(s) not in "
                f"this build's smali (ignored)")
        clinit, _, _ = build_clinit(desc, fields, values)
        if not dry_run:
            text = open(path, encoding="utf-8").read()
            with open(path, "w", encoding="utf-8") as f:
                f.write(text.rstrip("\n") + "\n" + clinit)
        done.add(desc)

    uncovered = sorted(set(present) - set(holders)) if not fallback else []
    if uncovered:
        problems.append(f"{len(uncovered)} holder-like class(es) in this dex are NOT in the dump "
                        f"(their strings stay null): " + ", ".join(to_dotted(d) for d in uncovered[:5])
                        + (" ..." if len(uncovered) > 5 else ""))

    n = sum(counts.values())
    log(f"materialize_holders: {len(done)} holder classes, {n} string fields "
        f"{'would be ' if dry_run else ''}initialised in this dex "
        f"(from dump: {counts['dump']}, from seed: {counts['seed']}, placeholder: {counts['placeholder']})")
    if counts["placeholder"]:
        log(f"materialize_holders: WARNING {counts['placeholder']} field(s) hold PLACEHOLDERS, not the real "
            f"strings -- fine for a boot test, features that read them will misbehave")
    if problems:
        for p in problems:
            log(f"materialize_holders: PROBLEM: {p}")
        if not allow_missing:
            sys.exit("materialize_holders: refusing to continue (re-dump with scripts/dump_holders.py, "
                     "or set PAIRIP_ALLOW_MISSING_HOLDERS=1 to accept null strings, or "
                     "PAIRIP_HOLDER_FALLBACK=placeholder to fill the gaps)")
    return done


def main(argv):
    if len(argv) >= 2 and argv[0] == "--list":
        total = 0
        for d in argv[1:]:
            for desc, (_, names) in sorted(find_holders(d).items()):
                print(f"{to_dotted(desc)}  # {len(names)} fields")
                total += len(names)
        print(f"# total fields: {total}", file=sys.stderr)
        return 0
    argv = list(argv)
    seed = None
    if "--seed" in argv:
        i = argv.index("--seed"); seed = load(argv[i + 1]); del argv[i:i + 2]
    flags = {a for a in argv if a.startswith("--")}
    args = [a for a in argv if not a.startswith("--")]
    fb = "--fallback" in flags
    if not (len(args) == 2 or (fb and len(args) in (1, 2))):
        print(__doc__)
        return 2
    holders = load(args[1]) if len(args) == 2 else {}
    done = materialize(args[0], holders, allow_missing="--allow-missing" in flags,
                       dry_run="--dry-run" in flags, fallback=fb, seed=seed)
    missing = set(holders) - done
    if missing:
        print(f"materialize_holders: {len(missing)} class(es) from the dump not found in {args[0]} "
              f"(fine if they live in another dex)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
