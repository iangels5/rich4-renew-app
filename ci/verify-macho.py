#!/usr/bin/env python3
"""CI gate: every Mach-O in an .app must be loadable by the iOS 14 dyld3.

Hard-fails when a binary hard-links an iOS-15-only dylib (e.g. CoreServices:
dyld3 "Library not loaded" -> app dies before any UI), or when it has NO
binding info at all.

NOTE on chained fixups: LC_DYLD_CHAINED_FIXUPS is FINE on iOS 14 — dyld3
(dyld-750.6) fully parses chained fixups with no OS gate (verified against
apple-oss-distributions/dyld dyld-750.6 MachOAnalyzer.cpp). Apple's ld emits
chains by default for minOS >= 13.4, so official prebuilt frameworks
(capacitor-swift-pm xcframeworks) ship chains-only and remain loadable.
chains-only / classic-only / both are all acceptable; neither = violation.

Only warns on LC_BUILD_VERSION oddities.

Load-command constants (from <mach-o/loader.h>):
  LC_DYLD_INFO 0x22, LC_DYLD_INFO_ONLY 0x80000022, LC_CODE_SIGNATURE 0x1D,
  LC_VERSION_MIN_IPHONEOS 0x26, LC_BUILD_VERSION 0x32, LC_MAIN 0x80000028,
  LC_DYLD_CHAINED_FIXUPS 0x80000034

Usage: verify-macho.py <label> <path/to/App.app> [...more .app paths]
Exit 0 = all hard checks passed; exit 1 = at least one hard violation.
"""
import os
import plistlib
import struct
import sys

LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_CODE_SIGNATURE = 0x1D
LC_VERSION_MIN_IPHONEOS = 0x26
LC_BUILD_VERSION = 0x32
LC_MAIN = 0x80000028
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x80000018

# dylibs that must NOT be hard-linked (first shipped on iOS in iOS 15.0;
# a hard load kills the launch on iOS 14.x with "Library not loaded")
IOS15_ONLY_HARD_PATTERNS = (
    b"/System/Library/Frameworks/CoreServices.framework/",
)

MAGIC_THIN_LE = b"\xcf\xfa\xed\xfe"
MAGIC_THIN_BE = b"\xce\xfa\xed\xfe"
MAGIC_FAT = b"\xca\xfe\xba\xbe"
MAGIC_FAT64 = b"\xca\xfe\xba\xbf"

CPU_TYPE_ARM64 = 0x0100000C


def parse_load_commands(data, off, endian):
    ncmds = struct.unpack_from(endian + "I", data, off + 16)[0]
    p = off + 32
    cmds = []
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from(endian + "II", data, p)
        cmds.append((cmd, data[p:p + sz]))
        p += sz
    return cmds


def arch_offsets(data, path):
    magic = data[:4]
    if magic in (MAGIC_THIN_LE, MAGIC_THIN_BE):
        return [0]
    if magic == MAGIC_FAT:
        n = struct.unpack_from(">I", data, 4)[0]
        return [struct.unpack_from(">I", data, 8 + 20 * i + 8)[0] for i in range(n)]
    if magic == MAGIC_FAT64:
        raise SystemExit(f"{path}: fat64 not supported by this checker")
    raise SystemExit(f"{path}: not a Mach-O (magic {magic!r})")


def collect_macho(bundle):
    """Mach-O files inside the .app bundle: main binary, frameworks, plugins."""
    cands = []
    ip = os.path.join(bundle, "Info.plist")
    if os.path.isfile(ip):
        try:
            with open(ip, "rb") as f:
                exe = plistlib.load(f).get("CFBundleExecutable")
            if exe:
                cands.append(os.path.join(bundle, exe))
        except Exception as e:
            print(f"  WARN: cannot read {ip}: {e}")
    for sub in ("Frameworks", "Plugins", "XPCServices"):
        d = os.path.join(bundle, sub)
        if os.path.isdir(d):
            for root, dirs, files in os.walk(d):
                dirs[:] = [x for x in dirs if not os.path.islink(os.path.join(root, x))]
                for fn in files:
                    p = os.path.join(root, fn)
                    if not os.path.islink(p) and os.path.isfile(p):
                        cands.append(p)
    seen = set()
    hits = []
    for p in cands:
        if p in seen:
            continue
        seen.add(p)
        try:
            with open(p, "rb") as f:
                head = f.read(4)
        except OSError:
            continue
        if head in (MAGIC_THIN_LE, MAGIC_THIN_BE, MAGIC_FAT):
            hits.append(p)
    return hits


def analyze(path):
    with open(path, "rb") as f:
        data = f.read()
    abspath = os.path.abspath(path)
    violations = []
    warnings = []
    for off in arch_offsets(data, abspath):
        magic = data[off:off + 4]
        endian = "<" if magic == MAGIC_THIN_LE else ">"
        cputype = struct.unpack_from(endian + "I", data, off + 4)[0]
        cmds = parse_load_commands(data, off, endian)
        ids = [c for c, _ in cmds]

        chains = LC_DYLD_CHAINED_FIXUPS in ids
        classic = LC_DYLD_INFO in ids or LC_DYLD_INFO_ONLY in ids
        hard_dylibs = []
        for c, raw in cmds:
            if c == LC_LOAD_DYLIB:
                off_field = struct.unpack_from(endian + "I", raw, 8)[0]
                hard_dylibs.append(raw[off_field:].split(b"\x00")[0])
        bad_hard = [d.decode(errors="replace") for d in hard_dylibs
                    if any(p in d for p in IOS15_ONLY_HARD_PATTERNS)]
        buildver = None
        for c, raw in cmds:
            if c == LC_BUILD_VERSION and len(raw) >= 24:
                plat, minos, sdk, _ntools = struct.unpack_from(endian + "IIII", raw, 8)
                buildver = (plat, minos, sdk)
        vermin = LC_VERSION_MIN_IPHONEOS in ids
        signed = LC_CODE_SIGNATURE in ids
        has_main = LC_MAIN in ids

        if cputype != CPU_TYPE_ARM64:
            warnings.append(f"cputype 0x{cputype:08X} (expected arm64)")
        if not chains and not classic:
            violations.append("no LC_DYLD_CHAINED_FIXUPS and no LC_DYLD_INFO(_ONLY): no binding info, unloadable")
        for name in bad_hard:
            violations.append(f"hard-links iOS15-only dylib: {name} (kills launch on iOS 14)")

        if buildver:
            plat, minos, sdk = buildver
            min_s = f"{minos >> 16}.{(minos >> 8) & 0xFF}.{minos & 0xFF}"
            if plat != 2:
                warnings.append(f"LC_BUILD_VERSION platform={plat:#x} (expected 2=iOS)")
            if (minos >> 16, (minos >> 8) & 0xFF) < (14, 0):
                warnings.append(f"LC_BUILD_VERSION minos={min_s} (expected >= 14.0)")
            bver = f"p={plat} min={min_s} sdk={sdk >> 16}.{(sdk >> 8) & 0xFF}.{sdk & 0xFF}"
        elif vermin:
            bver = "version_min_iphoneos"
        else:
            warnings.append("no LC_BUILD_VERSION/LC_VERSION_MIN_IPHONEOS")
            bver = "-"

        arch = "arm64" if cputype == CPU_TYPE_ARM64 else f"cputype 0x{cputype:08X}"
        status = "FAIL" if violations else "ok"
        print(f"  [{status}] {abspath} ({arch}) chains={'YES' if chains else 'no'} "
              f"classic_info={'yes' if classic else 'NO'} hard_dylibs={len(hard_dylibs)} buildver={bver} "
              f"codesig={'yes' if signed else 'no'} main={'yes' if has_main else '-'}")
    return violations, warnings


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    label = sys.argv[1]
    bundles = sys.argv[2:]
    print(f"== verify-macho [{label}] ==")
    all_v, all_w = [], []
    for bundle in bundles:
        if not os.path.isdir(bundle):
            print(f"ERROR: not a directory: {bundle}")
            return 2
        machos = collect_macho(bundle)
        if not machos:
            print(f"ERROR: no Mach-O found in {bundle}")
            return 2
        print(f" {os.path.abspath(bundle)}: {len(machos)} Mach-O file(s)")
        for p in machos:
            v, w = analyze(p)
            all_v += [f"{p}: {x}" for x in v]
            all_w += [f"{p}: {x}" for x in w]
    if all_w:
        print("WARNINGS:")
        for w in all_w:
            print(f"  - {w}")
    if all_v:
        print("HARD VIOLATIONS (iOS 14 device would abort at exec):")
        for v in all_v:
            print(f"  - {v}")
        return 1
    print(f"PASS [{label}]: every binary has binding info (classic and/or chained fixups) "
          f"and hard-links no iOS15-only dylib — safe for iOS 14.x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
