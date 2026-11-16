#!/usr/bin/env python3
"""Weak-link iOS 15+-only dylibs so the app can launch on iOS 14.x.

Root cause (run#4/#5 investigation): Capacitor.framework (the prebuilt
xcframework from capacitor-swift-pm) hard-links CoreServices.framework
via LC_LOAD_DYLIB. CoreServices first shipped on iOS in iOS 15.0, so on
iOS 14.x dyld aborts the launch with "Library not loaded" before any UI.

Fix: flip that load command to LC_LOAD_WEAK_DYLIB (same cmdsize, only the
cmd field changes). On iOS 15+ it still binds normally; on iOS 14.x the
missing dylib resolves to nil instead of killing the process.

Run BEFORE ldid signing (flipping bytes invalidates any signature).
Usage: weakify-dylibs.py <path/to/App.app> [...more .app paths]
"""
import os
import struct
import sys

LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_ID_DYLIB = 0x0D

WEAKEN_PATH_PATTERNS = (
    b"/System/Library/Frameworks/CoreServices.framework/",
)

MAGIC_THIN_LE = b"\xcf\xfa\xed\xfe"
MAGIC_THIN_BE = b"\xce\xfa\xed\xfe"
MAGIC_FAT = b"\xca\xfe\xba\xbe"


def collect_macho(bundle):
    cands = []
    for sub in ("Frameworks", "Plugins"):
        d = os.path.join(bundle, sub)
        if os.path.isdir(d):
            for root, dirs, files in os.walk(d):
                for fn in files:
                    p = os.path.join(root, fn)
                    if not os.path.islink(p) and os.path.isfile(p):
                        cands.append(p)
    main_exe = os.path.join(bundle, "App")
    if os.path.isfile(main_exe):
        cands.insert(0, main_exe)
    hits = []
    for p in cands:
        try:
            with open(p, "rb") as f:
                head = f.read(4)
        except OSError:
            continue
        if head in (MAGIC_THIN_LE, MAGIC_THIN_BE, MAGIC_FAT):
            hits.append(p)
    return hits


def weakify(data):
    """Return (data, changed_names) for one Mach-O file buffer."""
    changed = []
    offs = [0]
    if data[:4] == MAGIC_FAT:
        n = struct.unpack_from(">I", data, 4)[0]
        offs = [struct.unpack_from(">I", data, 8 + 20 * i + 8)[0] for i in range(n)]
    for off in offs:
        magic = data[off:off + 4]
        endian = "<" if magic == MAGIC_THIN_LE else ">"
        ncmds = struct.unpack_from(endian + "I", data, off + 16)[0]
        p = off + 32
        for _ in range(ncmds):
            cmd, sz = struct.unpack_from(endian + "II", data, p)
            if cmd == LC_LOAD_DYLIB:
                off_field = struct.unpack_from(endian + "I", data, p + 8)[0]
                name = data[p + off_field:p + sz].split(b"\x00")[0]
                if any(pat in name for pat in WEAKEN_PATH_PATTERNS):
                    struct.pack_into(endian + "I", data, p, LC_LOAD_WEAK_DYLIB)
                    changed.append(name.decode(errors="replace"))
            p += sz
    return data, changed


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    total = 0
    for bundle in sys.argv[1:]:
        if not os.path.isdir(bundle):
            print(f"ERROR: not a directory: {bundle}")
            return 2
        print(f"== weakify-dylibs: {os.path.abspath(bundle)} ==")
        for p in collect_macho(bundle):
            with open(p, "rb") as f:
                data = bytearray(f.read())
            data, changed = weakify(data)
            if changed:
                with open(p, "wb") as f:
                    f.write(data)
            for name in changed:
                print(f"  [weakened] {os.path.relpath(p, bundle)}: {name}")
            total += len(changed)
    if total == 0:
        print("  nothing to weaken (no iOS15+-only hard loads found)")
    else:
        print(f"  total: {total} LC_LOAD_DYLIB -> LC_LOAD_WEAK_DYLIB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
