#!/usr/bin/env python3
"""Patch the generated Capacitor Xcode project so every target links with
-Wl,-no_fixup_chains (classic dyld binding), preserving existing flags.

Run AFTER `plutil -convert xml1 project.pbxproj` (plistlib needs XML plist).
Usage: patch-pbxproj.py <path/to/project.pbxproj>
"""
import plistlib
import sys

FLAG = "-Wl,-no_fixup_chains"

def main() -> int:
    path = sys.argv[1]
    with open(path, "rb") as f:
        proj = plistlib.load(f)

    patched = []
    for key, obj in proj.get("objects", {}).items():
        if not isinstance(obj, dict) or obj.get("isa") != "XCBuildConfiguration":
            continue
        bs = obj.setdefault("buildSettings", {})
        cur = bs.get("OTHER_LDFLAGS")
        if cur is None:
            new = ["$(inherited)", FLAG]
        elif isinstance(cur, str):
            new = [cur, FLAG]
        elif isinstance(cur, list):
            if FLAG in cur:
                patched.append((obj.get("name", key), "already"))
                continue
            new = list(cur) + [FLAG]
        else:
            new = ["$(inherited)", FLAG]
        bs["OTHER_LDFLAGS"] = new
        patched.append((obj.get("name", key), "patched"))

    with open(path, "wb") as f:
        plistlib.dump(proj, f)

    n = sum(1 for _, s in patched if s == "patched")
    print(f"patch-pbxproj: {n} build configuration(s) got {FLAG}")
    for name, state in patched:
        print(f"  - {name}: {state}")
    if n == 0:
        print("patch-pbxproj: WARNING - nothing patched, project layout unexpected?")
    return 0

if __name__ == "__main__":
    sys.exit(main())
