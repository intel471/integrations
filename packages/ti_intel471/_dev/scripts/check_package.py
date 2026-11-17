"""Consistency checks for packages/ti_intel471 that elastic-package can't do.

The CEL template can't read the package version, so the User-Agent version is
written into cel.yml.hbs. This checks it (and the newest changelog entry) match
manifest.yml. Pass --fix to rewrite the User-Agent from the manifest.

Usage: python3 _dev/scripts/check_package.py [--fix]
"""
import re
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent.parent
MANIFEST = PKG / "manifest.yml"
CHANGELOG = PKG / "changelog.yml"
HBS = PKG / "data_stream" / "indicator" / "agent" / "stream" / "cel.yml.hbs"
UA_RE = re.compile(r'(user_agent:\s*"Intel471-Elastic/)([^"]+)(")')


def main() -> int:
    version = re.search(r'^version:\s*"?([^"\n]+)"?', MANIFEST.read_text(), re.M).group(1)
    changelog = re.search(r'^- version:\s*"?([^"\n]+)"?', CHANGELOG.read_text(), re.M).group(1)
    hbs = HBS.read_text()
    match = UA_RE.search(hbs)
    errors = []
    if not match:
        errors.append(f"{HBS.name}: no user_agent: \"Intel471-Elastic/<version>\" line")
    elif match.group(2) != version:
        if "--fix" in sys.argv:
            HBS.write_text(UA_RE.sub(rf"\g<1>{version}\g<3>", hbs))
            print(f"fixed User-Agent version {match.group(2)} -> {version}")
        else:
            errors.append(f"User-Agent version {match.group(2)} != manifest version {version} (run with --fix)")
    if changelog != version:
        errors.append(f"newest changelog entry {changelog} != manifest version {version}")
    for e in errors:
        print("FAIL", e)
    if not errors:
        print(f"ok: manifest, changelog and User-Agent all at {version}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
