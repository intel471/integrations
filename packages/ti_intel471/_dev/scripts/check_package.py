"""Consistency checks for packages/ti_intel471 that elastic-package can't do.

The CEL templates can't read the package version, so the User-Agent version is
written into each data stream's cel.yml.hbs. This checks it (and the newest
changelog entry) match manifest.yml. Pass --fix to rewrite the User-Agent from
the manifest.

Each latest transform declares the same intel471.* fields as its source data
stream (in a copy of fields.yml); this checks the copies haven't drifted.

Usage: python3 _dev/scripts/check_package.py [--fix]
"""
import re
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent.parent
MANIFEST = PKG / "manifest.yml"
CHANGELOG = PKG / "changelog.yml"
HBS_FILES = sorted(PKG.glob("data_stream/*/agent/stream/cel.yml.hbs"))
# transform -> its source data stream
TRANSFORMS = {"latest_ioc": "indicator", "latest_vulnerability": "vulnerability"}
UA_RE = re.compile(r'(user_agent:\s*"Intel471-Elastic/)([^"]+)(")')


def main() -> int:
    version = re.search(r'^version:\s*"?([^"\n]+)"?', MANIFEST.read_text(), re.M).group(1)
    changelog = re.search(r'^- version:\s*"?([^"\n]+)"?', CHANGELOG.read_text(), re.M).group(1)
    errors = []
    for hbs_file in HBS_FILES:
        name = hbs_file.relative_to(PKG)
        hbs = hbs_file.read_text()
        match = UA_RE.search(hbs)
        if not match:
            errors.append(f"{name}: no user_agent: \"Intel471-Elastic/<version>\" line")
        elif match.group(2) != version:
            if "--fix" in sys.argv:
                hbs_file.write_text(UA_RE.sub(rf"\g<1>{version}\g<3>", hbs))
                print(f"{name}: fixed User-Agent version {match.group(2)} -> {version}")
            else:
                errors.append(f"{name}: User-Agent version {match.group(2)} != manifest version {version} (run with --fix)")
    for transform, data_stream in TRANSFORMS.items():
        src = PKG / "data_stream" / data_stream / "fields" / "fields.yml"
        dst = PKG / "elasticsearch" / "transform" / transform / "fields" / "fields.yml"
        if src.read_text() != dst.read_text():
            errors.append(f"{dst.relative_to(PKG)} differs from {src.relative_to(PKG)} (copy it over)")
    if changelog != version:
        errors.append(f"newest changelog entry {changelog} != manifest version {version}")
    for e in errors:
        print("FAIL", e)
    if not errors:
        print(f"ok: manifest, changelog and {len(HBS_FILES)} User-Agents at {version}; transform fields in sync")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
