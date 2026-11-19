# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///
"""Pull a sample of credentials from the Credentials API stream and store
them, with all personal data replaced by consistent dummy values, as a test
fixture. The raw API response is only ever held in memory.

Kept as is: IDs' shape (but not their value), timestamps, password strength
and complexity numbers, affiliations, credential set types, GIRs, statistics,
and the infostealer malware family, OS, antivirus and version.
Replaced: credential IDs, logins, every domain, password IDs, credential set
IDs and names, and the infected machine's IP, ISP, machine ID, PC name, user
name and file paths. A plaintext password becomes "FixturePlaintext-<n>": the
integration must never index it, and the tests check that it doesn't.

The sample is picked to cover affiliations, password strengths, credential
set types, infostealer data present/absent, non-email logins and a missing
accessed domain, then topped up to the requested size.

Usage:
    INTEGRAUTH=client_id:client_secret uv run _dev/scripts/get_credentials_fixture.py [size]
"""
import datetime
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

import requests

STREAM_URL = "https://api.intel471.cloud/integrations/creds/v1/credentials/stream"
LOOKBACK_DAYS = 30
OUTPUT = Path(__file__).resolve().parent / "credentials_fixtures.json"
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
KEEP_STEALER = {"malware_family", "os", "antivirus_software", "version", "infection_ts"}


def fetch(session: requests.Session) -> list[dict]:
    from_ts = int((datetime.datetime.now() - datetime.timedelta(days=LOOKBACK_DAYS)).timestamp() * 1000)
    items, cursor = [], None
    while True:
        params = {"from": from_ts, "size": 1000} | ({"cursor": cursor} if cursor else {})
        resp = session.get(STREAM_URL, params=params)
        resp.raise_for_status()
        body = resp.json()
        page = body.get("credentials") or []
        items += page
        cursor = body.get("cursor_next")
        if len(page) < 1000 or len(items) >= 5000:
            return items


def traits(c: dict) -> set:
    d = c.get("data") or {}
    stealer = d.get("info_stealer") or {}
    return {
        ("affiliations", json.dumps(d.get("affiliations"))),
        ("strength", (d.get("password") or {}).get("strength")),
        ("set_type", json.dumps(sorted(d.get("credential_set_type") or []))),
        ("stealer_host", bool(stealer.get("pc_name") or stealer.get("ip"))),
        ("stealer_family", bool(stealer.get("malware_family"))),
        ("email_login", "@" in (d.get("credential_login") or "")),
        ("accessed_domain", "accessed_domain" in d),
        ("plaintext", bool((d.get("password") or {}).get("password_plain"))),
        ("many_sets", len(d.get("credential_sets") or []) > 1),
    }


def pick(items: list[dict], size: int) -> list[dict]:
    chosen, seen = [], set()
    for c in items:
        if traits(c) - seen:
            chosen.append(c)
            seen |= traits(c)
    for c in items:
        if len(chosen) >= size:
            break
        if c not in chosen:
            chosen.append(c)
    return chosen


class Redactor:
    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}
        self.counters: dict[str, int] = {}

    def fake(self, kind: str, original, make):
        if original in (None, ""):
            return original
        if original not in self.mapping:
            n = self.counters[kind] = self.counters.get(kind, 0) + 1
            self.mapping[original] = make(n)
        return self.mapping[original]

    def uuid_id(self, value: str) -> str:
        return UUID_RE.sub(lambda m: self.fake("uuid", m.group(0), lambda n: f"00000000-0000-5000-8000-{n:012d}"), value)

    def domain(self, value):
        return self.fake("domain", value, lambda n: f"domain-{n}.example")

    def login(self, value):
        if value and "@" in value:
            _, _, dom = value.rpartition("@")
            fake_dom = self.domain(dom)
            return self.fake("email", value, lambda n: f"user-{n}@{fake_dom}")
        return self.fake("login", value, lambda n: f"login-{n}")

    def credential(self, c: dict) -> dict:
        c = json.loads(json.dumps(c))
        c["id"] = self.uuid_id(c["id"])
        d = c.get("data") or {}
        d["credential_login"] = self.login(d.get("credential_login"))
        for k in ("credential_domain", "detection_domain"):
            if k in d:
                d[k] = self.domain(d[k])
        for k in ("accessed_domain", "accessed_url"):
            if k in d:
                d[k] = self.fake("accessed", d[k], lambda n: f"site-{n}.example")
        pw = d.get("password") or {}
        if pw.get("id"):
            pw["id"] = self.fake("password_id", pw["id"], lambda n: f"{n:064x}")
        if pw.get("password_plain"):
            pw["password_plain"] = self.fake("plain", pw["password_plain"], lambda n: f"FixturePlaintext-{n}")
        for s in d.get("credential_sets") or []:
            if s.get("id"):
                s["id"] = self.uuid_id(s["id"])
            if s.get("name"):
                s["name"] = self.fake("set_name", s["name"], lambda n: f"Fixture credential set {n}")
        stealer = d.get("info_stealer") or {}
        makers = {
            "ip": lambda n: str(ipaddress.IPv4Address("10.18.1.0") + n),
            "isp": lambda n: f"Example ISP {n}",
            "machine_id": lambda n: f"fixture-machine-{n}",
            "pc_name": lambda n: f"FIXTURE-PC-{n}",
            "computer_username": lambda n: f"fixture-user-{n}",
            "malware_install_path": lambda n: f"C:\\Users\\fixture\\AppData\\fixture-{n}.exe",
            "screenshot_path": lambda n: f"fixture/screenshot-{n}.jpg",
        }
        for k, v in list(stealer.items()):
            if k in KEEP_STEALER:
                continue
            make = makers.get(k, lambda n, k=k: f"fixture-{k}-{n}")
            stealer[k] = [self.fake(k, x, make) for x in v] if isinstance(v, list) else self.fake(k, v, make)
        return c


def main(size: int = 12) -> None:
    client_id, client_secret = os.environ["INTEGRAUTH"].split(":", 1)
    session = requests.Session()
    session.auth = (client_id, client_secret)
    items = fetch(session)
    sample = pick(items, size)
    redactor = Redactor()
    redacted = [redactor.credential(c) for c in sample]

    # Any original personal value that survived is a bug. GIRs and the kept
    # infostealer fields are public taxonomy/product names and may repeat a
    # short original string by coincidence, so they're left out of the check.
    def checked(c: dict) -> dict:
        c = {k: v for k, v in c.items() if k != "classification"}
        d = dict(c.get("data") or {})
        d["info_stealer"] = {k: v for k, v in (d.get("info_stealer") or {}).items() if k not in KEEP_STEALER}
        return c | {"data": d}
    dumped = json.dumps([checked(c) for c in redacted])
    leaked = [o for o in redactor.mapping if isinstance(o, str) and json.dumps(o)[1:-1] in dumped]
    if leaked:
        sys.exit(f"refusing to write, {len(leaked)} original value(s) still present")

    OUTPUT.write_text(json.dumps(redacted, sort_keys=True, indent=2) + "\n")
    print(f"wrote {len(redacted)} of {len(items)} credentials ({len(redactor.mapping)} values redacted) to {OUTPUT}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 12)
