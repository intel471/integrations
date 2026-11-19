# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///
"""Pull a sample of vulnerability reports from the Reports API stream and store
them, with everything identifying replaced by consistent dummy values, as a
test fixture.

Kept as is: enums (status, risk level, patch/exploit/PoC status, interest
level, activity location), CVSS scores, CVE type, GIRs and timestamps.
Replaced: report and linked object IDs, CVE names and aliases, vendor and
product names, the HTML summaries, and the titles and URLs of sources, PoCs,
patches and countermeasures (sources point at underground forum threads).

The sample is picked to cover every value of the enum fields seen in the
window, then topped up to the requested size.

Usage:
    INTEGRAUTH=client_id:client_secret uv run _dev/scripts/get_vulnerabilities_fixture.py [size]
"""
import datetime
import json
import os
import re
import sys
from pathlib import Path

import requests

STREAM_URL = "https://api.intel471.cloud/integrations/intel-report/v1/reports/vulnerability/stream"
LOOKBACK_DAYS = 30
OUTPUT = Path(__file__).resolve().parent / "vulnerabilities_fixtures.json"
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
HEX_ID_RE = re.compile(r"\b[0-9a-f]{32}\b")  # legacy (Titan) portal report IDs
LINK_LISTS = ("sources", "poc_links", "patch_links", "counter_measure_links")
COVER = ("status", "risk_level", "patch_status", "poc")


def fetch(session: requests.Session) -> list[dict]:
    from_ts = int((datetime.datetime.now() - datetime.timedelta(days=LOOKBACK_DAYS)).timestamp() * 1000)
    reports, cursor = [], None
    while True:
        params = {"from": from_ts, "size": 100} | ({"cursor": cursor} if cursor else {})
        resp = session.get(STREAM_URL, params=params)
        resp.raise_for_status()
        body = resp.json()
        page = body.get("reports") or []
        reports += page
        cursor = body.get("cursor_next")
        if len(page) < 100 or len(reports) >= 1000:
            return reports


def pick(reports: list[dict], size: int) -> list[dict]:
    chosen, seen = [], set()
    for r in reports:
        values = {(k, json.dumps(r.get(k))) for k in COVER} | {("aliases", bool(r.get("aliases")))}
        if values - seen:
            chosen.append(r)
            seen |= values
    for r in reports:
        if len(chosen) >= size:
            break
        if r not in chosen:
            chosen.append(r)
    return chosen


class Redactor:
    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}
        self.counters: dict[str, int] = {}

    def fake(self, kind: str, original: str, make) -> str:
        if original not in self.mapping:
            n = self.counters[kind] = self.counters.get(kind, 0) + 1
            self.mapping[original] = make(n)
        return self.mapping[original]

    def uuids(self, s: str) -> str:
        s = UUID_RE.sub(lambda m: self.fake("uuid", m.group(0), lambda n: f"00000000-0000-5000-8000-{n:012d}"), s)
        return HEX_ID_RE.sub(lambda m: self.fake("hex_id", m.group(0), lambda n: f"{n:032x}"), s)

    def html(self, kind: str, original: str) -> str:
        # Keeps a little markup and an entity so the pipeline's HTML stripping is exercised.
        return self.fake(kind, original, lambda n: f"<p>Fixture {kind} {n} &amp; details.</p><ul><li>Point {n}</li></ul>")

    def link(self, link: dict, kind: str) -> dict:
        out = dict(link)
        if "title" in out:
            out["title"] = self.fake(f"{kind}-title", link["title"] or "", lambda n: f"Fixture {kind} {n}")
        hrefs = {}
        for k, v in (link.get("links") or {}).items():
            href = v.get("href", "")
            if k == "external":
                href = self.fake("external", href, lambda n: f"https://external.example/{kind}/{n}")
            else:
                href = self.uuids(href)
            hrefs[k] = {"href": href}
        out["links"] = hrefs
        return out

    def report(self, r: dict) -> dict:
        r = json.loads(json.dumps(r))
        r["id"] = self.uuids(r["id"])
        r["links"] = {k: {"href": self.uuids(v["href"])} for k, v in r["links"].items()}
        r["name"] = self.fake("cve", r["name"], lambda n: f"CVE-2099-{10000 + n}")
        r["aliases"] = [self.fake("alias", a, lambda n: f"FixtureAlias{n}") for a in r.get("aliases") or []]
        r["vendor_name"] = self.fake("vendor", r["vendor_name"], lambda n: f"Example Vendor {n}")
        r["product_name"] = self.fake("product", r["product_name"], lambda n: f"Example Product {n}")
        for k in ("body", "underground_activity_summary_html", "counter_measures_html"):
            if r.get(k):
                r[k] = self.html(k.removesuffix("_html"), r[k])
        for k in LINK_LISTS:
            r[k] = [self.link(link, k.removesuffix("_links")) for link in r.get(k) or []]
        return r


def main(size: int = 12) -> None:
    client_id, client_secret = os.environ["INTEGRAUTH"].split(":", 1)
    session = requests.Session()
    session.auth = (client_id, client_secret)
    reports = fetch(session)
    sample = pick(reports, size)
    redactor = Redactor()
    redacted = [redactor.report(r) for r in sample]

    # Anything identifying that survived (original IDs, CVEs, names, text) is a bug.
    # GIRs are kept on purpose (public taxonomy) and may contain a product name.
    dumped = json.dumps([{k: v for k, v in r.items() if k != "classification"} for r in redacted])
    leaked = [o for o in redactor.mapping if o and json.dumps(o)[1:-1] in dumped]
    originals = UUID_RE.findall(json.dumps(sample)) + HEX_ID_RE.findall(json.dumps(sample))
    leaked += [u for u in originals if u in dumped and u not in redactor.mapping.values()]
    if leaked:
        sys.exit(f"refusing to write, {len(leaked)} original value(s) still present")

    OUTPUT.write_text(json.dumps(redacted, sort_keys=True, indent=2) + "\n")
    print(f"wrote {len(redacted)} of {len(reports)} reports ({len(redactor.mapping)} values redacted) to {OUTPUT}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 12)
