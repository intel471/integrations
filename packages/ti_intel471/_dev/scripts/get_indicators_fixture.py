# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///
"""Pull a sample of indicators from the Indicators API stream and store them,
with the sensitive values under ``data`` replaced by consistent dummy values,
as a test fixture.

Every real value found under ``data`` (domain, email, url, ipv4 + ISP info,
file hashes, yara rule) is mapped to a fake one, and that mapping is then
applied to *every* string in the indicator, so ``data`` and ``pattern`` (and
``description``, if it happens to contain the value) stay in sync, e.g.:

    data.domain = "acme.com"   pattern = "[domain-name:value = 'acme.com']"
 -> data.domain = "domain-1.example"   pattern = "[domain-name:value = 'domain-1.example']"

The same real value always maps to the same fake one across the whole fixture.
Intel 471 object IDs (indicator, malware, malware family) are replaced too.

Usage:
    INTEGRAUTH=client_id:client_secret uv run _dev/scripts/get_indicators_fixture.py [per_combo]
"""
import datetime
import hashlib
import ipaddress
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import requests

STREAM_URL = "https://api.intel471.cloud/integrations/indicators/v1/indicators/stream"
THREAT_TYPES = ("malware", "bulletproof_hosting")
INDICATOR_TYPES = ("domain", "email", "file", "ipv4", "url", "yara")
LOOKBACK_DAYS = (1, 7, 30, 90, 365)  # widen the window until something turns up
OUTPUT = Path(__file__).resolve().parent / "indicators_fixtures.json"


def fetch(session: requests.Session, threat_type: str, ind_type: str, size: int) -> list[dict]:
    for days in LOOKBACK_DAYS:
        from_ts = int((datetime.datetime.now() - datetime.timedelta(days=days)).timestamp() * 1000)
        resp = session.get(
            STREAM_URL,
            params={"threat_type": threat_type, "type": ind_type, "from": from_ts, "size": size},
        )
        resp.raise_for_status()
        if indicators := resp.json().get("indicators"):
            return indicators
    return []


class Redactor:
    """Maps real values to deterministic, well-formed dummy values."""

    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}
        self.yara_titles: dict[str, str] = {}  # fake signature -> fake title
        self._counters: dict[str, int] = {}

    def _fake(self, kind: str, original: str, make) -> str:
        if original not in self.mapping:
            n = self._counters[kind] = self._counters.get(kind, 0) + 1
            self.mapping[original] = make(n)
        return self.mapping[original]

    @staticmethod
    def _hex(seed: str, length: int) -> str:
        return hashlib.sha256(seed.encode()).hexdigest()[:length]

    # --- per value kind -------------------------------------------------
    def ip(self, value: str) -> str:
        # Private range (RFC 1918): never a real public host, and elastic-package
        # only accepts private or its own GeoIP test addresses in test documents.
        return self._fake("ip", value, lambda n: str(ipaddress.IPv4Address("10.18.0.0") + n))

    def network(self, value: str, fake_ip: str) -> str:
        # keep the original prefix length, but build it around the fake IP so it contains it
        prefix = value.split("/", 1)[1] if "/" in value else "24"
        return self._fake("network", value,
                          lambda n: str(ipaddress.IPv4Network(f"{fake_ip}/{prefix}", strict=False)))

    def domain(self, value: str) -> str:
        return self._fake("domain", value, lambda n: f"domain-{n}.example")

    def host(self, value: str) -> str:
        try:
            ipaddress.IPv4Address(value)
            return self.ip(value)
        except ValueError:
            return self.domain(value)

    def email(self, value: str) -> str:
        local, _, dom = value.rpartition("@")
        fake_dom = self.domain(dom) if dom else "domain.example"
        return self._fake("email", value, lambda n: f"user-{n}@{fake_dom}")

    def url(self, value: str) -> str:
        def make(n: int) -> str:
            parts = urlsplit(value)
            if not parts.hostname:
                return f"http://domain-url-{n}.example/path-{n}"
            netloc = self.host(parts.hostname)
            if parts.port:
                netloc += f":{parts.port}"
            path = f"/path-{n}" if parts.path not in ("", "/") else parts.path
            query = f"q={n}" if parts.query else ""
            return urlunsplit((parts.scheme, netloc, path, query, ""))
        return self._fake("url", value, make)

    def file_hash(self, algo: str, value: str, length: int) -> str:
        return self._fake(algo, value, lambda n: self._hex(f"{algo}-{n}", length))

    def ssdeep(self, value: str) -> str:
        def make(n: int) -> str:
            block = value.split(":", 1)[0]
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            digest = hashlib.sha256(f"ssdeep-{n}".encode()).digest()
            chunk = "".join(alphabet[b % 64] for b in digest)
            return f"{block}:{chunk[:24]}:{chunk[24:]}"
        return self._fake("ssdeep", value, make)

    def yara(self, signature: str, title: str | None) -> None:
        if signature in self.mapping:
            return
        n = self._counters["yara"] = self._counters.get("yara", 0) + 1
        fake_title = f"fixture_rule_{n}"
        fake_sig = (
            f"rule {fake_title}\n{{\n"
            f"    meta:\n        author = \"fixture\"\n        description = \"Dummy rule {n}\"\n\n"
            f"    strings:\n        $s1 = \"fixture-string-{n}\" ascii wide\n\n"
            f"    condition:\n        $s1\n}}\n"
        )
        self.mapping[signature] = fake_sig
        # The title is usually the malware family name, which also appears (not
        # sensitive) in threat.data; so it's swapped only in data.yara.title,
        # never globally like the other values.
        self.yara_titles[fake_sig] = fake_title

    # --- indicator ------------------------------------------------------
    def collect(self, data: dict) -> None:
        """Register fakes for every sensitive value in an indicator's ``data``."""
        if v := data.get("domain"):
            self.domain(v)
        if v := data.get("email"):
            self.email(v)
        if v := data.get("url"):
            self.url(v)
        if f := data.get("file"):
            for algo, length in (("md5", 32), ("sha1", 40), ("sha256", 64)):
                if f.get(algo):
                    self.file_hash(algo, f[algo], length)
            if f.get("ssdeep"):
                self.ssdeep(f["ssdeep"])
        if ip4 := data.get("ipv4"):
            fake_ip = self.ip(ip4["ip_address"]) if ip4.get("ip_address") else "10.18.0.0"
            isp = (ip4.get("geo_ip") or {}).get("isp") or {}
            if v := isp.get("network"):
                self.network(v, fake_ip)
            if v := isp.get("autonomous_system"):
                self._fake("asn", v, lambda n: f"AS{64495 + n} Example Networks {n}")  # RFC 5398
            for key, label in (("isp", "ISP"), ("organization", "Org")):
                if v := isp.get(key):
                    self._fake(key, v, lambda n, label=label: f"Example {label} {n}")
        if y := data.get("yara"):
            if y.get("signature"):
                self.yara(y["signature"], y.get("title"))

    def collect_ids(self, indicator: dict) -> None:
        """Register fakes for Intel 471 object IDs (indicator, malware, family).

        Real IDs would let anyone with API access look up the original
        indicator, so they are replaced with obviously fake ones that keep the
        STIX ``<type>--<uuid>`` shape.
        """
        threat_data = (indicator.get("threat") or {}).get("data") or {}
        ids = [indicator.get("id"),
               (threat_data.get("malware") or {}).get("id"),
               (threat_data.get("malware_family") or {}).get("id")]
        for v in filter(None, ids):
            prefix = v.split("--", 1)[0]
            self._fake(f"id:{prefix}", v,
                       lambda n, prefix=prefix: f"{prefix}--00000000-0000-5000-8000-{n:012d}")

    def apply(self, obj):
        """Replace every known original value in every string of ``obj``."""
        if isinstance(obj, dict):
            return {k: self.apply(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.apply(v) for v in obj]
        if isinstance(obj, str):
            if obj in self.mapping:
                return self.mapping[obj]
            # longest first, so a URL is replaced before the domain inside it
            for original in sorted(self.mapping, key=len, reverse=True):
                if original in obj:
                    obj = obj.replace(original, self.mapping[original])
            return obj
        return obj

    def leaks(self, obj) -> list[str]:
        dumped = json.dumps(obj)
        return [o for o in self.mapping if json.dumps(o)[1:-1] in dumped]


def main(per_combo: int = 2) -> None:
    client_id, client_secret = os.environ["INTEGRAUTH"].split(":", 1)
    session = requests.Session()
    session.auth = (client_id, client_secret)

    collected = []
    for threat_type in THREAT_TYPES:
        for ind_type in INDICATOR_TYPES:
            indicators = fetch(session, threat_type, ind_type, per_combo)
            print(f"{threat_type:20} {ind_type:7} {len(indicators)}")
            collected.extend(indicators)

    redactor = Redactor()
    for indicator in collected:
        redactor.collect(indicator.get("data") or {})
        redactor.collect_ids(indicator)
    redacted = redactor.apply(collected)
    for indicator in redacted:
        if (y := (indicator.get("data") or {}).get("yara")) and y.get("title"):
            y["title"] = redactor.yara_titles[y["signature"]]

    if leaked := redactor.leaks(redacted):
        sys.exit(f"refusing to write, {len(leaked)} original value(s) still present: {leaked[:3]}")

    OUTPUT.write_text(json.dumps(redacted, sort_keys=True, indent=2) + "\n")
    print(f"wrote {len(redacted)} indicators ({len(redactor.mapping)} values redacted) to {OUTPUT}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 2)
