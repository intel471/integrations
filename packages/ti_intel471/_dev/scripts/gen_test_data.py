"""Generate ti_intel471 test data from the redacted API fixtures.

Reads indicators_fixtures.json, vulnerabilities_fixtures.json and
credentials_fixtures.json (produced by the get_*_fixture.py scripts, values
already redacted) and writes:

  * indicator pipeline test inputs, one file per indicator type, plus synthetic
    edge cases (revoked in several shapes; no expiration_ts so the fallback
    expiry applies; an ASN string the pipeline can't parse)
  * vulnerability pipeline test inputs, plus CVSS edge cases (no 3.x score; no
    score at all, with a name that isn't a CVE ID)
  * credential pipeline test inputs as the CEL program emits them (plaintext
    password dropped), plus one that still carries a plaintext password, which
    the pipeline must remove along with event.original
  * the mock API config used by the system tests: for each stream, three pages
    served with cursor_next chaining, the last one short so the stream drains

Usage:  python3 _dev/scripts/gen_test_data.py
Then:   elastic-package test pipeline --generate
"""
import copy
import json
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "indicators_fixtures.json"
VULN_FIXTURE = HERE / "vulnerabilities_fixtures.json"
CREDS_FIXTURE = HERE / "credentials_fixtures.json"
PKG = HERE.parent.parent
PIPELINE_DIR = PKG / "data_stream" / "indicator" / "_dev" / "test" / "pipeline"
VULN_PIPELINE_DIR = PKG / "data_stream" / "vulnerability" / "_dev" / "test" / "pipeline"
CREDS_PIPELINE_DIR = PKG / "data_stream" / "credential" / "_dev" / "test" / "pipeline"
MOCK_CONFIG = PKG / "_dev" / "deploy" / "docker" / "files" / "config.yml"

SYSTEM_TEST_PAGE_SIZE = 2  # must match each stream's _dev/test/system/test-default-config.yml
SYSTEM_TEST_PAGES = 3      # 2 + 2 + 1 items -> hit_count 5

# (API path, response key) per stream, as the CEL programs request them.
INDICATORS_API = ("/integrations/indicators/v1/indicators/stream", "indicators")
VULNERABILITIES_API = ("/integrations/intel-report/v1/reports/vulnerability/stream", "reports")
CREDENTIALS_API = ("/integrations/creds/v1/credentials/stream", "credentials")


def write_events(name: str, items: list[dict], directory: Path = PIPELINE_DIR) -> None:
    events = {"events": [{"message": json.dumps(i, sort_keys=True)} for i in items]}
    (directory / f"test-{name}.json").write_text(json.dumps(events, indent=2) + "\n")


def clear_inputs(directory: Path) -> None:
    for old in directory.glob("test-*.json"):
        if not old.name.endswith("-expected.json"):
            old.unlink()


def pipeline_tests(indicators: list[dict]) -> None:
    clear_inputs(PIPELINE_DIR)
    by_type = defaultdict(list)
    for i in indicators:
        by_type[f"{i['threat']['type'].replace('_', '-')}-{i['type']}"].append(i)
    for name, items in sorted(by_type.items()):
        write_events(name, items)

    base = next(i for i in indicators if i["type"] == "domain")
    revoked = copy.deepcopy(base)
    revoked["revocation"] = {"revoked": True}
    write_events("revoked", [revoked])

    # The same indicator arriving live, then revoked with last_seen unchanged:
    # both must be indexed (different _id) and the second must expire at ingest.
    live = copy.deepcopy(base)
    live["revocation"] = {"revoked": False}
    write_events("revoked-update", [live, revoked])

    revoked_str = copy.deepcopy(base)
    revoked_str["revocation"] = {"revoked": "true"}
    write_events("revoked-string", [revoked_str])

    no_expiry = copy.deepcopy(base)
    no_expiry.pop("expiration_ts", None)
    write_events("no-expiration-ts", [no_expiry])

    # An ASN string the grok can't parse: tagged, but not an error document,
    # so the indicator still reaches the latest IOC index.
    ipv4 = next(i for i in indicators if i["type"] == "ipv4")
    bad_asn = copy.deepcopy(ipv4)
    bad_asn["data"]["ipv4"]["geo_ip"]["isp"]["autonomous_system"] = "Unknown ASN"
    write_events("asn-unparsed", [bad_asn])


def vulnerability_pipeline_tests(reports: list[dict]) -> None:
    VULN_PIPELINE_DIR.mkdir(parents=True, exist_ok=True)
    clear_inputs(VULN_PIPELINE_DIR)
    write_events("vulnerability", reports, VULN_PIPELINE_DIR)

    # No CVSS 3.x score (-1 is the API's "not scored"): the base score falls back
    # to 4.0 ahead of 2.0.
    no_v3 = copy.deepcopy(reports[0])
    no_v3["cvss"] = [{"version": "2.0", "score": 5.0}, {"version": "3.0", "score": -1.0},
                     {"version": "3.1", "score": -1.0}, {"version": "4.0", "score": 7.3}]
    # No score at all (the API's sentinel is -1), and a name that isn't a CVE ID:
    # no score, no enumeration.
    no_cvss = copy.deepcopy(reports[1])
    no_cvss["cvss"] = [{"version": v, "score": -1.0} for v in ("2.0", "3.0", "3.1", "4.0")]
    no_cvss["name"] = "Fixture vulnerability without CVE"
    write_events("vulnerability-cvss-edge-cases", [no_v3, no_cvss], VULN_PIPELINE_DIR)


def without_plaintext(credential: dict) -> dict:
    """The credential as the CEL program emits it."""
    c = copy.deepcopy(credential)
    ((c.get("data") or {}).get("password") or {}).pop("password_plain", None)
    return c


def credential_pipeline_tests(credentials: list[dict]) -> None:
    CREDS_PIPELINE_DIR.mkdir(parents=True, exist_ok=True)
    clear_inputs(CREDS_PIPELINE_DIR)
    write_events("credential", [without_plaintext(c) for c in credentials], CREDS_PIPELINE_DIR)
    # Defence in depth: a plaintext password that reaches the pipeline anyway.
    leaked = next(c for c in credentials if (c["data"].get("password") or {}).get("password_plain"))
    write_events("credential-plaintext-password", [leaked], CREDS_PIPELINE_DIR)
    # Stealer logs can report a machine IP that isn't an IP address; it must not
    # reach the ip-typed fields (the latest transform would stop on it).
    stolen = copy.deepcopy(next(c for c in credentials if (c["data"].get("info_stealer") or {}).get("ip")))
    stolen["data"]["info_stealer"]["ip"] = stolen["data"]["info_stealer"]["ip"][:1] + ["10.18.1.999", "2001:db8::1", "unknown"]
    write_events("credential-invalid-stealer-ip", [without_plaintext(stolen)], CREDS_PIPELINE_DIR)


def mock_rules(api: tuple[str, str], items: list[dict]) -> list[str]:
    path, key = api
    sample = items[: SYSTEM_TEST_PAGE_SIZE * (SYSTEM_TEST_PAGES - 1) + 1]
    pages = [sample[n:n + SYSTEM_TEST_PAGE_SIZE] for n in range(0, len(sample), SYSTEM_TEST_PAGE_SIZE)]
    lines = []
    # Rules are matched in order, so the cursor-specific ones come first and the
    # first page (no cursor) is the catch-all at the end.
    lines.append(f"""  - path: {path}
    methods: [GET]
    query_params:
      cursor: cursor-{len(pages)}
    responses:
      - status_code: 200
        headers:
          Content-Type: [application/json]
        body: |-
          {{"count": 0, "cursor_next": "cursor-{len(pages)}"}}""")
    for n in range(len(pages), 0, -1):
        body = {"count": len(sample), "cursor_next": f"cursor-{n}", key: pages[n - 1]}
        query = f"\n    query_params:\n      cursor: cursor-{n - 1}" if n > 1 else ""
        lines.append(f"""  - path: {path}
    methods: [GET]{query}
    request_headers:
      Authorization: "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ="
    responses:
      - status_code: 200
        headers:
          Content-Type: [application/json]
        body: |-
          {json.dumps(body, sort_keys=True)}""")
    return lines


def mock_config(indicators: list[dict], reports: list[dict], credentials: list[dict]) -> None:
    lines = [
        "# Generated by _dev/scripts/gen_test_data.py - do not edit by hand.",
        "# Mock Intel 471 API: for each stream, pages chained by cursor_next; the",
        "# last page is short, which tells the integration the stream is drained.",
        "rules:",
    ]
    lines += mock_rules(INDICATORS_API, indicators)
    lines += mock_rules(VULNERABILITIES_API, reports)
    # Served with plaintext passwords, as the real API does; the CEL program drops them.
    lines += mock_rules(CREDENTIALS_API, credentials)
    MOCK_CONFIG.write_text("\n".join(lines) + "\n")


def main() -> None:
    indicators = json.loads(FIXTURE.read_text())
    reports = json.loads(VULN_FIXTURE.read_text())
    credentials = json.loads(CREDS_FIXTURE.read_text())
    PIPELINE_DIR.mkdir(parents=True, exist_ok=True)
    pipeline_tests(indicators)
    vulnerability_pipeline_tests(reports)
    credential_pipeline_tests(credentials)
    mock_config(indicators, reports, credentials)
    print(f"wrote pipeline tests for 3 data streams and {MOCK_CONFIG.relative_to(PKG)}")


if __name__ == "__main__":
    main()
