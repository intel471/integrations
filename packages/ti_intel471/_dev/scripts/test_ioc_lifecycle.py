"""Live check of IOC expiry/revocation against a running elastic-package stack.

Writes indicators into logs-ti_intel471.indicator-default (through the real
ingest pipeline) and watches the latest IOC index the transform maintains:

  1. a live indicator appears in the latest index
  2. an exact replay of it is rejected as a duplicate (same _id)
  3. an indicator whose expiration_ts has passed does not stay there
  4. the same indicator re-sent as revoked, with last_seen unchanged, is
     accepted (new _id) and removed from the latest index

Prereqs: `elastic-package stack up -d` and `elastic-package install` in
the package directory. Takes a few minutes: the transform runs every 30s and
waits 120s for late data (sync.time.delay).

Usage: python3 _dev/scripts/test_ioc_lifecycle.py [--es https://127.0.0.1:9200]
"""
import base64
import copy
import datetime as dt
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "indicators_fixtures.json"
ES = sys.argv[sys.argv.index("--es") + 1] if "--es" in sys.argv else "https://127.0.0.1:9200"
AUTH = "Basic " + base64.b64encode(b"elastic:changeme").decode()
SOURCE = "logs-ti_intel471.indicator-default"
LATEST = "logs-ti_intel471_latest.indicator"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # elastic-package stack uses a self-signed CA


def es(method: str, path: str, body=None) -> tuple[int, dict]:
    req = urllib.request.Request(ES + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": AUTH, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=CTX) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def ingest(indicator: dict) -> int:
    doc = {"message": json.dumps(indicator, sort_keys=True), "_conf": {"ioc_expiration_duration": "90d"},
           "tags": ["forwarded", "intel471-indicator"]}
    code, body = es("POST", f"/{SOURCE}/_doc?refresh=true&op_type=create", doc)
    if code not in (201, 409):
        sys.exit(f"unexpected {code} indexing: {body}")
    return code


def in_latest(indicator_id: str) -> int:
    code, body = es("POST", f"/{LATEST}/_count", {"query": {"term": {"event.id": indicator_id}}})
    return body.get("count", 0) if code == 200 else 0


def in_source(indicator_id: str) -> int:
    es("POST", f"/{SOURCE}/_refresh")
    _, body = es("POST", f"/{SOURCE}/_count", {"query": {"term": {"event.id": indicator_id}}})
    return body.get("count", 0)


def wait_for(desc: str, cond, timeout=420) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        es("POST", f"/_transform/{TRANSFORM}/_schedule_now")
        if cond():
            print(f"  ok   {desc} (after {int(time.time() - start)}s)")
            return True
        time.sleep(15)
    print(f"  FAIL {desc} (gave up after {timeout}s)")
    return False


def iso(delta_days: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=delta_days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> None:
    global TRANSFORM
    _, tr = es("GET", "/_transform/*intel471*")
    ids = [t["id"] for t in tr.get("transforms", [])]
    if not ids:
        sys.exit("ti_intel471 transform not found - run `elastic-package install` first")
    TRANSFORM = ids[0]
    _, st = es("GET", f"/_transform/{TRANSFORM}/_stats")
    print(f"transform {TRANSFORM}: {st['transforms'][0]['state']}")

    base = next(i for i in json.loads(FIXTURE.read_text()) if i["type"] == "domain")
    run = uuid.uuid4().hex[:8]
    ok = True

    live = copy.deepcopy(base)
    live["id"] = f"malware-indicator--lifecycle-live-{run}"
    live["activity"] = {"first_seen_ts": iso(-2), "last_seen_ts": iso(-0.01)}
    live["expiration_ts"] = iso(30)
    live["revocation"] = {"revoked": False}

    expired = copy.deepcopy(live)
    expired["id"] = f"malware-indicator--lifecycle-expired-{run}"
    expired["expiration_ts"] = iso(-1)

    print("step 1: live + already-expired indicators")
    ok &= ingest(live) == 201
    ok &= ingest(expired) == 201
    ok &= wait_for("live indicator present in latest index", lambda: in_latest(live["id"]) == 1)
    # Same checkpoint as the live one, so by now retention has run on it too.
    ok &= wait_for("expired indicator absent from latest index", lambda: in_latest(expired["id"]) == 0)

    print("step 2: exact replay")
    code = ingest(live)
    print(f"  {'ok  ' if code == 409 else 'FAIL'} replay rejected as duplicate (HTTP {code})")
    ok &= code == 409

    print("step 3: same indicator revoked, last_seen unchanged")
    revoked = copy.deepcopy(live)
    revoked["revocation"] = {"revoked": True}
    code = ingest(revoked)
    print(f"  {'ok  ' if code == 201 else 'FAIL'} revoked version accepted (HTTP {code})")
    ok &= code == 201
    print(f"  {'ok  ' if in_source(live['id']) == 2 else 'FAIL'} source data stream holds both versions")
    ok &= wait_for("revoked indicator removed from latest index", lambda: in_latest(live["id"]) == 0)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
