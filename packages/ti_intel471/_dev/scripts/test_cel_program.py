"""Run each ti_intel471 CEL program (indicator, vulnerability) through mito
against a recording mock API and check the stream-following rules:

  * first run: `from` = now - initial_interval (epoch ms), no cursor sent
  * pages chain via cursor_next; `from` and filters are replayed verbatim
  * a short page stops the run (want_more=false); its cursor_next is kept
  * the next polling cycle resumes from that cursor, same `from`
  * a drained page with the items key (`indicators`, `reports`) absent yields no events
  * changing a filter discards the cursor and re-bootstraps
  * an HTTP error emits an error event and leaves the cursor untouched
  * Basic auth and the Intel471-Elastic/<version> User-Agent are sent
  * credentials: plaintext passwords never make it into an event

Needs mito:  go install github.com/elastic/mito/cmd/mito@latest
Usage:       python3 _dev/scripts/test_cel_program.py
"""
import base64
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
PKG = HERE.parent.parent
MANIFEST = PKG / "manifest.yml"
MITO = shutil.which("mito") or str(Path.home() / "go" / "bin" / "mito")

# Per data stream: API path, response items key, the fixture, and a filter to
# exercise as (state var, query param, first value, changed value). `vars` are
# the stream's other filter vars, sent empty.
STREAMS = [
    {"name": "indicator", "path": "/integrations/indicators/v1/indicators/stream", "key": "indicators",
     "fixture": "indicators_fixtures.json", "filter": ("threat_type", "threat_type", "malware", "bulletproof_hosting"),
     "vars": {"indicator_type": "", "confidence": ""}},
    {"name": "vulnerability", "path": "/integrations/intel-report/v1/reports/vulnerability/stream", "key": "reports",
     "fixture": "vulnerabilities_fixtures.json", "filter": ("risk_level", "risk_level", "high", "low"),
     "vars": {}},
    {"name": "credential", "path": "/integrations/creds/v1/credentials/stream", "key": "credentials",
     "fixture": "credentials_fixtures.json", "filter": ("affiliation_group", "affiliation_group", "my_employees", "third_parties"),
     "vars": {}},
]
STREAM: dict = {}  # the stream under test, read by the mock API
ITEMS: list = []
PAGES = {None: (0, "c1"), "c1": (2, "c2"), "c2": (4, "c3"), "c3": (5, "c3")}  # cursor -> (offset, next)
AUTH = "Basic " + base64.b64encode(b"cid:secret").decode()
REQUESTS: list[dict] = []


class MockAPI(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        url = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        REQUESTS.append({"path": url.path, "q": q, "ua": self.headers.get("User-Agent"),
                         "auth": self.headers.get("Authorization")})
        if self.headers.get("Authorization") != AUTH:
            return self._send(401, {"error": "Unauthorized"})
        if url.path != STREAM["path"]:
            return self._send(404, {"error": "Not Found"})
        if q.get("cursor") not in PAGES:
            return self._send(403, {"error": "Forbidden"})
        offset, nxt = PAGES[q.get("cursor")]
        page = ITEMS[offset:offset + int(q["size"])]
        body = {"count": len(ITEMS), "cursor_next": nxt}
        if page:
            body[STREAM["key"]] = page  # a drained page omits the key, like the real API can
        self._send(200, body)

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)


def program(stream: dict) -> str:
    hbs = PKG / "data_stream" / stream["name"] / "agent" / "stream" / "cel.yml.hbs"
    lines, inside = [], False
    for line in hbs.read_text().splitlines():
        if line.startswith("program: |"):
            inside = True
            continue
        if inside and line and not line.startswith(" "):
            break
        if inside:
            lines.append(line[2:])
    return "\n".join(lines) + "\n"


def run(workdir: Path, state: dict) -> list[dict]:
    """Run one polling cycle (mito repeats while want_more); return each execution's output."""
    data = workdir / "state.json"
    data.write_text(json.dumps(state))
    out = subprocess.run([MITO, "-data", str(data), str(workdir / "program.cel")],
                         capture_output=True, text=True, check=True).stdout
    dec, objs, i = json.JSONDecoder(), [], 0
    while i < len(out):
        if out[i].isspace():
            i += 1
            continue
        obj, i = dec.raw_decode(out, i)
        objs.append(obj)
    return objs


def events(execution: dict) -> list:
    ev = execution.get("events", [])
    return ev if isinstance(ev, list) else [ev]


def next_cycle(last: dict) -> dict:
    """What Elastic Agent carries into the next interval: state minus events."""
    return {k: v for k, v in last.items() if k not in ("events", "want_more")}


def check(cond: bool, msg: str) -> None:
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        check.failed = True


check.failed = False


def test_stream(stream: dict, port: int, version: str) -> None:
    STREAM.clear()
    STREAM.update(stream)
    # Items carrying a plaintext password first, so the drop is always exercised.
    items = json.loads((HERE / stream["fixture"]).read_text())
    items.sort(key=lambda i: not ((i.get("data") or {}).get("password") or {}).get("password_plain"))
    ITEMS[:] = items[:5]
    REQUESTS.clear()
    var, param, value, changed = stream["filter"]
    base = {
        "url": f"http://127.0.0.1:{port}/",
        "client_id": "cid", "client_secret": "secret",
        "user_agent": f"Intel471-Elastic/{version}",
        "page_size": 2, "initial_interval": "24h",
        var: value, **stream["vars"],
    }
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "program.cel").write_text(program(stream))

        print(f"{stream['name']} cycle 1: first run")
        before = int((time.time() - 86400) * 1000)
        execs = run(work, base)
        reqs = list(REQUESTS)
        froms = {r["q"].get("from") for r in reqs}
        check(len(execs) == 3, f"three pages fetched (got {len(execs)})")
        check([len(events(e)) for e in execs] == [2, 2, 1], "2 + 2 + 1 events")
        check([e["want_more"] for e in execs] == [True, True, False], "stops on the short page")
        check(all(r["path"] == stream["path"] for r in reqs), f"requests {stream['path']}")
        check("cursor" not in reqs[0]["q"], "no cursor on the very first request")
        check([r["q"].get("cursor") for r in reqs[1:]] == ["c1", "c2"], "cursor_next chained")
        check(len(froms) == 1 and abs(int(froms.pop()) - before) < 60_000, "`from` = now-24h in ms, frozen across pages")
        check(all(r["q"].get(param) == value and r["q"]["size"] == "2" for r in reqs), "filters + size replayed")
        check(all(r["auth"] == AUTH for r in reqs), "Basic auth sent")
        check(all(r["ua"] == f"Intel471-Elastic/{version}" for r in reqs), f"User-Agent Intel471-Elastic/{version}")
        check(execs[-1]["cursor"]["next"] == "c3", "terminal cursor_next kept")
        check(all(json.loads(e["message"])["id"] for e in events(execs[0])), "events carry the item JSON in `message`")
        if any("password_plain" in json.dumps(i) for i in ITEMS):
            messages = [e["message"] for x in execs for e in events(x)]
            check(not any("password_plain" in m or "FixturePlaintext" in m for m in messages),
                  "plaintext passwords served by the API are not in any event")
        cursor1 = execs[-1]["cursor"]

        print(f"{stream['name']} cycle 2: next interval resumes")
        REQUESTS.clear()
        execs = run(work, next_cycle(execs[-1]))
        check(len(REQUESTS) == 1 and REQUESTS[0]["q"].get("cursor") == "c3", "resumes from the stored cursor")
        check(REQUESTS[0]["q"]["from"] == cursor1["from"], "same `from` as the first run")
        check(events(execs[-1]) == [] and execs[-1]["want_more"] is False, "drained page (key absent) -> no events")
        check(execs[-1]["cursor"] == cursor1, "cursor unchanged")

        print(f"{stream['name']} cycle 3: filter change re-bootstraps")
        REQUESTS.clear()
        state = next_cycle(execs[-1]) | {var: changed}
        execs = run(work, state)
        check("cursor" not in REQUESTS[0]["q"], "old cursor not sent")
        check(REQUESTS[0]["q"].get(param) == changed, "new filter sent")
        check(execs[-1]["cursor"]["filter_key"] != cursor1["filter_key"], "new filter key stored")

        print(f"{stream['name']} cycle 4: HTTP error keeps the cursor")
        REQUESTS.clear()
        broken = next_cycle(execs[-1])
        broken["cursor"] = dict(broken["cursor"], next="expired")
        execs = run(work, broken)
        err = events(execs[-1])
        check(len(err) == 1 and err[0].get("error", {}).get("code") == "403", "error event with status 403")
        check(execs[-1]["cursor"] == broken["cursor"], "cursor untouched on error")
        check(execs[-1]["want_more"] is False, "no retry loop within the cycle")

        print(f"{stream['name']} cycle 5: bad credentials")
        REQUESTS.clear()
        execs = run(work, base | {"client_secret": "wrong"})
        check(events(execs[-1])[0]["error"]["code"] == "401", "401 surfaced as an error event")
        check("cursor" not in execs[-1], "no cursor stored")



def main() -> None:
    version = re.search(r'^version:\s*"?([^"\n]+)"?', MANIFEST.read_text(), re.M).group(1)
    server = HTTPServer(("127.0.0.1", 0), MockAPI)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    for stream in STREAMS:
        test_stream(stream, server.server_port, version)
    server.shutdown()
    sys.exit(1 if check.failed else 0)


if __name__ == "__main__":
    main()
