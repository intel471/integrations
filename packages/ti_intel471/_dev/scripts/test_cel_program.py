"""Run the ti_intel471 CEL program through mito against a recording mock API and
check the stream-following rules:

  * first run: `from` = now - initial_interval (epoch ms), no cursor sent
  * pages chain via cursor_next; `from` and filters are replayed verbatim
  * a short page stops the run (want_more=false); its cursor_next is kept
  * the next polling cycle resumes from that cursor, same `from`
  * a drained page with the `indicators` key absent yields no events
  * changing a filter discards the cursor and re-bootstraps
  * an HTTP error emits an error event and leaves the cursor untouched
  * Basic auth and the Intel471-Elastic/<version> User-Agent are sent

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
HBS = PKG / "data_stream" / "indicator" / "agent" / "stream" / "cel.yml.hbs"
MANIFEST = PKG / "manifest.yml"
FIXTURE = HERE / "indicators_fixtures.json"
MITO = shutil.which("mito") or str(Path.home() / "go" / "bin" / "mito")

ITEMS = json.loads(FIXTURE.read_text())[:5]
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
        if q.get("cursor") not in PAGES:
            return self._send(403, {"error": "Forbidden"})
        offset, nxt = PAGES[q.get("cursor")]
        page = ITEMS[offset:offset + int(q["size"])]
        body = {"count": len(ITEMS), "cursor_next": nxt}
        if page:
            body["indicators"] = page  # a drained page omits the key, like the real API can
        self._send(200, body)

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)


def program() -> str:
    lines, inside = [], False
    for line in HBS.read_text().splitlines():
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


def main() -> None:
    version = re.search(r'^version:\s*"?([^"\n]+)"?', MANIFEST.read_text(), re.M).group(1)
    server = HTTPServer(("127.0.0.1", 0), MockAPI)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = {
        "url": f"http://127.0.0.1:{server.server_port}/",
        "client_id": "cid", "client_secret": "secret",
        "user_agent": f"Intel471-Elastic/{version}",
        "page_size": 2, "initial_interval": "24h",
        "threat_type": "malware", "indicator_type": "", "confidence": "",
    }
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "program.cel").write_text(program())

        print("cycle 1: first run")
        before = int((time.time() - 86400) * 1000)
        execs = run(work, base)
        reqs = list(REQUESTS)
        froms = {r["q"].get("from") for r in reqs}
        check(len(execs) == 3, f"three pages fetched (got {len(execs)})")
        check([len(events(e)) for e in execs] == [2, 2, 1], "2 + 2 + 1 events")
        check([e["want_more"] for e in execs] == [True, True, False], "stops on the short page")
        check("cursor" not in reqs[0]["q"], "no cursor on the very first request")
        check([r["q"].get("cursor") for r in reqs[1:]] == ["c1", "c2"], "cursor_next chained")
        check(len(froms) == 1 and abs(int(froms.pop()) - before) < 60_000, "`from` = now-24h in ms, frozen across pages")
        check(all(r["q"].get("threat_type") == "malware" and r["q"]["size"] == "2" for r in reqs), "filters + size replayed")
        check(all(r["auth"] == AUTH for r in reqs), "Basic auth sent")
        check(all(r["ua"] == f"Intel471-Elastic/{version}" for r in reqs), f"User-Agent Intel471-Elastic/{version}")
        check(execs[-1]["cursor"]["next"] == "c3", "terminal cursor_next kept")
        check(all(json.loads(e["message"])["id"] for e in events(execs[0])), "events carry the indicator JSON in `message`")
        cursor1 = execs[-1]["cursor"]

        print("cycle 2: next interval resumes")
        REQUESTS.clear()
        execs = run(work, next_cycle(execs[-1]))
        check(len(REQUESTS) == 1 and REQUESTS[0]["q"].get("cursor") == "c3", "resumes from the stored cursor")
        check(REQUESTS[0]["q"]["from"] == cursor1["from"], "same `from` as the first run")
        check(events(execs[-1]) == [] and execs[-1]["want_more"] is False, "drained page (key absent) -> no events")
        check(execs[-1]["cursor"] == cursor1, "cursor unchanged")

        print("cycle 3: filter change re-bootstraps")
        REQUESTS.clear()
        state = next_cycle(execs[-1]) | {"threat_type": "bulletproof_hosting"}
        execs = run(work, state)
        check("cursor" not in REQUESTS[0]["q"], "old cursor not sent")
        check(REQUESTS[0]["q"].get("threat_type") == "bulletproof_hosting", "new filter sent")
        check(execs[-1]["cursor"]["filter_key"] != cursor1["filter_key"], "new filter key stored")

        print("cycle 4: HTTP error keeps the cursor")
        REQUESTS.clear()
        broken = next_cycle(execs[-1])
        broken["cursor"] = dict(broken["cursor"], next="expired")
        execs = run(work, broken)
        err = events(execs[-1])
        check(len(err) == 1 and err[0].get("error", {}).get("code") == "403", "error event with status 403")
        check(execs[-1]["cursor"] == broken["cursor"], "cursor untouched on error")
        check(execs[-1]["want_more"] is False, "no retry loop within the cycle")

        print("cycle 5: bad credentials")
        REQUESTS.clear()
        execs = run(work, base | {"client_secret": "wrong"})
        check(events(execs[-1])[0]["error"]["code"] == "401", "401 surfaced as an error event")
        check("cursor" not in execs[-1], "no cursor stored")

    server.shutdown()
    sys.exit(1 if check.failed else 0)


if __name__ == "__main__":
    main()
