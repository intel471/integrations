"""Generate the ti_intel471 Kibana dashboards (ES|QL Lens panels).

The panel queries, layout and controls live here; kibana/dashboard/*.json is
what Kibana exports after importing them, so the committed files stay in the
format elastic-package and Kibana expect.

  python3 gen_dashboards.py test       # run every panel query against the stack (prints counts and column names only)
  python3 gen_dashboards.py import     # import the dashboards into the stack's Kibana
  elastic-package export dashboards --id ti_intel471-overview --id ti_intel471-indicators \
      --id ti_intel471-vulnerabilities --id ti_intel471-credentials

Dashboards edited by hand in Kibana can be exported the same way; port the
change back here if you want to keep generating them.
"""
import datetime
import hashlib
import json
import subprocess
import sys
import uuid

ES = "https://127.0.0.1:9200"
AUTH = "elastic:changeme"
NS = uuid.UUID("5d6c1f4e-4f71-4c1a-9b47-1471a0000000")

IND = "logs-ti_intel471_latest.indicator"
VUL = "logs-ti_intel471_latest.vulnerability"
CRED = "logs-ti_intel471_latest.credential"
RAW = "logs-ti_intel471.*-*"

DASH = {
    "overview": ("ti_intel471-overview", "[Logs Intel 471] Overview"),
    "indicator": ("ti_intel471-indicators", "[Logs Intel 471] Indicators"),
    "vulnerability": ("ti_intel471-vulnerabilities", "[Logs Intel 471] Vulnerabilities"),
    "credential": ("ti_intel471-credentials", "[Logs Intel 471] Credentials"),
}


def pid(*parts) -> str:
    return str(uuid.uuid5(NS, "/".join(parts)))


# ---------------------------------------------------------------- panels ----
# Each panel: dict(title, kind, q, cols={name: type}, grid=(x, y, w, h), + kind opts)
# kinds: metric(value), bar(x, y, split?, horizontal?), donut(cat, value), table(order?, wrap?)
# time: the field the dashboard time picker filters on, or None to ignore the
# time picker (health panels always look at "now").

def P(title, kind, q, cols, grid, time="@timestamp", **kw):
    q = q.strip()
    # Charts don't show a "(null)" category: records without the value are
    # left out of that chart (they still count everywhere else).
    cat = kw.get("cat") or kw.get("x")
    if kind in ("bar", "donut") and cols.get(cat) == "string" and "IS NOT NULL" not in q:
        lines = q.split("\n")
        at = next(n for n, l in enumerate(lines) if l.startswith("| STATS"))
        name = f"`{cat}`" if " " in cat else cat
        lines.insert(at + 1, f"| WHERE {name} IS NOT NULL")
        q = "\n".join(lines)
    return dict(title=title, kind=kind, q=q, cols=cols, grid=grid, time=time, **kw)


AGENT = "metrics-elastic_agent.filebeat_input-*"

# The overview always shows the current state and ignores the time picker.
OVERVIEW_PANELS = [
    # One row per stream, from two sources:
    # - the raw data streams (kept 5 days): what was received and the errors;
    # - the agent's input metrics, sampled every minute: filebeat_input.cel_executions
    #   goes up on every run, so the first sample with its latest value is the
    #   last run (to the minute), whether or not the run fetched anything. Runs
    #   are looked for in the last 24 hours; an agent restart resets the counter,
    #   which still shows as a run.
    # The first STATS groups the metrics by counter value (the raw data has none,
    # so it's one group per stream); the second folds them into one row.
    P("Collection health", "table",
      f"""
FROM {RAW}, {AGENT}
| WHERE (event.ingested >= NOW() - 5 days AND data_stream.dataset LIKE "ti_intel471.*")
     OR (@timestamp >= NOW() - 24 hours AND filebeat_input.id LIKE "cel-ti_intel471.*")
| EVAL Stream = COALESCE(REPLACE(filebeat_input.id, "^cel-ti_intel471[.]([a-z]+)-.*", "$1"),
                         REPLACE(data_stream.dataset, "^ti_intel471[.]", "")),
       run = TO_LONG(filebeat_input.cel_executions),
       data = filebeat_input.id IS NULL,
       ok = data AND error.message IS NULL
| STATS since = MIN(@timestamp),
        received = MAX(CASE(ok, event.ingested, null)),
        r1h = SUM(CASE(ok AND event.ingested >= NOW() - 1 hour, 1, 0)),
        r24h = SUM(CASE(ok AND event.ingested >= NOW() - 24 hours, 1, 0)),
        r5d = SUM(CASE(ok, 1, 0)),
        e24h = SUM(CASE(data AND NOT ok AND event.ingested >= NOW() - 24 hours, 1, 0))
  BY Stream, run
| STATS last_change = MAX(CASE(run IS NOT NULL, since, null)),
        first_sample = MIN(CASE(run IS NOT NULL, since, null)),
        `Last data received` = MAX(received),
        `Received (1h)` = SUM(r1h), `Received (24h)` = SUM(r24h), `Received (5 days)` = SUM(r5d),
        `Errors (24h)` = SUM(e24h)
  BY Stream
| EVAL `Last run` = CASE(last_change > first_sample, last_change, null)
| KEEP Stream, `Last run`, `Last data received`, `Received (1h)`, `Received (24h)`, `Received (5 days)`, `Errors (24h)`
| SORT Stream
""",
      {"Stream": "string", "Last run": "date", "Last data received": "date", "Received (1h)": "number",
       "Received (24h)": "number", "Received (5 days)": "number", "Errors (24h)": "number"},
      (0, 4, 48, 8), time=None,
      order=["Stream", "Last run", "Last data received", "Received (1h)", "Received (24h)",
             "Received (5 days)", "Errors (24h)"]),
    P("Collection errors (last 5 days)", "table",
      f"""
FROM {RAW}
| WHERE error.message IS NOT NULL AND event.ingested >= NOW() - 5 days
| STATS Errors = COUNT(*), `Last seen` = MAX(event.ingested) BY Stream = data_stream.dataset, Error = error.message
| EVAL Stream = REPLACE(Stream, "^ti_intel471[.]", "")
| SORT `Last seen` DESC
| LIMIT 50
""",
      {"Last seen": "date", "Stream": "string", "Errors": "number", "Error": "string"}, (0, 12, 48, 14),
      time=None, order=["Last seen", "Stream", "Errors", "Error"], wrap=True),
]

INDICATOR_PANELS = [
    # ?_tstart/?_tend are the time picker's range, so the bars adapt to it.
    P("Active indicators by last seen", "bar",
      f"FROM {IND}\n| STATS Indicators = COUNT(*) BY `Last seen` = BUCKET(@timestamp, 60, ?_tstart, ?_tend)",
      {"Last seen": "date", "Indicators": "number"}, (0, 4, 48, 12), x="Last seen", y="Indicators"),
]

# The latest (transform) indices only, not the raw data streams that hold every
# update. Indicators have a label for it; the other two match the index name.
LATEST_ONLY = {"alias": "Latest index only", "query": {"wildcard": {"_index": "logs-ti_intel471_latest.dest_*"}}}

# Saved searches embedded in a dashboard: unlike an ES|QL table, a row expands
# to show the whole document.
SEARCHES = {
    "indicator": dict(
        id="ti_intel471-active-indicators", title="[Logs Intel 471] Active indicators",
        # Latest IOC index only: the raw data stream holds every update.
        filters=[("data_stream.dataset", "ti_intel471.indicator"), ("labels.is_ioc_transform_source", "false")],
        columns=["intel471.indicator.type", "threat.indicator.name", "threat.software.name",
                 "threat.indicator.confidence", "threat.tactic.name", "intel471.indicator.ioc_expired_at"],
        grid=(0, 16, 48, 24)),
    "vulnerability": dict(
        id="ti_intel471-vulnerability-reports", title="[Logs Intel 471] Vulnerability reports",
        filters=[("data_stream.dataset", "ti_intel471.vulnerability"), LATEST_ONLY],
        columns=["vulnerability.id", "intel471.vulnerability.vendor_name", "intel471.vulnerability.product_name",
                 "vulnerability.severity", "vulnerability.score.base", "intel471.vulnerability.exploit_status",
                 "intel471.vulnerability.patch_status", "intel471.vulnerability.status"],
        grid=(0, 16, 48, 24)),
    "credential": dict(
        id="ti_intel471-compromised-credentials", title="[Logs Intel 471] Compromised credentials",
        filters=[("data_stream.dataset", "ti_intel471.credential"), LATEST_ONLY],
        columns=["user.email", "intel471.credential.data.affiliations", "intel471.credential.data.detection_domain",
                 "url.domain", "intel471.credential.data.password.strength",
                 "intel471.credential.data.credential_set_type", "intel471.credential.data.info_stealer.malware_family"],
        grid=(0, 16, 48, 24)),
}

VULNERABILITY_PANELS = [
    P("Reports by last updated", "bar",
      f"FROM {VUL}\n| STATS Reports = COUNT(*) BY Updated = BUCKET(@timestamp, 60, ?_tstart, ?_tend)",
      {"Updated": "date", "Reports": "number"}, (0, 4, 48, 12), x="Updated", y="Reports"),
]

CRED_PANELS = [
    P("Credentials by last updated", "bar",
      f"FROM {CRED}\n| STATS Credentials = COUNT(*) BY Updated = BUCKET(@timestamp, 60, ?_tstart, ?_tend)",
      {"Updated": "date", "Credentials": "number"}, (0, 4, 48, 12), x="Updated", y="Credentials"),
]

PANELS = {"overview": OVERVIEW_PANELS, "indicator": INDICATOR_PANELS,
          "vulnerability": VULNERABILITY_PANELS, "credential": CRED_PANELS}

CONTROLS = {
    "overview": [],
    "indicator": [
        # Contains-search over the indicator value (URL, domain, IP, email,
        # SHA-256, YARA rule title). MD5 and SHA-1 are found with the search bar.
        ("threat.indicator.name", "Indicator", "wildcard"),
        ("intel471.indicator.type", "Indicator type"),
        ("threat.software.name", "Malware family"),
        ("threat.indicator.confidence", "Confidence"),
    ],
    "vulnerability": [
        ("vulnerability.id", "CVE", "wildcard"),
        ("intel471.vulnerability.status", "Report status"),
        ("vulnerability.severity", "Risk"),
        ("intel471.vulnerability.exploit_status", "Exploit"),
        ("intel471.vulnerability.vendor_name", "Vendor"),
    ],
    "credential": [
        # The full login and, for an email address, the part before the @.
        ("related.user", "Login", "wildcard"),
        ("intel471.credential.data.affiliations", "Affiliation"),
        ("intel471.credential.data.detection_domain", "Monitored domain"),
        ("intel471.credential.data.password.strength", "Password strength"),
    ],
}

DESCRIPTIONS = {
    "overview": "Health of the Intel 471 integration: per data stream, when it last ran, when data last arrived, how much arrived, and collection errors.",
    "indicator": "Active Intel 471 malware indicators (URLs, IPs, file hashes, domains, email addresses and YARA rules) from the latest IOC index, searchable by value.",
    "vulnerability": "Intel 471 vulnerability reports, one per CVE, searchable by CVE and filterable by status, risk, exploitation and vendor.",
    "credential": "Compromised credentials from Intel 471 that match your monitored domains, searchable by login.",
}

INTRO = {
    "overview": "Health of the Intel 471 integration, always as of now (the time picker doesn't apply). **Last run** is when the agent last ran the stream, whether or not it fetched anything (from the agent's monitoring metrics; empty if it hasn't run in 24 hours or agent monitoring is off); **Last data received** is when data last arrived. A stream that hasn't run for longer than its interval, or has errors, needs a look.",
    "indicator": "Active malware indicators from the Intel 471 Indicators API, one row each; expired and revoked ones are removed automatically. The time picker filters on when an indicator was last seen. Find an indicator with the **Indicator** control, or type any value (including an MD5 or SHA-1 hash) in the search bar, in quotes. Expand a row to see the whole indicator.",
    "vulnerability": "Vulnerability reports from the Intel 471 Reports API, one row per report. The time picker filters on when a report was last updated. Find a report with the **CVE** control; expand a row to read the whole report, including its summary, underground activity and countermeasures.",
    "credential": "Compromised credentials from the Intel 471 Credentials API, one row per credential. The time picker filters on when a credential was last updated. Find one with the **Login** control; filter on **Affiliation** for your employees and VIP emails. Expand a row to see the whole credential. Plaintext passwords are never stored.",
}


# ------------------------------------------------------------ lens state ----

def lens_panel(dash_key: str, p: dict) -> dict:
    index = p["q"].split("\n", 1)[0].removeprefix("FROM ").split(" METADATA ")[0].strip()
    time = p["time"]
    dv_id = hashlib.sha256(f"{index}|{time}".encode()).hexdigest()
    layer = pid(dash_key, p["title"], "layer")
    names = list(p["cols"])
    metric_cols = {p.get("value"), p.get("y")}
    columns = []
    for n in names:
        t = p["cols"][n]
        c = {"columnId": n, "fieldName": n, "label": n, "customLabel": False, "meta": {"type": t}}
        if n in metric_cols:
            c["inMetricDimension"] = True
        columns.append(c)

    k = p["kind"]
    if k == "metric":
        vis = {"layerId": layer, "layerType": "data", "metricAccessor": p["value"]}
        if p.get("breakdown"):
            vis |= {"breakdownByAccessor": p["breakdown"], "maxCols": 6}
        vtype = "lnsMetric"
    elif k == "bar":
        series = "bar_horizontal" if p.get("horizontal") else ("bar_stacked" if p.get("split") else "bar")
        if p.get("horizontal") and p.get("split"):
            series = "bar_horizontal_stacked"
        layer_cfg = {"layerId": layer, "layerType": "data", "seriesType": series,
                     "xAccessor": p["x"], "accessors": [p["y"]]}
        if p.get("split"):
            layer_cfg["splitAccessor"] = p["split"]
        vis = {
            "preferredSeriesType": series,
            "legend": {"isVisible": bool(p.get("split")), "position": "right"},
            "valueLabels": "hide",
            "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": False},
            "layers": [layer_cfg],
        }
        vtype = "lnsXY"
    elif k == "donut":
        vis = {"shape": "donut", "layers": [{
            "layerId": layer, "layerType": "data",
            "primaryGroups": [p["cat"]], "metrics": [p["value"]],
            "numberDisplay": "percent", "categoryDisplay": "default",
            "legendDisplay": "show", "nestedLegend": False, "emptySizeRatio": 0.6,
        }]}
        vtype = "lnsPie"
    elif k == "table":
        order = p.get("order", names)
        vis = {"layerId": layer, "layerType": "data",
               "columns": [{"columnId": n, "isTransposed": False} for n in order],
               "paging": {"enabled": True, "size": 10}}
        if p.get("wrap"):
            vis |= {"rowHeight": "auto", "headerRowHeight": "single"}
        vtype = "lnsDatatable"
    else:
        raise ValueError(k)

    state = {
        "adHocDataViews": {dv_id: {
            "id": dv_id, "title": index, "name": index, **({"timeFieldName": time} if time else {}),
            "type": "esql", "allowNoIndex": False, "allowHidden": False,
            "sourceFilters": [], "fieldFormats": {}, "runtimeFieldMap": {},
        }},
        "datasourceStates": {"textBased": {
            "indexPatternRefs": [{"id": dv_id, "title": index, **({"timeField": time} if time else {})}],
            "layers": {layer: {"index": dv_id, "query": {"esql": p["q"]}, "columns": columns,
                               **({"timeField": time} if time else {})}},
        }},
        "filters": [], "query": {"esql": p["q"]}, "visualization": vis,
        "internalReferences": [], "needsRefresh": False,
    }
    x, y, w, h = p["grid"]
    i = pid(dash_key, p["title"])
    return {
        "type": "lens", "panelIndex": i, "title": p["title"],
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": i},
        "embeddableConfig": {
            "attributes": {"title": p["title"], "visualizationType": vtype, "type": "lens",
                           "references": [], "state": state},
            "enhancements": {"dynamicActions": {"events": []}},
            "syncColors": False, "syncCursor": True, "syncTooltips": False,
            "filters": [], "query": {"esql": p["q"]},
        },
    }


def links_panel(dash_key: str):
    i = pid(dash_key, "links")
    links, refs = [], []
    for n, (key, (dash_id, title)) in enumerate(DASH.items()):
        lid = pid(dash_key, "link", key)
        links.append({"id": lid, "type": "dashboardLink", "order": n,
                      "label": title.removeprefix("[Logs Intel 471] "),
                      "destinationRefName": f"link_{lid}_dashboard",
                      "options": {"openInNewTab": False, "useCurrentDateRange": True, "useCurrentFilters": False}})
        refs.append({"type": "dashboard", "id": dash_id, "name": f"{i}:link_{lid}_dashboard"})
    panel = {"type": "links", "panelIndex": i, "title": "",
             "gridData": {"x": 0, "y": 0, "w": 20, "h": 4, "i": i},
             "embeddableConfig": {"attributes": {"layout": "horizontal", "links": links},
                                  "enhancements": {}, "hidePanelTitles": True}}
    return panel, refs


def markdown_panel(dash_key: str):
    i = pid(dash_key, "intro")
    return {
        "type": "visualization", "panelIndex": i,
        "gridData": {"x": 20, "y": 0, "w": 28, "h": 4, "i": i},
        "embeddableConfig": {
            "hidePanelTitles": True,
            "enhancements": {"dynamicActions": {"events": []}},
            "savedVis": {
                "type": "markdown", "title": "", "description": "", "uiState": {},
                "params": {"fontSize": 11, "openLinksInNewTab": False, "markdown": INTRO[dash_key]},
                "data": {"aggs": [], "searchSource": {"query": {"query": "", "language": "kuery"}, "filter": []}},
            },
        },
    }


def controls(dash_key: str):
    panels, refs = {}, []
    for n, (field, title, *technique) in enumerate(CONTROLS[dash_key]):
        cid = pid(dash_key, "control", field)
        panels[cid] = {"type": "optionsListControl", "order": n, "grow": True, "width": "medium",
                       "explicitInput": {"id": cid, "dataViewId": "logs-*", "fieldName": field, "title": title,
                                         "searchTechnique": technique[0] if technique else "prefix", "selectedOptions": [],
                                         "sort": {"by": "_count", "direction": "desc"},
                                         "exclude": False, "existsSelected": False}}
        refs.append({"type": "index-pattern", "id": "logs-*", "name": f"controlGroup_{cid}:optionsListDataView"})
    cg = {"chainingSystem": "HIERARCHICAL", "controlStyle": "oneLine", "showApplySelections": False,
          "ignoreParentSettingsJSON": json.dumps({"ignoreFilters": False, "ignoreQuery": False,
                                                  "ignoreTimerange": False, "ignoreValidations": False}),
          "panelsJSON": json.dumps(panels)}
    return cg, refs


def phrase_filter(field: str, value: str, ref: str) -> dict:
    return {"$state": {"store": "appState"},
            "meta": {"alias": None, "disabled": False, "negate": False, "type": "phrase",
                     "key": field, "field": field, "params": {"query": value}, "indexRefName": ref},
            "query": {"match_phrase": {field: value}}}


def custom_filter(f: dict, ref: str) -> dict:
    return {"$state": {"store": "appState"},
            "meta": {"alias": f["alias"], "disabled": False, "negate": False, "type": "custom", "key": "query",
                     "value": json.dumps(f["query"]), "indexRefName": ref},
            "query": f["query"]}


def saved_search(dash_key: str) -> dict:
    s = SEARCHES[dash_key]
    refs = [{"type": "index-pattern", "id": "logs-*", "name": "kibanaSavedObjectMeta.searchSourceJSON.index"}]
    filters = []
    for n, f in enumerate(s["filters"]):
        ref = f"kibanaSavedObjectMeta.searchSourceJSON.filter[{n}].meta.index"
        filters.append(custom_filter(f, ref) if isinstance(f, dict) else phrase_filter(*f, ref))
        refs.append({"type": "index-pattern", "id": "logs-*", "name": ref})
    return {
        "type": "search", "id": s["id"],
        "coreMigrationVersion": "8.8.0", "typeMigrationVersion": "10.2.0",
        "attributes": {
            "title": s["title"], "description": "", "columns": s["columns"],
            "sort": [["@timestamp", "desc"]], "grid": {}, "hideChart": True, "isTextBasedQuery": False,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "", "language": "kuery"}, "filter": filters,
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})},
        },
        "references": refs,
    }


def search_panel(dash_key: str):
    s = SEARCHES[dash_key]
    i = pid(dash_key, "search", s["id"])
    x, y, w, h = s["grid"]
    title = s["title"].removeprefix("[Logs Intel 471] ")
    panel = {"type": "search", "panelIndex": i, "title": title, "panelRefName": f"panel_{i}",
             "gridData": {"x": x, "y": y, "w": w, "h": h, "i": i},
             "embeddableConfig": {"description": "", "enhancements": {"dynamicActions": {"events": []}}}}
    return panel, [{"type": "search", "id": s["id"], "name": f"{i}:panel_{i}"}]


def dashboard(dash_key: str) -> dict:
    dash_id, title = DASH[dash_key]
    links, refs = links_panel(dash_key)
    panels = [links, markdown_panel(dash_key)] + [lens_panel(dash_key, p) for p in PANELS[dash_key]]
    if dash_key in SEARCHES:
        sp, srefs = search_panel(dash_key)
        panels.append(sp)
        refs += srefs
    cg, crefs = controls(dash_key)
    # The overview spans every stream and the agent metrics, so it has no
    # dataset filter (validation.yml exempts it from SVR00002).
    filters = [] if dash_key == "overview" else [phrase_filter(
        "data_stream.dataset", f"ti_intel471.{dash_key}", "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index")]
    frefs = [{"type": "index-pattern", "id": "logs-*",
              "name": "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index"}] if filters else []
    return {
        "type": "dashboard", "id": dash_id,
        "coreMigrationVersion": "8.8.0", "typeMigrationVersion": "10.2.0",
        "attributes": {
            "title": title, "description": DESCRIPTIONS[dash_key],
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True,
                                       "syncTooltips": False, "hidePanelTitles": False}),
            "timeRestore": True, "timeFrom": "now-30d", "timeTo": "now",
            "refreshInterval": {"pause": True, "value": 60000},
            "controlGroupInput": cg,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": filters})},
            "version": 1,
        },
        "references": refs + crefs + frefs,
    }


# ------------------------------------------------------------------ main ----

# What Kibana passes for ?_tstart/?_tend: the time picker's range (here, 30 days).
_now = datetime.datetime.now(datetime.timezone.utc)
TIME_PARAMS = [{"_tstart": (_now - datetime.timedelta(days=30)).isoformat()}, {"_tend": _now.isoformat()}]


def esql(q: str) -> dict:
    out = subprocess.run(["curl", "-sk", "-u", AUTH, "-H", "Content-Type: application/json",
                          f"{ES}/_query", "-d", json.dumps({"query": q, "params": TIME_PARAMS if "?_tstart" in q else []})],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def test():
    bad = 0
    for key, panels in PANELS.items():
        for p in panels:
            r = esql(p["q"])
            if "error" in r:
                bad += 1
                print(f"FAIL {key} / {p['title']}: {r['error'].get('reason', r['error'])[:400]}")
                continue
            got = [c["name"] for c in r["columns"]]
            missing = set(p["cols"]) - set(got)
            extra = set(got) - set(p["cols"])
            status = "ok  " if not missing and not extra else "COLS"
            if missing or extra:
                bad += 1
            # Only counts and column names: values may be personal data.
            print(f"{status} {key:13} {p['title'][:45]:45} rows={len(r['values']):4}"
                  + (f" missing={sorted(missing)} extra={sorted(extra)}" if missing or extra else ""))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    if sys.argv[1] == "test":
        test()
    elif sys.argv[1] == "import":
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".ndjson") as f:
            objs = [saved_search(k) for k in SEARCHES] + [dashboard(k) for k in DASH]
            f.write("".join(json.dumps(o) + "\n" for o in objs))
            f.flush()
            out = subprocess.run(["curl", "-sk", "-u", AUTH, "-H", "kbn-xsrf: true",
                                  "https://127.0.0.1:5601/api/saved_objects/_import?overwrite=true",
                                  "-F", f"file=@{f.name}"], capture_output=True, text=True, check=True).stdout
        print(out)
