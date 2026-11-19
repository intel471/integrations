# Intel 471 Integration

The Intel 471 integration collects threat intelligence from
[Intel 471](https://intel471.com/):

- **Indicators** from the Indicators API, indexed as ECS `threat.indicator`
  documents, ready for Elastic Security indicator match rules and the
  Intelligence page.
- **Vulnerability reports** from the Reports API, indexed as ECS
  `vulnerability` documents: Intel 471's risk assessment of a CVE, with its
  exploitation, proof-of-concept and patch status and underground activity.

Indicators come in two threat types:

- **Malware**: domains, email addresses, file hashes (MD5, SHA-1, SHA-256,
  SSDeep), IPv4 addresses, URLs and YARA rules, each linked to a malware family.
- **Bulletproof hosting**: domains and IPv4 addresses belonging to bulletproof
  hosting services, each linked to the hosting provider (no malware family).

Every indicator has a confidence score, first/last seen times and Intel 471
General Intelligence Requirements (GIRs). Most also have a description, an
expiry time and MITRE ATT&CK tactics; YARA rules have none of these three. IPv4
indicators usually include geolocation and autonomous system (ASN) details.

## Data streams

- **indicator**: follows the Indicators API stream (`/integrations/indicators/v1/indicators/stream`).
- **vulnerability**: follows the Reports API vulnerability stream
  (`/integrations/intel-report/v1/reports/vulnerability/stream`).

Both data streams use the same API URL and credentials. Disable the one your
subscription doesn't cover.

## Requirements

- Elastic Agent, and Kibana 8.19+ or 9.1+.
- An Intel 471 **Client ID** and **Client Secret** with access to the Indicators
  API and/or the Reports API, issued by the
  [Intel 471 Developer Portal](https://developer.intel471.com/).

## Setup

1. In Kibana, go to **Management > Integrations**, search for **Intel 471** and
   click **Add Intel 471**.
2. Enter the **Client ID** and **Client Secret**.
3. For each data stream, optionally set the **Initial Interval** (how far back
   the first run starts: `24h` for indicators, `720h` for vulnerability reports)
   and the filters: **Threat Type** for indicators (**Indicator Type** and
   **Confidence** are under the advanced options), **Risk Level** for
   vulnerability reports.
4. Save and deploy to an agent policy.

## How collection works

Each data stream follows its API stream with an opaque cursor:

- On the first run it starts at *now − Initial Interval*. That start point and the
  filters are stored with the cursor and sent unchanged on every request; only the
  cursor (`cursor_next`) advances.
- Each interval it pages until a page comes back with fewer indicators than the
  page size, then stores the last cursor and waits for the next interval.
- The cursor is saved only after the page's events are published, so a failure
  re-fetches the page (at-least-once delivery). The document ID is a hash of the
  item exactly as received, so a re-fetched copy is rejected as a duplicate,
  while any change (an indicator's revocation, new expiry or new sighting; a
  report update) is indexed as a new document.
- Changing a filter discards the cursor and starts the stream again from
  *now − Initial Interval*. Changing only the Initial Interval has no effect once
  the first run has happened.
- The cursor is kept on the agent (in its Filebeat registry), not in
  Elasticsearch. It survives agent restarts, but **disabling the integration's
  input in Fleet discards it**, as do changing the API URL and removing and
  re-adding the integration. Collection then starts again from
  *now − Initial Interval*, and indicators that changed in between are missed
  (see Troubleshooting).
- Requests are retried with backoff on HTTP 429 and 5xx. Other errors, or retries
  running out, are reported as `error.message` documents and the cursor is left
  unchanged, so the next interval tries the same request again.

Requests identify themselves with the `User-Agent` `Intel471-Elastic/<version>`.

## Expiration of indicators of compromise (IOCs)

A transform (`logs-ti_intel471_latest.indicator`) keeps the latest copy of each
indicator, which is what detection rules should query. An indicator is removed
from it when `intel471.indicator.ioc_expired_at` passes:

- revoked indicators (`revocation.revoked: true`) expire at ingest, even if
  nothing else about the indicator changed;
- otherwise the API's `expiration_ts` is used;
- indicators without `expiration_ts` (for example YARA rules) expire **IOC
  Expiration Duration** (default `90d`) after they were last seen.

`intel471.indicator.ioc_expiration_reason` records which rule applied. The
transform runs every 30 seconds and waits 2 minutes for late-arriving data, so
an expired or revoked indicator leaves the latest index within about 3 minutes.
When an indicator is received again, its most recently received version wins.

### Data retention

The source data stream `logs-ti_intel471.indicator-*` keeps raw documents for 5
days (data stream lifecycle); the latest index holds the current state.

## Vulnerability reports

Each report covers one vulnerability, usually a CVE:

- `vulnerability.id` is the CVE ID (`vulnerability.enumeration: CVE`), and
  `vulnerability.reference` links to the report in the Intel 471 portal.
- `vulnerability.severity` is Intel 471's **risk level** (High, Medium, Low), which
  weighs exploitation and underground interest, not only the CVSS score.
- `vulnerability.score.base` is the CVSS 3.1 score, or else 3.0, 4.0 or 2.0;
  every version's score is in `intel471.vulnerability.cvss.v3_1` and so on.
  Versions the API reports as unscored (`-1`) are left out.
- `vulnerability.description` and `intel471.vulnerability.underground_activity_summary`
  and `counter_measures` hold the report's summaries as plain text.
- `intel471.vulnerability.*` has the exploitation status, proof-of-concept and patch
  status, interest level, where activity was seen, the vendor and product, and
  links to sources, proofs of concept, patches and countermeasures.

`@timestamp` is when the report was last updated. A transform
(`logs-ti_intel471_latest.vulnerability`) keeps the latest version of each
report; reports don't expire. The source data stream
`logs-ti_intel471.vulnerability-*` keeps raw documents for 5 days.

## Troubleshooting

- `401`/`403` in `error.message`: check the Client ID/Secret and that your
  account has access to the API of that data stream (Indicators API for
  indicators, Reports API for vulnerability reports).
- Less history than expected: the first run only fetches indicators from the
  last **Initial Interval**, and that start point is fixed once collection has
  begun. To backfill further, remove the integration and add it again with a
  larger Initial Interval; the new integration starts with a fresh cursor.
- Indicators missing after the input was disabled and re-enabled: re-enabling
  starts from *now − Initial Interval*. Before re-enabling, raise the Initial
  Interval to cover the pause; indicators that are already indexed are rejected
  as duplicates, so only the missed ones are added. To pause collection without
  losing the cursor, stop the agent instead of disabling the input.
- Nothing in Discover for recent runs: `@timestamp` is the indicator's last seen
  time or the report's last update, not when it was ingested, so a short time
  range can be empty. Filter on `event.ingested` instead.
- Enable **request tracing** temporarily to log requests and responses on the agent.

## Logs reference

### indicator

{{event "indicator"}}

{{fields "indicator"}}

### vulnerability

{{event "vulnerability"}}

{{fields "vulnerability"}}
