# Intel 471 Integration

The Intel 471 integration collects threat intelligence indicators from the
[Intel 471](https://intel471.com/) Indicators API and indexes them as ECS
`threat.indicator` documents, ready for Elastic Security indicator match rules
and the Intelligence page.

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

- **indicator**: follows the `/indicators/stream` endpoint.

## Requirements

- Elastic Agent, and Kibana 8.19+ or 9.1+.
- An Intel 471 **Client ID** and **Client Secret** for the Indicators API, issued by
  the [Intel 471 Developer Portal](https://developer.intel471.com/).

## Setup

1. In Kibana, go to **Management > Integrations**, search for **Intel 471** and
   click **Add Intel 471**.
2. Enter the **Client ID** and **Client Secret**.
3. Optionally set the **Initial Interval** (how far back the first run starts,
   default `24h`) and narrow the stream by **Threat Type**. **Indicator Type** and
   **Confidence** filters are under the advanced options.
4. Save and deploy to an agent policy.

## How collection works

The integration follows the API stream with an opaque cursor:

- On the first run it starts at *now − Initial Interval*. That start point and the
  filters are stored with the cursor and sent unchanged on every request; only the
  cursor (`cursor_next`) advances.
- Each interval it pages until a page comes back with fewer indicators than the
  page size, then stores the last cursor and waits for the next interval.
- The cursor is saved only after the page's events are published, so a failure
  re-fetches the page (at-least-once delivery). The document ID is a hash of the
  indicator exactly as received, so a re-fetched copy is rejected as a duplicate,
  while any change to the indicator (revocation, new expiry, new sighting) is
  indexed as a new document.
- Changing a filter discards the cursor and starts the stream again from
  *now − Initial Interval*. Changing only the Initial Interval has no effect once
  the first run has happened.
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

## Troubleshooting

- `401`/`403` in `error.message`: check the Client ID/Secret and that your
  account has Indicators API access.
- Less history than expected: the first run only fetches indicators from the
  last **Initial Interval**, and that start point is fixed once collection has
  begun. To backfill further, remove the integration and add it again with a
  larger Initial Interval; the new integration starts with a fresh cursor.
- Enable **request tracing** temporarily to log requests and responses on the agent.

## Logs reference

### indicator

{{event "indicator"}}

{{fields "indicator"}}
