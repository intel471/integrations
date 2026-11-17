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

- **indicator**: follows the Indicators API stream (`/integrations/indicators/v1/indicators/stream`).

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

An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2026-11-08T17:21:25.000Z",
    "agent": {
        "ephemeral_id": "953ca31b-ae48-4c2d-8d41-9953ec49227a",
        "id": "031481ee-0179-4008-b7a8-9c6d9ab7b281",
        "name": "elastic-agent-28214",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "ti_intel471.indicator",
        "namespace": "73991",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "031481ee-0179-4008-b7a8-9c6d9ab7b281",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_intel471.indicator",
        "id": "malware-indicator--00000000-0000-5000-8000-000000000003",
        "ingested": "2026-11-09T15:09:49Z",
        "kind": "enrichment",
        "original": "{\"activity\":{\"first_seen_ts\":\"2026-11-03T02:36:12Z\",\"last_seen_ts\":\"2026-11-08T17:21:25Z\"},\"classification\":{\"girs\":[{\"name\":\"Information-stealer malware\",\"path\":\"1.1.5\"},{\"name\":\"Windows\",\"path\":\"1.4.1\"}]},\"confidence\":85,\"data\":{\"email\":\"user-1@domain-3.example\"},\"description\":\"agent_tesla exfiltration email receiver\",\"expiration_ts\":\"2027-02-06T17:21:25Z\",\"id\":\"malware-indicator--00000000-0000-5000-8000-000000000003\",\"kill_chain_phases\":[{\"kill_chain_name\":\"mitre-attack\",\"phase_name\":\"exfiltration\"}],\"pattern\":\"[email-addr:value = 'user-1@domain-3.example']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"threat\":{\"data\":{\"malware\":{\"family\":\"agent_tesla\",\"id\":\"malware--00000000-0000-5000-8000-000000000002\",\"variant\":\"v3_variant_h\"},\"malware_family\":{\"id\":\"malware-family--00000000-0000-5000-8000-000000000002\",\"name\":\"agent_tesla\"}},\"type\":\"malware\"},\"type\":\"email\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "intel471": {
        "indicator": {
            "classification": {
                "girs": [
                    {
                        "name": "Information-stealer malware",
                        "path": "1.1.5"
                    },
                    {
                        "name": "Windows",
                        "path": "1.4.1"
                    }
                ]
            },
            "confidence": 85,
            "expiration_ts": "2027-02-06T17:21:25.000Z",
            "ioc_expiration_reason": "expiration_ts",
            "ioc_expired_at": "2027-02-06T17:21:25.000Z",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "exfiltration"
                }
            ],
            "pattern": "[email-addr:value = 'user-1@domain-3.example']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "threat": {
                "data": {
                    "malware": {
                        "family": "agent_tesla",
                        "id": "malware--00000000-0000-5000-8000-000000000002",
                        "variant": "v3_variant_h"
                    },
                    "malware_family": {
                        "id": "malware-family--00000000-0000-5000-8000-000000000002",
                        "name": "agent_tesla"
                    }
                },
                "type": "malware"
            },
            "type": "email"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "intel471-indicator"
    ],
    "threat": {
        "feed": {
            "description": "Threat indicators from the Intel 471 Indicators API.",
            "name": "Intel 471",
            "reference": "https://intel471.com/"
        },
        "framework": "MITRE ATT&CK",
        "indicator": {
            "confidence": "High",
            "description": "agent_tesla exfiltration email receiver",
            "email": {
                "address": "user-1@domain-3.example"
            },
            "first_seen": "2026-11-03T02:36:12.000Z",
            "last_seen": "2026-11-08T17:21:25.000Z",
            "name": "user-1@domain-3.example",
            "provider": "Intel 471",
            "type": "email-addr"
        },
        "software": {
            "name": "agent_tesla",
            "type": "Malware"
        },
        "tactic": {
            "id": [
                "TA0010"
            ],
            "name": [
                "Exfiltration"
            ]
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp (when the indicator was last seen). | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Input type. | keyword |
| intel471.indicator.activity.first_seen_ts | First time the indicator was seen. | date |
| intel471.indicator.activity.last_seen_ts | Last time the indicator was seen. | date |
| intel471.indicator.classification.girs.name | GIR name. | keyword |
| intel471.indicator.classification.girs.path | GIR path, for example 1.1.13. | keyword |
| intel471.indicator.confidence | Confidence score for the indicator, 0-100. | long |
| intel471.indicator.data.domain | Domain name. | keyword |
| intel471.indicator.data.email | Email address. | keyword |
| intel471.indicator.data.file.md5 | MD5 hash. | keyword |
| intel471.indicator.data.file.sha1 | SHA-1 hash. | keyword |
| intel471.indicator.data.file.sha256 | SHA-256 hash. | keyword |
| intel471.indicator.data.file.size | File size in bytes. | long |
| intel471.indicator.data.file.ssdeep | SSDeep hash. | keyword |
| intel471.indicator.data.file.type | File type, for example MSI or PEEXE_x86. | keyword |
| intel471.indicator.data.ipv4.geo_ip.city | City. | keyword |
| intel471.indicator.data.ipv4.geo_ip.country | Country name. | keyword |
| intel471.indicator.data.ipv4.geo_ip.country_code | ISO 3166-1 alpha-2 country code. | keyword |
| intel471.indicator.data.ipv4.geo_ip.isp.autonomous_system | Autonomous system, for example "AS64496 Example Networks". | keyword |
| intel471.indicator.data.ipv4.geo_ip.isp.isp | Internet service provider. | keyword |
| intel471.indicator.data.ipv4.geo_ip.isp.network | Network range (CIDR) containing the address. | keyword |
| intel471.indicator.data.ipv4.geo_ip.isp.organization | Organization the address is registered to. | keyword |
| intel471.indicator.data.ipv4.geo_ip.subdivision | Administrative subdivisions (states, provinces, ...). | keyword |
| intel471.indicator.data.ipv4.ip_address | IPv4 address. | ip |
| intel471.indicator.data.url | URL. | keyword |
| intel471.indicator.data.yara.signature | YARA rule source. | match_only_text |
| intel471.indicator.data.yara.title | YARA rule name. | keyword |
| intel471.indicator.description | Description of the indicator. | keyword |
| intel471.indicator.expiration_ts | When the indicator expires, as reported by the API. | date |
| intel471.indicator.id | Unique identifier of the indicator. | keyword |
| intel471.indicator.ioc_expiration_reason | Why `ioc_expired_at` has its value (revoked, expiration_ts, or the configured fallback). | keyword |
| intel471.indicator.ioc_expired_at | When the indicator is removed from the latest IOC index. | date |
| intel471.indicator.kill_chain_phases.kill_chain_name | Kill chain framework. | keyword |
| intel471.indicator.kill_chain_phases.phase_name | Phase within the kill chain. | keyword |
| intel471.indicator.pattern | Detection pattern for the indicator (a STIX 2.1 pattern, or a YARA rule). | keyword |
| intel471.indicator.pattern_type | Pattern language, `stix` or `yara`. | keyword |
| intel471.indicator.pattern_version | Version of the pattern language. | keyword |
| intel471.indicator.revocation.revoked | Whether the indicator has been revoked. | boolean |
| intel471.indicator.threat.data.bulletproof_hosting.provider | Bulletproof hosting provider. | keyword |
| intel471.indicator.threat.data.malware.component | Malware component. | keyword |
| intel471.indicator.threat.data.malware.family | Malware family name. | keyword |
| intel471.indicator.threat.data.malware.id | Malware identifier. | keyword |
| intel471.indicator.threat.data.malware.variant | Malware variant. | keyword |
| intel471.indicator.threat.data.malware.version | Malware version. | keyword |
| intel471.indicator.threat.data.malware_family.id | Malware family identifier. | keyword |
| intel471.indicator.threat.data.malware_family.name | Malware family name. | keyword |
| intel471.indicator.threat.type | Threat type, `malware` or `bulletproof_hosting`. | keyword |
| intel471.indicator.type | Indicator type (domain, email, file, ipv4, url, yara). | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or in the latest destination index. | constant_keyword |

