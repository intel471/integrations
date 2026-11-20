# Intel 471 Integration

The Intel 471 integration collects threat intelligence from
[Intel 471](https://intel471.com/):

- **Indicators** from the Indicators API, indexed as ECS `threat.indicator`
  documents, ready for Elastic Security indicator match rules and the
  Intelligence page.
- **Vulnerability reports** from the Reports API, indexed as ECS
  `vulnerability` documents: Intel 471's risk assessment of a CVE, with its
  exploitation, proof-of-concept and patch status and underground activity.
- **Compromised credentials** from the Credentials API: logins related to your
  organisation found in infostealer logs, combo lists and breaches, with
  password strength and the infected machine's details. Plaintext passwords
  are never ingested.

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
- **credential**: follows the Credentials API stream
  (`/integrations/creds/v1/credentials/stream`), one document per unique
  credential (login, password and accessed domain).

All data streams use the same API URL and credentials. Disable the ones your
subscription doesn't cover.

## Requirements

- Elastic Agent, and Kibana 8.19+ or 9.1+.
- An Intel 471 **Client ID** and **Client Secret** with access to the Indicators,
  Reports and/or Credentials APIs, issued by the
  [Intel 471 Developer Portal](https://developer.intel471.com/).

## Setup

1. In Kibana, go to **Management > Integrations**, search for **Intel 471** and
   click **Add Intel 471**.
2. Enter the **Client ID** and **Client Secret**.
3. For each data stream, optionally set the **Initial Interval** (how far back
   the first run starts: `24h` for indicators, `720h` for vulnerability reports)
   and the filters: **Threat Type** for indicators (**Indicator Type** and
   **Confidence** are under the advanced options), **Risk Level** for
   vulnerability reports, **Affiliation** for credentials (`168h` by default).
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
  report update; a credential's new sighting) is indexed as a new document.
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

## Compromised credentials

Each document is one unique credential: a login, its password and the domain it
was used on. The same credential is sent again when it is seen in a new
credential set, and the latest version replaces the old one in
`logs-ti_intel471_latest.credential`.

- **The plaintext password is never stored.** The agent removes it before the
  event is built, so it is not in `event.original` either. Password strength,
  length, entropy, score and per-character-class counts are kept under
  `intel471.credential.data.password`, and `password.id` is equal for equal
  passwords, which finds reused passwords.
- The login is mapped to `user.email` (when it is an email address), `user.name`
  and `user.domain`, so it can be matched against authentication logs and your
  directory. The domain the credential was used on is `url.domain`.
- `intel471.credential.data.affiliations` says how the credential relates to
  you (`my_employees`, `vip_emails`, `my_customers`, `third_parties`), and
  `detection_domain` which of your monitored domains matched.
- For credentials captured by an information stealer,
  `intel471.credential.data.info_stealer` has the stealer family and the
  infected machine (host name, user, IP, OS, antivirus). Each field lists the
  values from every sighting, so with several sightings the values in different
  fields aren't paired. Reported machine IPs that aren't valid IP addresses are
  kept in `intel471.credential.data.info_stealer.invalid_ip`.
- `event.kind` is `alert`. `@timestamp` is when the credential was last updated.

To limit volume, set **Affiliation**, for example to *My employees*.

## Dashboards

The package has four dashboards, linked to each other:

- **[Logs Intel 471] Overview**: the health of the integration, as of now. Per
  data stream: when it last ran, whether or not it fetched anything (from the
  agent's monitoring metrics, so only with agent monitoring on), when data last
  arrived, how much arrived in the last hour, 24 hours and 5 days, and errors in
  the last 24 hours; below, the collection errors of the last 5 days.
- **[Logs Intel 471] Indicators**: active indicators over time and the list of
  them, filtered by type, malware family, confidence or the indicator value.
  Expand a row to see the whole indicator.
- **[Logs Intel 471] Vulnerabilities**: reports over time and the list of them,
  filtered by CVE, report status, risk, exploitation or vendor. Expand a row to
  read the whole report.
- **[Logs Intel 471] Credentials**: credentials over time and the list of them,
  filtered by login, affiliation (for example your employees and VIP emails),
  monitored domain or password strength. Expand a row to see the whole
  credential.

The stream dashboards read the latest indices, so each indicator, report or
credential is counted once, in its current version. They open on the last 30
days; the time picker filters on `@timestamp` (last seen or last updated, not
ingestion time). The Overview always shows the current state and ignores the
time picker.

## Troubleshooting

- `401`/`403` in `error.message`: check the Client ID/Secret and that your
  account has access to the API of that data stream (Indicators API for
  indicators, Reports API for vulnerability reports, Credentials API for
  credentials).
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
  time or the report's or credential's last update, not when it was ingested, so a short time
  range can be empty. Filter on `event.ingested` instead.
- Enable **request tracing** temporarily to log requests and responses on the agent.
  Don't enable it on the credential data stream: the trace holds the raw API
  responses, including plaintext passwords and logins.

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
| error.message | Error message. | match_only_text |
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


### vulnerability

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2026-10-20T17:42:52.000Z",
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "category": [
            "vulnerability"
        ],
        "id": "vulnerability--00000000-0000-5000-8000-000000000023",
        "kind": "enrichment",
        "provider": "Intel 471",
        "type": [
            "info"
        ],
        "agent_id_status": "verified",
        "dataset": "ti_intel471.vulnerability",
        "ingested": "2026-11-19T13:40:12Z"
    },
    "intel471": {
        "vulnerability": {
            "activity": {
                "first_seen_ts": "2026-06-30T08:53:14.000Z",
                "last_seen_ts": "2026-10-20T17:42:52.000Z"
            },
            "activity_location": [
                "location_underground",
                "location_opensource",
                "location_private"
            ],
            "classification": {
                "girs": [
                    {
                        "name": "Vulnerabilities",
                        "path": "2.1"
                    },
                    {
                        "name": "Web application vulnerabilities",
                        "path": "2.1.2.4"
                    },
                    {
                        "name": "Initial access vulnerabilities",
                        "path": "2.1.13"
                    },
                    {
                        "name": "Exploit development",
                        "path": "2.2"
                    },
                    {
                        "name": "Exploited in wild",
                        "path": "2.2.2"
                    }
                ]
            },
            "counter_measures": "Fixture counter_measures 3 & details. Point 3",
            "creation_ts": "2026-06-30T08:53:14.000Z",
            "cvss": {
                "v3_1": 9.8
            },
            "exploit_status": [
                "weaponized"
            ],
            "interest_level": [
                "researched_publicly",
                "disclosed_publicly"
            ],
            "last_updated_ts": "2026-10-20T17:42:52.000Z",
            "links": {
                "verity_api": {
                    "href": "https://api.intel471.cloud/integrations/intel-report/v1/reports/vulnerability/vulnerability--00000000-0000-5000-8000-000000000023"
                },
                "verity_portal": {
                    "href": "https://verity.intel471.com/vulnerabilities/vulnerability--00000000-0000-5000-8000-000000000023"
                }
            },
            "patch_links": [
                {
                    "links": {
                        "external": {
                            "href": "https://external.example/patch/10"
                        }
                    },
                    "title": "Fixture patch 3",
                    "type": "external"
                }
            ],
            "patch_status": "available",
            "poc": "not_observed",
            "poc_links": [
                {
                    "links": {
                        "external": {
                            "href": "https://external.example/poc/8"
                        }
                    },
                    "title": "Fixture poc 5",
                    "type": "external"
                },
                {
                    "links": {
                        "external": {
                            "href": "https://external.example/poc/9"
                        }
                    },
                    "title": "Fixture poc 6",
                    "type": "external"
                }
            ],
            "product_name": "Example Product 1",
            "released_ts": "2026-10-20T17:42:52.000Z",
            "risk_level": "high",
            "sort_priority": 0,
            "sources": [
                {
                    "links": {
                        "verity_api": {
                            "href": "https://api.intel471.cloud/integrations/intel-report/v1/reports/info/report--00000000-0000-5000-8000-000000000024"
                        },
                        "verity_portal": {
                            "href": "https://verity.intel471.com/intelligence/infoReportView/report--00000000-0000-5000-8000-000000000024"
                        }
                    },
                    "title": "Fixture sources 15",
                    "type": "internal"
                }
            ],
            "status": "historical",
            "type": "vulnerability_report",
            "underground_activity_summary": "Fixture underground_activity_summary 3 & details. Point 3",
            "vendor_name": "Example Vendor 3"
        }
    },
    "vulnerability": {
        "category": [
            "Unspecified"
        ],
        "classification": "CVSS",
        "description": "Fixture body 3 & details. Point 3",
        "enumeration": "CVE",
        "id": "CVE-2099-10003",
        "reference": "https://verity.intel471.com/vulnerabilities/vulnerability--00000000-0000-5000-8000-000000000023",
        "score": {
            "base": 9.8,
            "version": "3.1"
        },
        "severity": "High"
    },
    "agent": {
        "ephemeral_id": "953ca31b-ae48-4c2d-8d41-9953ec49227a",
        "id": "031481ee-0179-4008-b7a8-9c6d9ab7b281",
        "name": "elastic-agent-28214",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "elastic_agent": {
        "id": "031481ee-0179-4008-b7a8-9c6d9ab7b281",
        "snapshot": false,
        "version": "8.19.0"
    },
    "input": {
        "type": "cel"
    },
    "data_stream": {
        "dataset": "ti_intel471.vulnerability",
        "namespace": "73991",
        "type": "logs"
    },
    "tags": [
        "forwarded",
        "intel471-vulnerability"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp (when the report was last updated). | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| error.message | Error message. | match_only_text |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Input type. | keyword |
| intel471.vulnerability.activity.first_seen_ts | First time activity related to the vulnerability was seen. | date |
| intel471.vulnerability.activity.last_seen_ts | Last time activity related to the vulnerability was seen. | date |
| intel471.vulnerability.activity_location | Where activity related to the vulnerability was observed, for example location_underground. | keyword |
| intel471.vulnerability.aliases | Alternative names of the vulnerability. | keyword |
| intel471.vulnerability.body | Summary of the vulnerability (HTML removed). | text |
| intel471.vulnerability.classification.girs.name | GIR name. | keyword |
| intel471.vulnerability.classification.girs.path | GIR path, for example 1.1.13. | keyword |
| intel471.vulnerability.counter_measure_links.index | Index of the source in the report text. | long |
| intel471.vulnerability.counter_measure_links.last_updated_ts | When the source was last updated. | date |
| intel471.vulnerability.counter_measure_links.links.external.href | External URL. | keyword |
| intel471.vulnerability.counter_measure_links.links.verity_api.href | URL in the Intel 471 API. | keyword |
| intel471.vulnerability.counter_measure_links.links.verity_portal.href | URL in the Intel 471 portal. | keyword |
| intel471.vulnerability.counter_measure_links.source_type | Characterisation of the source. | keyword |
| intel471.vulnerability.counter_measure_links.title | Title. | keyword |
| intel471.vulnerability.counter_measure_links.type | Link type (internal or external). | keyword |
| intel471.vulnerability.counter_measures | Summary of countermeasures for the vulnerability (HTML removed). | text |
| intel471.vulnerability.creation_ts | When the report was first published. | date |
| intel471.vulnerability.cve_type | Weakness type, for example Path traversal or Use after free. | keyword |
| intel471.vulnerability.cvss.v2_0 | CVSS 2.0 base score. | float |
| intel471.vulnerability.cvss.v3_0 | CVSS 3.0 base score. | float |
| intel471.vulnerability.cvss.v3_1 | CVSS 3.1 base score. | float |
| intel471.vulnerability.cvss.v4_0 | CVSS 4.0 base score. | float |
| intel471.vulnerability.exploit_status | Exploitation status, for example weaponized, productized, available or not_observed. | keyword |
| intel471.vulnerability.id | Unique identifier of the report. | keyword |
| intel471.vulnerability.interest_level | Levels of interest in the vulnerability, for example researched_publicly or exploit_sought. | keyword |
| intel471.vulnerability.last_updated_ts | When the report was last updated. | date |
| intel471.vulnerability.links.verity_api.href | The report in the Intel 471 API. | keyword |
| intel471.vulnerability.links.verity_portal.href | The report in the Intel 471 portal. | keyword |
| intel471.vulnerability.name | Name of the vulnerability, usually its CVE ID. | keyword |
| intel471.vulnerability.patch_links.index | Index of the source in the report text. | long |
| intel471.vulnerability.patch_links.last_updated_ts | When the source was last updated. | date |
| intel471.vulnerability.patch_links.links.external.href | External URL. | keyword |
| intel471.vulnerability.patch_links.links.verity_api.href | URL in the Intel 471 API. | keyword |
| intel471.vulnerability.patch_links.links.verity_portal.href | URL in the Intel 471 portal. | keyword |
| intel471.vulnerability.patch_links.source_type | Characterisation of the source. | keyword |
| intel471.vulnerability.patch_links.title | Title. | keyword |
| intel471.vulnerability.patch_links.type | Link type (internal or external). | keyword |
| intel471.vulnerability.patch_status | Patch availability (available, some_available, unavailable). | keyword |
| intel471.vulnerability.poc | Whether proof-of-concept code has been observed (observed, not_observed). | keyword |
| intel471.vulnerability.poc_links.index | Index of the source in the report text. | long |
| intel471.vulnerability.poc_links.last_updated_ts | When the source was last updated. | date |
| intel471.vulnerability.poc_links.links.external.href | External URL. | keyword |
| intel471.vulnerability.poc_links.links.verity_api.href | URL in the Intel 471 API. | keyword |
| intel471.vulnerability.poc_links.links.verity_portal.href | URL in the Intel 471 portal. | keyword |
| intel471.vulnerability.poc_links.source_type | Characterisation of the source. | keyword |
| intel471.vulnerability.poc_links.title | Title. | keyword |
| intel471.vulnerability.poc_links.type | Link type (internal or external). | keyword |
| intel471.vulnerability.product_name | Affected product. | keyword |
| intel471.vulnerability.released_ts | When the report was last published. | date |
| intel471.vulnerability.risk_level | Intel 471 risk level (high, medium, low). | keyword |
| intel471.vulnerability.sort_priority | Priority Intel 471 uses for sorting vulnerability reports. | long |
| intel471.vulnerability.sources.index | Index of the source in the report text. | long |
| intel471.vulnerability.sources.last_updated_ts | When the source was last updated. | date |
| intel471.vulnerability.sources.links.external.href | External URL. | keyword |
| intel471.vulnerability.sources.links.verity_api.href | URL in the Intel 471 API. | keyword |
| intel471.vulnerability.sources.links.verity_portal.href | URL in the Intel 471 portal. | keyword |
| intel471.vulnerability.sources.source_type | Characterisation of the source. | keyword |
| intel471.vulnerability.sources.title | Title. | keyword |
| intel471.vulnerability.sources.type | Link type (internal or external). | keyword |
| intel471.vulnerability.status | Report status (new, existing, historical). | keyword |
| intel471.vulnerability.type | Report type (vulnerability_report). | keyword |
| intel471.vulnerability.underground_activity_summary | Summary of underground activity related to the vulnerability (HTML removed). | text |
| intel471.vulnerability.vendor_name | Vendor of the affected software. | keyword |


### credential

An example event for `credential` looks as following:

```json
{
    "@timestamp": "2026-10-20T14:19:03.379Z",
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "id": "cred--00000000-0000-5000-8000-000000000027",
        "kind": "alert",
        "provider": "Intel 471",
        "agent_id_status": "verified",
        "dataset": "ti_intel471.credential",
        "ingested": "2026-11-19T14:10:31Z"
    },
    "intel471": {
        "credential": {
            "activity": {
                "first_seen_ts": "2023-10-18T15:08:46.937Z",
                "last_seen_ts": "2026-10-20T14:19:03.379Z"
            },
            "classification": {
                "girs": [
                    {
                        "name": "Credential combination list(s)",
                        "path": "4.2.2.1"
                    },
                    {
                        "name": "Information-stealer malware",
                        "path": "1.1.5"
                    },
                    {
                        "name": "Phishing",
                        "path": "4.4.1"
                    },
                    {
                        "name": "Credential access tactic",
                        "path": "5.2.6"
                    },
                    {
                        "name": "Compromised credentials",
                        "path": "4.2.2"
                    }
                ]
            },
            "data": {
                "affiliations": [
                    "my_customers"
                ],
                "credential_domain": "domain-6.example",
                "credential_set_type": [
                    "infostealers",
                    "combolists"
                ],
                "credential_sets": [
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000014",
                        "name": "Fixture credential set 7"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000028",
                        "name": "Fixture credential set 19"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000015",
                        "name": "Fixture credential set 8"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000029",
                        "name": "Fixture credential set 20"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000016",
                        "name": "Fixture credential set 9"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000017",
                        "name": "Fixture credential set 10"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000030",
                        "name": "Fixture credential set 21"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000004",
                        "name": "Fixture credential set 3"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000018",
                        "name": "Fixture credential set 11"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000019",
                        "name": "Fixture credential set 12"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000020",
                        "name": "Fixture credential set 13"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000031",
                        "name": "Fixture credential set 22"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000022",
                        "name": "Fixture credential set 15"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000032",
                        "name": "Fixture credential set 23"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000006",
                        "name": "Fixture credential set 5"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000033",
                        "name": "Fixture credential set 24"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000011",
                        "name": "Fixture credential set 6"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000023",
                        "name": "Fixture credential set 16"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000024",
                        "name": "Fixture credential set 17"
                    },
                    {
                        "id": "cred-set--00000000-0000-5000-8000-000000000025",
                        "name": "Fixture credential set 18"
                    }
                ],
                "detection_domain": "domain-7.example",
                "info_stealer": {
                    "computer_username": [
                        "fixture-user-1"
                    ],
                    "ip": [
                        "10.18.1.1"
                    ],
                    "malware_family": [
                        "Redline",
                        "Unidentified"
                    ],
                    "malware_install_path": [
                        "C:\\Users\\fixture\\AppData\\fixture-1.exe"
                    ],
                    "os": [
                        "Windows 10 Enterprise x64"
                    ]
                },
                "password": {
                    "complexity": {
                        "entropy": 39.86314,
                        "length": 12,
                        "lowercase": 5,
                        "numbers": 4,
                        "other": 0,
                        "punctuation_marks": 1,
                        "score": 0.49809,
                        "separators": 0,
                        "symbols": 0,
                        "uppercase": 2,
                        "weakness": 0.0
                    },
                    "id": "0000000000000000000000000000000000000000000000000000000000000009",
                    "strength": "medium"
                }
            },
            "last_updated_ts": "2026-10-20T14:19:03.379Z",
            "statistics": {
                "accessed_domains_count": 1
            }
        }
    },
    "related": {
        "hosts": [
            "site-3.example"
        ],
        "ip": [
            "10.18.1.1"
        ],
        "user": [
            "user-8@domain-6.example",
            "user-8"
        ]
    },
    "url": {
        "domain": "site-3.example"
    },
    "user": {
        "domain": "domain-6.example",
        "email": "user-8@domain-6.example",
        "name": "user-8"
    },
    "agent": {
        "ephemeral_id": "953ca31b-ae48-4c2d-8d41-9953ec49227a",
        "id": "031481ee-0179-4008-b7a8-9c6d9ab7b281",
        "name": "elastic-agent-28214",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "elastic_agent": {
        "id": "031481ee-0179-4008-b7a8-9c6d9ab7b281",
        "snapshot": false,
        "version": "8.19.0"
    },
    "input": {
        "type": "cel"
    },
    "data_stream": {
        "dataset": "ti_intel471.credential",
        "namespace": "73991",
        "type": "logs"
    },
    "tags": [
        "forwarded",
        "intel471-credential"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp (when the credential was last updated). | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| error.message | Error message. | match_only_text |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Input type. | keyword |
| intel471.credential.activity.first_seen_ts | Start of the credential's activity range. | date |
| intel471.credential.activity.last_seen_ts | End of the credential's activity range. | date |
| intel471.credential.classification.girs.name | GIR name. | keyword |
| intel471.credential.classification.girs.path | GIR path, for example 1.1.13. | keyword |
| intel471.credential.data.accessed_domain | Domain the credential was used on when it was captured. | keyword |
| intel471.credential.data.affiliations | Affiliation to your organisation (my_employees, vip_emails, my_customers, third_parties). | keyword |
| intel471.credential.data.credential_domain | Domain of the login. | keyword |
| intel471.credential.data.credential_login | Login of the credential, usually an email address. | keyword |
| intel471.credential.data.credential_set_type | Types of the credential sets the credential was found in (infostealers, combolists, breaches). | keyword |
| intel471.credential.data.credential_sets.id | Credential set identifier. | keyword |
| intel471.credential.data.credential_sets.name | Credential set name. | keyword |
| intel471.credential.data.detection_domain | Monitored domain that caused the credential to be detected. | keyword |
| intel471.credential.data.info_stealer.antivirus_software | Antivirus software reported on the infected machines. | keyword |
| intel471.credential.data.info_stealer.computer_username | Local user accounts on the infected machines. | keyword |
| intel471.credential.data.info_stealer.infection_ts | When the machines were infected. | date |
| intel471.credential.data.info_stealer.invalid_ip | Values the stealer reported as the machine's IP address that aren't valid IP addresses. | keyword |
| intel471.credential.data.info_stealer.ip | IP addresses of the infected machines. | ip |
| intel471.credential.data.info_stealer.isp | Internet service providers of the infected machines. | keyword |
| intel471.credential.data.info_stealer.machine_id | Identifiers of the infected machines. | keyword |
| intel471.credential.data.info_stealer.malware_family | Stealer families, for example Redline, Lumma, VIDAR. | keyword |
| intel471.credential.data.info_stealer.malware_install_path | Where the stealer was installed. | keyword |
| intel471.credential.data.info_stealer.os | Operating systems of the infected machines. | keyword |
| intel471.credential.data.info_stealer.pc_name | Host names of the infected machines. | keyword |
| intel471.credential.data.info_stealer.screenshot_path | Paths of screenshots taken by the stealer. | keyword |
| intel471.credential.data.info_stealer.version | Stealer versions. | keyword |
| intel471.credential.data.password.complexity.entropy | Password entropy. | double |
| intel471.credential.data.password.complexity.length | Number of characters. | long |
| intel471.credential.data.password.complexity.lowercase | Number of lowercase letters. | long |
| intel471.credential.data.password.complexity.numbers | Number of digits. | long |
| intel471.credential.data.password.complexity.other | Number of other characters. | long |
| intel471.credential.data.password.complexity.punctuation_marks | Number of punctuation marks. | long |
| intel471.credential.data.password.complexity.score | Password score, 0 to 1. | double |
| intel471.credential.data.password.complexity.separators | Number of separators. | long |
| intel471.credential.data.password.complexity.symbols | Number of symbols. | long |
| intel471.credential.data.password.complexity.uppercase | Number of uppercase letters. | long |
| intel471.credential.data.password.complexity.weakness | Password weakness. | double |
| intel471.credential.data.password.id | Opaque password identifier; equal IDs mean equal passwords. | keyword |
| intel471.credential.data.password.strength | Password strength (excellent, strong, medium, weak, poor, not_provided). | keyword |
| intel471.credential.id | Unique identifier of the credential. | keyword |
| intel471.credential.last_updated_ts | When the credential was last updated. | date |
| intel471.credential.statistics.accessed_domains_count | Number of distinct domains the credential was used on. | long |

