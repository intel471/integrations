# ti_intel471 development scripts

Helpers for developing and testing the `ti_intel471` package. Run them from
the package directory (`packages/ti_intel471`). They are not part of the built
package.

```
check_package.py           User-Agent / changelog / manifest version sync
test_cel_program.py        runs the CEL program in mito against a mock API
gen_test_data.py           fixture -> pipeline tests + mock API config
test_ioc_lifecycle.py      live check: expired/revoked IOCs leave the latest index
get_indicators_fixture.py  pulls a redacted sample from the real API
indicators_fixtures.json   that sample (sensitive values replaced)
```

Package layout, for orientation:

```
data_stream/indicator/
  agent/stream/cel.yml.hbs     CEL input: cursor paging, auth, User-Agent
  elasticsearch/ingest_pipeline/default.yml   Intel 471 -> ECS mapping
  _dev/test/pipeline/          pipeline tests (generated from the fixture)
  _dev/test/system/            system test against a mock API
elasticsearch/transform/latest_ioc/   one doc per indicator, expiry handling
_dev/deploy/docker/            mock Indicators API for the system test
```

## Tooling

```
go install github.com/elastic/elastic-package@latest
go install github.com/elastic/mito/cmd/mito@latest
```

## Tests

```
python3 _dev/scripts/check_package.py         # versions in sync
python3 _dev/scripts/test_cel_program.py      # CEL cursor/auth/error behaviour, no stack needed

elastic-package check                         # lint + build
elastic-package stack up -d                   # local Elastic stack (Docker)
elastic-package test pipeline                 # ingest pipeline vs expected output
elastic-package test system                   # agent + CEL input + mock API end to end
elastic-package install && python3 _dev/scripts/test_ioc_lifecycle.py   # expiry/revocation in the latest index (~5 min)
elastic-package stack down
```

## Refreshing test data

```
INTEGRAUTH=client_id:client_secret uv run _dev/scripts/get_indicators_fixture.py 3
python3 _dev/scripts/gen_test_data.py
elastic-package test pipeline --generate
```

Review the regenerated `*-expected.json` diffs before committing.

## Releasing a new version

Bump `version` in `manifest.yml`, add a `changelog.yml` entry, then
`python3 _dev/scripts/check_package.py --fix` to update the User-Agent.

## Findings not yet in the package docs

To add to `_dev/build/docs/README.md` ("How collection works" /
"Troubleshooting"):

- **Disabling the input resets the stream.** The cursor lives in the agent's
  Filebeat registry (`<agent data>/run/cel-default/registry/filebeat/`), not in
  Elasticsearch. Disabling the input in Fleet, when it is the only CEL input on
  the agent, stops the `cel-default` component and the agent deletes its run
  directory, registry included. Re-enabling starts again from
  *now - Initial Interval*, so indicators that changed while it was off are
  missed. Removing/re-adding the integration or changing the URL or a filter has
  the same effect.
  Tested 2026-11-16 on 8.19.0: disabled at 15:32 UTC, directory gone within 90s;
  re-enabled 16:16, new `from` = 16:11:29 (Initial Interval 5m).
- **Recovering a gap:** before re-enabling, raise Initial Interval to cover the
  pause; already-indexed indicators are rejected as duplicates (`_id` is a hash
  of the raw indicator), so only the missed ones are added.
- **Pausing without losing the cursor:** stop the agent (service or container)
  instead of disabling the input; the registry survives agent restarts
  (confirmed 2026-11-17 after a stack stop/start).
- **Untested:** whether the registry's 30-minute TTL drops the cursor when the
  input is disabled but another CEL integration keeps `cel-default` running.
- **Discover:** `@timestamp` is the indicator's last_seen, not the ingest time,
  so short time-picker windows show nothing; filter on `event.ingested`.
