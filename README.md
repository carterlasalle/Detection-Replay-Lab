# Detection Replay Lab

[![CI](https://github.com/carterlasalle/Detection-Replay-Lab/actions/workflows/ci.yml/badge.svg)](https://github.com/carterlasalle/Detection-Replay-Lab/actions/workflows/ci.yml)
[![Security](https://github.com/carterlasalle/Detection-Replay-Lab/actions/workflows/security.yml/badge.svg)](https://github.com/carterlasalle/Detection-Replay-Lab/actions/workflows/security.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Sigma-inspired](https://img.shields.io/badge/rules-Sigma--inspired-6f42c1)](https://sigmahq.io/)
[![ATT&CK mapped](https://img.shields.io/badge/MITRE-ATT%26CK-e21b2d)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-22c55e.svg)](LICENSE)

Detection Replay Lab (`drl`) is an offline workbench for proving that security detections behave as
intended. It normalizes synthetic or sanitized telemetry, replays it deterministically against
Sigma-style YAML rules, evaluates stateless and correlated detections, and turns labeled scenarios
into precision, recall, F1, per-rule, and ATT&CK coverage gates.

```text
$ drl test scenarios/credential_access scenarios/defense_evasion
STATUS  SCENARIO           EVENTS  ALERTS  PRECISION  RECALL  F1     DETAIL
──────  ─────────────────  ──────  ──────  ─────────  ──────  ─────  ──────
PASS    credential-access  6       2       1.000      1.000   1.000  —
PASS    defense-evasion    5       2       1.000      1.000   1.000  —
```

## Why this project matters

Detection content is code, but it is often reviewed as prose and tested in production. DRL gives it
the engineering loop normal software already has:

- **Deterministic replay.** Events are ordered by UTC timestamp and stable ID. Input order cannot
  change results. The optional replay clock scales recorded delays without affecting detection time.
- **Practical Sigma-style rules.** YAML rules support named selections, `and`/`or`/`not`, grouped
  `1 of`/`all of`, wildcards, logsource constraints, and common field modifiers without using `eval`.
- **Stateful detection.** Threshold rules group events over bounded windows; sequence rules require
  ordered steps from the same entity within a timespan.
- **Ground-truth quality.** `malicious`/`benign` labels produce a confusion matrix, precision, recall,
  and F1. `expected_rules` exposes rule-specific misses and unexpected detections.
- **ATT&CK evidence.** Rule tags become loaded and observed technique coverage rather than a static
  spreadsheet claiming protection that has never fired.
- **Explainability.** `drl explain` shows logsource decisions and each selection's field-level match
  or miss. Alert IDs and reports are stable for CI deduplication.
- **Portable evidence.** Table, JSON, JSONL, Markdown, JUnit XML, and SARIF 2.1.0 serve humans,
  pipelines, test dashboards, and code-scanning systems from the same model.
- **Safe lab boundary.** No network access, live attack execution, endpoint changes, credential use,
  or production telemetry is required. Bundled data is synthetic and documentation-safe.

## Install

```bash
git clone https://github.com/carterlasalle/Detection-Replay-Lab.git
cd Detection-Replay-Lab
uv sync --extra dev
uv run drl --help
```

Runtime requirements are Python 3.11+ and PyYAML. `uv.lock` pins the complete development graph.

## Quick start

Run the bundled lab:

```bash
uv run drl validate --rules rules --scenarios scenarios/credential_access scenarios/defense_evasion
uv run drl test scenarios/credential_access scenarios/defense_evasion
uv run drl replay --events scenarios/defense_evasion/events.ndjson --rules rules --trace
uv run drl coverage --events scenarios/credential_access/events.ndjson --rules rules --output reports/coverage.md
```

Create a new test pack:

```bash
uv run drl init scenarios/my_detection
uv run drl test scenarios/my_detection
```

Use standard input for generated telemetry:

```bash
telemetry-generator | uv run drl replay --stdin --stdin-filename generated.ndjson --rules rules
```

## Commands

| Command | Purpose |
| --- | --- |
| `drl replay` | Normalize and replay events against rules; optionally use recorded-time pacing |
| `drl test` | Run scenario manifests and enforce alert/precision/recall/F1/coverage gates |
| `drl validate` | Fail fast on malformed rules, manifests, paths, or event schemas |
| `drl coverage` | Generate JSON or Markdown quality and ATT&CK coverage evidence |
| `drl explain` | Show why one rule matched or missed one event |
| `drl rules` | Inventory normalized rule metadata |
| `drl init` | Create a passing malicious/benign starter scenario |

Exit codes are stable:

| Code | Meaning |
| ---: | --- |
| `0` | Operation and all requested gates succeeded |
| `1` | Scenario gate failed, explain missed, or `--fail-on-alert` observed an alert |
| `2` | Rule, event, manifest, path, I/O, or configuration error |

## Event model

DRL reads JSON, JSON arrays, NDJSON/JSONL, CSV, and gzip variants. Every event requires an RFC3339
or epoch timestamp. The normalizer preserves original fields and adds canonical aliases for common
Sysmon/Windows, AWS CloudTrail, identity, network, file, registry, user, host, and process shapes.

```json
{
  "id": "ps-1",
  "timestamp": "2026-01-02T00:00:00Z",
  "drl.product": "windows",
  "category": "process_creation",
  "process_name": "powershell.exe",
  "command_line": "powershell.exe -NoP -enc SYNTHETIC",
  "label": "malicious",
  "expected_rules": ["drl-windows-encoded-powershell"]
}
```

Labels are optional for replay and required for meaningful quality metrics. Use only `malicious` or
`benign`; unlabeled events are counted separately instead of silently becoming negatives.

## Rule format

Rules intentionally follow familiar [Sigma rule concepts](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
while adding a compact correlation block owned by this project.

```yaml
id: drl-auth-repeated-failures
title: Repeated Authentication Failures
status: stable
level: high
tags: [attack.credential_access, attack.t1110]
detection:
  selection:
    event.action: [user_login_failed, authentication_failure]
  condition: selection
correlation:
  type: threshold
  group_by: [user.name, source.ip]
  timespan: 5m
  count: 3
```

Supported modifiers:

| Modifier | Behavior |
| --- | --- |
| `contains`, `startswith`, `endswith` | Case-insensitive string comparison |
| `re` | Trusted-policy Python regular expression |
| `cidr` | IP membership in IPv4/IPv6 network |
| `exists` | Field presence/absence |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison |
| `all` | Require all values instead of the default any |
| `windash` | Treat `/` and `-` CLI option prefixes equivalently |

Plain values support `*` and `?` wildcards. Conditions support parentheses with normal
`not` → `and` → `or` precedence. No expression is sent to `eval`.

Read [docs/rule-format.md](docs/rule-format.md) for validation and compatibility boundaries.

## Correlation semantics

Threshold state is keyed by rule and `group_by`. Matches older than `timespan` are evicted; reaching
`count` emits one alert containing the window's event IDs and clears that group window.

Sequence state is also group-scoped. Events must match the named `ordered` selections in order and
finish inside `timespan`. A new first-stage event safely restarts progress. Replay sorts all input,
so files and directories may be supplied in any order.

## Scenario manifests

```yaml
id: credential-access
title: Credential access detection pack
events: [events.ndjson]
rules: [../../rules/repeated_auth_failures.yml]
techniques: [attack.t1110]
gates:
  minimum_precision: 1.0
  minimum_recall: 1.0
  minimum_f1: 1.0
  expected_alerts: 1
```

Event paths cannot escape the scenario root. Rule paths may reference a reviewed shared catalog.
Every declared ATT&CK technique must have a loaded tagged rule. See
[docs/scenario-authoring.md](docs/scenario-authoring.md).

## Included lab

| Scenario | Detection behavior | ATT&CK |
| --- | --- | --- |
| Credential access | Three-event authentication threshold; LSASS access with security-tool filter | T1110, T1003.001 |
| Defense evasion | Encoded PowerShell; CloudTrail discovery→disable sequence | T1059.001, T1562.008 |

All data uses reserved documentation networks, synthetic command material, fictional identities,
and inert event records. Nothing performs the represented actions.

## CI and integrations

The repository runs Python 3.11–3.13 on Linux plus current macOS and Windows, strict typing, lint,
format, coverage, scenario gates, self-validation, wheel/source builds, benchmark workload,
dependency audit, and the reusable action itself.

Use DRL as an action:

```yaml
- uses: actions/checkout@v4
- uses: carterlasalle/Detection-Replay-Lab@v0.1.0
  with:
    scenarios: scenarios/credential_access scenarios/defense_evasion
    report: reports/drl-junit.xml
```

Or with pre-commit for rule schema validation:

```yaml
repos:
  - repo: https://github.com/carterlasalle/Detection-Replay-Lab
    rev: v0.1.0
    hooks:
      - id: drl-rule-validate
```

## Scope and safety

This is detection-content testing, not an attack execution framework and not a production SIEM. It
does not run commands, validate cloud credentials, contact endpoints, emulate malware, or ingest data
over a network. Use sanitized or synthetic telemetry; logs can contain credentials, personal data,
internal hostnames, and customer identifiers even when the represented behavior is benign.

ATT&CK mappings use the official [MITRE ATT&CK Enterprise matrix](https://attack.mitre.org/matrices/enterprise/).
A tagged rule is coverage intent; an observed scenario alert is tested evidence; neither proves full
defense against a technique.

## Development

```bash
uv sync --extra dev
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest --cov=detection_replay_lab --cov-report=term-missing
uv run drl validate --rules rules --scenarios scenarios/credential_access scenarios/defense_evasion
uv run drl test scenarios/credential_access scenarios/defense_evasion
uv build
```

The suite covers normalization, formats, operators, condition parsing, logsource filters, correlation
windows, deterministic ordering, scenario path boundaries, metrics, outputs, CLI exits, bundled
scenarios, thousands of arbitrary events/conditions, and packaging.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[docs/architecture.md](docs/architecture.md).

## License

MIT © Carter LaSalle. See [LICENSE](LICENSE).

