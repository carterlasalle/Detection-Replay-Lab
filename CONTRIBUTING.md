# Contributing

Detection content is production logic. Every rule change needs positive, negative, and explainable
evidence.

```bash
uv sync --extra dev
uv run pytest
uv run drl test scenarios/credential_access scenarios/defense_evasion
```

Rule checklist:

1. Use a stable unique ID and authoritative ATT&CK mapping.
2. Add malicious events with `expected_rules`.
3. Add realistic adjacent benign events and document false positives.
4. Test case, missing fields, aliases, alternate argument spellings, and boundary timing.
5. Keep regexes bounded and free of ambiguous nested repetition.
6. Explain why logsource and correlation grouping are correct.
7. Enforce precision, recall, F1, alert count, and declared technique coverage.
8. Use synthetic public-safe data only.

Before committing:

```bash
uv run ruff format .
uv run ruff check .
uv run mypy src
uv run pytest --cov=detection_replay_lab --cov-report=term-missing
uv run drl validate --rules rules --scenarios scenarios/credential_access scenarios/defense_evasion
uv build
```

Commit messages use `type: imperative description`, such as
`test: add benign deployment PowerShell fixture`.

