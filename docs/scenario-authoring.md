# Scenario authoring

A useful scenario is a falsifiable detection claim, not a pile of alerts.

1. State the behavior and ATT&CK mapping.
2. Build the smallest inert malicious event chain that should detect.
3. Add adjacent benign activity that resembles it but should not detect.
4. Add `expected_rules` to malicious events for rule-level accountability.
5. Set precision, recall, F1, alert-count, and technique gates.
6. Run `drl explain` on surprising events before changing a rule.
7. Commit rule, telemetry, manifest, and report expectation together.

Use reserved IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), fictional domains,
synthetic command payloads, and invented identities. Never copy credentials, customer telemetry,
session tokens, internal domains, or personal data into a public fixture.

Precision-only tests reward rules that never alert. Recall-only tests reward noisy rules. Require
both—and F1—when a pack has sufficient positives and negatives. Alert count catches correlation
semantic changes that event-level metrics alone can miss.

