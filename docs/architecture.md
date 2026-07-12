# Architecture and trust boundaries

```text
sanitized bytes → source loader → normalizer → ordered replay → rule/correlation engine → evidence
 JSON/CSV/gzip     schema errors    aliases      virtual clock    bounded state             reports
```

## Core boundaries

Event files are untrusted data. YAML rules and scenario manifests are trusted, reviewed detection
policy. DRL uses `yaml.safe_load`, never evaluates condition text as Python, restricts operators,
validates paths and schemas before replay, and performs no network requests or command execution.

The `re` modifier is a trusted-policy escape hatch. Python regular expressions have no built-in
timeout, so rule reviewers must reject catastrophic patterns. All bundled rules avoid nested
ambiguous quantifiers.

## Determinism

Events are sorted by `(UTC timestamp, stable event ID)`. Alert IDs are BLAKE2s digests over rule,
events, and group. Replay speed sleeps between events but detection always uses recorded timestamps.
Wall-clock scheduling therefore cannot change correlation windows or outputs.

## Stateless evaluation

Logsource is evaluated before the condition result. Every named selection produces a structured
trace of field checks. The recursive-descent parser implements parentheses, `not`, `and`, `or`, and
Sigma-style `1/all of` groups. Unknown selections and unsupported characters fail validation.

## Stateful evaluation

Threshold queues are bounded by their configured timespan and cleared when an alert is emitted.
Sequence progress is one bounded list per rule/group and resets on expiry or a new first-stage event.
This model is intentionally deterministic and explainable; overlapping/branching CEP graphs are a
future format version, not implicit behavior.

## Evaluation meaning

An alert marks every participating event as detected. Malicious detected events are true positives;
malicious undetected events are false negatives; benign detected events are false positives. Rule
scores use explicit `expected_rules`, avoiding the false assumption that every malicious event should
trigger every loaded rule. Unlabeled events are excluded and counted.

ATT&CK loaded coverage is tagged intent. Observed coverage requires at least one emitted alert from a
tagged rule. Scenario gates can additionally require the technique be represented by a loaded rule.

