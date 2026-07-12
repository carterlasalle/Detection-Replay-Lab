# Security policy

Use GitHub private vulnerability reporting for parser bypasses, condition-evaluation flaws, path
boundary escapes, denial-of-service patterns, unsafe archive handling, command execution, or reports
that expose data unexpectedly. Do not attach production telemetry, credentials, internal detection
content, customer identifiers, or active infrastructure details.

Include the affected version, minimal synthetic reproducer, expected behavior, actual behavior, and
impact. Expect acknowledgement within seven days.

DRL is an offline lab tool, not a sandbox for hostile rules. Run untrusted rules only after review and
use synthetic/sanitized telemetry. A passing scenario demonstrates its declared fixtures and gates;
it does not prove universal detection coverage.

