# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Use GitHub's private vulnerability reporting for this repository:

https://github.com/georgejudah/turbocloakrs/security/advisories/new

Include:

- A description of the issue and the potential impact
- A minimal reproducer or test case
- The affected version and platform
- Any suggested remediation

You can expect an initial acknowledgement within a few business days. Please
allow time for a fix and coordinated disclosure before publishing details.

## Scope

Reports are especially useful for:

- PII or secret values that bypass detection
- Reversible vault leakage or incorrect restoration
- Prompt-injection or obfuscation bypasses
- Memory-safety issues in the Rust extension
- Supply-chain or build issues in the packaging pipeline

## Limitations

`turbocloak` uses deterministic rules and heuristics. It reduces risk but does
not guarantee that every sensitive value or adversarial prompt is detected.
Treat detections and clean text as one layer of a defense-in-depth strategy.
