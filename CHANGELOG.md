# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-10-20

### Added

- Rust formatting, clippy, and dependency audit jobs in CI.
- Dependabot configuration for Cargo and GitHub Actions.
- Contributing, security policy, and changelog documentation.
- PyPI and CI badges in the README.
- Average benchmark results documented in the README.
- Red-team regression suite covering paraphrases, obfuscation, false-positive
  bait, and alternate PII/secret formats.
- Detection for short instruction overrides, role-play bypasses, prompt leaks,
  leetspeak, Cyrillic homoglyphs, meta-refresh, SVG event handlers, and
  protocol-relative images.
- Detection for zero-width-split credentials, password assignments, obfuscated
  emails, contiguous and international phone numbers, contiguous SSNs, and
  IPv4 addresses with leading zeros.

### Fixed

- Upgraded PyO3 to 0.29.3 to address RUSTSEC-2026-0176 and
  RUSTSEC-2026-0177.
- Reduced secret false positives for UUIDs, git SHAs, hex digests, and URL path
  segments.
- Avoided injection false positives on negated safety instructions.

## [0.1.0] - 2026-10-20

### Added

- Rust/PyO3 engine with pre-compiled regular expressions for high-throughput
  text inspection.
- PII detection and reversible redaction for emails, credit cards, IPv4/IPv6
  addresses, phone numbers, and US Social Security numbers.
- Secret detection for OpenAI, Anthropic, GitHub, AWS, Slack, Google, Stripe,
  JWT, Bearer, private-key, generic API-key, and high-entropy credentials.
- Prompt-injection heuristics for instruction overrides, jailbreak signatures,
  invisible Unicode, chat-template tokens, and Markdown/HTML exfiltration
  vectors.
- Unified `SafetyReport` via `inspect_all`, with JSON serialization.
- `Vault` for restoring redacted values locally after a model response.
- Python type stubs (`py.typed`), cross-platform wheels, TestPyPI/PyPI
  publishing, and GitHub release automation.

[Unreleased]: https://github.com/georgejudah/turbocloakrs/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/georgejudah/turbocloakrs/releases/tag/v0.1.1
[0.1.0]: https://github.com/georgejudah/turbocloakrs/releases/tag/v0.1.0
