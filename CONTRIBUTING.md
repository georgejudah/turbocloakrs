# Contributing

Thanks for helping improve `turbocloak`.

## Development setup

Requirements:

- Rust stable (1.83 or newer)
- Python 3.8 or newer
- Maturin

```bash
python -m pip install maturin pytest
maturin develop --release
python -m pytest -q
```

## Before opening a pull request

Run the same checks as CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo audit
python -m pytest -q
```

The tests include sub-millisecond performance assertions. Set
`TURBOCLOAK_SKIP_PERF=1` only when running on a constrained machine.

## Adding detection rules

When adding or changing a rule:

1. Add positive tests for the new pattern.
2. Add a nearby negative test to protect against false positives.
3. Prefer specific, validated patterns over broad regexes.
4. Keep the hot path fast; avoid cloning unless required by the API.
5. Update the README and CHANGELOG when behavior changes.

Rules should use stable categories in `pii_detected` and `secrets_detected`.
Token prefixes should be uppercase and unique per category.

## Pull request process

- Keep pull requests focused and describe the security or performance impact.
- Update tests, documentation, and the changelog as needed.
- CI must pass before merge.
- Do not commit generated artifacts such as `target/`, `dist/`, or caches.

## Release process

1. Update the version in `Cargo.toml`.
2. Update `CHANGELOG.md`.
3. Commit and push the changes.
4. Push a test tag such as `v0.1.1-test1` to publish to TestPyPI.
5. Verify installation from TestPyPI.
6. Push the release tag, for example `v0.1.1`.

Tags containing `-test` only publish to TestPyPI. Normal version tags also
publish to PyPI when the `PUBLISH_TO_PYPI` repository variable is `true`.

## Security issues

Do not report vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md).
