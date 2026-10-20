"""Fast, privacy-focused PII, secret, and prompt-injection protection.

The performance-critical engine is implemented in Rust and exposed through
PyO3. All public functions are safe to call from regular Python code.
"""

from ._cloakrs import (
    SafetyReport,
    Vault,
    __version__,
    clean_pii,
    contains_secrets,
    find_pii,
    find_secrets,
    injection_score,
    inspect_all,
    is_jailbreak,
    redact_secrets,
    sanitize_text,
)

__all__ = [
    "SafetyReport",
    "Vault",
    "__version__",
    "clean_pii",
    "contains_secrets",
    "find_pii",
    "find_secrets",
    "injection_score",
    "inspect_all",
    "is_jailbreak",
    "redact_secrets",
    "sanitize_text",
]
