use once_cell::sync::Lazy;
use regex::Regex;

use crate::engine::{redact_hits, select_non_overlapping, Hit};
use crate::vault::Vault;

struct SecretPattern {
    kind: &'static str,
    token_prefix: &'static str,
    regex: Regex,
}

/// Pattern order is priority order: earlier entries win when two rules match
/// the same span. High-entropy fallback is applied last.
static SECRET_PATTERNS: Lazy<Vec<SecretPattern>> = Lazy::new(|| {
    let patterns: &[(&str, &str, &str)] = &[
        (
            "private_key",
            "PRIVATE_KEY",
            r"(?s)-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
        ),
        (
            "private_key",
            "PRIVATE_KEY",
            r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----",
        ),
        (
            "anthropic_api_key",
            "ANTHROPIC_API_KEY",
            r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
        ),
        (
            "openai_api_key",
            "OPENAI_API_KEY",
            r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b",
        ),
        (
            "github_token",
            "GITHUB_TOKEN",
            r"\bgithub_pat_[A-Za-z0-9_]{40,}\b",
        ),
        (
            "github_token",
            "GITHUB_TOKEN",
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b",
        ),
        (
            "aws_access_key",
            "AWS_ACCESS_KEY",
            r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b",
        ),
        (
            "aws_secret_key",
            "AWS_SECRET_KEY",
            r#"(?i)\b(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?"#,
        ),
        (
            "slack_token",
            "SLACK_TOKEN",
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        ),
        (
            "google_api_key",
            "GOOGLE_API_KEY",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
        ),
        (
            "stripe_key",
            "STRIPE_KEY",
            r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
        ),
        (
            "jwt",
            "JWT",
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        ),
        (
            "bearer_token",
            "BEARER_TOKEN",
            r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{16,}=*\b",
        ),
        (
            "generic_api_key",
            "API_KEY",
            r#"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_\-./+=]{16,}['"]"#,
        ),
    ];

    patterns
        .iter()
        .map(|(kind, token_prefix, pattern)| SecretPattern {
            kind,
            token_prefix,
            regex: Regex::new(pattern).expect("invalid secret regex"),
        })
        .collect()
});

static HIGH_ENTROPY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9+/=_\-]{24,}").expect("invalid high entropy regex"));

pub(crate) fn secret_hits(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();

    for (index, pattern) in SECRET_PATTERNS.iter().enumerate() {
        for matched in pattern.regex.find_iter(text) {
            hits.push(Hit {
                kind: pattern.kind,
                token_prefix: pattern.token_prefix,
                start: matched.start(),
                end: matched.end(),
                priority: index as u16,
            });
        }
    }

    for matched in HIGH_ENTROPY_RE.find_iter(text) {
        if is_high_entropy(matched.as_str()) {
            hits.push(Hit {
                kind: "high_entropy",
                token_prefix: "SECRET",
                start: matched.start(),
                end: matched.end(),
                priority: 500,
            });
        }
    }

    hits
}

/// Fast boolean scan that avoids building the full hit list.
pub fn contains_secrets(text: &str) -> bool {
    SECRET_PATTERNS
        .iter()
        .any(|pattern| pattern.regex.is_match(text))
        || HIGH_ENTROPY_RE
            .find_iter(text)
            .any(|matched| is_high_entropy(matched.as_str()))
}

/// Redact credentials using kind-specific tokens such as `[OPENAI_API_KEY_1]`.
pub fn redact_secrets(text: &str) -> String {
    let hits = select_non_overlapping(secret_hits(text));
    let mut vault = Vault::default();
    redact_hits(text, &hits, &mut vault)
}

/// Return the sorted, unique categories of secrets found in `text`.
pub fn find_secrets(text: &str) -> Vec<String> {
    let mut kinds: Vec<&str> = secret_hits(text).iter().map(|hit| hit.kind).collect();
    kinds.sort_unstable();
    kinds.dedup();
    kinds.into_iter().map(str::to_owned).collect()
}

fn is_high_entropy(candidate: &str) -> bool {
    if candidate.len() < 24 {
        return false;
    }

    let has_alpha = candidate.bytes().any(|byte| byte.is_ascii_alphabetic());
    let has_digit = candidate.bytes().any(|byte| byte.is_ascii_digit());

    // Random credentials nearly always mix letters and digits. Requiring both
    // removes common false positives from long lowercase words.
    if !has_alpha || !has_digit {
        return false;
    }

    let entropy = shannon_entropy(candidate);
    if candidate.len() >= 32 {
        entropy >= 3.5
    } else {
        entropy >= 4.2
    }
}

fn shannon_entropy(value: &str) -> f64 {
    let mut counts = [0usize; 256];
    let mut length = 0usize;

    for byte in value.bytes() {
        counts[byte as usize] += 1;
        length += 1;
    }

    if length == 0 {
        return 0.0;
    }

    let length = length as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}
