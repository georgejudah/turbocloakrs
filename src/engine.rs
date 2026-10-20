use std::collections::BTreeSet;
use std::net::Ipv6Addr;

use once_cell::sync::Lazy;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::Regex;
use serde::Serialize;

use crate::injection;
use crate::secrets;
use crate::vault::Vault;

const PII_BASE_PRIORITY: u16 = 200;

#[derive(Debug, Clone)]
pub(crate) struct Hit {
    pub kind: &'static str,
    pub token_prefix: &'static str,
    pub start: usize,
    pub end: usize,
    pub priority: u16,
}

struct PiiPattern {
    kind: &'static str,
    token_prefix: &'static str,
    regex: Regex,
    validator: Option<fn(&str) -> bool>,
}

type PiiDefinition = (
    &'static str,
    &'static str,
    &'static str,
    Option<fn(&str) -> bool>,
);

static PII_PATTERNS: Lazy<Vec<PiiPattern>> = Lazy::new(|| {
    let patterns: &[PiiDefinition] = &[
        (
            "email",
            "EMAIL",
            r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}\b",
            None,
        ),
        (
            "credit_card",
            "CREDIT_CARD",
            r"\b\d(?:[ -]?\d){12,18}\b",
            Some(is_valid_credit_card),
        ),
        (
            "ssn",
            "SSN",
            r"\b\d{3}[ -]\d{2}[ -]\d{4}\b",
            Some(is_valid_ssn),
        ),
        (
            "ipv4",
            "IPV4",
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
            None,
        ),
        (
            "ipv6",
            "IPV6",
            r"(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}",
            Some(is_valid_ipv6),
        ),
        (
            "phone",
            "PHONE",
            r"(?:\+?1[\s.\-]?)?(?:\(\d{3}\)[\s.\-]?|\d{3}[\s.\-])\d{3}[\s.\-]?\d{4}\b",
            Some(is_valid_phone),
        ),
        (
            "phone",
            "PHONE",
            r"\b\+\d{1,3}[\s.\-]?(?:\d[\s.\-]?){6,14}\d\b",
            Some(is_valid_phone),
        ),
    ];

    patterns
        .iter()
        .map(|(kind, token_prefix, pattern, validator)| PiiPattern {
            kind,
            token_prefix,
            regex: Regex::new(pattern).expect("invalid PII regex"),
            validator: *validator,
        })
        .collect()
});

pub(crate) fn pii_hits(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();

    for (index, pattern) in PII_PATTERNS.iter().enumerate() {
        for matched in pattern.regex.find_iter(text) {
            if let Some(validator) = pattern.validator {
                if !validator(matched.as_str()) {
                    continue;
                }
            }

            hits.push(Hit {
                kind: pattern.kind,
                token_prefix: pattern.token_prefix,
                start: matched.start(),
                end: matched.end(),
                priority: PII_BASE_PRIORITY + index as u16,
            });
        }
    }

    hits
}

/// Replace PII with numbered vault tokens such as `[EMAIL_1]`.
pub fn sanitize_text(text: &str) -> String {
    let hits = select_non_overlapping(pii_hits(text));
    let mut vault = Vault::default();
    redact_hits(text, &hits, &mut vault)
}

/// Redact PII and return the vault needed to restore the original values.
pub fn clean_pii(text: &str) -> (String, Vault) {
    let hits = select_non_overlapping(pii_hits(text));
    let mut vault = Vault::default();
    let clean = redact_hits(text, &hits, &mut vault);
    (clean, vault)
}

/// Return the sorted, unique categories of PII found in `text`.
pub fn find_pii(text: &str) -> Vec<String> {
    unique_kinds(&pii_hits(text))
}

/// One-pass inspection for PII, secrets, and prompt-injection risk.
pub fn inspect_all(text: &str) -> SafetyReport {
    let pii = pii_hits(text);
    let pii_detected = unique_kinds(&pii);

    let secret_hits = secrets::secret_hits(text);
    let secrets_detected = unique_kinds(&secret_hits);

    let mut all_hits = pii;
    all_hits.extend(secret_hits);

    let selected = select_non_overlapping(all_hits);
    let mut vault = Vault::default();
    let mut clean_text = redact_hits(text, &selected, &mut vault);

    let analysis = injection::analyze(text);
    if analysis.has_obfuscation {
        clean_text = injection::strip_invisible(&clean_text);
    }

    SafetyReport {
        is_safe: pii_detected.is_empty() && secrets_detected.is_empty() && !analysis.has_injection,
        clean_text,
        pii_detected,
        secrets_detected,
        contains_injection: analysis.has_injection,
        injection_score: analysis.score,
    }
}

pub(crate) fn select_non_overlapping(mut hits: Vec<Hit>) -> Vec<Hit> {
    // Select the most specific (lowest priority value) hits first so a secret
    // is never obscured by a broader PII or high-entropy match.
    hits.sort_unstable_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then(a.start.cmp(&b.start))
            .then(b.end.cmp(&a.end))
    });

    let mut selected: Vec<Hit> = Vec::with_capacity(hits.len());

    'candidates: for hit in hits {
        for existing in &selected {
            if hit.start < existing.end && existing.start < hit.end {
                continue 'candidates;
            }
        }
        selected.push(hit);
    }

    selected.sort_unstable_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    selected
}

pub(crate) fn redact_hits(text: &str, hits: &[Hit], vault: &mut Vault) -> String {
    if hits.is_empty() {
        return text.to_owned();
    }

    let mut output = String::with_capacity(text.len() + hits.len() * 8);
    let mut cursor = 0usize;

    for hit in hits {
        output.push_str(&text[cursor..hit.start]);
        output.push_str(&vault.token_for(hit.token_prefix, &text[hit.start..hit.end]));
        cursor = hit.end;
    }

    output.push_str(&text[cursor..]);
    output
}

fn unique_kinds(hits: &[Hit]) -> Vec<String> {
    let kinds: BTreeSet<&str> = hits.iter().map(|hit| hit.kind).collect();
    kinds.into_iter().map(str::to_owned).collect()
}

fn is_valid_credit_card(value: &str) -> bool {
    let digits: Vec<u8> = value
        .bytes()
        .filter(|byte| byte.is_ascii_digit())
        .map(|byte| byte - b'0')
        .collect();

    if !(13..=19).contains(&digits.len()) {
        return false;
    }

    let parity = digits.len() % 2;
    let sum: u32 = digits
        .iter()
        .enumerate()
        .map(|(index, &digit)| {
            let mut digit = digit as u32;
            if index % 2 == parity {
                digit *= 2;
                if digit > 9 {
                    digit -= 9;
                }
            }
            digit
        })
        .sum();

    sum % 10 == 0
}

fn is_valid_ssn(value: &str) -> bool {
    let digits: Vec<u8> = value
        .bytes()
        .filter(|byte| byte.is_ascii_digit())
        .map(|byte| byte - b'0')
        .collect();

    if digits.len() != 9 {
        return false;
    }

    let area = digits[0] as u16 * 100 + digits[1] as u16 * 10 + digits[2] as u16;
    let group = digits[3] as u16 * 10 + digits[4] as u16;
    let serial =
        digits[5] as u16 * 1000 + digits[6] as u16 * 100 + digits[7] as u16 * 10 + digits[8] as u16;

    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

fn is_valid_ipv6(value: &str) -> bool {
    value.parse::<Ipv6Addr>().is_ok()
}

fn is_valid_phone(value: &str) -> bool {
    let digit_count = value.bytes().filter(|byte| byte.is_ascii_digit()).count();
    (7..=15).contains(&digit_count)
}

/// Consolidated result of a full safety inspection.
#[pyclass(module = "cloakrs", skip_from_py_object)]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SafetyReport {
    #[pyo3(get)]
    pub is_safe: bool,
    #[pyo3(get)]
    pub clean_text: String,
    #[pyo3(get)]
    pub pii_detected: Vec<String>,
    #[pyo3(get)]
    pub secrets_detected: Vec<String>,
    #[pyo3(get)]
    pub contains_injection: bool,
    #[pyo3(get)]
    pub injection_score: f32,
}

#[pymethods]
impl SafetyReport {
    /// Serialize the report to JSON for logging or event pipelines.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|error| PyValueError::new_err(error.to_string()))
    }

    fn __repr__(&self) -> String {
        format!(
            "SafetyReport(is_safe={}, pii_detected={:?}, secrets_detected={:?}, contains_injection={}, injection_score={:.3})",
            self.is_safe,
            self.pii_detected,
            self.secrets_detected,
            self.contains_injection,
            self.injection_score,
        )
    }
}
