use once_cell::sync::Lazy;
use regex::{Regex, RegexSet};

const STRONG_PATTERNS: &[(&str, &str)] = &[
    (
        "ignore_previous",
        r"(?i)\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+)?(?:previous|prior|above|earlier|existing|system)\s+(?:instructions?|prompts?|rules?|directives?|context|guidelines?)\b",
    ),
    (
        "ignore_above",
        r"(?i)\b(?:ignore|disregard|forget)\s+(?:the\s+|everything\s+)?(?:above|all\s+above|everything\s+above)\b",
    ),
    (
        "system_override",
        r"(?i)\b(?:system|developer|admin)\s+(?:override|prompt\s+override|message\s+override)\b",
    ),
    (
        "dan_mode",
        r"(?i)\b(?:dan|do\s+anything\s+now|jailbreak|developer|god|unrestricted|evil)\s+mode\b",
    ),
    (
        "reveal_prompt",
        r"(?i)\b(?:reveal|print|show|leak|repeat|output|display)\s+(?:your|the)\s+(?:system\s+prompt|hidden\s+instructions|initial\s+prompt|instructions|rules)\b",
    ),
    (
        "new_instructions",
        r"(?i)\b(?:new|updated|real|true)\s+instructions?\s*[:=]",
    ),
    (
        "role_override",
        r"(?i)\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+(?:are|will)|act\s+as\s+(?:if\s+you\s+have\s+no|an?\s+unrestricted))",
    ),
    (
        "no_restrictions",
        r"(?i)\b(?:without|ignore|bypass|disable|remove)\s+(?:any\s+|all\s+)?(?:restrictions?|safety|filters?|guardrails?|content\s+policy|limitations?)\b",
    ),
    (
        "do_not_follow",
        r"(?i)\b(?:do\s+not|don't|never)\s+(?:follow|obey|listen\s+to)\s+(?:your|the)\s+(?:instructions|rules|system\s+prompt)\b",
    ),
    (
        "special_tokens",
        r"(?i)<\|(?:im_start|im_end|system|assistant|endoftext)\|>",
    ),
    ("chat_template", r"(?i)(?:<<SYS>>|</?system>|\[/?INST\])"),
    (
        "prompt_exfil",
        r"(?is)\b(?:send|post|exfiltrate|upload|transmit|leak)\b.{0,80}\b(?:to|at|via)\b.{0,120}(?:https?://|webhook|api|email|@)",
    ),
    (
        "repeat_above",
        r"(?i)\b(?:repeat|print|output|show)\s+(?:the\s+|all\s+)?(?:text|words|content|instructions?)\s+(?:above|before|preceding)\b",
    ),
    (
        "debug_mode",
        r"(?i)\b(?:debug|maintenance|test|sudo|root)\s+(?:mode|access)\b",
    ),
];

const EXFIL_PATTERNS: &[&str] = &[
    r"(?is)<\s*(?:script|iframe|object|embed)\b[^>]*>",
    r#"(?is)<\s*img\b[^>]*\bsrc\s*=\s*['"]?\s*(?:https?:|data:|javascript:)[^>]*>"#,
    r"(?is)!\[[^\]]{0,200}\]\(\s*(?:https?:|data:|javascript:)[^)]*\)",
    r"(?is)\[[^\]]{0,200}\]\(\s*(?:javascript:|data:)[^)]*\)",
    r"(?i)\bdata:(?:text/html|application/javascript|image/svg\+xml)[;,]",
    r#"(?is)<\s*(?:a|form)\b[^>]*(?:href|action)\s*=\s*['"]\s*(?:https?:|javascript:|data:)[^>]*>"#,
    r#"(?i)\b(?:curl|wget)\s+(?:-\S+\s+)*['"]?https?://"#,
];

static STRONG_RE: Lazy<Vec<Regex>> = Lazy::new(|| {
    STRONG_PATTERNS
        .iter()
        .map(|(_, pattern)| Regex::new(pattern).expect("invalid injection regex"))
        .collect()
});

static STRONG_SET: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new(STRONG_PATTERNS.iter().map(|(_, pattern)| *pattern))
        .expect("invalid injection regex set")
});

static EXFIL_SET: Lazy<RegexSet> =
    Lazy::new(|| RegexSet::new(EXFIL_PATTERNS).expect("invalid exfiltration regex set"));

static INVISIBLE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{FEFF}\x{E0000}-\x{E007F}]",
    )
    .expect("invalid invisible character regex")
});

pub struct InjectionAnalysis {
    pub has_injection: bool,
    pub score: f32,
    pub has_obfuscation: bool,
}

/// Inspect text for instruction overrides, hidden characters, and exfiltration
/// vectors. The score is a bounded heuristic, not a probability estimate.
pub fn analyze(text: &str) -> InjectionAnalysis {
    let signature_count = if STRONG_SET.is_match(text) {
        STRONG_RE
            .iter()
            .filter(|pattern| pattern.is_match(text))
            .count()
    } else {
        0
    };

    let has_exfiltration = EXFIL_SET.is_match(text);
    let has_obfuscation = INVISIBLE_RE.is_match(text);

    let mut score = 0.0_f32;
    if signature_count > 0 {
        score += 0.62 + 0.12 * signature_count.saturating_sub(1) as f32;
    }
    if has_exfiltration {
        score += 0.33;
    }
    if has_obfuscation {
        score += 0.33;
    }

    let score = score.min(1.0);

    InjectionAnalysis {
        has_injection: signature_count > 0 || has_exfiltration || has_obfuscation,
        score,
        has_obfuscation,
    }
}

pub fn is_jailbreak(text: &str) -> bool {
    analyze(text).has_injection
}

pub fn injection_score(text: &str) -> f32 {
    analyze(text).score
}

/// Remove zero-width, bidi-control, and Unicode-tag characters used to hide
/// instructions from human reviewers.
pub fn strip_invisible(text: &str) -> String {
    if INVISIBLE_RE.is_match(text) {
        INVISIBLE_RE.replace_all(text, "").into_owned()
    } else {
        text.to_owned()
    }
}
