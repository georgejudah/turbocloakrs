use once_cell::sync::Lazy;
use regex::{Regex, RegexSet};

const STRONG_PATTERNS: &[(&str, &str)] = &[
    (
        "instruction_override",
        r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^.!?\n]{0,80}\b(?:instructions?|rules?|prompts?|directives?|guidelines?|restrictions?|safety|filters?|guardrails?|polic(?:y|ies)|context|system\s+message)\b",
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
        "do_anything_now",
        r"(?i)\b(?:do\s+anything\s+now|act\s+as\s+dan|jailbroken)\b",
    ),
    (
        "reveal_prompt",
        r"(?i)\b(?:reveal|print|show|leak|repeat|output|display)\s+(?:your|the)\s+(?:system\s+prompt|hidden\s+(?:prompt|instructions)|initial\s+prompt|instructions|rules|context)\b",
    ),
    (
        "new_instructions",
        r"(?i)\b(?:new|updated|real|true)\s+(?:instructions?|rules?|directives?)\s*[:=]",
    ),
    (
        "role_override",
        r"(?i)\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+(?:are|will)|act\s+as\s+(?:if\s+you\s+have\s+no|an?\s+unrestricted))",
    ),
    (
        "role_play",
        r"(?i)\b(?:pretend|act|behave|roleplay)\b[^.!?\n]{0,60}\b(?:no\s+(?:rules|restrictions|limits|filters|guidelines)|unrestricted|unfiltered|unbounded)\b",
    ),
    (
        "from_now_on",
        r"(?i)\bfrom\s+now\s+on\b[^.!?\n]{0,60}\b(?:respond|answer|reply|obey|act|behave|output|only)\b",
    ),
    (
        "no_restrictions",
        r"(?i)\b(?:without|ignore|bypass|disable|remove|override)\s+(?:any\s+|all\s+)?(?:your\s+|the\s+)?(?:restrictions?|safety|filters?|guardrails?|content\s+policy|limitations?|guidelines?)\b",
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
        r"(?is)\b(?:send|post|exfiltrate|upload|transmit|leak|email|forward)\b.{0,80}\b(?:to|at|via)\b.{0,120}(?:https?://|webhook|api|email|@)",
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
    r#"(?is)<\s*img\b[^>]*\bsrc\s*=\s*['"]?\s*(?:https?:|//|data:|javascript:)[^>]*>"#,
    r"(?is)!\[[^\]]{0,200}\]\(\s*(?:https?:|//|data:|javascript:)[^)]*\)",
    r"(?is)\[[^\]]{0,200}\]\(\s*(?:javascript:|data:)[^)]*\)",
    r"(?i)\bdata:(?:text/html|application/javascript|image/svg\+xml)[;,]",
    r#"(?is)<\s*(?:a|form)\b[^>]*(?:href|action)\s*=\s*['"]\s*(?:https?:|//|javascript:|data:)[^>]*>"#,
    r#"(?i)\b(?:curl|wget)\s+(?:-\S+\s+)*['"]?https?://"#,
    r#"(?is)<meta\b[^>]*http-equiv\s*=\s*['"]?refresh['"]?[^>]*>"#,
    r#"(?is)<\s*[a-z][a-z0-9]*\b[^>]*\bon[a-z]+\s*=\s*['"]?[^>]*>"#,
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

pub struct InjectionAnalysis {
    pub has_injection: bool,
    pub score: f32,
    pub has_obfuscation: bool,
}

/// Inspect text for instruction overrides, hidden characters, and exfiltration
/// vectors. The score is a bounded heuristic, not a probability estimate.
pub fn analyze(text: &str) -> InjectionAnalysis {
    let mut signature_count = strong_signature_count(text);

    // Catch simple leetspeak and Cyrillic homoglyphs without penalizing the
    // common case: normalization only runs when the original text misses.
    if signature_count == 0 {
        if let Some(normalized) = detection_normalized(text) {
            signature_count = strong_signature_count(&normalized);
        }
    }

    let has_exfiltration = EXFIL_SET.is_match(text);
    let has_obfuscation = has_invisible(text);

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
    if !has_invisible(text) {
        return text.to_owned();
    }

    text.chars().filter(|ch| !is_invisible_char(*ch)).collect()
}

pub(crate) fn has_invisible(text: &str) -> bool {
    text.chars().any(is_invisible_char)
}

pub(crate) fn is_invisible_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

fn strong_signature_count(text: &str) -> usize {
    if !STRONG_SET.is_match(text) {
        return 0;
    }

    let mut count = 0usize;

    for ((label, _), pattern) in STRONG_PATTERNS.iter().zip(STRONG_RE.iter()) {
        for matched in pattern.find_iter(text) {
            if matches!(*label, "instruction_override" | "no_restrictions")
                && is_negated(text, matched.start())
            {
                continue;
            }

            count += 1;
            break;
        }
    }

    count
}

fn is_negated(text: &str, start: usize) -> bool {
    let prefix = &text[..start];
    let word = prefix
        .split_whitespace()
        .last()
        .unwrap_or("")
        .trim_matches(|ch: char| !ch.is_alphanumeric() && ch != '\'')
        .to_ascii_lowercase();

    matches!(
        word.as_str(),
        "not" | "never" | "no" | "don't" | "doesn't" | "won't" | "cannot" | "can't"
    )
}

fn detection_normalized(text: &str) -> Option<String> {
    let mut changed = false;
    let mut normalized = String::with_capacity(text.len());

    for ch in text.chars() {
        let mapped = normalize_char(ch);
        if mapped != ch {
            changed = true;
        }
        normalized.push(mapped);
    }

    if changed {
        Some(normalized)
    } else {
        None
    }
}

fn normalize_char(ch: char) -> char {
    match ch {
        '0' => 'o',
        '1' => 'i',
        '3' => 'e',
        '4' => 'a',
        '5' => 's',
        '7' => 't',
        '@' => 'a',
        '$' => 's',
        '\u{0430}' => 'a',
        '\u{0435}' => 'e',
        '\u{043E}' => 'o',
        '\u{0440}' => 'p',
        '\u{0441}' => 'c',
        '\u{0443}' => 'y',
        '\u{0445}' => 'x',
        '\u{0456}' => 'i',
        '\u{0458}' => 'j',
        '\u{0455}' => 's',
        '\u{0410}' => 'A',
        '\u{0412}' => 'B',
        '\u{0415}' => 'E',
        '\u{041A}' => 'K',
        '\u{041C}' => 'M',
        '\u{041D}' => 'H',
        '\u{041E}' => 'O',
        '\u{0420}' => 'P',
        '\u{0421}' => 'C',
        '\u{0422}' => 'T',
        '\u{0425}' => 'X',
        '\u{0406}' => 'I',
        '\u{0408}' => 'J',
        '\u{0405}' => 'S',
        other => other,
    }
}
