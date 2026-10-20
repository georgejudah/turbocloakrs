mod engine;
mod injection;
mod secrets;
mod vault;

use pyo3::prelude::*;

use engine::SafetyReport;
use vault::Vault;

/// Redact PII using numbered tokens such as `[EMAIL_1]`.
#[pyfunction]
#[pyo3(text_signature = "(text, /)")]
fn sanitize_text(text: &str) -> PyResult<String> {
    Ok(engine::sanitize_text(text))
}

/// Redact PII and return `(clean_text, vault)` so the caller can restore it.
#[pyfunction]
#[pyo3(text_signature = "(text, /)")]
fn clean_pii(text: &str) -> PyResult<(String, Vault)> {
    Ok(engine::clean_pii(text))
}

/// Return the sorted PII categories found in `text`.
#[pyfunction]
#[pyo3(text_signature = "(text, /)")]
fn find_pii(text: &str) -> PyResult<Vec<String>> {
    Ok(engine::find_pii(text))
}

/// Fast boolean credential scan.
#[pyfunction]
#[pyo3(text_signature = "(text, /)")]
fn contains_secrets(text: &str) -> bool {
    secrets::contains_secrets(text)
}

/// Redact credentials with kind-specific tokens such as `[OPENAI_API_KEY_1]`.
#[pyfunction]
#[pyo3(text_signature = "(text, /)")]
fn redact_secrets(text: &str) -> String {
    secrets::redact_secrets(text)
}

/// Return the sorted secret categories found in `text`.
#[pyfunction]
#[pyo3(text_signature = "(text, /)")]
fn find_secrets(text: &str) -> Vec<String> {
    secrets::find_secrets(text)
}

/// Flag prompt-injection, jailbreak, obfuscation, or exfiltration heuristics.
#[pyfunction]
#[pyo3(text_signature = "(text, /)")]
fn is_jailbreak(text: &str) -> bool {
    injection::is_jailbreak(text)
}

/// Return a bounded heuristic threat score in the range `0.0..=1.0`.
#[pyfunction]
#[pyo3(text_signature = "(text, /)")]
fn injection_score(text: &str) -> f32 {
    injection::injection_score(text)
}

/// Run PII, secret, and injection checks in a single inspection pass.
#[pyfunction]
#[pyo3(text_signature = "(text, /)")]
fn inspect_all(text: &str) -> SafetyReport {
    engine::inspect_all(text)
}

#[pymodule]
fn _cloakrs(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Vault>()?;
    module.add_class::<SafetyReport>()?;

    module.add_function(wrap_pyfunction!(sanitize_text, module)?)?;
    module.add_function(wrap_pyfunction!(clean_pii, module)?)?;
    module.add_function(wrap_pyfunction!(find_pii, module)?)?;
    module.add_function(wrap_pyfunction!(contains_secrets, module)?)?;
    module.add_function(wrap_pyfunction!(redact_secrets, module)?)?;
    module.add_function(wrap_pyfunction!(find_secrets, module)?)?;
    module.add_function(wrap_pyfunction!(is_jailbreak, module)?)?;
    module.add_function(wrap_pyfunction!(injection_score, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_all, module)?)?;

    module.add("__version__", env!("CARGO_PKG_VERSION"))?;

    Ok(())
}
