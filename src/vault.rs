use std::collections::HashMap;

use pyo3::prelude::*;

/// Bi-directional mapping between redaction tokens and the original values.
///
/// The vault is intentionally session-scoped: callers can send a redacted
/// prompt to a remote model and restore the original values only after the
/// response comes back, without ever exposing PII to the model provider.
#[pyclass(module = "turbocloak", skip_from_py_object)]
#[derive(Debug, Default, Clone)]
pub struct Vault {
    forward: HashMap<String, String>,
    reverse: HashMap<String, String>,
    counters: HashMap<String, u32>,
}

impl Vault {
    /// Return a stable token for `original`, creating one on first use.
    pub fn token_for(&mut self, prefix: &str, original: &str) -> String {
        if let Some(token) = self.reverse.get(original) {
            return token.clone();
        }

        let counter = self.counters.entry(prefix.to_owned()).or_default();
        *counter += 1;

        let token = format!("[{prefix}_{counter}]");
        self.forward.insert(token.clone(), original.to_owned());
        self.reverse.insert(original.to_owned(), token.clone());
        token
    }
}

#[pymethods]
impl Vault {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    /// Restore every known token in `text` back to its original value.
    fn restore(&self, text: &str) -> String {
        let mut restored = text.to_owned();

        // Replace longest tokens first so `[EMAIL_10]` is never partially
        // consumed by `[EMAIL_1]` in an older/looser implementation.
        let mut entries: Vec<(&String, &String)> = self.forward.iter().collect();
        entries.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0.len()));

        for (token, original) in entries {
            if restored.contains(token.as_str()) {
                restored = restored.replace(token.as_str(), original);
            }
        }

        restored
    }

    /// Look up the original value for a redaction token.
    fn get_original(&self, token: &str) -> Option<String> {
        self.forward.get(token).cloned()
    }

    /// Look up the redaction token for an original value.
    fn get_token(&self, original: &str) -> Option<String> {
        self.reverse.get(original).cloned()
    }

    /// Remove every mapping from the vault.
    fn clear(&mut self) {
        self.forward.clear();
        self.reverse.clear();
        self.counters.clear();
    }

    fn __len__(&self) -> usize {
        self.forward.len()
    }

    fn __repr__(&self) -> String {
        format!("Vault(entries={})", self.forward.len())
    }
}
