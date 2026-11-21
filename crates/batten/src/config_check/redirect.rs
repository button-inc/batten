use crate::config_model::Redirect;
use crate::error::UsageError;

use anyhow::Result;

/// Reject a table that would make a refusal dishonest or silent.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for an empty `glob`, an empty
/// `mutation`, or a duplicated `glob`. The last is the load-bearing one: two
/// rows for one path class are two answers to one question, and silently taking
/// the first is how a corrected remedy gets lost behind a stale row — the same
/// refusal [`crate::verbs::validate`] gives a verb declared twice.
///
/// An empty `mutation` is refused rather than treated as absent, because it
/// would render a fix clause that is present and says nothing, which reads worse
/// than the explicit "none declared" a row's absence already produces.
pub fn validate(table: &[Redirect]) -> Result<()> {
    for (index, entry) in table.iter().enumerate() {
        if entry.glob.trim().is_empty() {
            return Err(UsageError::raise(
                "redirect: `glob` must not be empty".to_owned(),
            ));
        }
        if entry.mutation.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "redirect {}: `mutation` must not be empty — a redirect that names nothing is a \
                 fix clause that says nothing",
                entry.glob
            )));
        }
        // Same refusal as `mutation`'s, for the same reason: a declared `read`
        // that says nothing renders a fix clause that says nothing, which reads
        // worse than the row simply not declaring one. Absent and empty are
        // different statements and the engine keeps them different.
        if entry
            .read
            .as_ref()
            .is_some_and(|read| read.trim().is_empty())
        {
            return Err(UsageError::raise(format!(
                "redirect {}: `read` is declared and empty — omit the key to gate no read, or \
                 name the tool that answers",
                entry.glob
            )));
        }
        if table[..index].iter().any(|prior| prior.glob == entry.glob) {
            return Err(UsageError::raise(format!(
                "redirect {}: declared twice; a path class has one sanctioned mutation",
                entry.glob
            )));
        }
    }
    Ok(())
}

/// The words of the `batten` invocation a remedy names, or `None` for a remedy
/// that names none (CLOUD-1189).
///
/// # An invocation is a CODE SPAN, and that bound is the whole of what makes
/// this decidable
///
/// A remedy is a sentence, and a sentence does not say where its command stops.
/// The first version of this collected every following token that LOOKED like a
/// subcommand word, which reads `run `batten capture show <handle>` instead` as
/// a four-word invocation ending in `instead` — and then reports `instead` as an
/// undeclared rule id. That is a finding invented out of English, and it is the
/// false positive that gets a gate switched off.
///
/// A backtick-delimited span has an author-written end, so inside it every word
/// IS part of the command and the rule-id arm below can be exact rather than a
/// guess. `verify` over this repository's own table is what the bound is sized
/// against.
///
/// **What it deliberately under-denies, stated rather than discovered:** a
/// remedy naming a command in bare prose. That is the sanctioned direction here
/// — the alternative is not a stricter gate but a wrong one, and this repository
/// writes every remedy's command as a code span.
pub(crate) fn invocation(text: &str) -> Option<Vec<String>> {
    for span in text.split('`').skip(1).step_by(2) {
        let mut words = span.split_whitespace();
        if words.next() != Some("batten") {
            continue;
        }
        let taken: Vec<String> = words.map(str::to_owned).collect();
        if !taken.is_empty() {
            return Some(taken);
        }
    }
    None
}

/// `--json` — a flag, judged by neither authority.
///
/// Which flags a verb takes is `SURFACE`'s own declaration and `clap`'s to
/// enforce at the call; resolving one here would be a third reading of it.
pub(crate) fn is_flag(word: &str) -> bool {
    word.starts_with('-')
}

/// `<handle>` — an operand the author wrote as a hole to fill in.
///
/// Judged by neither authority: what a verb's operands may be is a per-verb
/// arity question, and this row reads the command surface and the rule table
/// rather than a third one.
pub(crate) fn is_placeholder(word: &str) -> bool {
    word.starts_with('<') && word.ends_with('>') && word.len() > 2
}

/// Refuse a remedy naming a `batten` command that resolves to nothing
/// (CLOUD-1189).
///
/// # Why this exists
///
/// A deny naming a command that does not exist is worse than a deny naming
/// none: it sends the reader to a shell error instead of a remedy, and it looks
/// authoritative doing it. `redirect` strings are free-form prose and nothing
/// resolved the command they name against anything, so a renamed verb turned
/// every remedy naming it into a lie, silently.
///
/// # Both object shapes, because a gate that knew one would report the other
///
/// `batten show config` resolves against [`crate::surface_table::SURFACE`];
/// `batten check <rule-id>` resolves its prefix against `SURFACE` and its
/// remaining word against the declared `[[rule]]` table. A checker knowing only
/// the first would report every rule-scoped remedy as broken, which is the false
/// positive that gets a gate switched off.
///
/// # What it deliberately does not decide
///
/// A remedy naming a **non-batten** command (`mise run …`, `git …`) — that is
/// the operator's PATH, and resolving it needs a second authority over what is
/// installed, which is `policy/verdict-routes-resolve.rego`'s `mise run` arm and
/// not this one. Whether the remedy is *good* advice, which is judgement and
/// rule 3 forbids gating it. And an operand written as a `<placeholder>`.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) naming the remedy's own key and the
/// unresolvable words. **Pointer-only** (rule 4): the key and the command, never
/// the remedy prose that carries it.
pub fn validate_remedies<'a>(
    remedies: impl IntoIterator<Item = (String, &'a str)>,
    rules: &[String],
) -> Result<()> {
    for (key, text) in remedies {
        let Some(words) = invocation(text) else {
            continue;
        };
        let mut matched = 0;
        for take in (1..=words.len()).rev() {
            let candidate = words[..take].join(" ");
            if crate::surface_table::SURFACE
                .iter()
                .any(|decl| decl.path == candidate)
            {
                matched = take;
                break;
            }
        }
        if matched == 0 {
            return Err(UsageError::raise(format!(
                "{key}: the remedy names `batten {}`, which is not a declared command — correct \
                 the remedy, or declare the command on the surface",
                words.join(" ")
            )));
        }
        for word in &words[matched..] {
            if is_flag(word) || is_placeholder(word) || rules.iter().any(|id| id == word) {
                continue;
            }
            return Err(UsageError::raise(format!(
                "{key}: the remedy names `batten {}` and then `{word}`, which is neither a \
                 declared rule id nor a <placeholder> — correct the remedy, or declare the rule",
                words[..matched].join(" ")
            )));
        }
    }
    Ok(())
}
