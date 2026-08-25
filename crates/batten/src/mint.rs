//! Receipts minted from the tool result that earned them (CLOUD-1024).
//!
//! # The gap this closes
//!
//! Of roughly twenty receipt families in this repo, all but two are written as a
//! side effect of the action they attest to. The two exceptions are both
//! read-shaped — `issue-read.<KEY>` and `issue-search.<branch>` — and both
//! required the agent to make a **second** call carrying a payload it
//! re-assembled by hand, for a read it had already performed seconds earlier.
//! Measured 2026-08-23: one filing plus four board repairs, each charging a
//! `get_issue` -> recover -> mint -> write cycle, and the read tool has no field
//! projection (CLOUD-782) so each cycle re-paid a whole body to record two
//! scalars.
//!
//! It also closes a gap the hand-run path concedes. The receipt's **mtime**
//! bounds mint->write, not read->write, so a 33-minute-old payload has been
//! measured minting a valid 300-second window. A mint taken from the result
//! collapses the two instants and the gap becomes inexpressible.
//!
//! # Why this is the boundary and not [`crate::sink`]
//!
//! CLOUD-851's production axis looks like the home for this and structurally is
//! not, measured against the tree rather than inferred:
//! [`crate::rules::Rule::validate_sink`] refuses `produces` on any non-`Tree`
//! scoped row **at load, by name**, and both rows this serves are
//! `mediated_call`; and `hook`'s dispatch adjudicates only the PRE-tool event,
//! so on the event this mint must happen on there is no decision and no
//! [`crate::sink::Requested`] to carry.
//!
//! The precedent that does fit is one module over: [`crate::facts::Declared`],
//! whose record is written by `record_agent_fact` at exactly this boundary from
//! exactly this envelope. This is that shape with a tool selector where that one
//! has a command.
//!
//! # Success is part of the predicate, not an afterthought
//!
//! A mint that fired on an errored or empty response would forge a read receipt
//! for a read that never happened — the exact forgery class this module exists to
//! remove. [`Declared::requires`] is what makes that impossible: the projection a
//! receipt needs **is** its success predicate here. A payload missing any
//! required path mints NOTHING, which is the posture `issue-read-check.sh` takes
//! one layer over, where a body with no `updatedAt` is turned away by name rather
//! than recorded with an invented value.
//!
//! # Rule 1 holds because the vocabulary is all config
//!
//! `get_issue`, `issue-read`, `id`, `updatedAt` are a consumer's tracker facts.
//! None of them appears here: this module knows that a mint has a name, a tool
//! selector, a key, a required projection and a body template, and `batten.toml`
//! says which strings fill them.

use serde::{Deserialize, Serialize};

/// What a mint's receipt is filed under.
///
/// The two keyings the censused receipts actually use, and a closed enum rather
/// than a free string for [`crate::rules::SinkKey`]'s reason: a key a config
/// could spell arbitrarily is a filename a config could point anywhere, and the
/// store lives under `$GIT_DIR`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum MintKey {
    /// Filed under a subject the RESULT names — one row of somebody's board.
    /// The subject comes from [`Declared::key_from`].
    Named,
    /// Filed under the current branch, so every commit on it continues to serve
    /// the same record.
    Branch,
}

/// Whether a mint replaces its record or appends to it.
///
/// The distinction is the censused one and it is not cosmetic. A read receipt
/// answers *how old is the newest read*, so the freshest must overwrite the
/// stalest; a search receipt accumulates what the author has seen, so it appends.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum MintMode {
    /// Truncate and write. The freshest answer is the only answer.
    Replace,
    /// Append a line. The record is a journal of what was seen.
    Append,
}

/// One receipt this repository mints from a tool result.
///
/// Every column is a consumer's string or a closed enum; nothing here names a
/// tracker, a tool or a field (non-negotiable rule 1).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Declared {
    /// The receipt namespace — the same token a `receipt` rule's `checks` list
    /// names, so the file this writes is the file that rule reads.
    pub name: String,
    /// Which tool's result mints it, matched by [`crate::rules::selects_tool_name`].
    ///
    /// **A tool name, never a field shape.** A write response and a read payload
    /// are shape-identical across the fields either carries, so duck-typing lets
    /// the later, poorer payload win; and the match is on the whole name or its
    /// whole final `__`-delimited segment because a connector is exposed under
    /// more than one name over its lifetime (CLOUD-178).
    pub tool: String,
    /// What the record is filed under.
    pub key: MintKey,
    /// The path whose value is the subject, for [`MintKey::Named`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_from: Option<String>,
    /// Paths that must be present and non-null in the result for anything to be
    /// written. **This is the success predicate** — see the module doc.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// Whether the record is replaced or appended.
    pub mode: MintMode,
    /// The record's bytes, as a template over the closed placeholder vocabulary
    /// [`Piece`] documents.
    pub body: String,
}

/// One element of a body template.
///
/// A **closed** vocabulary: six forms, each an engine primitive over a
/// consumer-supplied path. Closed rather than open for the reason every other
/// axis in this crate is — an unrecognised placeholder is a load error, never a
/// value that silently renders as itself and writes a receipt nobody can read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    /// Text outside any placeholder, verbatim.
    Literal(String),
    /// `{path}` — the scalar at that path.
    Path(String),
    /// `{now}` — seconds since the epoch, read at the boundary.
    Now,
    /// `{digest:path}` — the git blob hash of the string there.
    Digest(String),
    /// `{slug:path}` — lowercased with non-alphanumeric runs folded to `-`.
    Slug(String),
    /// `{join:path}` — the values an iterating path yields, space-joined.
    Join(String),
    /// `{git:ref}` — what that ref resolves to in this checkout.
    Git(String),
}

/// The token an absent optional records.
///
/// **Load-bearing, and inherited rather than invented.** `issue-read-check.sh`
/// used to fall through an absent field to the empty string, whose hash was a
/// real-looking 40-hex digest that a later gate then compared against — two
/// payloads with no body matched each other, measured nine times over two days
/// (CLOUD-691). `-` reads downstream as *could not look*, so sending less always
/// makes a later gate LOUDER, never quieter, which is the direction the incentive
/// has to point.
const ABSENT: &str = "-";

/// Split a body template into its pieces, or name the first thing wrong with it.
///
/// Shared by [`validate`] and [`render`] so a template that loads is a template
/// that renders: a second parser would be a second thing to drift, and the
/// drift's shape would be a rule that passes validation and writes nothing.
fn parse(body: &str) -> Result<Vec<Piece>, String> {
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut rest = body;
    while let Some(open) = rest.find('{') {
        literal.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Err(format!("`{body}` has an unclosed `{{`"));
        };
        let token = &after[..close];
        rest = &after[close + 1..];
        if !literal.is_empty() {
            pieces.push(Piece::Literal(std::mem::take(&mut literal)));
        }
        pieces.push(piece_for(token)?);
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        pieces.push(Piece::Literal(literal));
    }
    Ok(pieces)
}

/// One placeholder's meaning, or a refusal naming it.
fn piece_for(token: &str) -> Result<Piece, String> {
    if token == "now" {
        return Ok(Piece::Now);
    }
    let Some((verb, argument)) = token.split_once(':') else {
        if token.is_empty() {
            return Err(String::from("`{}` names no path"));
        }
        return Ok(Piece::Path(token.to_owned()));
    };
    if argument.is_empty() {
        return Err(format!("`{{{token}}}` names an empty argument"));
    }
    match verb {
        "digest" => Ok(Piece::Digest(argument.to_owned())),
        "slug" => Ok(Piece::Slug(argument.to_owned())),
        "join" => Ok(Piece::Join(argument.to_owned())),
        "git" => Ok(Piece::Git(argument.to_owned())),
        other => Err(format!(
            "`{{{token}}}` names `{other}`, which is not one of `digest`, `slug`, `join` or `git`"
        )),
    }
}

/// Every value a path selects, or `None` where the path does not resolve.
///
/// The grammar is dotted segments, where a segment ending `[]` iterates the array
/// there. `None` and an EMPTY vector are different answers and the difference is
/// what makes a zero-hit search still mint: a path that does not resolve is a
/// payload this mint cannot read, while a path resolving to no elements is a real
/// reading of nothing.
///
/// A `null` at the end of a path is `None` rather than a value, because every
/// caller here is asking whether the result actually said something.
fn select<'a>(value: &'a serde_json::Value, path: &str) -> Option<Vec<&'a serde_json::Value>> {
    let mut current = vec![value];
    for segment in path.split('.') {
        let (name, iterate) = match segment.strip_suffix("[]") {
            Some(name) => (name, true),
            None => (segment, false),
        };
        let mut next = Vec::new();
        for value in current {
            // An empty name is the top-level array's spelling (`[].id`), so the
            // value is already the thing to iterate.
            let value = if name.is_empty() {
                value
            } else {
                value.get(name)?
            };
            if iterate {
                next.extend(value.as_array()?);
            } else {
                next.push(value);
            }
        }
        current = next;
    }
    if current.iter().any(|value| value.is_null()) {
        return None;
    }
    Some(current)
}

/// The single scalar a path selects, rendered as a bare string.
///
/// `None` for anything that is not exactly one non-null scalar, so a caller can
/// never accidentally write a JSON fragment into a receipt a shell reads
/// positionally.
fn scalar(value: &serde_json::Value, path: &str) -> Option<String> {
    let selected = select(value, path)?;
    let [only] = selected.as_slice() else {
        return None;
    };
    match only {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Bool(_) | serde_json::Value::Number(_) => Some(only.to_string()),
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            None
        }
    }
}

/// Whether every required path resolved, which is this module's success test.
#[must_use]
pub fn satisfied(declared: &Declared, result: &serde_json::Value) -> bool {
    declared
        .requires
        .iter()
        .all(|path| select(result, path).is_some())
}

/// The subject this result's receipt is filed under, for a [`MintKey::Named`] row.
///
/// **Refused, never rewritten**, which is [`crate::receipt::safe_subject`]'s rule
/// and its reason: rewriting a bad subject would file two different subjects
/// under one receipt and let a fresh read of A authorise a stale write to B.
#[must_use]
pub fn subject(declared: &Declared, result: &serde_json::Value) -> Option<String> {
    let from = declared.key_from.as_deref()?;
    let subject = scalar(result, from)?;
    crate::receipt::safe_subject(&subject).then_some(subject)
}

/// The git blob id of `text`, byte-identical to `git hash-object --stdin`.
///
/// That equality is the contract rather than an implementation note: the digest
/// is read back by a gate that recomputes it with `git hash-object`, so any other
/// value would be a field that exists and never matches.
///
/// **Asked of `gix` rather than computed from a hash crate**, and the difference
/// is not stylistic. What this wants is *git's object id*, not *a SHA-1* — the
/// framing bytes, the object kind and the hash are git's format, so the git
/// implementation already in this tree is the authority on all three. Reaching
/// for `sha1` directly spelled that format out by hand AND took a second direct
/// dependency resolving `digest 0.10`, splitting the major `hmac` and `sha2`
/// share at `0.11`. That is exactly what those two crates' own note forbids, and
/// `digest-major-agreement` did not catch it because its crate list is named
/// rather than derived — so the wrong reach was also an unguarded one.
fn blob_hash(text: &str) -> String {
    gix::objs::compute_hash(
        gix::hash::Kind::Sha1,
        gix::object::Kind::Blob,
        text.as_bytes(),
    )
    .map_or_else(|_| String::from(ABSENT), |id| id.to_string())
}

/// Lowercase with runs of non-alphanumerics folded to a single `-`.
///
/// The receipt is space-delimited and half the values this renders carry a space,
/// so writing one through would split one field into two and every positional
/// reader downstream would be reading a fragment.
fn slug(text: &str) -> String {
    let mut out = String::new();
    let mut pending = false;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            if pending && !out.is_empty() {
                out.push('-');
            }
            pending = false;
            out.extend(ch.to_lowercase());
        } else {
            pending = true;
        }
    }
    out
}

/// The record this result mints, or `None` when it mints nothing.
///
/// **Pure given its inputs**, including the clock and the ref resolver, which the
/// boundary supplies for the reason every other predicate in this crate takes
/// them as arguments: a function that read one would stop being testable without
/// a world.
///
/// `None` on an unsatisfied [`Declared::requires`] or an unparseable body — the
/// second cannot happen on a config that loaded, and answering `None` rather than
/// writing a partial record is what keeps that true if it ever does.
#[must_use]
pub fn render(
    declared: &Declared,
    result: &serde_json::Value,
    now: u64,
    resolve_ref: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    if !satisfied(declared, result) {
        return None;
    }
    let Ok(pieces) = parse(&declared.body) else {
        return None;
    };
    let mut out = String::new();
    for piece in pieces {
        match piece {
            Piece::Literal(text) => out.push_str(&text),
            Piece::Now => out.push_str(&now.to_string()),
            // Every projection below records `-` rather than refusing: the
            // required set has already decided whether this result is readable
            // at all, and an absent OPTIONAL is a reading of "could not look".
            Piece::Path(path) => {
                out.push_str(scalar(result, &path).as_deref().unwrap_or(ABSENT));
            }
            Piece::Digest(path) => out.push_str(
                &scalar(result, &path).map_or_else(|| ABSENT.to_owned(), |text| blob_hash(&text)),
            ),
            Piece::Slug(path) => {
                let slugged = scalar(result, &path).map(|text| slug(&text));
                out.push_str(match slugged.as_deref() {
                    Some("") | None => ABSENT,
                    Some(text) => text,
                });
            }
            Piece::Join(path) => {
                let joined = select(result, &path).map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                });
                out.push_str(joined.as_deref().unwrap_or(ABSENT));
            }
            // `-` on a ref that does not resolve, and the reader treats that as
            // unproven — a record whose base could not be established is exactly
            // as unproven as one taken against something that has since moved.
            Piece::Git(reference) => {
                out.push_str(resolve_ref(&reference).as_deref().unwrap_or(ABSENT));
            }
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Some(out)
}

/// Refuse a malformed `[[mint]]` table.
///
/// Each refusal below is a row that would parse, read as configured, and mint
/// nothing — CLOUD-253's inert-coverage shape, which is why a table nothing
/// validates is itself refused. Refused at LOAD rather than skipped at run time,
/// because a skip is invisible: the call succeeds, the receipt simply is not
/// there, and the gate that reads it denies forever with no way to see why.
///
/// # Errors
///
/// Returns a [`crate::error::UsageError`] (-> exit `1`) naming the offending row.
/// Pointer-only: the mint's NAME and the malformed placeholder, never a value.
pub fn validate(mints: &[Declared]) -> anyhow::Result<()> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for mint in mints {
        if mint.name.trim().is_empty() {
            return Err(crate::error::UsageError::raise(
                "a `[[mint]]` row declares an empty `name`, so the receipt it writes could not be \
                 the one any `checks` entry reads",
            ));
        }
        if mint.tool.trim().is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` declares an empty `tool`: an empty selector matches the empty \
                 final segment of any name ending `__`, so the row would mint from calls nobody \
                 named",
                mint.name
            )));
        }
        if mint.key == MintKey::Named && mint.key_from.is_none() {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` is keyed `named` and declares no `key_from`, so nothing says \
                 which projection supplies the subject and no receipt could be filed",
                mint.name
            )));
        }
        if let Err(problem) = parse(&mint.body) {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` has an unreadable `body`: {problem}",
                mint.name
            )));
        }
        // A `named` row whose subject projection the body never has to render is
        // still required to name one the ENGINE can read, so the same parser
        // decides both and a typo cannot reach the filename.
        if let Some(from) = mint.key_from.as_deref()
            && from.trim().is_empty()
        {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` declares an empty `key_from`",
                mint.name
            )));
        }
        if !seen.insert(mint.name.as_str()) {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` is declared twice; two rows writing one receipt name would let \
                 the sorted-later one silently decide the record",
                mint.name
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_optional_records_the_could_not_look_token_never_a_hash_of_nothing() {
        // CLOUD-691's measured forgery, in the one place this module could
        // rebuild it: `-` and a 40-hex digest must not be reachable from the
        // same absent field.
        assert_eq!(
            slug(""),
            "",
            "an empty slug is caught by `render`, not by pretending it is a value"
        );
        assert_ne!(blob_hash(""), ABSENT);
    }

    #[test]
    fn the_blob_hash_is_gits_own() {
        // The one value in this module with an external contract: a gate compares
        // it against `git hash-object --stdin`. The empty blob's hash is the
        // published constant, so this pins the framing bytes without a spawn.
        assert_eq!(blob_hash(""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    }

    #[test]
    fn a_path_that_does_not_resolve_and_one_resolving_to_nothing_are_different_answers() {
        // The distinction a zero-hit search rests on.
        let empty = serde_json::json!({ "issues": [] });
        let absent = serde_json::json!({});
        assert_eq!(select(&empty, "issues[].id").map(|v| v.len()), Some(0));
        assert!(select(&absent, "issues[].id").is_none());
    }

    #[test]
    fn an_unknown_placeholder_is_a_load_error_rather_than_a_literal() {
        assert!(piece_for("shout:id").is_err());
        assert!(parse("{unclosed").is_err());
    }
}
