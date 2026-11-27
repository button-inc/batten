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
//! [`crate::config_model::Rule::validate_sink`] refuses `produces` on any non-`Tree`
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

use crate::config_check::mint::Authority;
use crate::config_check::mint::Piece;
use crate::config_check::mint::parse;
#[cfg(test)]
use crate::config_check::mint::piece_for;
#[cfg(test)]
use crate::config_check::mint::validate;
use crate::config_model::MintDeclared as Declared;
#[cfg(test)]
use crate::config_model::MintKey;
#[cfg(test)]
use crate::config_model::MintMode;

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

// Housed in `crate::facts` (CLOUD-2789), which walks the same paths; the path
// here is unchanged.
use crate::facts::select;

/// The single scalar a path selects, rendered as a bare string.
///
/// `None` for anything that is not exactly one non-null scalar, so a caller can
/// never accidentally write a JSON fragment into a receipt a shell reads
/// positionally.
///
/// `pub(crate)` for [`crate::capture::find`] (CLOUD-1121), which resolves a
/// stored response by the same dotted path this module keys a receipt on. One
/// selector rather than two: a resolver that addressed `id` differently from the
/// mint that filed the receipt would look up a payload under a key nothing wrote.
pub(crate) fn scalar(value: &serde_json::Value, path: &str) -> Option<String> {
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

/// Whether this result is the one the row selects (CLOUD-1484).
///
/// **A SELECTION, kept separate from [`satisfied`]'s SUCCESS test**, and the two
/// must not be folded together even though both gate the same write. `requires`
/// asks *did the call this row is about actually answer*; this asks *is this even
/// the call this row is about*. Collapsing them would make a row that selects
/// nothing indistinguishable from one whose call failed, and only the second of
/// those is a reason to try again.
///
/// A row declaring no selector selects every call its `tool` matched, which is
/// every landed row's behaviour.
///
/// **THE SUBJECT IS THE TOOL'S INPUT, NEVER ITS RESULT**, and the parameter is
/// named for it: a dispatch names ITSELF in its arguments, while its result is
/// whatever came back and on most hosts is prose. An author who reads this as the
/// result writes a path that resolves to nothing on every call, and the row then
/// mints nothing while loading clean — the dead gate this crate keeps recording.
///
/// **A path that does not resolve to a single scalar does NOT select.** The
/// failure direction is deliberate: an unreadable field means the boundary cannot
/// tell whether this is the declared call, and minting on a maybe is exactly the
/// forgery this column was added to remove. A gate over the receipt then denies
/// again with the same remedy, which is the safe direction and one the agent can
/// see.
#[must_use]
pub fn selects(declared: &Declared, input: &serde_json::Value) -> bool {
    let (Some(path), Some(expected)) =
        (declared.selects_at.as_deref(), declared.selects.as_deref())
    else {
        return true;
    };
    scalar(input, path).is_some_and(|found| found == expected)
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
/// **Refused, never rewritten**, which is [`crate::config_check::receipt::safe_subject`]'s rule
/// and its reason: rewriting a bad subject would file two different subjects
/// under one receipt and let a fresh read of A authorise a stale write to B.
///
/// From the INPUT when the row declares [`Declared::key_from_input`], and only
/// when it matches [`Declared::key_shape`], if declared (CLOUD-2294).
#[must_use]
pub fn subject(
    declared: &Declared,
    input: &serde_json::Value,
    result: &serde_json::Value,
) -> Option<String> {
    let subject = match declared.key_from_input.as_deref() {
        Some(from) => scalar(input, from)?,
        None => scalar(result, declared.key_from.as_deref()?)?,
    };
    // THE RULE COLUMN'S READING, unanchored: the author writes `^…$`, so one
    // pattern means the same thing on a mint row and on the rule that reads it.
    if let Some(shape) = declared.key_shape.as_deref()
        && !regex::Regex::new(shape).ok()?.is_match(&subject)
    {
        return None;
    }
    crate::config_check::receipt::safe_subject(&subject).then_some(subject)
}

/// The git blob id of `text`, byte-identical to `git hash-object --stdin`.
///
/// That equality is the contract rather than an implementation note: the digest
/// is read back by a gate that recomputes it with `git hash-object`, so any other
/// value would be a field that exists and never matches.
///
/// **Asked of [`crate::git`] rather than computed here**, and the difference is
/// not stylistic. What this wants is *git's object id*, not *a SHA-1* — the
/// framing bytes, the object kind and the hash are all git's format, so the
/// module that owns this crate's git implementation owns the answer, and
/// `gix_is_confined_to_this_module` is the gate that says so. The first version
/// reached for `sha1` here, which spelled git's format out by hand AND took a
/// second direct dependency resolving `digest 0.10`, splitting the major `hmac`
/// and `sha2` share at `0.11` — the thing those two crates' own note forbids,
/// missed by `digest-major-agreement` because its crate list is named rather
/// than derived.
fn blob_hash(text: &str) -> String {
    crate::git::blob_id(text).unwrap_or_else(|| String::from(ABSENT))
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
    grammar: Option<&crate::ready::Grammar>,
    root: &std::path::Path,
) -> Option<String> {
    if !satisfied(declared, result) {
        return None;
    }
    let Ok(pieces) = parse(&declared.body) else {
        return None;
    };
    // A RESULT THAT SAID NOTHING CANNOT RENDER A BODY THAT READS IT (CLOUD-1484).
    //
    // `record_mints` now passes `Value::Null` where it used to return early, so a
    // row reading none of the result can mint from a call whose answer carried no
    // JSON. That widening must not reach a row that DOES read it: with
    // `requires = []` its success test is vacuously true, every path piece records
    // the could-not-look token, and under `MintMode::Replace` the all-`-` record
    // overwrites a good receipt. No landed row is shaped that way, which is
    // precisely why nothing would have caught it.
    if result.is_null() && pieces.iter().any(Piece::reads_the_result) {
        return None;
    }
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
            // `-` on could-not-look, which is the direction that makes a thin
            // payload read LOUDER downstream rather than quieter: the gate that
            // consumes this field treats the absent token as "no verdict" and
            // ALLOWS, so a receipt whose authority could not judge never becomes
            // a refusal about the environment wearing a verdict's shape.
            Piece::Authority(authority) => out.push_str(match authority {
                Authority::Ready => grammar
                    .and_then(|grammar| crate::ready::verdict_token(grammar, result, root))
                    .unwrap_or(ABSENT),
            }),
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[cfg(test)]
    /// A row declaring a selector mints only for the value it names.
    ///
    /// Fails by: comparing with `starts_with`, or returning `true` on an
    /// unresolvable path. Either makes the row mint on every dispatch its tool
    /// matched, which is the false green `batten.toml` says the column exists to
    /// remove — the receipt would attest that *something* ran.
    #[test]
    fn a_selector_admits_only_the_value_it_names() {
        let row: Declared = serde_json::from_value(serde_json::json!({
            "name": "code-review", "tool": "Skill",
            "selects_at": "skill", "selects": "code-review",
            "key": "delta", "key_base": "origin/main",
            "mode": "replace", "body": "{now}",
        }))
        .expect("the committed row's shape loads");

        assert!(selects(&row, &serde_json::json!({"skill": "code-review"})));
        assert!(
            !selects(&row, &serde_json::json!({"skill": "batten"})),
            "another skill must not mint this row's receipt"
        );
        assert!(
            !selects(&row, &serde_json::json!({"skill": "code-review-extra"})),
            "EQUALITY, never a prefix: a longer name nobody declared must not match"
        );
        assert!(
            !selects(&row, &serde_json::json!({})),
            "an unresolvable path does not select — minting on a maybe is the forgery this removes"
        );
        assert!(
            !selects(&row, &serde_json::Value::Null),
            "the dispatch path passes a null input, which must select nothing"
        );
    }

    /// A `key_from` on a row keyed otherwise is refused, symmetrically with
    /// `key_base`.
    ///
    /// Fails by: dropping the second arm. The first was landed alone, and the
    /// asymmetry is the inert-declaration shape `validate` exists to refuse — a
    /// column read by nothing, loading clean.
    #[test]
    fn a_projection_no_key_reads_is_refused_whichever_column_it_is() {
        let named: Declared = serde_json::from_value(serde_json::json!({
            "name": "r", "tool": "T", "key": "named", "key_from": "id",
            "mode": "replace", "body": "{id}",
        }))
        .expect("shape loads");
        assert!(
            validate(&[named]).is_ok(),
            "`key_from` on a `named` row is what it is for"
        );

        let delta: Declared = serde_json::from_value(serde_json::json!({
            "name": "r", "tool": "T", "key": "delta", "key_base": "origin/main",
            "key_from": "id", "mode": "replace", "body": "{now}",
        }))
        .expect("shape loads");
        assert!(
            validate(&[delta]).is_err(),
            "a `key_from` a `delta` row never reads is the same inert declaration \
             the `key_base` arm already refuses"
        );
    }

    /// A row from JSON, for the `after_mode` cases (CLOUD-2680).
    fn row(value: serde_json::Value) -> Declared {
        serde_json::from_value(value).expect("shape loads")
    }

    /// A writer of `gates` keyed on the delta, and a dependent named `name`
    /// selecting `selects`, in `mode` (`None` for the default).
    fn bridged(name: &str, tool: &str, selects: &str, mode: Option<&str>) -> Declared {
        let mut value = serde_json::json!({
            "name": name, "tool": tool, "key": "delta", "key_base": "origin/main",
            "selects_at": "skill", "selects": selects, "after": "gates",
            "mode": "replace", "body": "{now}",
        });
        if let Some(mode) = mode {
            value["after_mode"] = serde_json::json!(mode);
        }
        row(value)
    }

    fn gates() -> Declared {
        row(serde_json::json!({
            "name": "gates", "tool": "Bash", "key": "delta", "key_base": "origin/main",
            "mode": "replace", "body": "{now}",
        }))
    }

    /// Two `require` rows on one tool may share a prerequisite; two `spend` rows
    /// selecting the same call still refuse, since the first spends it.
    #[test]
    fn require_rows_share_a_prerequisite_and_spend_rows_still_refuse() {
        let shared = [
            gates(),
            bridged("a", "Skill", "x", Some("require")),
            bridged("b", "Skill", "x", Some("require")),
        ];
        assert!(validate(&shared).is_ok(), "{:?}", validate(&shared));
        let spent = [
            gates(),
            bridged("a", "Skill", "x", None),
            bridged("b", "Skill", "x", None),
        ];
        assert!(validate(&spent).is_err());
    }

    /// Two `spend` rows on one tool with selectors at DIFFERENT paths can both
    /// select one call, so they still race for the record; at the same path
    /// with different values they never can. Fails by: rows read as disjoint
    /// because their values differ, whatever path each reads.
    #[test]
    fn spend_rows_selecting_at_different_paths_still_race() {
        let mut elsewhere = bridged("b", "Skill", "y", None);
        elsewhere.selects_at = Some("args".to_owned());
        let racing = [gates(), bridged("a", "Skill", "x", None), elsewhere];
        assert!(validate(&racing).is_err());
        let disjoint = [
            gates(),
            bridged("a", "Skill", "x", None),
            bridged("b", "Skill", "y", None),
        ];
        assert!(validate(&disjoint).is_ok(), "{:?}", validate(&disjoint));
    }

    /// One prerequisite has one mode, on one tool or across two.
    #[test]
    fn mixed_after_modes_on_one_prerequisite_refuse() {
        let same_tool = [
            gates(),
            bridged("a", "Skill", "x", Some("require")),
            bridged("b", "Skill", "y", None),
        ];
        assert!(validate(&same_tool).is_err());
        let across = [
            gates(),
            bridged("a", "Skill", "x", Some("require")),
            bridged("b", "ReportFindings", "y", Some("spend")),
        ];
        assert!(validate(&across).is_err());
    }

    /// An `after_mode` with no `after` modes nothing, in any mode and on a
    /// `clear` row.
    #[test]
    fn an_after_mode_without_an_after_refuses() {
        for mode in ["spend", "require"] {
            let orphan = row(serde_json::json!({
                "name": "r", "tool": "T", "key": "named", "key_from": "id",
                "after_mode": mode, "mode": "replace", "body": "{id}",
            }));
            assert!(validate(&[orphan]).is_err(), "{mode}");
        }
        let clear = row(serde_json::json!({
            "name": "gates", "tool": "T", "key": "delta", "key_base": "origin/main",
            "after_mode": "require", "mode": "clear", "body": "",
        }));
        assert!(validate(&[gates(), clear]).is_err());
    }

    /// A row declaring NO selector is judged exactly as it was before the column
    /// existed, which is every landed row.
    #[test]
    fn a_row_with_no_selector_selects_everything_its_tool_matched() {
        let row: Declared = serde_json::from_value(serde_json::json!({
            "name": "issue-read", "tool": "get_issue", "key": "named",
            "key_from": "id", "mode": "replace", "body": "{id}",
        }))
        .expect("a landed row's shape loads");
        assert!(selects(&row, &serde_json::json!({"anything": 1})));
        assert!(selects(&row, &serde_json::Value::Null));
    }

    /// A `clear` row shares its writer's name and loads; a second writer, a second
    /// clear, and a clear with no writer are each refused (CLOUD-2083).
    #[test]
    fn a_clear_row_loads_only_beside_the_one_writer_it_ends() {
        let row = |mode: &str| -> Declared {
            serde_json::from_value(serde_json::json!({
                "name": "pr-open", "tool": "T", "key": "branch",
                "mode": mode, "body": "{now}",
            }))
            .expect("shape loads")
        };
        assert!(validate(&[row("replace"), row("clear")]).is_ok());
        assert!(
            validate(&[row("replace"), row("replace")]).is_err(),
            "two writers"
        );
        assert!(
            validate(&[row("replace"), row("clear"), row("clear")]).is_err(),
            "two clears"
        );
        assert!(validate(&[row("clear")]).is_err(), "a clear with no writer");
    }

    /// An `after` loads only beside a writer of that name keyed the same way
    /// (CLOUD-2261).
    ///
    /// Fails by: dropping the key comparison. A prerequisite filed under another
    /// identity is never on file under this row's, so the row would load clean
    /// and mint nothing — its gate denying forever with an uncleanable remedy.
    #[test]
    fn an_after_loads_only_beside_a_writer_keyed_alike() {
        let row = |name: &str, key: &str, after: Option<&str>| -> Declared {
            let mut value = serde_json::json!({
                "name": name, "tool": "T", "key": key, "mode": "replace", "body": "{now}",
            });
            if key == "delta" {
                value["key_base"] = serde_json::json!("origin/main");
            }
            if let Some(after) = after {
                value["after"] = serde_json::json!(after);
            }
            serde_json::from_value(value).expect("shape loads")
        };
        let asked = row("asked", "delta", None);
        assert!(validate(&[asked.clone(), row("done", "delta", Some("asked"))]).is_ok());
        assert!(
            validate(&[row("done", "delta", Some("asked"))]).is_err(),
            "no writer of that name"
        );
        assert!(
            validate(&[
                row("asked", "branch", None),
                row("done", "delta", Some("asked"))
            ])
            .is_err(),
            "a writer keyed otherwise files under another identity"
        );
        assert!(
            validate(&[row("done", "delta", Some("done"))]).is_err(),
            "a row cannot be its own prerequisite"
        );
        // A distinct name, so only the clear refusal can fire: `done` has its
        // writer and `asked` is keyed alike.
        let mut clear = row("done", "delta", Some("asked"));
        clear.mode = MintMode::Clear;
        assert!(
            validate(&[asked.clone(), row("done", "delta", None), clear]).is_err(),
            "a clear gated on a prerequisite"
        );
        assert!(
            validate(&[
                asked.clone(),
                row("done", "delta", Some("asked")),
                row("also", "delta", Some("asked")),
            ])
            .is_err(),
            "two rows spending one prerequisite: the first would starve the second"
        );
        let mut elsewhere = row("also", "delta", Some("asked"));
        elsewhere.tool = "Other".to_owned();
        assert!(
            validate(&[
                asked.clone(),
                row("done", "delta", Some("asked")),
                elsewhere
            ])
            .is_ok(),
            "alternative completions on different tools may share a prerequisite"
        );
        let selecting = |name: &str, value: &str| {
            let mut selected = row(name, "delta", Some("asked"));
            selected.selects_at = Some("kind".to_owned());
            selected.selects = Some(value.to_owned());
            selected
        };
        assert!(
            validate(&[
                asked.clone(),
                selecting("done", "a"),
                selecting("also", "b")
            ])
            .is_ok(),
            "rows whose selectors exclude each other cannot race"
        );
        assert!(
            validate(&[
                asked.clone(),
                selecting("done", "a"),
                selecting("also", "a")
            ])
            .is_err(),
            "rows selecting the same value would race"
        );
    }

    /// Each new load-time refusal fires, and a well-formed row still loads.
    ///
    /// Fails by: dropping any one arm. Half a selector is the dangerous half —
    /// `selects_at` alone narrows nothing while reading as though it did.
    #[test]
    fn the_new_load_refusals_each_fire() {
        let row = |extra: serde_json::Value| -> Declared {
            let mut base = serde_json::json!({
                "name": "r", "tool": "T", "key": "delta",
                "key_base": "origin/main", "mode": "replace", "body": "{now}",
            });
            let (Some(o), Some(e)) = (base.as_object_mut(), extra.as_object()) else {
                unreachable!("both are objects")
            };
            for (k, v) in e {
                if v.is_null() {
                    o.remove(k);
                } else {
                    o.insert(k.clone(), v.clone());
                }
            }
            serde_json::from_value(base).expect("shape loads")
        };

        assert!(
            validate(&[row(serde_json::json!({}))]).is_ok(),
            "the well-formed row loads"
        );
        assert!(
            validate(&[row(serde_json::json!({"key_base": null}))]).is_err(),
            "`delta` with no `key_base` names no base to measure against"
        );
        assert!(
            validate(&[row(
                serde_json::json!({"key": "branch", "key_base": "origin/main"})
            )])
            .is_err(),
            "a `key_base` on a row keyed otherwise would be read by nothing"
        );
        assert!(
            validate(&[row(serde_json::json!({"selects_at": "skill"}))]).is_err(),
            "half a selector narrows nothing while reading as though it did"
        );
        assert!(
            validate(&[row(serde_json::json!({"selects": "x"}))]).is_err(),
            "a value compared to nothing"
        );
        assert!(
            validate(&[row(serde_json::json!({"selects_at": "  ", "selects": "x"}))]).is_err(),
            "an empty `selects_at`"
        );
        // PADDING FAILS THE SAME WAY AS EMPTY, and only the empty half was
        // checked: a padded value compares against nothing any host sends, so
        // the row mints nothing and its gate denies forever.
        assert!(
            validate(&[row(
                serde_json::json!({"selects_at": " skill", "selects": "x"})
            )])
            .is_err(),
            "a padded `selects_at` resolves nothing"
        );
        assert!(
            validate(&[row(
                serde_json::json!({"selects_at": "skill", "selects": "x "})
            )])
            .is_err(),
            "a padded `selects` matches nothing"
        );
    }

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

    /// The path forms and the authority read the result; a literal, the clock
    /// and a git ref do not.
    #[test]
    fn only_the_result_reading_pieces_read_the_result() {
        for piece in [
            Piece::Path("id".to_owned()),
            Piece::Digest("id".to_owned()),
            Piece::Slug("id".to_owned()),
            Piece::Join("id".to_owned()),
            Piece::Authority(Authority::Ready),
        ] {
            assert!(piece.reads_the_result(), "{piece:?}");
        }
        for piece in [
            Piece::Literal("x".to_owned()),
            Piece::Now,
            Piece::Git("HEAD".to_owned()),
        ] {
            assert!(!piece.reads_the_result(), "{piece:?}");
        }
    }

    /// Literal text either side of a placeholder is its own piece, in order, and
    /// no empty literal is ever pushed.
    #[test]
    fn a_template_splits_into_its_literals_and_placeholders_in_order() {
        assert_eq!(
            parse("a{now}b"),
            Ok(vec![
                Piece::Literal("a".to_owned()),
                Piece::Now,
                Piece::Literal("b".to_owned()),
            ])
        );
        assert_eq!(parse("{now}{now}"), Ok(vec![Piece::Now, Piece::Now]));
    }

    /// A slug folds each run of separators to one `-`, and never leads with one.
    #[test]
    fn a_slug_folds_separator_runs_and_never_leads_with_one() {
        assert_eq!(slug("  Hello,  World!"), "hello-world");
    }

    /// A result missing any required path is not a success.
    #[test]
    fn a_result_missing_a_required_path_is_unsatisfied() {
        let declared: Declared = serde_json::from_value(serde_json::json!({
            "name": "r", "tool": "T", "key": "named", "key_from": "id",
            "requires": ["id", "state"], "mode": "replace", "body": "{id}",
        }))
        .expect("shape loads");
        assert!(satisfied(
            &declared,
            &serde_json::json!({"id": "A-1", "state": "x"})
        ));
        assert!(!satisfied(&declared, &serde_json::json!({"id": "A-1"})));
    }

    /// The subject is the declared scalar, from the result or the input, and
    /// only where it fits the declared shape.
    #[test]
    fn the_subject_is_the_declared_scalar_held_to_its_shape() {
        let row = |columns: serde_json::Value| -> Declared {
            let mut value = serde_json::json!({
                "name": "r", "tool": "T", "key": "named", "mode": "replace", "body": "{now}",
            });
            for (column, declared) in columns.as_object().expect("columns are an object") {
                value[column] = declared.clone();
            }
            serde_json::from_value(value).expect("shape loads")
        };
        let input = serde_json::json!({"args": "B-2"});
        let result = serde_json::json!({"id": "A-1"});
        assert_eq!(
            subject(&row(serde_json::json!({"key_from": "id"})), &input, &result).as_deref(),
            Some("A-1")
        );
        let from_input =
            row(serde_json::json!({"key_from_input": "args", "key_shape": "^[A-Z]-[0-9]$"}));
        assert_eq!(
            subject(&from_input, &input, &result).as_deref(),
            Some("B-2")
        );
        assert_eq!(
            subject(
                &from_input,
                &serde_json::json!({"args": "not-a-key"}),
                &result
            ),
            None
        );
    }

    #[test]
    fn an_unknown_placeholder_is_a_load_error_rather_than_a_literal() {
        assert!(piece_for("shout:id").is_err());
        assert!(parse("{unclosed").is_err());
    }

    #[test]
    fn an_authority_is_selected_by_name_and_an_unknown_one_is_a_load_error() {
        // The closed-vocabulary rule reaching one level deeper than the verb.
        // `{authority:relevance}` is a well-formed placeholder naming a predicate
        // nothing answers to, and rendering it as itself would write a receipt
        // whose sixth field reads as a verdict and is a template fragment.
        assert_eq!(
            piece_for("authority:ready"),
            Ok(Piece::Authority(Authority::Ready))
        );
        assert!(piece_for("authority:relevance").is_err());
        assert!(piece_for("authority:").is_err());
    }

    #[test]
    fn an_unjudgeable_payload_renders_the_absent_token_rather_than_a_verdict() {
        // The fail-open direction, at the renderer rather than at the gate that
        // reads it. A result with no body is not an unready row — it is a payload
        // the authority could not read — and the two must not reach the receipt
        // as the same token, because the gate downstream denies on one and allows
        // on the other.
        let declared = Declared {
            name: "issue-read".to_owned(),
            tool: "get_issue".to_owned(),
            key: MintKey::Named,
            key_from: Some("id".to_owned()),
            key_from_input: None,
            key_shape: None,
            key_base: None,
            selects_at: None,
            selects: None,
            requires: vec!["id".to_owned()],
            after: None,
            after_mode: None,
            mode: MintMode::Replace,
            body: "{id} {authority:ready}".to_owned(),
        };
        let root = &crate::fixture_root::fixture_root(
            "an_unjudgeable_payload_renders_the_absent_token_rather_than_a_verdict",
        );
        // The committed grammar, so this case asserts as a side effect that
        // `batten.toml` still declares the whole vocabulary the authority reads.
        let grammar = crate::ready::Grammar::committed();
        let bodyless = serde_json::json!({ "id": "CLOUD-1" });
        assert_eq!(
            render(&declared, &bodyless, 0, &|_| None, Some(&grammar), root).as_deref(),
            Some("CLOUD-1 -\n"),
            "a payload the authority cannot parse records could-not-look"
        );

        let unready = serde_json::json!({
            "id": "CLOUD-1",
            "description": "**Refinement — Ready**\n\nnothing checkable here",
        });
        assert_eq!(
            render(&declared, &unready, 0, &|_| None, Some(&grammar), root).as_deref(),
            Some("CLOUD-1 unready\n"),
            "and a body it CAN read records the verdict it reached"
        );
    }

    /// A `named` row takes its subject from exactly one non-empty source and
    /// holds it to a shape that compiles; a row keyed otherwise declares neither
    /// column (CLOUD-2294).
    ///
    /// Fails by: dropping any one arm. Two sources is a precedence nobody
    /// declared, an uncompilable shape mints nothing forever, and either column
    /// on a `delta` or `branch` row is read by nothing.
    #[test]
    fn a_named_row_takes_one_subject_source_and_a_shape_that_compiles() {
        let row = |columns: serde_json::Value| -> Declared {
            let mut value = serde_json::json!({
                "name": "groom", "tool": "Skill", "mode": "replace", "body": "{now}",
            });
            for (column, declared) in columns.as_object().expect("columns are an object") {
                value[column] = declared.clone();
            }
            serde_json::from_value(value).expect("shape loads")
        };
        let refused = |columns: serde_json::Value| {
            validate(&[row(columns)]).map_or_else(|error| error.to_string(), |()| "<loaded>".into())
        };

        // A shape loads exactly when it compiles, as a receipt rule's does: a
        // tight one that also matches the empty subject is no exception.
        for shape in ["^[A-Z]+-[0-9]+$", "^([A-Z]+-[0-9]+)?$"] {
            assert!(
                validate(&[row(serde_json::json!({
                    "key": "named", "key_from_input": "args", "key_shape": shape,
                }))])
                .is_ok(),
                "{shape} compiles, so it loads"
            );
        }
        for (columns, refusal) in [
            (serde_json::json!({"key": "named"}), "exactly one of"),
            (
                serde_json::json!({"key": "named", "key_from": "id", "key_from_input": "args"}),
                "exactly one of",
            ),
            (
                serde_json::json!({"key": "named", "key_from": " "}),
                "an empty `key_from`",
            ),
            (
                serde_json::json!({"key": "named", "key_from_input": " "}),
                "an empty `key_from_input`",
            ),
            (
                serde_json::json!({"key": "delta", "key_base": "origin/main", "key_shape": "("}),
                "declares a `key_shape` and is not keyed `named`",
            ),
            (
                serde_json::json!({"key": "named", "key_from_input": "args", "key_shape": "("}),
                "`key_shape` is not a valid regular expression",
            ),
            (
                serde_json::json!({"key": "delta", "key_base": "origin/main", "key_shape": "^x$"}),
                "declares a `key_shape` and is not keyed `named`",
            ),
            (
                serde_json::json!({"key": "branch", "key_shape": "^x$"}),
                "declares a `key_shape` and is not keyed `named`",
            ),
            (
                serde_json::json!({"key": "branch", "key_from_input": "args"}),
                "declares a `key_from_input` and is not keyed `named`",
            ),
        ] {
            let said = refused(columns.clone());
            assert!(said.contains(refusal), "{columns} was refused as {said:?}");
        }
    }
}
