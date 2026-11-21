use crate::config_check::receipt::safe_subject;
use crate::config_model::{AfterMode, MintDeclared as Declared, MintKey, MintMode};
use crate::mint::AuthorityExt as _;

/// A compiled authority a template may ask for a value.
///
/// **Closed, and this is the axis that makes CLOUD-1100's renderer repo-agnostic**
/// (`[[recorder]]`'s [`crate::config_model::Ask`] is its twin). A `[program]` row
/// names a path the consumer owns and the engine spawns; an authority names a
/// predicate the CRATE owns and answers in-process. Consumers get the second
/// without the engine learning a tracker's vocabulary: this enum's one variant
/// says *the Definition-of-Ready grammar*, and nothing here says which tool,
/// which field or which board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authority {
    /// [`crate::ready`] — the Ready-block grammar over a tracker payload.
    Ready,
}

/// One element of a body template.
///
/// A **closed** vocabulary: seven forms, each an engine primitive over a
/// consumer-supplied path. Closed rather than open for the reason every other
/// axis in this crate is — an unrecognised placeholder is a load error, never a
/// value that silently renders as itself and writes a receipt nobody can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Piece {
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
    /// `{authority:name}` — the verdict a compiled authority gives the whole
    /// result, as a token.
    ///
    /// **The whole result, never a path into it**, and that is the difference
    /// from every form above. An authority is a predicate over the DOCUMENT: the
    /// Ready grammar reads the body and the relation set together, and a template
    /// naming one field of it would hand the predicate a payload it could not
    /// judge while looking exactly like one it could.
    Authority(Authority),
}

/// Split a body template into its pieces, or name the first thing wrong with it.
///
/// Shared by [`validate`] and [`render`] so a template that loads is a template
/// that renders: a second parser would be a second thing to drift, and the
/// drift's shape would be a rule that passes validation and writes nothing.
pub(crate) fn parse(body: &str) -> Result<Vec<Piece>, String> {
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
pub(crate) fn piece_for(token: &str) -> Result<Piece, String> {
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
        "authority" => Authority::named(argument)
            .map(Piece::Authority)
            .ok_or_else(|| {
                format!("`{{{token}}}` names `{argument}`, which is not a compiled authority")
            }),
        other => Err(format!(
            "`{{{token}}}` names `{other}`, which is not one of `digest`, `slug`, `join`, `git` or \
             `authority`"
        )),
    }
}

/// The subject columns of one row (CLOUD-2294): where a `named` row reads its
/// subject from, and that no other keying declares a column only it reads.
pub(crate) fn validate_subject(mint: &Declared) -> anyhow::Result<()> {
    // A `named` row takes its subject from EXACTLY ONE source: none files
    // nothing, and two would be a precedence nobody declared.
    if mint.key == MintKey::Named && mint.key_from.is_some() == mint.key_from_input.is_some() {
        return Err(crate::error::UsageError::raise(format!(
            "`[[mint]]` `{}` is keyed `named` and must declare exactly one of `key_from` \
             (a result path) and `key_from_input` (an input path)",
            mint.name
        )));
    }
    // THE SYMMETRIC CASE to the `key_base` arm. A `key_from` on a row keyed
    // `delta` or `branch` is read by nothing exactly as a `key_base` on a
    // `named` one is — the same inert declaration, and refusing one while
    // ignoring the other is the half-coverage `validate` exists to refuse. The
    // same holds for `key_from_input` and `key_shape`.
    if mint.key != MintKey::Named
        && let Some(column) = [
            ("key_from", mint.key_from.is_some()),
            ("key_from_input", mint.key_from_input.is_some()),
            ("key_shape", mint.key_shape.is_some()),
        ]
        .into_iter()
        .find_map(|(column, declared)| declared.then_some(column))
    {
        return Err(crate::error::UsageError::raise(format!(
            "`[[mint]]` `{}` declares a `{column}` and is not keyed `named`, so the \
             projection would be read by nothing",
            mint.name
        )));
    }
    // A SHAPE IS JUDGED ONLY WHERE IT IS READ, after the arm above, so a stray
    // one is told to go rather than to be fixed; and only as a `receipt` rule's
    // `key_shape` is, so one pattern loads on both rows.
    if let Some(shape) = mint.key_shape.as_deref()
        && let Err(problem) = regex::Regex::new(shape)
    {
        return Err(crate::error::UsageError::raise(format!(
            "`[[mint]]` `{}`: `key_shape` is not a valid regular expression: {problem}",
            mint.name
        )));
    }
    Ok(())
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
    let mut seen: std::collections::BTreeSet<(&str, bool)> = std::collections::BTreeSet::new();
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
        if mint.key == MintKey::Delta && mint.key_base.is_none() {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` is keyed `delta` and declares no `key_base`, so nothing says \
                 which base the change is measured against and no receipt could be filed",
                mint.name
            )));
        }
        // A `key_base` on a row keyed any other way is refused rather than
        // ignored: an ignored declaration reads as configured and decides
        // nothing, which is the inert-coverage shape this whole function exists
        // to refuse.
        if mint.key != MintKey::Delta && mint.key_base.is_some() {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` declares a `key_base` and is not keyed `delta`, so the base \
                 would be read by nothing",
                mint.name
            )));
        }
        validate_subject(mint)?;
        // HALF A SELECTOR IS THE DANGEROUS HALF. `selects_at` alone would leave
        // the row minting on every result its tool matched while LOOKING
        // narrowed, which is the reading a reviewer takes from the column's
        // presence; `selects` alone names a value nothing is compared to.
        if mint.selects_at.is_some() != mint.selects.is_some() {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` declares only one of `selects_at` and `selects`; a selector \
                 with no value narrows nothing while reading as though it did",
                mint.name
            )));
        }
        // BOTH HALVES, because only one was checked and the unchecked half is the
        // one that fails silently: `selects = ""` loads clean, matches no value any
        // host sends, and the row mints nothing — so its gate denies forever with a
        // remedy that cannot clear it. A blank `selects_at` at least fails to
        // resolve loudly.
        for (column, value) in [
            ("selects_at", mint.selects_at.as_deref()),
            ("selects", mint.selects.as_deref()),
        ] {
            // TRIMMED-EMPTY *AND* SURROUNDED BY WHITESPACE, because only the first
            // was checked and the second fails in the same silent direction:
            // `selects = "code-review "` loads clean, compares against a value no
            // host sends, and the row mints nothing — so its gate denies forever
            // with a remedy that cannot clear it. Refusing rather than trimming,
            // because trimming would decide on the author's behalf which of two
            // readings they meant.
            if let Some(text) = value
                && (text.trim().is_empty() || text.trim() != text)
            {
                return Err(crate::error::UsageError::raise(format!(
                    "`[[mint]]` `{}` declares a `{column}` that is empty or padded, which can \
                     never match",
                    mint.name
                )));
            }
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
        for (column, from) in [
            ("key_from", mint.key_from.as_deref()),
            ("key_from_input", mint.key_from_input.as_deref()),
        ] {
            if from.is_some_and(|path| path.trim().is_empty()) {
                return Err(crate::error::UsageError::raise(format!(
                    "`[[mint]]` `{}` declares an empty `{column}`",
                    mint.name
                )));
            }
        }
        // ONE WRITER AND AT MOST ONE CLEAR PER NAME (CLOUD-2083). A `clear` row
        // shares its writer's name because it is the same record's other end, so
        // the uniqueness is per mode class: two writers would still let the
        // sorted-later one silently decide the record.
        if !seen.insert((mint.name.as_str(), mint.mode == MintMode::Clear)) {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` is declared twice; two rows writing one receipt name would let \
                 the sorted-later one silently decide the record",
                mint.name
            )));
        }
    }
    validate_across(mints)
}

/// The refusals that read more than one row: a `clear` with no writer, and an
/// `after` naming no writer keyed the same way.
///
/// Each is a row that loads clean and does nothing, the inert-coverage shape
/// [`validate`] exists to refuse.
pub(crate) fn validate_across(mints: &[Declared]) -> anyhow::Result<()> {
    // A CLEAR WITH NO WRITER removes a record nothing makes.
    if let Some(orphan) = mints.iter().find(|clear| {
        clear.mode == MintMode::Clear
            && !mints
                .iter()
                .any(|writer| writer.mode != MintMode::Clear && writer.name == clear.name)
    }) {
        return Err(crate::error::UsageError::raise(format!(
            "`[[mint]]` `{}` is `mode = \"clear\"` and no row of that name writes the record, \
             so it would clear nothing",
            orphan.name
        )));
    }
    // AN `after_mode` WITHOUT AN `after` modes nothing (CLOUD-2680), and on a
    // `clear` row it would read as a gate the row does not have.
    for mint in mints {
        if mint.after_mode.is_some() && mint.after.is_none() {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` declares `after_mode` and no `after`; the mode says how a \
                 prerequisite is met, and this row names none",
                mint.name
            )));
        }
    }
    // AN `after` NAMING NO WRITER KEYED ALIKE can never be satisfied, so its gate
    // denies forever with a remedy that cannot clear it (CLOUD-2261). "Alike" is
    // the same `key` and `key_base`: the prerequisite is looked up under THIS
    // row's subject, and a writer filing under another identity never wrote one
    // there.
    for mint in mints {
        let Some(after) = mint.after.as_deref() else {
            continue;
        };
        // The name becomes a path component under the receipt store, which the
        // completion then removes: held to the rule every subject is held to.
        if !safe_subject(after) {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` declares an `after` that is not a single safe path component",
                mint.name
            )));
        }
        // A CLEAR gated on a prerequisite would end its record only while
        // another record happened to exist: a shape `after` does not define.
        if mint.mode == MintMode::Clear {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` is `mode = \"clear\"` and declares `after`; a prerequisite \
                 gates a record being written, never one being ended",
                mint.name
            )));
        }
        // ONE ROW PER PREREQUISITE PER CALL: a completion spends the record it
        // was admitted by, so a second row selecting the SAME call and naming the
        // same prerequisite would find it gone and never mint, decided by row
        // order alone. Rows on different tools are alternative completions, of
        // which the first to arrive spending the dispatch is the design.
        if mints
            .iter()
            .filter(|other| {
                other.after.as_deref() == Some(after)
                    && other.tool == mint.tool
                    && other.key == mint.key
                    && other.key_base == mint.key_base
                    // The same path holding different values can never select
                    // the same call, so those rows cannot race for the record.
                    && !(other.selects_at == mint.selects_at
                        && other.selects.is_some()
                        && mint.selects.is_some()
                        && other.selects != mint.selects)
                    // Two `require` rows read the record and leave it, so
                    // neither can starve the other (CLOUD-2680). A spend row
                    // beside a require row is refused below, for its mode.
                    && mint.spends()
            })
            .count()
            > 1
        {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` names `after = \"{after}\"` on the same tool and key as another \
                 row; the first to mint spends the record, so the other could never mint",
                mint.name
            )));
        }
        // ONE PREREQUISITE HAS ONE MODE (CLOUD-2680): a `spend` row would
        // consume the record a `require` row reads, decided by declaration
        // order, whatever tool each names.
        if mints.iter().any(|other| {
            other.after.as_deref() == Some(after)
                && other.key == mint.key
                && other.key_base == mint.key_base
                && other.effective_after_mode() != mint.effective_after_mode()
        }) {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` and another row name `after = \"{after}\"` with different \
                 `after_mode`s; a `spend` row consumes the record a `require` row reads",
                mint.name
            )));
        }
        if !mints.iter().any(|writer| {
            writer.mode != MintMode::Clear
                && writer.name == after
                && writer.name != mint.name
                && writer.key == mint.key
                && writer.key_base == mint.key_base
        }) {
            return Err(crate::error::UsageError::raise(format!(
                "`[[mint]]` `{}` declares `after = \"{after}\"` and no other row of that name \
                 writes a record under the same `key` and `key_base`, so it could never mint",
                mint.name
            )));
        }
    }
    Ok(())
}

impl Declared {
    /// Whether the row consumes its prerequisite.
    pub(crate) fn spends(&self) -> bool {
        self.effective_after_mode() == AfterMode::Spend
    }
}

impl Declared {
    /// The row's `after_mode`, `spend` where it declares none.
    #[must_use]
    pub fn effective_after_mode(&self) -> AfterMode {
        self.after_mode.unwrap_or_default()
    }
}
