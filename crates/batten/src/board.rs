//! The board's column vocabulary, resolved from the consumer's config
//! (non-negotiable rule 1).
//!
//! # Why this module exists
//!
//! [`crate::landed`] and [`crate::claim`] decide over a board's COLUMN NAMES,
//! and those are one tracker's words. They were `const`s inside those modules
//! until CLOUD-1623 measured what that costs: on any board spelling its columns
//! differently — Jira's `To Do`/`In Development`, a GitHub Project's whatever
//! the owner typed — every comparison is false. `is_started` never fires, the
//! landed-honesty sweep reports **zero findings over a board full of dishonest
//! columns**, and `claim` never refuses.
//!
//! That failure is invisible from outside, which is the whole reason it
//! survived: a gate that cannot fire and a gate that found nothing emit the same
//! bytes and the same exit code.
//!
//! # The one rule this module enforces: absent is could-not-look
//!
//! [`Columns::resolve`] refuses an undeclared column **by name** rather than
//! substituting a default. A default would put this repository's own words back
//! in the engine with one more step in front of them, and would restore exactly
//! the property that made the original defect unobservable — the dead path and
//! the working path answering identically.
//!
//! So a consumer who has not declared a column gets a refusal that says which
//! one, and the verb decides nothing. That is the same three-valued read
//! [`crate::ready::Grammar`] already gives for the pattern registry, and this
//! module is deliberately its sibling rather than a second mechanism.
//!
//! # Layering: this module reaches nothing
//!
//! It owns both halves — the declared table [`Board`] and the resolved
//! [`Columns`] — and imports no other module in the crate, not even `error`.
//! `config` reads it at load; `landed`, `claim` and `lib` read it at decision
//! time; it reads none of them. That is `crate::secret`'s placement arrived at
//! from the same direction: a vocabulary every layer may consult must depend on
//! nothing, or the honesty of a gate becomes conditional on the layer its words
//! came through.
//!
//! The table lives here rather than in `config` for the reason
//! [`crate::mcp::McpConfig`] and [`crate::recorder::Declared`] do: a module that
//! exists owns its own declaration, so the type and the predicate that reads it
//! cannot drift apart across a module boundary.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The `[board]` table: this consumer's column vocabulary.
///
/// # Why this table exists (non-negotiable rule 1)
///
/// [`crate::landed`] and [`crate::claim`] decide over a board's COLUMN NAMES —
/// which column is the ready queue, which means "pulled", which mean "somebody
/// has this, or it landed, or it shipped". Those are one tracker's words. Linear
/// ships `Todo`/`In Progress`/`In Review`/`Done`; Jira ships `To Do`/`In
/// Development`; a GitHub Project ships whatever the owner typed.
///
/// Carried as engine constants they were rule 1's violation in its worst form.
/// Off this board every comparison is false, so `is_started` never fires, the
/// landed-honesty sweep reports **zero findings over a board full of dishonest
/// columns**, and `claim` never refuses. A gate that cannot fire is
/// indistinguishable from a gate that found nothing, which is the one failure
/// this whole module family exists to avoid.
///
/// # Absent is could-not-look, never a default
///
/// An undeclared table does **not** fall back to this repository's own words.
/// A default would reinstate the violation with an extra step and make the dead
/// path byte-identical to the working one again — the exact shape that let the
/// constants survive. A verb needing a column this table does not declare says
/// so, by name, and decides nothing.
///
/// # Why values and not `[[pattern]]` rows
///
/// [`crate::config::Ready`]'s reason (CLOUD-472), and one more directly: a
/// column is matched by
/// EQUALITY against the string the tracker echoes back, never by a regex over
/// it. The pattern registry exists so one CONCEPT has one spelling; a literal
/// the round trip returns verbatim is a value.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Board {
    /// The column a row must sit in to be pullable — the ready queue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<String>,
    /// The column meaning "pulled": somebody is on this now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_progress: Option<String>,
    /// The column a row whose branch is behind git is asked to move back to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<String>,
    /// Every column meaning "somebody has this, or it has landed, or it has
    /// shipped".
    ///
    /// **The released column belongs in this set, and leaving it out was a
    /// measured defect** (CLOUD-1458). The engine constant this replaces read
    /// `["In Progress", "In Review"]`, so a declined key that reached the
    /// released column escaped the sweep entirely — and released is where the
    /// claim is strongest and the lie therefore costs most. Measured on that
    /// gate's own two rows: CLOUD-186 and CLOUD-1127 were declined with
    /// `DO-NOT-CLOSE` in the body of the pull request that landed the module,
    /// advanced by the merge, moved back by hand, and advanced to the released
    /// column by a release 2026-09-05T02:52:56Z — past the far edge of a
    /// predicate written the day before.
    ///
    /// The ready-queue columns stay OUT: a declined key sitting there is
    /// `DO-NOT-CLOSE` working, and refusing it would make the marker unwritable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub started: Vec<String>,
}

/// The columns a landing or claim decision reads, each already proven present.
///
/// Built only through [`Columns::resolve`], so a value of this type is evidence
/// that the vocabulary it carries was declared rather than assumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Columns {
    /// The ready queue: the column a row must sit in to be pullable.
    pub ready: Option<String>,
    /// The column meaning "pulled": somebody is on this now.
    pub in_progress: Option<String>,
    /// The column a row whose branch is behind git is asked to move back to.
    pub review: Option<String>,
    /// Every column meaning "somebody has this, or it landed, or it shipped".
    pub started: Vec<String>,
}

/// Which column a reader needed and this consumer did not declare.
///
/// Carries the config key rather than a sentence, so a caller renders one
/// remedy in its own voice and the same absence cannot acquire two spellings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undeclared {
    /// The dotted config key that would have answered, e.g. `board.in_progress`.
    pub key: &'static str,
}

impl std::fmt::Display for Undeclared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "`{}` is not declared, so this decides nothing rather than guessing a column name",
            self.key
        )
    }
}

impl Columns {
    /// Read the vocabulary this consumer declared, if any.
    ///
    /// An absent `[board]` table yields a value with every column absent — not
    /// an error here, because which columns a given verb needs is that verb's
    /// question. `landed abandoned` needs the started set and never the ready
    /// queue; `claim check` needs the ready queue and never the started set.
    /// Refusing the whole table up front would make a verb fail over a column it
    /// does not read.
    #[must_use]
    pub fn resolve(board: Option<&Board>) -> Self {
        let Some(board) = board else {
            return Self {
                ready: None,
                in_progress: None,
                review: None,
                started: Vec::new(),
            };
        };
        Self {
            ready: board.ready.clone(),
            in_progress: board.in_progress.clone(),
            review: board.review.clone(),
            started: board.started.clone(),
        }
    }

    /// The ready-queue column, or which key would have named it.
    ///
    /// # Errors
    ///
    /// [`Undeclared`] when `board.ready` is absent.
    pub fn ready(&self) -> Result<&str, Undeclared> {
        self.ready
            .as_deref()
            .ok_or(Undeclared { key: "board.ready" })
    }

    /// The pulled column, or which key would have named it.
    ///
    /// # Errors
    ///
    /// [`Undeclared`] when `board.in_progress` is absent.
    pub fn in_progress(&self) -> Result<&str, Undeclared> {
        self.in_progress.as_deref().ok_or(Undeclared {
            key: "board.in_progress",
        })
    }

    /// The review column, or which key would have named it.
    ///
    /// # Errors
    ///
    /// [`Undeclared`] when `board.review` is absent.
    pub fn review(&self) -> Result<&str, Undeclared> {
        self.review.as_deref().ok_or(Undeclared {
            key: "board.review",
        })
    }

    /// The started set, or which key would have named it.
    ///
    /// An EMPTY set is undeclared rather than "no column means started": a set
    /// that matches nothing makes every row read as not-advanced, which is the
    /// silent all-clear this module exists to refuse.
    ///
    /// # Errors
    ///
    /// [`Undeclared`] when `board.started` is empty.
    pub fn started(&self) -> Result<&[String], Undeclared> {
        if self.started.is_empty() {
            return Err(Undeclared {
                key: "board.started",
            });
        }
        Ok(&self.started)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn declared() -> Board {
        Board {
            ready: Some("Todo".to_owned()),
            in_progress: Some("In Progress".to_owned()),
            review: Some("In Review".to_owned()),
            started: vec![
                "In Progress".to_owned(),
                "In Review".to_owned(),
                "Done".to_owned(),
            ],
        }
    }

    #[test]
    fn an_absent_table_answers_undeclared_for_every_column() {
        let columns = Columns::resolve(None);
        assert_eq!(
            columns.ready().unwrap_err().key,
            "board.ready",
            "an absent table must name the key rather than substituting a default"
        );
        assert_eq!(columns.in_progress().unwrap_err().key, "board.in_progress");
        assert_eq!(columns.review().unwrap_err().key, "board.review");
        assert_eq!(columns.started().unwrap_err().key, "board.started");
    }

    #[test]
    fn a_declared_table_answers_its_own_words() {
        let board = declared();
        let columns = Columns::resolve(Some(&board));
        assert_eq!(columns.ready().unwrap(), "Todo");
        assert_eq!(columns.in_progress().unwrap(), "In Progress");
        assert_eq!(columns.review().unwrap(), "In Review");
        assert_eq!(columns.started().unwrap().len(), 3);
    }

    /// The anti-vacuity direction: a consumer spelling its columns differently
    /// must get ITS words back, not this repository's.
    #[test]
    fn another_boards_vocabulary_survives_resolution() {
        let board = Board {
            ready: Some("To Do".to_owned()),
            in_progress: Some("In Development".to_owned()),
            review: Some("Under Review".to_owned()),
            started: vec!["In Development".to_owned(), "Shipped".to_owned()],
        };
        let columns = Columns::resolve(Some(&board));
        assert_eq!(columns.ready().unwrap(), "To Do");
        assert_eq!(columns.in_progress().unwrap(), "In Development");
        // THE WHOLE SET, not "does it lack ours". An exact comparison says the
        // resolution is a function of the declaration and nothing else, where a
        // negative assertion would pass for a resolver that dropped every column.
        assert_eq!(
            columns.started().unwrap(),
            ["In Development".to_owned(), "Shipped".to_owned()],
            "resolution must not smuggle this repository's vocabulary into another board's set"
        );
    }

    /// An empty set is could-not-look, never "nothing counts as started" — the
    /// distinction the whole module turns on.
    #[test]
    fn an_empty_started_set_is_undeclared_rather_than_empty() {
        let board = Board {
            started: Vec::new(),
            ..declared()
        };
        let columns = Columns::resolve(Some(&board));
        assert_eq!(
            columns.started().unwrap_err().key,
            "board.started",
            "an empty set must refuse; matching nothing would report every row as not-advanced"
        );
    }
}
