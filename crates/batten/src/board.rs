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

use crate::config::Board;

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
