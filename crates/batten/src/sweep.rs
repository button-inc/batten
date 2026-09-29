//! `batten board sweep`: every board gate a consumer declares, run over ONE
//! payload set and reported as a SET (CLOUD-825), retiring `[tasks.board-sweep]`
//! (CLOUD-843).
//!
//! # A composer, and it re-derives no gate's predicate
//!
//! Each gate is invoked with the payload set on stdin and its exit code read as
//! the verdict its row declares. The report is a set, never a first failure,
//! because one payload set feeding N gates is what makes a sweep affordable —
//! and a sweep that stopped at the first refusal would hide every refusal after
//! it behind a fix for the first.
//!
//! # Four lanes, folded onto the engine's four codes
//!
//! **COULD-NOT-LOOK OUTRANKS A REFUSAL, AND A REFUSAL OUTRANKS AN ABSTENTION**
//! (CLOUD-921). A gate that could not answer means the board has not been judged,
//! and reporting the refusals that were reached as though they were the whole
//! answer is the vacuous green [`ExitCode::combine`] exists to refuse. An
//! abstention is a property of THIS CLONE — a gate declaring it cannot answer
//! here — so it must never buy a weaker verdict than a refusal beside it.
//!
//! The retired task spelled the lanes on the corpus's table, `2` for
//! could-not-look and `3` for an abstention. The engine has four codes and no
//! fifth, so both unanswered lanes are [`ExitCode::Internal`] and the REPORT
//! tells them apart: the summary line names which lane held, and every gate's own
//! line carries its lane token.
//!
//! # Rule 1 and rule 4
//!
//! Which gates a board has is the consumer's `[board] sweep` table; this module
//! names none. Output is gate names, lane tokens and counts — the gates'
//! own reports are forwarded as they wrote them, and every gate is itself a
//! pointer-only verb.

use std::io::Write;
use std::path::Path;

use anyhow::Result;

use crate::board::SweepGate;
use crate::exit::ExitCode;

/// What one gate's exit meant for the board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// The gate ran and named no dissonance.
    Clean,
    /// The gate ran and refused the board.
    Refused,
    /// The gate did not answer: unrunnable, killed, or an exit its row does not
    /// classify. The board has not been judged.
    CouldNotLook,
    /// The gate declared this exit a property of the clone, not of the board.
    Abstained,
}

impl Lane {
    /// The token the report prints. Stable, because the report is compared.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Clean => "ok",
            Self::Refused => "REFUSED",
            Self::CouldNotLook => "COULD NOT LOOK",
            Self::Abstained => "ABSTAINED",
        }
    }
}

/// Read one gate's exit against its row's own table.
///
/// `None` — the gate could not be run, or died without a code — is could-not-look,
/// and so is every code the row does not name. The unclassified direction is the
/// safe one: an answer nobody declared never reads as a clean board.
#[must_use]
pub fn lane_of(gate: &SweepGate, code: Option<i32>) -> Lane {
    match code {
        Some(0) => Lane::Clean,
        Some(code) if gate.refuses.contains(&code) => Lane::Refused,
        Some(code) if gate.abstains.contains(&code) => Lane::Abstained,
        _ => Lane::CouldNotLook,
    }
}

/// Fold every gate's lane into the one exit the sweep answers with.
///
/// The ORDER is the whole function, and each branch is a sentence of CLOUD-921:
/// could-not-look first, then a refusal, then an abstention, then clean.
#[must_use]
pub fn fold(lanes: &[Lane]) -> ExitCode {
    if lanes.contains(&Lane::CouldNotLook) {
        ExitCode::Internal
    } else if lanes.contains(&Lane::Refused) {
        ExitCode::Violation
    } else if lanes.contains(&Lane::Abstained) {
        ExitCode::Internal
    } else {
        ExitCode::Success
    }
}

/// Why a declared sweep table cannot be run as written.
///
/// Refused before any gate runs, because a malformed row does not decide
/// anything: an empty argv runs nothing, and a row that classifies `0` as a
/// refusal or an abstention could never report a clean gate.
#[must_use]
pub fn malformed(gates: &[SweepGate]) -> Option<String> {
    if gates.is_empty() {
        return Some(
            "`board.sweep` is not declared, so this decides nothing rather than reporting a \
             clean board over zero gates"
                .to_owned(),
        );
    }
    for gate in gates {
        if gate.name.trim().is_empty() {
            return Some("a `board.sweep` row has no name".to_owned());
        }
        if gate
            .run
            .first()
            .is_none_or(|program| program.trim().is_empty())
        {
            return Some(format!(
                "`board.sweep` row `{}` has no argv to run",
                gate.name
            ));
        }
        if gate.refuses.is_empty() {
            return Some(format!(
                "`board.sweep` row `{}` classifies no exit as a refusal, so it could never refuse",
                gate.name
            ));
        }
        if gate.refuses.contains(&0) || gate.abstains.contains(&0) {
            return Some(format!(
                "`board.sweep` row `{}` classifies exit 0, which is a clean gate",
                gate.name
            ));
        }
        if gate.refuses.iter().any(|code| gate.abstains.contains(code)) {
            return Some(format!(
                "`board.sweep` row `{}` names one exit as both a refusal and an abstention",
                gate.name
            ));
        }
    }
    None
}

/// The payload set, from whatever shape a caller piped.
///
/// One payload, a bare array, a stream of concatenated payloads (what reading a
/// directory of them one after another yields), or an array wrapping them — the
/// shapes the retired task's `jq -s` slurp accepted. `None` is "not JSON", which
/// is could-not-look rather than an empty set.
#[must_use]
pub fn payload_set(text: &str) -> Option<Vec<serde_json::Value>> {
    let mut values = Vec::new();
    for value in serde_json::Deserializer::from_str(text).into_iter::<serde_json::Value>() {
        values.push(value.ok()?);
    }
    Some(match values.as_slice() {
        [serde_json::Value::Array(inner)] => inner.clone(),
        _ => values,
    })
}

/// The payload set serialized once for every gate, and how many issues it holds
/// — or why it cannot be swept.
///
/// **An empty set is could-not-look, never a clean board** — the anti-vacuity
/// term: every gate run over nothing finds nothing, and the sweep would then
/// report a board it never looked at.
///
/// # Errors
///
/// The refusal's text when the input is not JSON or holds no payload.
pub fn prepare(text: &str) -> std::result::Result<(String, usize), &'static str> {
    let Some(set) = payload_set(text) else {
        return Err(
            "the payload set is not JSON. Read the rows through the tracker (the \
                    capture store keeps what was read: `batten capture find <key> --tool \
                    get_issue --raw`) rather than re-typing a payload (CLOUD-526)",
        );
    };
    if set.is_empty() {
        return Err(
            "the payload set is empty, so no gate can decide anything. That is COULD \
                    NOT LOOK, never a clean board — pipe the payloads, or name them with \
                    `--issue`",
        );
    }
    let issues = set.len();
    Ok((serde_json::Value::Array(set).to_string(), issues))
}

/// Run every declared gate over `payload` and report the set.
///
/// `payload` is the set already serialized as one JSON array, so every gate
/// reads byte-identical input. Each gate runs through [`crate::exec`]'s placed
/// adapter — this module adds no spawn of its own.
///
/// # Errors
///
/// Only when a write to `out` or `err` fails. Every gate failure is a lane.
pub fn run(
    root: &Path,
    gates: &[SweepGate],
    payload: &str,
    issues: usize,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    writeln!(out, "board sweep: {issues} issue(s)")?;
    let mut lanes = Vec::with_capacity(gates.len());
    for gate in gates {
        let answer = crate::exec::piped_argv(
            root,
            &gate.run,
            payload,
            crate::exec::Diagnostics::Keep,
            &[],
        );
        let lane = lane_of(gate, answer.as_ref().map(|(code, _)| *code));
        writeln!(out, "  {} {}", gate.name, lane.token())?;
        // Both streams, because gates disagree about which one carries a finding,
        // and forwarded only where the gate did not come back clean.
        if lane != Lane::Clean
            && let Some((_, report)) = &answer
            && !report.trim().is_empty()
        {
            write!(err, "{report}")?;
            if !report.ends_with('\n') {
                writeln!(err)?;
            }
        }
        lanes.push(lane);
    }
    let count = |lane: Lane| lanes.iter().filter(|seen| **seen == lane).count();
    let code = fold(&lanes);
    match code {
        ExitCode::Success => writeln!(
            out,
            "board sweep: every gate ran and none names dissonance ({issues} issue(s))"
        )?,
        ExitCode::Violation => writeln!(
            err,
            "batten: board sweep: {} gate(s) name dissonance above",
            count(Lane::Refused)
        )?,
        _ if count(Lane::CouldNotLook) > 0 => writeln!(
            err,
            "batten: board sweep: {} gate(s) could not look — the board has not been judged",
            count(Lane::CouldNotLook)
        )?,
        _ => writeln!(
            err,
            "batten: board sweep: the board is coherent ({issues} issue(s)); {} gate(s) \
             abstained on a property of this clone, not of the board",
            count(Lane::Abstained)
        )?,
    }
    Ok(code)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn gate(refuses: &[i32], abstains: &[i32]) -> SweepGate {
        SweepGate {
            name: "g".to_owned(),
            run: vec!["x".to_owned()],
            refuses: refuses.to_vec(),
            abstains: abstains.to_vec(),
        }
    }

    #[test]
    fn a_gate_is_read_against_its_own_exit_table() {
        let engine = gate(&[2], &[]);
        assert_eq!(lane_of(&engine, Some(0)), Lane::Clean);
        assert_eq!(lane_of(&engine, Some(2)), Lane::Refused);
        // The corpus's refusal code is could-not-look on the engine's table.
        assert_eq!(lane_of(&engine, Some(1)), Lane::CouldNotLook);
        let corpus = gate(&[1], &[3]);
        assert_eq!(lane_of(&corpus, Some(1)), Lane::Refused);
        assert_eq!(lane_of(&corpus, Some(3)), Lane::Abstained);
        assert_eq!(lane_of(&corpus, Some(2)), Lane::CouldNotLook);
    }

    #[test]
    fn a_gate_that_never_answered_is_could_not_look() {
        assert_eq!(lane_of(&gate(&[2], &[]), None), Lane::CouldNotLook);
    }

    #[test]
    fn could_not_look_outranks_a_refusal() {
        assert_eq!(
            fold(&[Lane::Refused, Lane::CouldNotLook, Lane::Clean]),
            ExitCode::Internal
        );
    }

    #[test]
    fn a_refusal_outranks_an_abstention() {
        assert_eq!(fold(&[Lane::Abstained, Lane::Refused]), ExitCode::Violation);
    }

    #[test]
    fn an_abstention_alone_is_not_a_clean_board() {
        assert_eq!(fold(&[Lane::Clean, Lane::Abstained]), ExitCode::Internal);
        assert_eq!(fold(&[Lane::Clean, Lane::Clean]), ExitCode::Success);
    }

    #[test]
    fn a_table_that_could_never_answer_is_refused_before_it_runs() {
        assert!(malformed(&[]).is_some());
        assert!(malformed(&[gate(&[], &[])]).is_some());
        assert!(malformed(&[gate(&[0], &[])]).is_some());
        assert!(malformed(&[gate(&[2], &[2])]).is_some());
        let mut unnamed = gate(&[2], &[]);
        unnamed.name = String::new();
        assert!(malformed(&[unnamed]).is_some());
        let mut empty = gate(&[2], &[]);
        empty.run = Vec::new();
        assert!(malformed(&[empty]).is_some());
        assert!(malformed(&[gate(&[1], &[3])]).is_none());
    }

    #[test]
    fn an_empty_or_unreadable_set_is_refused_before_any_gate_runs() {
        assert!(prepare("").is_err());
        assert!(prepare("[]").is_err());
        assert!(prepare("nope").is_err());
        let (body, issues) = prepare("{\"id\":\"A\"}\n{\"id\":\"B\"}").unwrap();
        assert_eq!(issues, 2);
        assert_eq!(body, r#"[{"id":"A"},{"id":"B"}]"#);
    }

    #[test]
    fn every_shape_a_caller_pipes_reads_as_one_set() {
        assert_eq!(payload_set(r#"{"id":"A"}"#).unwrap().len(), 1);
        assert_eq!(payload_set(r#"[{"id":"A"},{"id":"B"}]"#).unwrap().len(), 2);
        assert_eq!(
            payload_set("{\"id\":\"A\"}\n{\"id\":\"B\"}\n")
                .unwrap()
                .len(),
            2
        );
        assert_eq!(payload_set("").unwrap().len(), 0);
        assert!(payload_set("not json").is_none());
    }
}

/*
The composer's own mutations. Each removes one sentence of CLOUD-921, and the
named case is the compiled tier that stops discriminating.

#MUTANT-SUITE crates/batten/tests/it/board_sweep.rs
#MUTANT sweep-refusal-laundered|s@    } else if lanes.contains(&Lane::Refused) {@    } else if false {@|a_refusal_outranks_a_clone_scoped_abstention
#MUTANT sweep-could-not-look-laundered|s@    if lanes.contains(&Lane::CouldNotLook) {@    if false {@|a_board_scoped_could_not_look_outranks_a_refusal
#MUTANT sweep-abstention-is-clean|s@    } else if lanes.contains(&Lane::Abstained) {@    } else if false {@|an_abstaining_gate_is_not_a_clean_board
#MUTANT sweep-unclassified-is-refusal|s@        _ => Lane::CouldNotLook,@        _ => Lane::Refused,@|a_gate_exiting_outside_its_table_is_not_laundered_into_the_refusal_lane
#MUTANT sweep-empty-set-is-clean|s@    if set.is_empty() {@    if false {@|an_empty_payload_set_is_could_not_look
*/
