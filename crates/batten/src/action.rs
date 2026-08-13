//! The `[[hook.action]]` plugin surface (CLOUD-91) — house-style §9's
//! "repo-specific cleanup or keepalive is reconstructed here, not hardcoded".
//!
//! An **action** is a side effect an operator declares against an event: when
//! the host reports that event, Batten spawns the declared command. Nothing
//! about it is Batten's business except *that it was declared* — which is the
//! whole point, because the alternative is the engine carrying one consumer's
//! cleanup script (non-negotiable rule 1).
//!
//! ## An action can never change the answer
//!
//! This is the load-bearing property, and it is structural rather than
//! promised. [`fire`] returns nothing a decision path reads: it takes the error
//! channel, writes pointer lines to it, and returns `()`. There is no value for
//! a caller to branch on even by mistake, so the `hook` contract (§7's table,
//! CLOUD-40's per-harness channel) holds whatever an action does — including
//! when it fails, hangs on its own, or writes to stdout.
//!
//! A failing action is reported as `<id>: exit N` and nothing else. Never the
//! command's output: an action is user-supplied code, so its streams are the
//! likeliest place in this whole surface for a secret to surface (rule 4). Its
//! stdout and stderr are discarded rather than forwarded — forwarding to *our*
//! stderr would also corrupt the one channel two hosts read a deny reason from.
//!
//! ## Why `pre-tool` is refused
//!
//! [`Action::validate`] rejects an action keyed on the one event policy
//! adjudicates, for two independent reasons and either would be enough.
//!
//! A side effect there runs **before a possible deny** — the operator's script
//! would fire for a call Batten was about to refuse, which inverts what a
//! mediated gate is for. And `run_hook`'s hot path deliberately touches no
//! config when a pre-tool payload carries neither a command nor a write (§4,
//! "cheap when irrelevant"); an action table readable at that point would put a
//! config load back on the most frequent call in the binary.
//!
//! The issue's own framing agrees: actions attach to **optional-capability**
//! events, and `pre-tool` is the converged one every surveyed host emits.
//!
//! ## Firing is exact, never degraded
//!
//! [`crate::hook::Capabilities::degrade`] maps a policy keyed on an absent event
//! onto a stand-in, because *observing* a moment approximately is better than
//! not observing it. An action is the opposite case: it **does** something, so
//! running it at a moment the operator did not name is worse than not running
//! it. So an action fires only on an exact event match, and a host that does not
//! emit that event fires nothing — which `run_hook` already guarantees by
//! returning before this module is reached.

use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Stdio};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::hook::Event;

/// The `[hook]` table: what this repository attaches to hook events.
///
/// A table rather than a bare `[[hook.action]]` array at the top level, so the
/// noun has somewhere to grow — and so the config surface reads the way the
/// house style names it (§9).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    /// The declared actions, in declaration order. Order is the firing order:
    /// a reader should be able to predict it from the file without a rule.
    #[serde(default, rename = "action", skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Action>,
}

/// One declared side effect.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Action {
    /// The stable identifier a failure is reported under.
    ///
    /// Separate from the command for [`crate::markers::Marker`]'s reason: the
    /// argv is free to change without the thing it is called in reports changing
    /// with it.
    pub id: String,
    /// The event this action fires on, as [`Event::as_str`] spells it.
    ///
    /// A **normalized** token, never a host's own word: an action declared once
    /// should fire on every host that offers the moment, and keying it on
    /// Claude's spelling would silently not fire on Gemini's.
    pub on: String,
    /// The command, as argv. Never a shell string.
    ///
    /// argv rather than a command line because there is then no quoting layer
    /// between what an operator wrote and what runs — no word splitting, no
    /// glob expansion, no `$(…)`. §9's rule is that an extension surface names
    /// a command already on the operator's PATH; this is that, with the
    /// arguments spelled out rather than parsed back out of a string.
    pub run: Vec<String>,
}

impl Action {
    /// Reject an action that cannot honestly fire.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty `id`, an `on` naming
    /// no known event or naming `pre-tool` (see the module docs), an empty
    /// `run`, or a `run` whose program is empty.
    fn validate(&self) -> anyhow::Result<()> {
        if self.id.is_empty() {
            return Err(UsageError::raise("hook.action: `id` must not be empty"));
        }
        let Some(event) = event_of(&self.on) else {
            return Err(UsageError::raise(format!(
                "hook.action {}: `on` names no event ({:?}); expected one of {}",
                self.id,
                self.on,
                declarable_tokens().join(", ")
            )));
        };
        // The two reasons are in the module docs; the message carries the one an
        // author can act on.
        if event == Event::PreTool {
            return Err(UsageError::raise(format!(
                "hook.action {}: `on` may not be {:?} — it is the event policy adjudicates, so a \
                 side effect there would run before a possible deny",
                self.id,
                Event::PreTool.as_str()
            )));
        }
        // Not a moment, but the absence of one Batten could name. An action
        // keyed here would fire on any host event this build has never heard
        // of — the widest possible trigger, chosen by nobody.
        if event == Event::Unrecognized {
            return Err(UsageError::raise(format!(
                "hook.action {}: `on` may not be {:?} — it names no moment, only that the host \
                 said something this build does not normalize",
                self.id,
                Event::Unrecognized.as_str()
            )));
        }
        if self.run.is_empty() {
            return Err(UsageError::raise(format!(
                "hook.action {}: `run` must name a command",
                self.id
            )));
        }
        if self.run[0].is_empty() {
            return Err(UsageError::raise(format!(
                "hook.action {}: `run`'s first element is the program and must not be empty",
                self.id
            )));
        }
        Ok(())
    }

    /// The event this action fires on, when `on` names one.
    #[must_use]
    pub fn event(&self) -> Option<Event> {
        event_of(&self.on)
    }
}

/// Resolve a normalized event token, or `None` when it names none.
///
/// Derived from [`Event::ALL`] rather than a second table, so an event added to
/// the enum is declarable here in the same change.
fn event_of(token: &str) -> Option<Event> {
    Event::ALL
        .iter()
        .copied()
        .find(|event| event.as_str() == token)
}

/// Every token an action may declare: the events, minus the two an action may
/// not attach to.
///
/// `unrecognized` is excluded for a different reason than `pre-tool`: it is not
/// a moment, it is the *absence* of one Batten could name, so an action keyed on
/// it would fire on any host event this build has never heard of.
fn declarable_tokens() -> Vec<&'static str> {
    Event::ALL
        .iter()
        .filter(|event| !matches!(event, Event::PreTool | Event::Unrecognized))
        .map(|event| event.as_str())
        .collect()
}

/// Reject a table that cannot honestly fire, and duplicate ids within it.
///
/// A duplicate id is refused rather than merged: two actions reporting failures
/// under one name make the pointer ambiguous, which is the one thing the id
/// exists to prevent.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for any invalid row, or a repeated `id`.
pub fn validate(actions: &[Action]) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    for action in actions {
        action.validate()?;
        if !seen.insert(action.id.as_str()) {
            return Err(UsageError::raise(format!(
                "hook.action {}: declared twice; ids identify a row in its failure report",
                action.id
            )));
        }
    }
    Ok(())
}

/// The facts an action's argv may reference, as `{name}` placeholders.
///
/// Deliberately a **closed** set, and deliberately small. Every one of these is
/// already a pointer the hook layer carries; a placeholder for the whole tool
/// input would hand user-supplied code the payload rule 4 keeps out of Batten's
/// own output.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct Facts<'a> {
    /// The normalized event, always present.
    pub event: &'a str,
    /// The tool the host named, empty when it named none.
    pub tool: &'a str,
    /// The path a write-shaped call targets, empty when there is none.
    pub path: &'a str,
    /// The host's session identifier, empty when it supplied none.
    pub session: &'a str,
}

impl Facts<'_> {
    /// Substitute `{name}` placeholders in one argv word.
    ///
    /// An **unknown** placeholder is left exactly as written rather than
    /// emptied. Emptying it would silently hand the command a different argv
    /// than the operator read — a typo'd `{pathh}` collapsing to nothing turns
    /// `rm -rf {pathh}` into `rm -rf`, and the failure mode of guessing here is
    /// unbounded. Left alone, the command sees the literal and can fail on it.
    fn expand(self, word: &str) -> String {
        let mut out = String::with_capacity(word.len());
        let mut rest = word;
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else {
                // No closing brace: the rest is literal, including this `{`.
                out.push_str(&rest[open..]);
                return out;
            };
            let name = &after[..close];
            match name {
                "event" => out.push_str(self.event),
                "tool" => out.push_str(self.tool),
                "path" => out.push_str(self.path),
                "session" => out.push_str(self.session),
                _ => {
                    out.push('{');
                    out.push_str(name);
                    out.push('}');
                }
            }
            rest = &after[close + 1..];
        }
        out.push_str(rest);
        out
    }
}

/// Spawn every action declared for `event`, in declaration order.
///
/// **Returns nothing.** That is the contract, not an oversight: an action must
/// not be able to reach the decision, and a function with no return value gives
/// no caller anything to branch on. A failing action, an unspawnable one, and a
/// clean one are equally invisible to the answer.
///
/// The child's streams are discarded (rule 4, and so `hook`'s own stdout stays
/// the decision document a host parses); its stdin is closed, so an action that
/// waits on input fails immediately instead of hanging the mediated call.
pub fn fire(actions: &[Action], event: Event, facts: Facts<'_>, err: &mut dyn Write) {
    for action in actions {
        if action.event() != Some(event) {
            continue;
        }
        let expanded: Vec<String> = action.run.iter().map(|word| facts.expand(word)).collect();
        let Some((program, args)) = expanded.split_first() else {
            continue;
        };
        let status = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        // Pointer-only, and each outcome distinguishable: a command that could
        // not be spawned at all is a different thing to fix than one that ran
        // and failed, and reporting both as "failed" sends the reader to the
        // wrong place. A write to `err` that itself fails is dropped — this
        // function has no channel to report on, and by construction must not
        // acquire one.
        let line = match status {
            Ok(status) if status.success() => continue,
            Ok(status) => match status.code() {
                Some(code) => format!("hook.action {}: exit {code}", action.id),
                None => format!("hook.action {}: killed by signal", action.id),
            },
            Err(_) => format!("hook.action {}: could not spawn {program}", action.id),
        };
        let _ = writeln!(err, "{line}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn action(id: &str, on: &str, run: &[&str]) -> Action {
        Action {
            id: id.to_owned(),
            on: on.to_owned(),
            run: run.iter().map(|word| (*word).to_owned()).collect(),
        }
    }

    fn is_usage_error(err: &anyhow::Error) -> bool {
        err.downcast_ref::<UsageError>().is_some()
    }

    #[test]
    fn every_declarable_token_is_an_event_and_pre_tool_is_not_among_them() {
        // Derived from `Event::ALL`, so an event added to the enum becomes
        // declarable in the same change rather than in a forgotten second table.
        for token in declarable_tokens() {
            assert!(event_of(token).is_some(), "{token} names an event");
        }
        assert!(!declarable_tokens().contains(&Event::PreTool.as_str()));
        assert!(!declarable_tokens().contains(&Event::Unrecognized.as_str()));
        assert_eq!(declarable_tokens().len(), Event::ALL.len() - 2);
    }

    #[test]
    fn an_action_on_the_adjudicated_event_is_refused() {
        // The whole reason the surface is restricted: a side effect at pre-tool
        // runs before a deny that may be about to refuse the very call.
        let err = validate(&[action("cleanup", "pre-tool", &["true"])]).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(
            err.to_string().contains("before a possible deny"),
            "the message says why: {err}"
        );
    }

    #[test]
    fn a_row_that_cannot_fire_is_refused_at_load() {
        for bad in [
            action("", "stop", &["true"]),
            action("x", "not-an-event", &["true"]),
            action("x", "unrecognized", &["true"]),
            action("x", "stop", &[]),
            action("x", "stop", &[""]),
        ] {
            let err = validate(&[bad.clone()]).unwrap_err();
            assert!(is_usage_error(&err), "{bad:?} is bad input, not a failure");
        }
        validate(&[action("x", "stop", &["true"])]).expect("a well-formed row loads");
    }

    #[test]
    fn a_repeated_id_is_refused_because_the_pointer_would_be_ambiguous() {
        let err = validate(&[
            action("cleanup", "stop", &["true"]),
            action("cleanup", "session-start", &["true"]),
        ])
        .unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("declared twice"));
    }

    fn facts() -> Facts<'static> {
        Facts {
            event: "stop",
            tool: "Bash",
            path: "/repo/file.rs",
            session: "s-1",
        }
    }

    #[test]
    fn placeholders_expand_and_an_unknown_one_is_left_alone() {
        assert_eq!(facts().expand("{event}"), "stop");
        assert_eq!(facts().expand("--path={path}"), "--path=/repo/file.rs");
        assert_eq!(facts().expand("{tool}/{session}"), "Bash/s-1");
        // The load-bearing one: emptying an unknown placeholder would hand the
        // command a different argv than the operator read.
        assert_eq!(facts().expand("{pathh}"), "{pathh}");
        assert_eq!(facts().expand("{"), "{");
        assert_eq!(facts().expand("a{b"), "a{b");
        assert_eq!(facts().expand("plain"), "plain");
    }

    #[test]
    fn an_absent_fact_expands_to_nothing_rather_than_to_a_literal() {
        // A stop event carries no tool and no path. The word collapses, which is
        // what an operator writing `--tool={tool}` should get; inventing a
        // placeholder-shaped literal would be a value the command cannot tell
        // from a real one.
        let bare = Facts {
            event: "stop",
            ..Facts::default()
        };
        assert_eq!(bare.expand("--tool={tool}"), "--tool=");
    }

    #[test]
    fn only_the_declared_event_fires_and_a_failure_is_a_pointer() {
        let actions = vec![
            action("matching", "stop", &["false"]),
            action("other-event", "session-start", &["false"]),
        ];
        let mut err = Vec::new();
        fire(&actions, Event::Stop, facts(), &mut err);
        let text = String::from_utf8(err).unwrap();
        assert!(
            text.contains("hook.action matching: exit 1"),
            "the failure is one pointer line: {text:?}"
        );
        assert!(
            !text.contains("other-event"),
            "an action on another event does not fire: {text:?}"
        );
    }

    #[test]
    fn a_clean_action_says_nothing_and_an_unspawnable_one_is_distinguishable() {
        let mut quiet = Vec::new();
        fire(
            &[action("ok", "stop", &["true"])],
            Event::Stop,
            facts(),
            &mut quiet,
        );
        assert!(quiet.is_empty(), "a clean action is not news");

        let mut missing = Vec::new();
        fire(
            &[action(
                "gone",
                "stop",
                &["batten-no-such-program-exists-here"],
            )],
            Event::Stop,
            facts(),
            &mut missing,
        );
        let text = String::from_utf8(missing).unwrap();
        assert!(
            text.contains("could not spawn"),
            "not-installed is a different fix from ran-and-failed: {text:?}"
        );
    }

    #[test]
    fn the_argv_reaching_the_child_is_the_expanded_one() {
        // Observed through the child's own side effect rather than by
        // inspecting the Command: `fire` returns nothing, so the only honest
        // way to assert what ran is to have it do something.
        let dir = std::env::temp_dir().join("batten-action-argv");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("stop-Bash");

        let mut err = Vec::new();
        fire(
            &[action(
                "touch",
                "stop",
                &[
                    "sh",
                    "-c",
                    // `$1`/`$2` rather than interpolation: the point is that the
                    // expanded words arrive as separate argv entries.
                    "touch \"$1/$2-$3\"",
                    "sh",
                    dir.to_str().unwrap(),
                    "{event}",
                    "{tool}",
                ],
            )],
            Event::Stop,
            facts(),
            &mut err,
        );
        assert!(err.is_empty(), "{}", String::from_utf8_lossy(&err));
        assert!(target.exists(), "the child saw the expanded argv");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
