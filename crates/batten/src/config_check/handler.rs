use crate::config_model::Event;
use crate::config_model::Handler;
use crate::error::UsageError;
use crate::handler::HandlerExt as _;
use crate::hook::EventExt as _;
use regex::Regex;
use std::collections::BTreeSet;

/// Reject a handler set that cannot honestly run.
///
/// # Errors
///
/// Propagates the first row's validation failure, and raises on a duplicate
/// `id` — ids identify a row in its reports, and two rows sharing one would make
/// a timing series and a violation ambiguous.
pub fn validate(handlers: &[Handler]) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    for handler in handlers {
        handler.validate()?;
        if !seen.insert(handler.id.as_str()) {
            return Err(UsageError::raise(format!(
                "hook.handler {}: declared twice; ids identify a row in its reports",
                handler.id
            )));
        }
    }
    Ok(())
}

/// `Handler` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).
pub(crate) trait HandlerExt: Sized {
    /// Reject a handler that cannot honestly run.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty `id`, an `on` naming
    /// no known event or naming `unrecognized`, an empty `run`, a `run` whose
    /// program is empty, or a zero timeout.
    fn validate(&self) -> anyhow::Result<()>;
}

impl HandlerExt for Handler {
    fn validate(&self) -> anyhow::Result<()> {
        if self.id.is_empty() {
            return Err(UsageError::raise("hook.handler: `id` must not be empty"));
        }
        let Some(event) = self.event() else {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `on` names no event ({:?}); expected one of {}",
                self.id,
                self.on,
                declarable_tokens().join(", ")
            )));
        };
        // Not a moment, but the absence of one Batten could name — `action`'s
        // refusal verbatim, for the same reason. A handler keyed here would run
        // on any host event this build has never heard of: the widest possible
        // trigger, chosen by nobody.
        if event == Event::Unrecognized {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `on` may not be {:?} — it names no moment, only that the host \
                 said a word this build does not know",
                self.id,
                Event::Unrecognized.as_str()
            )));
        }
        let Some(program) = self.run.first() else {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `run` must name a command",
                self.id
            )));
        };
        if program.is_empty() {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `run`'s first element is the program and must not be empty",
                self.id
            )));
        }
        // The matcher compiles, and does not name a server literally.
        //
        // BOTH HALVES ARE REFUSALS AT LOAD rather than per-call surprises, for the
        // reason `key_shape` records one column over: an expression discarded per
        // call leaves the row it qualifies quietly dead, and the direction of that
        // failure is the one that runs the handler on everything.
        if let Some(matcher) = self.matcher.as_deref() {
            Regex::new(matcher).map_err(|err| {
                UsageError::raise(format!(
                    "hook.handler {}: `matcher` is not valid: {err}",
                    self.id
                ))
            })?;
            // CLOUD-178, MECHANIZED RATHER THAN DOCUMENTED. A matcher pinned to one
            // server segment is precisely the shape that measured inert: a claude.ai
            // connector's exposed name is chosen per registration episode by the
            // host, so `^mcp__Linear__` matches nothing the moment it comes back as
            // a UUID — and a handler that stops being dispatched is silent.
            // `^mcp__` is admitted: it names no server, which is what makes it
            // portable. A rule row avoids this by construction (its `tool` column is
            // a suffix); a regex has to be told.
            //
            // THE QUESTION IS ACCEPTANCE, NOT SPELLING, and the difference is a
            // measured bypass rather than a nicety. This clause first asked whether
            // the segment CONTAINED a regex metacharacter, which `^mcp__[L]inear__`
            // satisfies while still accepting only `mcp__Linear__…` — so the check
            // meant to prevent an inert handler admitted one, and `^mcp__(Linear|
            // Gmail)__` passed the same way. Review of #703 caught it. So the
            // segment's own fragment is compiled and asked whether it accepts a
            // server name it has never seen: two probes, fixed rather than random so
            // the verdict is byte-stable, neither one any real connector's label and
            // shaped like the two forms a host actually mints (readable and UUID).
            // A fragment that will not compile alone is could-not-look and admits,
            // which is this module's posture everywhere else.
            if let Some(rest) = matcher.trim_start_matches('^').strip_prefix("mcp__") {
                let fragment = rest.split("__").next().unwrap_or_default();
                if !fragment.is_empty()
                    && let Ok(segment) = Regex::new(&format!("^(?:{fragment})$"))
                    && !PROBE_SERVERS.iter().all(|probe| segment.is_match(probe))
                {
                    return Err(UsageError::raise(format!(
                        "hook.handler {}: `matcher`'s server segment {fragment:?} \
                                 does not accept a server name it has not seen, so it is \
                                 pinned to the label the host exposes today — which is \
                                 rotated per registration episode (CLOUD-178), and this \
                                 handler would then match nothing at all. Match the \
                                 prefix alone (`^mcp__`) and let the program decide the \
                                 rest.",
                        self.id
                    )));
                }
            }
        }
        // THE COMMAND SELECTOR COMPILES (CLOUD-1650).
        //
        // Refused at load for the sibling's reason and one of its own. An
        // expression discarded per call leaves the row it qualifies quietly dead,
        // and here the direction of that failure is the worse one: an
        // uncompilable `command_matcher` falls through to `selects_command`'s
        // fail-open arm and runs the handler on EVERY call the tool matcher
        // admitted — which for a `^Bash$` row is every shell command in the
        // session, spawning a program per call to decide nothing.
        //
        // No server-segment probe here, and its absence is not an omission:
        // CLOUD-178's trap is about a name the HOST rotates per registration
        // episode, and a command string is written by the agent rather than
        // minted by the host. There is no rotating label for an expression over
        // it to be pinned to.
        if let Some(matcher) = self.command_matcher.as_deref() {
            Regex::new(matcher).map_err(|err| {
                UsageError::raise(format!(
                    "hook.handler {}: `command_matcher` is not valid: {err}",
                    self.id
                ))
            })?;
        }
        // A GRANT NEEDS A MOMENT THAT DECIDES PERMISSION, and this is the one half
        // of that question a config load can answer.
        //
        // It cannot ask whether THIS host honours a pre-approval: `validate` runs
        // at config load, which knows nothing about the harness — that answer is
        // `Capabilities::preapprove_reachable`'s, consulted at the boundary, where
        // an unreachable channel degrades to silence. What is decidable here is
        // harness-INDEPENDENT: whether the MOMENT decides permission at all. An
        // inert grant is indistinguishable from the handler not running, which is
        // the failure this whole column exists to remove.
        //
        // `Event::decides_permission` and NOT `carries_a_verdict`, which is the
        // narrower answer and was found by a test rather than by reading: the
        // first version of this borrowed `carries_a_verdict` and admitted
        // `post-tool`, where a deny is a finding about a call that already ran and
        // a grant is permission for something already done. That authority lives
        // on `Event` so this validator and any future reader ask one question.
        if self.preapproves && !event.decides_permission() {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `preapproves` needs a moment that decides permission for a call \
                 that has not run, and {:?} is not one — so the grant would be inert on every \
                 host rather than unreachable on some. Drop the column, or move the row to the \
                 pre-tool event.",
                self.id, self.on
            )));
        }
        // A zero bound is not "no bound", it is a handler that can never
        // succeed. Refusing it at load is the difference between an author
        // learning this now and a turn losing every handler to a timeout later.
        if self.timeout_ms == Some(0) {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `timeout_ms` must be greater than zero",
                self.id
            )));
        }
        Ok(())
    }
}

/// Server names no connector is exposed under, used to ask a `matcher` whether it
/// accepts a label it has never seen (CLOUD-178).
///
/// Two rather than one, so a fragment cannot pass by coinciding with a single
/// probe's shape, and they are the two forms a host actually mints: a readable
/// alias and a UUID. **Fixed rather than random** — a gate's verdict is
/// byte-stable (house-style §6), and a probe drawn per run would make a refusal
/// depend on the draw. Neither contains `__`, which is the segment separator the
/// fragment is cut on.
pub(crate) const PROBE_SERVERS: [&str; 2] = ["zqxjkvwpbf", "00000000-0000-4000-8000-000000000000"];

/// Every event token a handler may name.
///
/// Derived from [`Event::ALL`] rather than re-typed, so an event added to the
/// enum becomes declarable in the same change instead of in a forgotten second
/// table. `pre-tool` IS among them — see the module docs for why it is here and
/// absent from `action`'s list.
#[must_use]
pub fn declarable_tokens() -> Vec<&'static str> {
    Event::ALL
        .iter()
        .filter(|event| **event != Event::Unrecognized)
        .map(super::super::hook::EventExt::as_str)
        .collect()
}

/// The event a token names, if any.
pub(crate) fn event_of(token: &str) -> Option<Event> {
    Event::ALL
        .iter()
        .copied()
        .find(|event| event.as_str() == token)
}

/// The id prefix of the harness-surface `[[pattern]]` family (CLOUD-1636).
pub const HARNESS_SURFACES: &str = "harness-config-";

/// The harness-surface census (CLOUD-1636): refuse a `harness-config-<harness>`
/// family that omits a harness with wiring, or names a harness this engine
/// does not adapt. A table declaring no family is not judged — a consumer that
/// has not adopted the declaration owes nothing.
///
/// Which paths are a harness's configuration is the consumer's (rule 1); which
/// harnesses exist is the core's, so the census is too. A variant with no row
/// would read to every module over the family as "keeps no configuration",
/// which is a confident wrong answer where the honest one is "nobody declared
/// it", so a new harness is refused rather than defaulted. A harness with no
/// wiring file (the neutral exit-code contract) keeps none, and owes no row.
///
/// Beside the handler checks because both judge the harness hook surface, and
/// this module already reaches [`crate::hook`] for the harness set.
///
/// # Errors
///
/// A [`UsageError`] naming the harness left out, or the row naming no harness.
pub fn validate_harness_surfaces(patterns: &[crate::pattern::NamedPattern]) -> anyhow::Result<()> {
    use crate::hook::HarnessExt as _;
    let harnesses = crate::config_model::Harness::ALL;
    let declared: BTreeSet<&str> = patterns
        .iter()
        .filter_map(|pattern| pattern.id.strip_prefix(HARNESS_SURFACES))
        .collect();
    if declared.is_empty() {
        return Ok(());
    }
    if let Some(unknown) = declared
        .iter()
        .find(|name| !harnesses.iter().any(|harness| harness.as_str() == **name))
    {
        return Err(UsageError::raise(format!(
            "[[pattern]] {HARNESS_SURFACES}{unknown}: names no harness this engine adapts, \
             so no write can be attributed to it"
        )));
    }
    if let Some(missing) = harnesses
        .iter()
        .find(|harness| harness.wiring().is_some() && !declared.contains(harness.as_str()))
    {
        return Err(UsageError::raise(format!(
            "[[pattern]] {HARNESS_SURFACES}{}: missing — the family declares harness \
             configuration surfaces, and this harness keeps its hook registration in a file \
             the family does not name",
            missing.as_str()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod harness_surface_tests {
    use super::*;
    use crate::hook::HarnessExt as _;

    fn row(id: &str) -> crate::pattern::NamedPattern {
        crate::pattern::NamedPattern {
            id: id.to_owned(),
            regex: String::from("x"),
        }
    }

    fn family(skip: Option<&str>) -> Vec<crate::pattern::NamedPattern> {
        crate::config_model::Harness::ALL
            .iter()
            .filter(|harness| harness.wiring().is_some())
            .map(|harness| harness.as_str())
            .filter(|name| Some(*name) != skip)
            .map(|name| row(&format!("{HARNESS_SURFACES}{name}")))
            .collect()
    }

    #[test]
    fn a_whole_family_loads() {
        assert!(validate_harness_surfaces(&family(None)).is_ok());
    }

    #[test]
    fn no_family_is_not_judged() {
        assert!(validate_harness_surfaces(&[row("unrelated")]).is_ok());
    }

    #[test]
    fn a_harness_left_out_is_refused_by_name() {
        let error =
            validate_harness_surfaces(&family(Some("cursor"))).expect_err("cursor is missing");
        assert!(
            error.to_string().contains("harness-config-cursor"),
            "{error}"
        );
    }

    #[test]
    fn a_row_naming_no_harness_is_refused() {
        let mut rows = family(None);
        rows.push(row("harness-config-nonesuch"));
        let error = validate_harness_surfaces(&rows).expect_err("nonesuch is no harness");
        assert!(error.to_string().contains("nonesuch"), "{error}");
    }
}
