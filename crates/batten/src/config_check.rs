//! The config model's invariants (CLOUD-2789): every section's validator.
//!
//! A section's rules are facts about the model, not about the feature that
//! later reads the section, so they sit beside [`crate::config_model`] and
//! below the loader. [`crate::config`] parses a file into the model and runs
//! these; a feature that loads the config therefore no longer sits underneath
//! the loader that validates it. Each feature's rules keep their own module
//! here, named for the feature, which re-exports them under their old names.

pub mod action {
    use crate::config_model::Action;
    use crate::config_model::Event;
    use crate::error::UsageError;
    use std::collections::BTreeSet;

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

    impl Action {
        /// Reject an action that cannot honestly fire.
        ///
        /// # Errors
        ///
        /// Returns a [`UsageError`] (→ exit `1`) for an empty `id`, an `on` naming
        /// no known event or naming `pre-tool` (see the module docs), an empty
        /// `run`, or a `run` whose program is empty.
        pub(crate) fn validate(&self) -> anyhow::Result<()> {
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
    }

    /// Resolve a normalized event token, or `None` when it names none.
    ///
    /// Derived from [`Event::ALL`] rather than a second table, so an event added to
    /// the enum is declarable here in the same change.
    pub(crate) fn event_of(token: &str) -> Option<Event> {
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
    pub(crate) fn declarable_tokens() -> Vec<&'static str> {
        Event::ALL
            .iter()
            .filter(|event| !matches!(event, Event::PreTool | Event::Unrecognized))
            .map(|event| event.as_str())
            .collect()
    }
}

pub mod advisory {
    use crate::config_model::Channel;

    /// Refuse a ceiling nothing could satisfy.
    ///
    /// # Errors
    ///
    /// When the declared ceiling is zero: it would suppress every advisory including
    /// the shortest, which is a channel switched off wearing a budget's clothes.
    pub fn validate(channel: Option<&Channel>) -> Result<(), String> {
        match channel {
            Some(declared) if declared.max_tokens == 0 => Err(
                "`[advisory] max_tokens = 0` suppresses every advisory the channel could carry — \
                 remove the table to leave the channel unbounded, or name a ceiling something can \
                 fit inside"
                    .to_owned(),
            ),
            _ => Ok(()),
        }
    }
}

pub mod budget {
    use crate::config_model::Budget;
    use crate::error::UsageError;

    use anyhow::Result;

    /// Validate the `[budget]` table at load.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a `[budget]` table declaring no
    /// budget. A table that parses and gates nothing is the half-change
    /// non-negotiable rule 2 exists to refuse.
    pub fn validate(budget: Option<&Budget>) -> Result<()> {
        let Some(budget) = budget else {
            return Ok(());
        };
        if budget.is_empty() {
            return Err(UsageError::raise(
                "budget: the table declares no set; remove it or declare [budget.<name>]"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

pub mod forge_query {
    use crate::config_check::record::safe_component;
    use crate::error::UsageError;

    use crate::rest::Query;
    use anyhow::Result;

    /// The forge's own ceiling on a page, which it CLAMPS to silently.
    ///
    /// A declared `per_page` above it would make every full page look short, and a
    /// short page is the walk's end-of-collection signal where no count is stated —
    /// so the walk would stop after one page and call the prefix whole.
    pub const MAX_PER_PAGE: u32 = 100;

    /// The placeholders the engine binds itself, which `--input` may not supply.
    ///
    /// `owner` and `repo` come from the checkout's forge remote and `since` from the
    /// producer's clock. Letting a caller bind them would let a record claim a
    /// repository or a window nobody resolved.
    pub(crate) const RESERVED: [&str; 3] = ["owner", "repo", "since"];

    /// One piece of a template: literal text, or a `{name}` to bind.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Piece<'a> {
        Literal(&'a str),
        Name(&'a str),
    }

    /// A placeholder name: ASCII letters, digits, `_` and `-`.
    pub(crate) fn is_name(name: &str) -> bool {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    }

    /// Split a template into literal text and placeholders.
    ///
    /// # Errors
    ///
    /// A message naming the fault — an unclosed `{`, a stray `}`, or a malformed
    /// name — never the template's surrounding text beyond the name itself.
    pub(crate) fn pieces(template: &str) -> std::result::Result<Vec<Piece<'_>>, String> {
        let mut found = Vec::new();
        let mut rest = template;
        while !rest.is_empty() {
            let Some(open) = rest.find('{') else {
                if rest.contains('}') {
                    return Err(String::from("carries a `}` that closes no placeholder"));
                }
                found.push(Piece::Literal(rest));
                break;
            };
            let (literal, tail) = rest.split_at(open);
            if literal.contains('}') {
                return Err(String::from("carries a `}` that closes no placeholder"));
            }
            if !literal.is_empty() {
                found.push(Piece::Literal(literal));
            }
            let tail = &tail[1..];
            let Some(close) = tail.find('}') else {
                return Err(String::from("opens a placeholder it never closes"));
            };
            let name = &tail[..close];
            if !is_name(name) {
                return Err(format!(
                    "names a placeholder `{{{name}}}` that is not letters, digits, `_` or `-`"
                ));
            }
            found.push(Piece::Name(name));
            rest = &tail[close + 1..];
        }
        Ok(found)
    }

    /// The placeholders a row's templates name, endpoint and parameter values both.
    ///
    /// Callable only on a row that already validated; an unparseable template
    /// contributes nothing rather than failing twice.
    pub(crate) fn placeholders(query: &Query) -> std::collections::BTreeSet<&str> {
        std::iter::once(query.endpoint.as_str())
            .chain(query.params.values().map(String::as_str))
            .filter_map(|template| pieces(template).ok())
            .flatten()
            .filter_map(|piece| match piece {
                Piece::Name(name) => Some(name),
                Piece::Literal(_) => None,
            })
            .collect()
    }

    /// A dot-separated field path's segments, or `None` where one is empty.
    pub(crate) fn segments(path: &str) -> Option<Vec<&str>> {
        let parts: Vec<&str> = path.split('.').collect();
        (!path.is_empty() && parts.iter().all(|part| !part.is_empty())).then_some(parts)
    }

    /// Prove every `[[forge.query]]` row well formed, and that a `[[record]]` row
    /// declares the family each one writes (CLOUD-253's obligation).
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for the first row that could never run as
    /// written, naming the row and the key. Each refusal is a row that would load
    /// clean and then fail — or worse, succeed — at fetch time: an id that escapes
    /// the store, a placeholder nothing can bind, a page size the forge clamps, a
    /// reduction that keeps nothing, or a family no module can read.
    pub fn validate(
        queries: &[Query],
        families: &[crate::config_model::RecordDeclared],
    ) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for query in queries {
            let id = query.id.as_str();
            safe_component("`[[forge.query]]` id", id)?;
            let refuse = |why: String| UsageError::raise(format!("forge query `{id}`: {why}"));
            if !seen.insert(id) {
                return Err(refuse(String::from(
                    "is declared twice; one query writes one family",
                )));
            }
            validate_endpoint(&query.endpoint)
                .map_err(|why| refuse(format!("`endpoint` {why}")))?;
            for (name, template) in &query.params {
                if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_graphic()) {
                    return Err(refuse(String::from(
                        "a `params` key is empty or not printable",
                    )));
                }
                if name == "page" || name == "per_page" {
                    return Err(refuse(format!(
                        "`params.{name}` is the walk's own; set `per_page`/`max_pages` instead"
                    )));
                }
                pieces(template).map_err(|why| refuse(format!("`params.{name}` {why}")))?;
            }
            if query.rows.as_deref().is_some_and(str::is_empty) {
                return Err(refuse(String::from(
                    "`rows` is empty; omit it for a bare array, or name the key the rows are under",
                )));
            }
            if !(1..=MAX_PER_PAGE).contains(&query.per_page) {
                return Err(refuse(format!(
                    "`per_page` must be 1..={MAX_PER_PAGE}; the forge clamps above that, and a clamped \
                     page reads as the last one"
                )));
            }
            if query.max_pages == 0 {
                return Err(refuse(String::from(
                    "`max_pages` is 0, so the walk could read nothing",
                )));
            }
            validate_select(&query.select).map_err(refuse)?;
            let named = placeholders(query);
            match &query.since {
                Some(since) => {
                    if segments(&since.field).is_none() {
                        return Err(refuse(String::from(
                            "`since.field` is not a dot-separated field path",
                        )));
                    }
                    if since.seconds == 0 {
                        return Err(refuse(String::from(
                            "`since.seconds` is 0, so the window holds nothing",
                        )));
                    }
                }
                None if named.contains("since") => {
                    return Err(refuse(String::from(
                        "a template names `{since}` but the row declares no `since` window to bind it",
                    )));
                }
                None => {}
            }
            if !families.iter().any(|family| family.record == id) {
                return Err(refuse(format!(
                    "writes the record family `{id}`, which no `[[record]]` row declares, so no module \
                     could read it"
                )));
            }
            validate_derived(query, queries, &named).map_err(refuse)?;
        }
        Ok(())
    }

    /// A row's fan-out and spans: every name they add to a recorded row is one no
    /// other key of that row already holds, and every path they read is well formed.
    pub(crate) fn validate_derived(
        query: &Query,
        queries: &[Query],
        named: &std::collections::BTreeSet<&str>,
    ) -> std::result::Result<(), String> {
        let mut keys: std::collections::BTreeSet<&str> =
            query.select.iter().map(String::as_str).collect();
        if let Some(each) = &query.each {
            if each.query == query.id {
                return Err(String::from(
                    "`each.query` names this row itself, whose record the walk is about to replace",
                ));
            }
            let Some(source) = queries.iter().find(|other| other.id == each.query) else {
                return Err(format!(
                    "`each.query` names `{}`, which no `[[forge.query]]` row declares",
                    each.query
                ));
            };
            // THE MEMBER IS READ OFF THE RECORDED ROW, which carries the source's
            // `select` paths as its keys, spelled as declared — so a field the source
            // never selected is a member no walk could ever find, refused here rather
            // than read at run time as could-not-look.
            if !source.select.iter().any(|path| path == &each.field) {
                return Err(format!(
                    "`each.field` `{}` is not one of `{}`'s `select` paths, which are the only keys its recorded rows carry",
                    each.field, each.query
                ));
            }
            if !is_name(&each.input) || RESERVED.contains(&each.input.as_str()) {
                return Err(String::from(
                    "`each.input` must be a placeholder name the engine does not bind itself",
                ));
            }
            if !named.contains(each.input.as_str()) {
                return Err(format!(
                    "`each.input` binds `{{{}}}`, which no template of this row names",
                    each.input
                ));
            }
            if !keys.insert(each.input.as_str()) {
                return Err(String::from(
                    "`each.input` is also a `select` path, so a recorded row would carry one key twice",
                ));
            }
        }
        for span in &query.span {
            if !is_name(&span.name) {
                return Err(String::from(
                    "a `span.name` is not letters, digits, `_` or `-`",
                ));
            }
            if !keys.insert(span.name.as_str()) {
                return Err(format!(
                    "`span.name` `{}` is already a key of the recorded row",
                    span.name
                ));
            }
            let unreadable = |path: &str| segments(path).is_none();
            if unreadable(&span.from) || span.to.as_deref().is_some_and(unreadable) {
                return Err(format!(
                    "span `{}` reads an instant at a path that is not dot-separated",
                    span.name
                ));
            }
        }
        Ok(())
    }

    /// An endpoint template's own rules, beyond the placeholder grammar.
    ///
    /// API-relative and path-only, for [`crate::rest::get`]'s contract: a leading
    /// slash doubles and 404s, and a query string belongs in `params`, where it is
    /// encoded. The literal text is held to a path's safe characters so nothing the
    /// transport would have to escape can hide in it.
    pub(crate) fn validate_endpoint(endpoint: &str) -> std::result::Result<(), String> {
        if endpoint.is_empty() {
            return Err(String::from("is empty"));
        }
        if endpoint.starts_with('/') {
            return Err(String::from(
                "starts with `/`; it is API-relative, and a rooted path doubles the slash and 404s",
            ));
        }
        for piece in pieces(endpoint)? {
            if let Piece::Literal(text) = piece
                && !text
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"/_.~-".contains(&byte))
            {
                return Err(String::from(
                    "carries a character outside a path's letters, digits and `/_.~-`; a query \
                     string belongs in `params`",
                ));
            }
        }
        Ok(())
    }

    /// The reduction's own rules: non-empty, every path well formed, none twice.
    pub(crate) fn validate_select(select: &[String]) -> std::result::Result<(), String> {
        if select.is_empty() {
            return Err(String::from(
                "`select` keeps no field; the whole row is never recorded (rule 4), so the \
                 reduction must say what it keeps",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for path in select {
            if segments(path).is_none() {
                return Err(String::from(
                    "a `select` entry is not a dot-separated field path",
                ));
            }
            if !seen.insert(path.as_str()) {
                return Err(String::from("a `select` entry is listed twice"));
            }
        }
        Ok(())
    }
}

pub mod githook {
    use crate::error::UsageError;

    /// Reject a `[hook.git]` row whose name is no git hook, or whose argv is empty
    /// (CLOUD-2339): either would load clean and run nothing at the moment the
    /// operator believes it guards.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) naming the row.
    pub fn validate(rows: &std::collections::BTreeMap<String, Vec<String>>) -> anyhow::Result<()> {
        for (name, argv) in rows {
            if !crate::config_model::is_git_hook(name) {
                return Err(UsageError::raise(format!(
                    "hook.git {name}: not a githooks(5) name, so git never runs it"
                )));
            }
            if argv.first().is_none_or(String::is_empty) {
                return Err(UsageError::raise(format!(
                    "hook.git {name}: an empty argv runs nothing"
                )));
            }
        }
        Ok(())
    }
}

pub mod handler {
    use crate::config_model::Event;
    use crate::config_model::Handler;
    use crate::error::UsageError;
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

    impl Handler {
        /// Reject a handler that cannot honestly run.
        ///
        /// # Errors
        ///
        /// Returns a [`UsageError`] (→ exit `1`) for an empty `id`, an `on` naming
        /// no known event or naming `unrecognized`, an empty `run`, a `run` whose
        /// program is empty, or a zero timeout.
        pub(crate) fn validate(&self) -> anyhow::Result<()> {
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
    pub(crate) const PROBE_SERVERS: [&str; 2] =
        ["zqxjkvwpbf", "00000000-0000-4000-8000-000000000000"];

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
            .map(|event| event.as_str())
            .collect()
    }

    /// The event a token names, if any.
    pub(crate) fn event_of(token: &str) -> Option<Event> {
        Event::ALL
            .iter()
            .copied()
            .find(|event| event.as_str() == token)
    }
}

pub mod hookcost {
    use crate::config_model::HookCeiling as Ceiling;

    /// Refuse a ceiling nothing could satisfy.
    ///
    /// # Errors
    ///
    /// When `max_tokens` is zero — no hook could speak at all — or when
    /// `max_repeats` is zero, which refuses a hook's FIRST emission and so silences
    /// the finding rather than its restatement.
    pub fn validate(ceiling: Option<&Ceiling>) -> Result<(), String> {
        let Some(declared) = ceiling else {
            return Ok(());
        };
        if declared.max_tokens == 0 {
            return Err(
                "`[hook_output] max_tokens = 0` refuses every hook that speaks at all — remove the \
                 table to leave hook output unbounded, or name a ceiling a session can fit inside"
                    .to_owned(),
            );
        }
        if declared.max_repeats == 0 {
            return Err(
                "`[hook_output] max_repeats = 0` refuses a hook's FIRST emission, which silences the \
                 finding rather than its restatement; 1 is the floor — say it once"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

pub mod markers {
    use crate::config_model::Marker;
    use crate::error::UsageError;

    use anyhow::Result;

    /// Validate a whole table, and refuse a duplicate `id`.
    ///
    /// Called at config load ([`crate::config`]), which is the point: before
    /// CLOUD-253 the only caller was [`find`], and `find` had no caller in `src/`,
    /// so every refusal below was a refusal that could not fire. A validator
    /// reachable only from its own tests is prose (non-negotiable rule 2) — the
    /// same defect CLOUD-242 fixed in the verb table, which shipped in the same
    /// commit as this one and was corrected without it.
    ///
    /// Two rows under one `id` are refused for the reason the two fields are
    /// separate axes at all: `id` is the name a count is reported under, so a
    /// duplicate makes a count that answers no question — is it one marker
    /// re-spelled, or two the author wanted counted apart?
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a malformed or duplicated entry.
    pub fn validate(table: &[Marker]) -> Result<()> {
        for (index, entry) in table.iter().enumerate() {
            entry.validate()?;
            if table[..index].iter().any(|prior| prior.id == entry.id) {
                return Err(UsageError::raise(format!(
                    "marker {}: declared twice; an id is the name one count is reported under",
                    entry.id
                )));
            }
        }
        Ok(())
    }

    impl Marker {
        /// Reject a marker that cannot honestly be counted.
        ///
        /// # Errors
        ///
        /// Returns a [`UsageError`] (→ exit `1`) for an empty `id`, an empty
        /// `token` — which would match every line of every file — or an empty
        /// `glob`, which reads as "everywhere" but selects nothing.
        pub(crate) fn validate(&self) -> Result<()> {
            if self.id.is_empty() {
                return Err(UsageError::raise("marker: `id` must not be empty"));
            }
            if self.token.is_empty() {
                return Err(UsageError::raise(format!(
                    "marker {}: `token` must not be empty; an empty token matches every line",
                    self.id
                )));
            }
            if self.glob.as_deref() == Some("") {
                return Err(UsageError::raise(format!(
                    "marker {}: `glob` must not be empty; omit the key to scan the whole tree",
                    self.id
                )));
            }
            Ok(())
        }
    }
}

pub mod mcp {
    use crate::Result;
    use crate::config_model::{McpConfig, McpSource as Source};
    use crate::error::UsageError;

    use std::path::Path;

    /// Refuse a `[mcp.source.credential]` row that cannot mean one thing.
    ///
    /// **At LOAD rather than at dispatch**, for the reason every other shape rule
    /// here is: a row naming neither source names nothing, and a row naming both is
    /// two answers to one question. Either would resolve to no header and dispatch an
    /// unauthenticated call that reads as the server refusing — a dead gate wearing a
    /// 401's clothes.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) naming the source id and which key is at fault.
    /// **Never a variable's VALUE** — the names are config and the values are not.
    pub(crate) fn validate_credential(source: &Source) -> Result<()> {
        let Some(row) = &source.credential else {
            return Ok(());
        };
        let id = &source.id;
        if row.header.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "mcp: source {id:?} declares a credential with an empty `header`; a credential with \
                 nowhere to go is a call that authenticates with nothing"
            )));
        }
        let named: Vec<&String> = [&row.env, &row.file_from, &row.helper]
            .into_iter()
            .flatten()
            .collect();
        match named.as_slice() {
            [] => Err(UsageError::raise(format!(
                "mcp: source {id:?} declares a credential naming none of `env`, `file_from` or \
                 `helper`; a row that names nothing resolves to nothing and would dispatch \
                 unauthenticated"
            ))),
            [_, _, ..] => Err(UsageError::raise(format!(
                "mcp: source {id:?} declares a credential naming more than one of `env`, `file_from` \
                 and `helper`; one row names one source, or which one the engine spends depends on \
                 the order it reads them"
            ))),
            [name] if name.trim().is_empty() => Err(UsageError::raise(format!(
                "mcp: source {id:?} declares a credential naming an empty variable or key; it is a \
                 NAME, never a value"
            ))),
            _ => Ok(()),
        }
    }

    /// Refuse a malformed `[mcp]` table at load.
    ///
    /// At load rather than at dispatch, for the reason house style §8 gives: a config
    /// fault must be reported by `config lint` and `doctor` rather than discovered by
    /// the one call that needed it.
    ///
    /// # Errors
    ///
    /// [`UsageError`] (→ exit `1`) for an empty or duplicated id, an empty root name,
    /// a path that would escape its root, a duplicated method, a field list that does
    /// not match the reduction it is written for, or a credential row naming neither
    /// variable or both.
    pub fn validate(config: &McpConfig) -> Result<()> {
        let mut seen: Vec<&str> = Vec::new();
        for source in &config.sources {
            if source.id.trim().is_empty() {
                return Err(UsageError::raise(
                    "mcp: a `[[mcp.source]]` row needs a non-empty `id`; it is the only name a report \
                     may carry, because the resolved path is a machine's home directory",
                ));
            }
            if source
                .root
                .as_ref()
                .is_some_and(|root| root.trim().is_empty())
            {
                return Err(UsageError::raise(format!(
                    "mcp: source {:?} declares an empty `root`; it is the NAME of an environment \
                     variable, and an empty one would resolve the path against the process's working \
                     directory. Omit the key for a repository-relative path",
                    source.id
                )));
            }
            if source.base.is_some() && source.root.is_some() {
                return Err(UsageError::raise(format!(
                    "mcp: source {:?} declares both `base` and `root`; one row has one base, or which \
                     directory the path resolves beneath depends on the order they are read",
                    source.id
                )));
            }
            if escapes(&source.path) {
                return Err(UsageError::raise(format!(
                    "mcp: source {:?} needs a `path` that is relative and stays beneath its root; an \
                     absolute path or a `..` component would read outside the root the row declared",
                    source.id
                )));
            }
            // THE PLACEHOLDER'S SYNTAX AT LOAD, its VALUE at dispatch. A malformed
            // `${` is the author's typo and belongs to `config lint`; what a variable
            // happens to hold on this host is not knowable here, which is why
            // `escapes` runs a second time over the expanded path.
            if let Err(err) = placeholders(&source.path) {
                return Err(UsageError::raise(format!(
                    "mcp: source {:?} has an unusable `path`: {err}",
                    source.id
                )));
            }
            if seen.contains(&source.id.as_str()) {
                return Err(UsageError::raise(format!(
                    "mcp: source id {:?} is declared twice; one id names one file, or which file the \
                     engine reads depends on row order",
                    source.id
                )));
            }
            validate_endpoint_selectors(source)?;
            validate_credential(source)?;
            seen.push(&source.id);
        }
        // A PERMISSION ALIAS NO SELECTOR DECLARES CAN NEVER RESOLVE, so it would read
        // as a governed server while translating nothing — refused here rather than
        // discovered as a prompt that never went away.
        for alias in &config.permission_aliases {
            if !config
                .sources
                .iter()
                .any(|source| source.endpoint_contains.contains_key(alias))
            {
                return Err(UsageError::raise(format!(
                    "mcp: `permission_aliases` names {alias:?}, which no `[[mcp.source]]` row's \
                     `endpoint_contains` declares; the endpoint is the only thing that identifies a \
                     renamed server, so this name could never be resolved"
                )));
            }
        }

        let mut methods: Vec<&str> = Vec::new();
        for row in &config.results {
            if row.method.trim().is_empty() {
                return Err(UsageError::raise(
                    "mcp: a `[[mcp.result]]` row needs a non-empty `method`; it is what selects the \
                     reduction, and an empty one would select nothing while reading as coverage",
                ));
            }
            if methods.contains(&row.method.as_str()) {
                return Err(UsageError::raise(format!(
                    "mcp: method {:?} carries two `[[mcp.result]]` rows; which reduction applies would \
                     depend on row order",
                    row.method
                )));
            }
            methods.push(&row.method);
            // A REDUCTION OVER NO FIELDS IS NOT A NARROWER ANSWER, it is an empty
            // one — and an empty object handed back where a payload was expected is
            // the silent-filter failure this whole family is built to avoid. Refused
            // at load rather than discovered by the caller that got `{}`.
            if row.fields.is_empty() {
                return Err(UsageError::raise(format!(
                    "mcp: method {:?} declares no `fields`, so its reduction would be empty — which is \
                     a dropped payload wearing the costume of a projection. Name the fields the \
                     caller needs",
                    row.method
                )));
            }
            if let Some(blank) = row.fields.iter().find(|field| field.trim().is_empty()) {
                return Err(UsageError::raise(format!(
                    "mcp: method {:?} declares an empty field name ({blank:?}); a field that names \
                     nothing can never be found and reads as a projection that dropped it",
                    row.method
                )));
            }
        }
        Ok(())
    }

    /// One piece of a declared path: text as written, or a variable to expand.
    pub(crate) enum Part<'a> {
        /// Text that reaches the resolved path unchanged.
        Literal(&'a str),
        /// A `${NAME}` placeholder, by name.
        Variable(&'a str),
    }

    /// Check a declared path's placeholder SYNTAX, touching no environment.
    ///
    /// The load-time half of [`expand`], and it is a separate entry point rather than
    /// a flag because the two questions have different homes: a malformed `${` is the
    /// author's typo and `config lint` must report it on every host, while what a
    /// variable holds is knowable only where the call is made.
    ///
    /// # Errors
    ///
    /// As [`parts`].
    pub(crate) fn placeholders(path: &str) -> Result<()> {
        parts(path).map(|_| ())
    }

    /// Split a declared path into literals and `${NAME}` placeholders.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for an unclosed `${`, or a name that is not
    /// `[A-Za-z_][A-Za-z0-9_]*`. Reading either as a literal would resolve a path
    /// nobody wrote, which is the failure this refuses rather than tolerates.
    pub(crate) fn parts(path: &str) -> Result<Vec<Part<'_>>> {
        let mut found = Vec::new();
        let mut rest = path;
        while let Some(open) = rest.find("${") {
            if open > 0 {
                found.push(Part::Literal(&rest[..open]));
            }
            let after = &rest[open + 2..];
            let close = after.find('}').ok_or_else(|| {
                UsageError::raise(format!(
                    "path {path:?} opens `${{` and never closes it; a placeholder that does not end \
                     cannot name a variable"
                ))
            })?;
            let name = &after[..close];
            if !name
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(UsageError::raise(format!(
                    "path {path:?} names {name:?}, which is not an environment variable name"
                )));
            }
            found.push(Part::Variable(name));
            rest = &after[close + 1..];
        }
        if !rest.is_empty() {
            found.push(Part::Literal(rest));
        }
        Ok(found)
    }

    /// Whether a declared path would leave the root it is resolved beneath.
    ///
    /// [`crate::facts::Rooted::escapes`]'s predicate, and it is spelled here rather
    /// than borrowed because the two families' rows are different types and sharing
    /// the check would mean sharing the type. The rule is the same one: rooted, or
    /// any upward component.
    ///
    /// **Run TWICE since CLOUD-1251's expansion landed**: once at load over the
    /// literal, and again over the EXPANDED path, because a variable's value is
    /// runtime input. A row spelling `${ID}.json` passes the load-time check whatever
    /// `ID` turns out to hold, so an `ID` of `../../etc` would otherwise walk out of
    /// the base the row declared — the one place this feature could have become a
    /// file-read primitive.
    ///
    /// # `is_absolute` IS THE WRONG QUESTION, and it is wrong in the dangerous
    /// direction
    ///
    /// `Path::is_absolute` is platform-dependent, and on Windows it answers **false**
    /// for `/etc/passwd`: that path has a root but no drive prefix, which Rust calls
    /// relative. `Path::join` does not agree — `base.join("/etc/passwd")` there
    /// discards the base's own path and yields `C:\etc\passwd`, outside the root the
    /// row declared. So the predicate would have admitted exactly the declaration it
    /// exists to refuse, on one platform, silently.
    ///
    /// Measured rather than reasoned: this shipped, `mise run verify` passed —
    /// `cross-check` TYPE-checks the Windows target and never runs a test there — and
    /// the Windows job in CI is what went red. Enumerating the components asks the
    /// portable question instead: a prefix, a root, or an upward step, any of which
    /// leaves the declared root on every platform.
    pub(crate) fn escapes(path: &str) -> bool {
        Path::new(path).components().any(|part| {
            matches!(
                part,
                std::path::Component::Prefix(_)
                    | std::path::Component::RootDir
                    | std::path::Component::ParentDir
            )
        })
    }

    /// Refuse an `endpoint_contains` map that cannot mean one thing.
    ///
    /// Split out of [`validate`] rather than inlined: the two refusals below are one
    /// question about one key, and the enclosing loop already carries five others.
    pub(crate) fn validate_endpoint_selectors(source: &Source) -> Result<()> {
        for (name, needle) in &source.endpoint_contains {
            if name.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "mcp: source {:?} declares an `endpoint_contains` entry with a blank name; it \
                     is what a caller types, and an empty one names nothing while reading as \
                     coverage",
                    source.id
                )));
            }
            // AN EMPTY NEEDLE IS THE ONE THAT MUST BE REFUSED AT LOAD. `contains`
            // is true of every string for an empty pattern, so the selector would
            // match the entire server map and turn the row into first-wins over
            // everything — the precise failure `Ambiguous` exists to prevent,
            // tripped on every call rather than reported once here.
            if needle.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "mcp: source {:?} maps {name:?} to an empty endpoint substring; every address \
                     contains it, so the name would select whichever server the wiring file \
                     happens to list first",
                    source.id
                )));
            }
        }
        Ok(())
    }
}

pub mod mint {
    use crate::config_check::receipt::safe_subject;
    use crate::config_model::{AfterMode, MintDeclared as Declared, MintKey, MintMode};

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
}

pub mod outputs {

    use crate::config_model::OutputPattern;
    use crate::error::UsageError;

    /// Refuse a malformed `[[exec_pattern]]` table at load, so a typo cannot sit inert.
    ///
    /// # Errors
    ///
    /// As [`validate_named`].
    pub fn validate(patterns: &[OutputPattern]) -> anyhow::Result<()> {
        validate_named(patterns, "exec_pattern")
    }

    /// Refuse a malformed `[[verify_environment_pattern]]` table at load.
    ///
    /// # A SECOND ENTRY POINT OVER ONE IMPLEMENTATION, and both reasons are real
    ///
    /// The checks are identical — same type, same four ways to be malformed — so the
    /// body is [`validate_named`] and this adds none of its own. What it adds is a
    /// NAME, twice over.
    ///
    /// It names the table in the refusal. `validate` spelled `exec_pattern` into
    /// every message, so the second table's malformed row would have reported a row
    /// in a table the author had not touched — a pointer to the wrong file, which is
    /// worse than no pointer.
    ///
    /// And it names the table to `config.rs`'s census, which resolves each declared
    /// table to its validator BY THE CALL STRING. Two tables sharing
    /// `outputs::validate(` are one call site to that gate: it finds the first,
    /// reads the class wrapping it, and reports the second as unwrapped. A distinct
    /// entry point is what makes the census able to see both.
    ///
    /// # Errors
    ///
    /// As [`validate_named`].
    pub fn validate_environment(patterns: &[OutputPattern]) -> anyhow::Result<()> {
        validate_named(patterns, "verify_environment_pattern")
    }

    /// Refuse a malformed pattern table at load, so a typo cannot sit inert.
    ///
    /// `table` is the caller's own table name, carried into every message so a
    /// refusal points at the file and row an author has to edit.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] for an empty id, pattern or reason, or a duplicate id.
    pub fn validate_named(patterns: &[OutputPattern], table: &str) -> anyhow::Result<()> {
        let mut seen: Vec<&str> = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            if pattern.id.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "{table}: id must not be empty — it is what a match is reported as"
                )));
            }
            if pattern.pattern.is_empty() {
                return Err(UsageError::raise(format!(
                    "{table} {}: pattern must not be empty — an empty literal matches every run",
                    pattern.id
                )));
            }
            if pattern.reason.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "{table} {}: reason is required — a promoted exit code is all the caller gets back",
                    pattern.id
                )));
            }
            if seen.contains(&pattern.id.as_str()) {
                return Err(UsageError::raise(format!(
                    "{table} {}: declared twice",
                    pattern.id
                )));
            }
            seen.push(&pattern.id);
        }
        Ok(())
    }
}

pub mod provision {

    use crate::config_model::{Provision, Unpack};
    use crate::error::UsageError;

    use anyhow::Result;

    use std::path::Path;

    /// This host's platform key: `<os>-<arch>`, e.g. `linux-x86_64`.
    ///
    /// Read off [`std::env::consts`], which is what the compiled binary knows about
    /// itself. See [`Provision::platforms`] for why this rather than a target triple.
    #[must_use]
    pub fn platform_key() -> String {
        format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
    }

    /// Validate the manifest at load.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a duplicate name, an empty required
    /// field, or a checksum that is not 64 hex characters. A malformed pin is worth
    /// refusing at load rather than at fetch time: it can never match, so every
    /// apply would fail with a mismatch that blames the artifact for a typo in the
    /// config.
    pub fn validate(entries: &[Provision]) -> Result<()> {
        let mut seen: Vec<&str> = Vec::new();
        for entry in entries {
            for (key, value) in [
                ("name", &entry.name),
                ("version", &entry.version),
                ("binary", &entry.binary),
            ] {
                if value.trim().is_empty() {
                    return Err(UsageError::raise(format!(
                        "provision: `{key}` must not be empty"
                    )));
                }
            }
            if seen.contains(&entry.name.as_str()) {
                return Err(UsageError::raise(format!(
                    "provision {}: declared twice; each entry owns its own cache path",
                    entry.name
                )));
            }
            seen.push(&entry.name);

            validate_artifact_spelling(entry)?;
            validate_subtree(entry)?;
        }
        Ok(())
    }

    /// `strip` and `bin`, on the entry and on each platform row (CLOUD-2682).
    ///
    /// Refused at load: either key where nothing is unpacked; `strip` without
    /// `bin`; a `bin` that is empty, absolute or climbs with `..`; and `bin` with
    /// `link` where the launcher, a `#!` file, cannot run.
    pub(crate) fn validate_subtree(entry: &Provision) -> Result<()> {
        let mut rows: Vec<(&str, Unpack, Option<usize>, Option<&str>)> = Vec::new();
        if entry.platforms.is_empty() {
            rows.push(("the entry", entry.unpack, entry.strip, entry.bin.as_deref()));
        }
        for (key, artifact) in &entry.platforms {
            rows.push((
                key.as_str(),
                artifact.unpack.unwrap_or(entry.unpack),
                artifact.strip.or(entry.strip),
                artifact.bin.as_deref().or(entry.bin.as_deref()),
            ));
        }
        let refuse = |row: &str, why: &str| {
            Err(UsageError::raise(format!(
                "provision {}: {row}: {why}",
                entry.name
            )))
        };
        for (row, unpack, strip, bin) in rows {
            if (strip.is_some() || bin.is_some()) && unpack == Unpack::None {
                return refuse(
                    row,
                    "`strip` and `bin` extract from an archive, and this row unpacks none",
                );
            }
            if strip.is_some() && bin.is_none() {
                return refuse(row, "`strip` shapes a subtree, and only `bin` asks for one");
            }
            let Some(bin) = bin else {
                continue;
            };
            let path = Path::new(bin);
            let climbs = path
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)));
            if bin.trim().is_empty() || path.is_absolute() || climbs {
                return refuse(
                    row,
                    "`bin` is a relative path inside the archive, with no `..`",
                );
            }
            if entry.link.is_some() && cfg!(not(unix)) {
                return refuse(
                    row,
                    "a subtree's `link` is a `#!` launcher, which this host cannot run",
                );
            }
        }
        Ok(())
    }

    /// The `url`/`sha256`-versus-`platforms` xor, plus every checksum's shape.
    ///
    /// Refused at load for the same reason a malformed checksum is: an entry
    /// spelling both, or neither, can never install anything, so every apply would
    /// fail with a message about the artifact rather than about the config.
    pub(crate) fn validate_artifact_spelling(entry: &Provision) -> Result<()> {
        // `url` and `sha256` are one spelling in two fields, so a half-written pair
        // is its own error — reporting it as "no artifact" would send the author
        // looking for a platform table they never meant to write.
        match (entry.url.as_ref(), entry.sha256.as_ref()) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(UsageError::raise(format!(
                    "provision {}: `url` and `sha256` are a pair; declare both or neither",
                    entry.name
                )));
            }
            _ => {}
        }

        let single = entry.url.is_some();
        let table = !entry.platforms.is_empty();
        if single && table {
            return Err(UsageError::raise(format!(
                "provision {}: declares both a single `url` and a `[provision.platforms]` table; \
                 exactly one, or two pins could disagree about what this host installs",
                entry.name
            )));
        }
        if !single && !table {
            return Err(UsageError::raise(format!(
                "provision {}: declares no artifact; give it a `url` + `sha256`, or a \
                 `[provision.platforms]` table keyed `<os>-<arch>` (this host is {})",
                entry.name,
                platform_key()
            )));
        }

        if let (Some(url), Some(sha256)) = (entry.url.as_ref(), entry.sha256.as_ref()) {
            check_url(&entry.name, "url", url)?;
            check_sha256(&entry.name, "sha256", sha256)?;
        }
        for (platform, artifact) in &entry.platforms {
            if platform.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "provision {}: a platform key must not be empty",
                    entry.name
                )));
            }
            check_url(&entry.name, platform, &artifact.url)?;
            check_sha256(&entry.name, platform, &artifact.sha256)?;
        }
        validate_env(entry)
    }

    /// The `prepend_list`-versus-`from_first_set` xor on every `[[provision.env]]` row.
    ///
    /// Refused at LOAD, on the same argument the artifact xor above is: a row
    /// spelling neither sets nothing, and a launcher that silently sets nothing is
    /// byte-identical to one that was never written — which is the failure this whole
    /// field exists to end rather than to reproduce one layer down. A row spelling
    /// both would have two rules for one variable and no stated precedence.
    pub(crate) fn validate_env(entry: &Provision) -> Result<()> {
        for rule in &entry.env {
            if rule.name.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "provision {}: an `[[provision.env]]` row must name a variable",
                    entry.name
                )));
            }
            // A REMOVAL IS THE THIRD SHAPE, and it is the one the "declares nothing"
            // arm below would otherwise refuse. `unset` states an outcome rather
            // than a source, so it is complete on its own and pairing it with a
            // source would be two rules for one variable with no order between them
            // — the same fault the first arm names (CLOUD-1569).
            if rule.unset {
                if !rule.prepend_list.is_empty() || !rule.from_first_set.is_empty() {
                    return Err(UsageError::raise(format!(
                        "provision {}: env {} declares `unset` beside a source; a row \
                         either removes the variable or decides its value, and one \
                         carrying both says nothing about which wins",
                        entry.name, rule.name
                    )));
                }
                if rule.reject_prefix.is_some() {
                    return Err(UsageError::raise(format!(
                        "provision {}: env {} declares `unset` beside `reject_prefix`; \
                         the prefix filters CANDIDATES, and a row that keeps none has \
                         nothing to filter",
                        entry.name, rule.name
                    )));
                }
                continue;
            }
            if rule.reject_prefix.is_some() && rule.from_first_set.is_empty() {
                return Err(UsageError::raise(format!(
                    "provision {}: env {} declares `reject_prefix` with no \
                     `from_first_set`; the prefix decides which CANDIDATE is real, so a \
                     row with no candidates applies it to nothing",
                    entry.name, rule.name
                )));
            }
            match (rule.prepend_list.is_empty(), rule.from_first_set.is_empty()) {
                (false, false) => {
                    return Err(UsageError::raise(format!(
                        "provision {}: env {} declares both `prepend_list` and \
                         `from_first_set`; exactly one, or two rules decide one variable \
                         with no stated order between them",
                        entry.name, rule.name
                    )));
                }
                (true, true) => {
                    return Err(UsageError::raise(format!(
                        "provision {}: env {} declares neither `prepend_list`, \
                         `from_first_set` nor `unset`, so it would set nothing — and a \
                         launcher that sets nothing cannot be told from one that was \
                         never written",
                        entry.name, rule.name
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(crate) fn check_url(name: &str, where_: &str, url: &str) -> Result<()> {
        if url.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "provision {name}: `{where_}` has an empty url"
            )));
        }
        Ok(())
    }

    pub(crate) fn check_sha256(name: &str, where_: &str, sha256: &str) -> Result<()> {
        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(UsageError::raise(format!(
                "provision {name}: `{where_}` sha256 must be 64 hex characters"
            )));
        }
        Ok(())
    }
}

pub mod receipt {
    use crate::error::UsageError;

    use anyhow::Result;

    /// Validate a check name for use as an identity field and a filename
    /// component: ASCII alphanumeric first, then alphanumeric plus `.`, `_`, `-`.
    pub(crate) fn validate_check_name(check: &str) -> Result<()> {
        let mut chars = check.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
        let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if first_ok && rest_ok {
            Ok(())
        } else {
            Err(UsageError::raise(format!(
                "check name {check:?} is not a valid identifier (ASCII alphanumeric, then alphanumeric or `.`, `_`, `-`)"
            )))
        }
    }

    /// Refuse a `[receipt] verified_by` naming a check no receipt can ever be
    /// written for.
    ///
    /// # AT LOAD, BECAUSE THE ALTERNATIVE IS A CONFIG THAT IS PERMANENTLY UNUSABLE
    ///
    /// `receipt record` and `receipt status` already refuse these names, and nothing
    /// held the config table to the same rule (review of #848). So
    /// `verified_by = ["fmt check"]` loaded clean, `receipt record "fmt check"`
    /// exited `1` with *"not a valid identifier"*, no receipt could ever exist, and
    /// [`run_verified`] — which validates nothing and hashes the name straight into
    /// a path — reported `NOT verified: <head> fmt check missing` forever. The
    /// refusal pointed at a missing receipt rather than at the unwritable name that
    /// made it missing, which is the inert-typo class every other declared table in
    /// `config::validate_tables` is refused at load for.
    ///
    /// Fail-closed either way; what changes is that the diagnosis names the cause.
    ///
    /// # Errors
    ///
    /// [`crate::UsageError`] naming the first offending check.
    pub fn validate_verified_by(checks: &[String]) -> Result<()> {
        for check in checks {
            validate_check_name(check)?;
        }
        Ok(())
    }

    /// Whether `subject` is safe to use as one path component under the receipt
    /// store (CLOUD-987).
    ///
    /// **Refused, never rewritten.** The subject of a [`ReceiptKey::Named`] receipt
    /// comes out of the mediated call's own arguments, so it is the least trusted
    /// string in the envelope that this engine turns into a filename. Rewriting a bad
    /// one — stripping separators, replacing `..` — would file two different subjects
    /// under one receipt and let a fresh read of A authorise a stale write to B,
    /// which is precisely the confusion `ReceiptKey::Named` exists to prevent. So a
    /// value that is not already a single safe component is not a subject at all.
    ///
    /// The bound is structural rather than a format: what a tracker's identifiers
    /// look like is a consumer fact (non-negotiable rule 1), and a row that wants to
    /// insist on a shape has `when_present` and its own selection for that. What the
    /// core knows is that a path component may not be empty, may not be `.` or `..`,
    /// may not contain a separator or a NUL, and may not be unboundedly long.
    ///
    /// `pub(crate)` since CLOUD-1024: the mint that WRITES a named receipt has to
    /// refuse exactly the subjects the reader refuses, or the two halves disagree
    /// about which filenames exist.
    pub(crate) fn safe_subject(subject: &str) -> bool {
        !subject.is_empty()
            && subject != "."
            && subject != ".."
            && subject.len() <= 128
            && !subject
                .contains(|ch: char| ch == '/' || ch == '\\' || ch == '\0' || ch.is_control())
    }
}

pub mod record {
    use crate::config_model::RecordDeclared as Declared;
    use crate::error::UsageError;

    use anyhow::Result;

    /// The record names this crate's own VERBS write, as opposed to the ones a
    /// `[[recorder]]` row mints from a tool envelope (CLOUD-472).
    ///
    /// # Why a verb writes this at all, which is the whole design decision
    ///
    /// A hook mediates a call the agent makes to somebody ELSE's tool, so it is
    /// per-harness by nature: `TaskCreate`/`TaskUpdate` here, `write_todos` on
    /// Gemini CLI, `todowrite` on `OpenCode`, `update_plan` on Codex. Recording from
    /// those envelopes needs a spelling per host, and its failure mode is the one
    /// this whole module exists to name — an unsurveyed harness, a tool a setting
    /// switched off, and an agent that did as it was told all produce NOTHING, so the gate reads
    /// clean. `OpenCode` makes that concrete: `todowrite` is denied to subagents at
    /// session creation regardless of configuration.
    ///
    /// A verb inverts the direction. The agent TELLS the engine, so a missing record
    /// refuses on every harness identically — no survey, no per-host spelling, and no
    /// setting that can quietly disarm it. Discovery still has a job (reporting which
    /// native surface exists, so a mirror can be kept for the human's benefit), but
    /// the gate reads this store and only this store.
    /// `claim` is here for a second reason worth stating: `claim check` writes it and
    /// nothing read it from a module before, but it is the honest signal for "this
    /// branch is doing tracked work". A gate that demands a plan from EVERY tree with
    /// a diff refuses every scratch fixture and every consumer checkout — measured,
    /// it reddened four `cli.rs` cases that only wanted to exercise other rules.
    /// Keyed to a claim, it asks the question exactly where the answer is owed.
    /// `lap` joins them for the same reason and with one difference worth stating:
    /// it is the only one of the three that is a HISTORY rather than a current
    /// state. `land::replay` appends a line per lap, and
    /// `replay halt conflict` reads the last one — so a conflict resolved by
    /// a later lap stops refusing, which a store keeping only the newest line could
    /// not express.
    pub const VERB_WRITTEN: &[&str] = &["claim", "plan", crate::config_model::LAP_RECORD];

    /// Prove every declared family well formed (CLOUD-253's obligation).
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for a family whose name is not a single path
    /// component, for an empty `writer`, and for two rows naming one family — the
    /// last because a second row is a second answer to "who writes this", which is
    /// the one question the table exists to settle.
    pub fn validate(
        declared: &[Declared],
        recorders: &[crate::config_model::RecorderDeclared],
    ) -> Result<()> {
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for family in declared {
            // ONE NAME, ONE SOURCE. The projection resolves a `[[recorder]]` row's
            // record, then a `[[record]]` family, then a verb-written store, and
            // keeps the first — so a family sharing a name with either was silently
            // shadowed, its producer writing a store no module reads as its own.
            if VERB_WRITTEN.contains(&family.record.as_str()) {
                return Err(UsageError::raise(format!(
                    "record `{}` is a store the engine writes itself; a declared family \
                     of that name would be a second writer for it",
                    family.record
                )));
            }
            if recorders
                .iter()
                .any(|recorder| recorder.record == family.record)
            {
                return Err(UsageError::raise(format!(
                    "record `{}` is already a `[[recorder]]` row's record; a declared family \
                     of that name would be shadowed by it",
                    family.record
                )));
            }
            // The same grammar the writer enforces, checked here so the refusal lands
            // at load. A name that escapes its store is why `safe_component` exists;
            // reaching it only from `run_named` would let a config sit green until a
            // producer ran.
            safe_component("record", &family.record)?;
            if family.writer.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "record `{}`: `writer` names what fills this store and is empty, so the \
                     family could only ever read could-not-look",
                    family.record
                )));
            }
            if !seen.insert(family.record.as_str()) {
                return Err(UsageError::raise(format!(
                    "record `{}` is declared twice; one family has one writer",
                    family.record
                )));
            }
        }
        Ok(())
    }

    /// A family name that cannot escape its store.
    ///
    /// **A path component, checked rather than trusted.** The family and the key both
    /// reach this from a caller's argv, and a `..` or a `/` in either would put a
    /// record outside the store the reader looks in — which is not a security
    /// boundary here so much as a silent miss: the write succeeds, the read finds
    /// nothing, and the gate reads clean.
    pub(crate) fn safe_component(what: &str, value: &str) -> Result<String> {
        let clean = value.trim();
        if clean.is_empty()
            || clean == "."
            || clean == ".."
            || clean.contains('/')
            || clean.contains('\\')
            || clean.contains('\0')
        {
            return Err(UsageError::raise(format!(
                "the {what} must be one path component and must not be `.`, `..`, or contain a separator"
            )));
        }
        Ok(clean.to_owned())
    }
}

pub mod recorder {
    use crate::config_model::{Program, Read, RecorderDeclared as Declared, Value};
    use anyhow::Result;
    use std::collections::BTreeMap;

    /// Refuse, at LOAD, every recorder that could not have written what it claims.
    ///
    /// The refusals below are all of the same kind and it is the kind this repository
    /// keeps choosing: a declaration naming something the tree does not carry is a
    /// gate that runs, resolves nothing, and reports clean. A recorder is worse than
    /// a rule that way, because it has no verdict at all — a column that silently
    /// renders `-` forever looks exactly like a column that looked and could not see.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::UsageError`] (→ exit `1`) naming the recorder, the
    /// column and the missing id.
    pub fn validate(
        recorders: &[Declared],
        programs: &BTreeMap<String, Program>,
        patterns: &std::collections::BTreeSet<String>,
    ) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for recorder in recorders {
            validate_shape(recorder, &mut seen, patterns)?;
            if let Some(recorded) = &recorder.requires_recorded {
                for value in recorded.matches.values() {
                    validate_value(
                        &recorder.name,
                        "requires-recorded",
                        value,
                        programs,
                        patterns,
                    )?;
                }
            }
            for column in &recorder.columns {
                for value in [
                    Some(&column.value),
                    column.minus.as_ref(),
                    column.without.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    validate_value(&recorder.name, &column.name, value, programs, patterns)?;
                }
            }
        }
        Ok(())
    }

    /// The shape refusals, split out of [`validate`] when it hit its own line
    /// ceiling. The seam is the one the function already had: everything here is a
    /// property of the ROW — its name, its selectors, its column count — and
    /// everything left behind walks the expressions inside a column.
    pub(crate) fn validate_shape(
        recorder: &Declared,
        seen: &mut std::collections::BTreeSet<String>,
        patterns: &std::collections::BTreeSet<String>,
    ) -> Result<()> {
        if recorder.name.trim().is_empty() {
            return Err(crate::error::UsageError::raise(
                "a `[[recorder]]` row carries an empty `name`, so nothing can point at it",
            ));
        }
        if recorder.record.trim().is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} names no `record`, so it would write nowhere",
                recorder.name
            )));
        }
        if !seen.insert(recorder.name.clone()) {
            return Err(crate::error::UsageError::raise(format!(
                "two `[[recorder]]` rows are named {:?}, so a finding could not say \
                 which one wrote a line",
                recorder.name
            )));
        }
        if recorder.tool.trim().is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} selects on an empty `tool`, which matches nothing",
                recorder.name
            )));
        }
        // A SELECTOR IS NOT A GLOB, and a row that thinks it is fails SILENTLY.
        //
        // `rules::selects_tool_name` matches the whole name or its final
        // `__`-delimited segment (CLOUD-178, so a connector renamed over its
        // lifetime still matches). A `*save_issue` written by habit from a shell
        // `case` pattern therefore matches nothing at all — and a recorder that
        // never fires is byte-identical, on every surface, to a tool nobody
        // called. Measured here: the whole table was dead and only the cases
        // asserting a row WAS written could see it, because the ones asserting
        // none passed vacuously.
        //
        // Refused at load for that asymmetry: the failure has no loud direction
        // at runtime, so the only place it can be caught is before the run.
        if let Some(found) = recorder
            .tool
            .find(['*', '?', '['])
            .and_then(|at| recorder.tool.get(at..=at))
        {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} selects on tool {:?}, which carries {found:?} — a tool \
                 selector is matched whole or by its final `__`-delimited segment, \
                 never as a glob, so this row would match nothing and record silently",
                recorder.name, recorder.tool
            )));
        }
        for (path, pattern) in &recorder.requires_input_matching {
            if path.trim().is_empty() {
                return Err(crate::error::UsageError::raise(format!(
                    "recorder {:?} matches on an empty input path, which reads nothing \
                     and so never selects",
                    recorder.name
                )));
            }
            if !patterns.contains(pattern) {
                return Err(crate::error::UsageError::raise(format!(
                    "recorder {:?} selects on input {path:?} matching pattern {pattern:?}, \
                     which no `[[pattern]]` row declares — the row would never fire and \
                     a recorder that never fires is indistinguishable from a tool nobody \
                     called",
                    recorder.name
                )));
            }
        }
        if recorder.columns.is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} declares no columns, so it would append blank lines",
                recorder.name
            )));
        }
        if let Some(recorded) = &recorder.requires_recorded {
            if recorded.matches.is_empty() {
                return Err(crate::error::UsageError::raise(format!(
                    "recorder {:?} gates on an empty `requires-recorded`, which every \
                     existing line satisfies — a precondition matching anything is not one",
                    recorder.name
                )));
            }
            for column in recorded.matches.keys() {
                if *column >= recorder.columns.len() {
                    return Err(crate::error::UsageError::raise(format!(
                        "recorder {:?} gates on column {column} of an existing line, but \
                         it declares only {} column(s) — the comparison could never hold",
                        recorder.name,
                        recorder.columns.len()
                    )));
                }
            }
        }
        Ok(())
    }

    /// Every id one expression names, checked against what the config declares.
    pub(crate) fn validate_value(
        recorder: &str,
        column: &str,
        value: &Value,
        programs: &BTreeMap<String, Program>,
        patterns: &std::collections::BTreeSet<String>,
    ) -> Result<()> {
        match value {
            Value::Literal(_)
            | Value::Branch
            | Value::Result(_)
            | Value::Input(_)
            | Value::Inputs(_)
            | Value::Wrap { .. } => Ok(()),
            Value::Object(fields) => fields
                .values()
                .try_for_each(|value| validate_value(recorder, column, value, programs, patterns)),
            Value::Section {
                from,
                label,
                select,
            } => {
                for id in [label, select] {
                    if !patterns.contains(id) {
                        return Err(crate::error::UsageError::raise(format!(
                            "recorder {recorder:?} column {column:?} narrows on pattern {id:?}, \
                             which no `[[pattern]]` row declares — an inline regex is refused here \
                             for the reason a policy module's is, so the id must exist"
                        )));
                    }
                }
                validate_value(recorder, column, from, programs, patterns)
            }
            Value::Program { run, stdin, read } => {
                if !programs.contains_key(run) {
                    return Err(crate::error::UsageError::raise(format!(
                        "recorder {recorder:?} column {column:?} runs program {run:?}, \
                         which no `[program]` row declares"
                    )));
                }
                validate_status_table(recorder, column, run, read)?;
                validate_value(recorder, column, stdin, programs, patterns)
            }
            // NO ID TO RESOLVE, and that is the point of the variant rather than a
            // gap in this function: `ask` is a closed enum, so serde has already
            // refused an authority no build carries. What still needs checking is the
            // status table, which is the consumer's either way.
            Value::Authority { ask, stdin, read } => {
                validate_status_table(recorder, column, &format!("{ask:?}").to_lowercase(), read)?;
                validate_value(recorder, column, stdin, programs, patterns)
            }
        }
    }

    /// A `read = { status = … }` table that can actually decide something.
    ///
    /// Shared by the spawning and the compiled arms: an empty table records
    /// could-not-look for every status, and a key that is not an exit code can never
    /// match one.
    pub(crate) fn validate_status_table(
        recorder: &str,
        column: &str,
        source: &str,
        read: &Read,
    ) -> Result<()> {
        let Read::Status(map) = read else {
            return Ok(());
        };
        if map.is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {recorder:?} column {column:?} reads {source:?}'s status through an empty \
                 table, so every status would record as could-not-look"
            )));
        }
        for status in map.keys() {
            if status.parse::<i32>().is_err() {
                return Err(crate::error::UsageError::raise(format!(
                    "recorder {recorder:?} column {column:?} maps status {status:?}, which is not an \
                     exit code"
                )));
            }
        }
        Ok(())
    }
}

pub mod redirect {
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
}

pub mod refusal {
    use crate::config_model::Ceiling;

    /// Refuse a `[refusal]` table that declares a ceiling nothing could satisfy.
    ///
    /// A zero ceiling would refuse every line including the shortest possible one,
    /// which is the switched-off gate CLOUD-418 names: it fires on everything, so
    /// the first person to run it turns it off. Refused at load, in the same
    /// direction and for the same reason `budget.rs` refuses an empty set.
    ///
    /// # Errors
    ///
    /// When the declared ceiling is zero.
    pub fn validate(ceiling: Option<&Ceiling>) -> Result<(), String> {
        let Some(declared) = ceiling else {
            return Ok(());
        };
        if declared.max_tokens == 0 {
            return Err(
                "`[refusal] max_tokens = 0` refuses every line a refusal could emit, including the \
                 shortest one the grammar can spell — a ceiling nothing can satisfy is a gate that \
                 gets switched off rather than one that holds"
                    .to_owned(),
            );
        }
        if declared.first_sighting_max_tokens == Some(0) {
            return Err(
                "`[refusal] first_sighting_max_tokens = 0` refuses every first sighting a refusal \
                 could emit, including the irreducible one — and the first sighting is the only \
                 firing that carries the class definition, so a zero there withholds the remedy \
                 from the one reader who has not read it"
                    .to_owned(),
            );
        }
        // The first sighting carries strictly more than the repeat — the same line
        // plus a gloss and at least one route — so a first-sighting ceiling at or
        // below the repeat's cannot be met by any line that arm can compose. Refused
        // here rather than discovered as an arm that silently never renders its
        // definition, which is the defect this row exists to remove.
        if let Some(first) = declared.first_sighting_max_tokens
            && first <= declared.max_tokens
        {
            return Err(format!(
                "`[refusal] first_sighting_max_tokens = {first}` is not above `max_tokens = {}`, and \
                 a first sighting is the repeat line plus a gloss and a route — so no line this arm \
                 can compose would fit, and the definition would never render",
                declared.max_tokens
            ));
        }
        Ok(())
    }
}

pub mod rules {

    use crate::config_model::{
        CeilingUnit, Direction, ReceiptKey, ReceiptTrigger, Rule, RuleKind, VerdictProgram,
    };
    use crate::error::UsageError;
    use crate::preset_catalog::RuleScope;

    use crate::selector::Selector;

    use regex::Regex;

    use std::collections::BTreeMap;

    /// Refuse a keying an agent-sourced record cannot be filed under (CLOUD-859).
    ///
    /// `key` became load-bearing on this path when the record started honouring it,
    /// and exactly one of the three values is unreachable here. **The two halves run
    /// on different envelopes**: the record is WRITTEN on the post-tool event of the
    /// fact's own command — a shell call carrying a command line and nothing else —
    /// and READ on the mediated call the receipt row selects. A `head` or `branch`
    /// subject is a fact about the checkout and resolves identically at both moments;
    /// a `named` subject is projected out of the reading call's own arguments, which
    /// the writing call does not have.
    ///
    /// So a `named` agent-sourced check would deny with a `Fix::Run`, the agent would
    /// run the command it names, and no record would be filed — a gate nobody can
    /// satisfy by doing what it asks. That is the failure this whole row exists to
    /// end, so it is refused at load rather than shipped as a column that reads as
    /// configured and files nothing.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::UsageError`] (→ exit `1`) naming the fact and the
    /// row. Pointer-only: two ids, never a command.
    ///
    /// Housed in `rules` rather than `crate::facts` (CLOUD-2789): it reads rule rows,
    /// and `facts` names no module above it.
    pub fn validate_keying(facts: &[crate::facts::Declared], rules: &[Rule]) -> anyhow::Result<()> {
        for rule in rules {
            if rule.kind != RuleKind::Receipt || rule.receipt_key() != ReceiptKey::Named {
                continue;
            }
            for check in rule.receipt_names() {
                if facts.iter().any(|fact| &fact.name == check) {
                    return Err(crate::error::UsageError::raise(format!(
                        "rule {}: `key = \"named\"` over the agent-sourced fact `{check}` — a named \
                         subject is projected from the call this row SELECTS, and the record is \
                         written on the post-tool event of the fact's own command, which carries no \
                         such subject. No record could ever be filed, so the check would deny \
                         forever and running the command it names would not satisfy it. Key it \
                         `head` or `branch`.",
                        rule.id
                    )));
                }
            }
        }
        Ok(())
    }

    /// Validate a whole `[[rule]]` table, and refuse a duplicated id.
    ///
    /// Called at **load** rather than only by a runner (`config::parse_ungated`),
    /// because there are now two runners: the tree engine and `batten hook`. A rule
    /// validated only by the surface that happens to run it is a rule the other
    /// surface accepts malformed — and for the hook that means a policy row that
    /// loads, matches nothing, and reads as coverage.
    ///
    /// Two rows for one id is a policy question with two answers, and silently
    /// taking the first is how a tightening edit gets lost behind a stale row. Same
    /// reasoning, and the same shape, as [`crate::verbs::validate`].
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a malformed or duplicated rule.
    pub fn validate(rules: &[Rule]) -> anyhow::Result<()> {
        validate_rows(rules)?;
        validate_composition(rules, None)
    }

    /// Everything [`validate`] checks except the cross-row composition — split out so
    /// [`validate_in`] can run the composition half with a locator instead of
    /// running it twice and reporting the unlocated message first.
    pub(crate) fn validate_rows(rules: &[Rule]) -> anyhow::Result<()> {
        for (index, rule) in rules.iter().enumerate() {
            rule.validate()?;
            if rules[..index].iter().any(|prior| prior.id == rule.id) {
                return Err(UsageError::raise(format!(
                    "rule {}: declared twice; a rule has one definition",
                    rule.id
                )));
            }
            // One check name, one keying (CLOUD-444). The boundary resolves each
            // required name to a single verdict, so two rows disagreeing about what
            // invalidates the same receipt would silently resolve it one row's way —
            // a branch-keyed claim expiring per commit, or a HEAD-keyed verification
            // outliving the bytes it validated. Both are false greens, and the
            // per-row `validate` cannot see the collision, so it is refused here.
            for prior in &rules[..index] {
                let (Some(mine), Some(theirs)) = (rule.checks.as_ref(), prior.checks.as_ref())
                else {
                    continue;
                };
                if rule.receipt_key() == prior.receipt_key() {
                    continue;
                }
                if let Some(shared) = mine.iter().find(|check| theirs.contains(check)) {
                    return Err(UsageError::raise(format!(
                        "rules {} and {}: both require the receipt `{shared}` under different `key` values; one check name has one keying",
                        prior.id, rule.id
                    )));
                }
            }
            // ONE PLAN ID, ONE QUERY — the same argument as the row above, over
            // `[[rule.plan]]` (CLOUD-949). `plan_facts` writes every declared query
            // into one map keyed by `id`, so two queries sharing an id and differing
            // in `hook`, `required` or `prohibited_profiles` resolve to whichever
            // was inserted last. That is a false green of the worst kind: the
            // module reads `input.tree.plan["gate"]` and is answered about a
            // DIFFERENT surface than the row it belongs to declared, so a required
            // step can go unchecked while the gate reports clean.
            //
            // Refused at LOAD rather than deduplicated at acquisition, because
            // silently picking one of two disagreeing declarations is the same
            // defect one layer down. An IDENTICAL redeclaration is accepted: it
            // names one query, so there is nothing to resolve.
            //
            // The per-row `validate` cannot see this — the collision is between
            // rows as often as within one — which is why it lives here beside
            // CLOUD-444's, whose reasoning it borrows wholesale.
            for query in &rule.plan {
                let collides =
                    |other: &crate::config_model::PlanQuery| other.id == query.id && other != query;
                if let Some(prior) = rules[..index]
                    .iter()
                    .find(|prior| prior.plan.iter().any(collides))
                {
                    return Err(UsageError::raise(format!(
                        "rules {} and {}: both declare the plan `{}` with different terms; one plan id has one query",
                        prior.id, rule.id, query.id
                    )));
                }
                if rule.plan.iter().any(collides) {
                    return Err(UsageError::raise(format!(
                        "rule {}: declares the plan `{}` twice with different terms; one plan id has one query",
                        rule.id, query.id
                    )));
                }
            }
        }
        Ok(())
    }

    /// [`validate`], with the config text in hand so a composition refusal can point
    /// at a **line** rather than only at a rule id (CLOUD-773's §5).
    ///
    /// The located form is what the two real loaders call; the bare [`validate`]
    /// stays for callers holding a rule table and no file — the defaults, and the
    /// runner's own defence in depth. One implementation, an optional locator, so
    /// the two can never disagree about what is refused.
    ///
    /// # Errors
    ///
    /// As [`validate`].
    pub fn validate_in(rules: &[Rule], text: &str, source: &str) -> anyhow::Result<()> {
        validate_rows(rules)?;
        validate_composition(rules, Some(Located { text, source }))
    }

    /// The config text and its path, for turning a rule id into `path:line`.
    #[derive(Clone, Copy)]
    pub(crate) struct Located<'a> {
        pub(crate) text: &'a str,
        pub(crate) source: &'a str,
    }

    /// Where a rule id renders when there is no config text to locate it in.
    pub(crate) fn pointer_for(at: Option<Located<'_>>, id: &str) -> String {
        match at {
            Some(located) => located.pointer(id),
            None => format!("rule {id}"),
        }
    }

    /// Refuse a composition a run could not honour, **at load and never later**.
    ///
    /// Four refusals, and the ordering matters only in that each is checked over the
    /// whole table rather than per row — which is why this cannot live in
    /// [`Rule::validate`]:
    ///
    /// 1. **Two rows deriving one name.** "Which one did I read" is not a question a
    ///    reviewer should have to answer, and the answer would be positional.
    /// 2. **A reference to a name nothing derives.** The row loads, matches a
    ///    document, and compares against a value that will never exist — the
    ///    present-and-inert gate this file is written against.
    /// 3. **A cycle.** Once B can reference A, A can reference B. CLOUD-647 measured
    ///    that the obvious candidate engine reports cycles at *evaluation*, which on
    ///    the mediated path is the worst possible time and the wrong exit class.
    /// 4. **A reference that changes the reading rule's class.** CLOUD-757 settled
    ///    composition as the **meet on both axes**: a derived fact is at most as
    ///    cheap as its most expensive input and at most as wide as its narrowest.
    ///    So if meeting the derivation's class with the reader's own moves it, the
    ///    reader is not the rule it declares itself to be — a `read`-class row would
    ///    silently inherit an `effect`-class dependency, or a hook-surface row would
    ///    answer from a fact never resolvable there.
    ///
    /// Pointer-only (rule 4): a `path:line` and a rule id, never a derived value.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for each of the four. A config declaring a
    /// composition the engine cannot honour is the config-or-usage class, never a
    /// policy verdict about the repository.
    pub(crate) fn validate_composition(
        rules: &[Rule],
        at: Option<Located<'_>>,
    ) -> anyhow::Result<()> {
        let mut derived: BTreeMap<&str, &Rule> = BTreeMap::new();
        for rule in rules {
            let Some(name) = rule.derives.as_deref() else {
                continue;
            };
            if let Some(prior) = derived.insert(name, rule) {
                return Err(UsageError::raise(format!(
                    "{} and {}: both derive `{name}`; a derived value has one definition",
                    pointer_for(at, &prior.id),
                    pointer_for(at, &rule.id)
                )));
            }
        }
        for rule in rules {
            let Some(name) = rule.reads.as_deref() else {
                continue;
            };
            let Some(producer) = derived.get(name).copied() else {
                return Err(UsageError::raise(format!(
                    "{}: reads `{name}`, which no rule derives",
                    pointer_for(at, &rule.id)
                )));
            };
            // The meet on BOTH axes. Equality with the reader's own class is the
            // predicate rather than a comparison per axis, because "did this
            // reference move me" is one question and asking it twice invites the
            // two halves to drift.
            //
            // EACH SIDE IS JUDGED AT ITS OWN SCOPE (CLOUD-833). `fact_class` used to
            // key on the kind alone; a `policy` row is `Free` x `Hook` on the
            // mediated call and `Read` x `Check` on the tree, so asking for one
            // rule's class while holding the other's scope would compare two things
            // neither row declares. `rule.scope` and `producer.scope` are the values
            // each row actually carries, and passing anything else here is how this
            // check would start answering a question nobody asked.
            let mine = rule.kind.fact_class(rule.scope);
            let theirs = producer.kind.fact_class(producer.scope);
            if mine.meet(theirs) != mine {
                return Err(UsageError::raise(format!(
                    "{}: reads `{name}`, derived by {} at cost `{}` on surface `{}`, which a rule at \
                     cost `{}` on surface `{}` cannot carry — composition takes the meet on both axes",
                    pointer_for(at, &rule.id),
                    pointer_for(at, &producer.id),
                    theirs.cost.as_str(),
                    theirs.surface.as_str(),
                    mine.cost.as_str(),
                    mine.surface.as_str()
                )));
            }
        }
        // Depth-first over the reference edges. The graph is tiny — one edge per row
        // that reads — so the walk is the whole algorithm and there is nothing to
        // memoise that would pay for itself.
        for rule in rules {
            if rule.reads.is_none() {
                continue;
            }
            let mut seen: Vec<&str> = vec![rule.id.as_str()];
            let mut here = rule;
            while let Some(name) = here.reads.as_deref() {
                let Some(next) = derived.get(name).copied() else {
                    break;
                };
                if seen.contains(&next.id.as_str()) {
                    return Err(UsageError::raise(format!(
                        "{} and {}: their `reads`/`derives` references form a cycle, so neither \
                         value can be resolved; refused at load, where a cycle costs a config error \
                         rather than a decision",
                        pointer_for(at, &here.id),
                        pointer_for(at, &next.id)
                    )));
                }
                seen.push(next.id.as_str());
                here = next;
            }
        }
        Ok(())
    }

    pub(crate) struct Declared<'a> {
        /// Files a row declared as parsed documents.
        pub documents: &'a [String],
        /// Files a row declared as line sets.
        pub lines: &'a [String],
        /// Rust files a row declared as call sites.
        pub invocations: &'a [String],
        /// Rust files a row declared as a `use` graph.
        pub uses: &'a [String],
        /// The paths this row declared a STAGED read of (CLOUD-1203).
        ///
        /// The ROW's own list rather than the run's, which is what scopes the read to
        /// the declaration: another row's staged path is not in this document.
        pub staged: &'a [String],
        /// The `[[rule.external]]` rows this row declared (CLOUD-1167).
        ///
        /// The ROW's own rows rather than the run's, which is what scopes the read
        /// to the declaration: another row's `external` id is not in this document,
        /// so a module cannot reach a file its own row did not name.
        pub external: &'a [crate::facts::Rooted],
        /// The format to read a STAGED path with when its extension names none.
        ///
        /// `None` is the ordinary case and means the extension is the only authority.
        /// See the `format` column's own note on why this is a fallback rather than
        /// an override.
        pub staged_format: Option<crate::facts::Format>,
    }

    impl Rule {
        pub(crate) fn validate(&self) -> anyhow::Result<()> {
            let kind = self.kind.as_str();
            // Ahead of every per-kind question, so the rename is what the author
            // reads. Left to the census, a `run` on a command rule would report
            // "requires `check`" — true, and silent about the key already holding
            // the value.
            if self.run.is_some() {
                return Err(UsageError::raise(format!(
                    "rule {}: `run` is now `check` (house style §9's check/fix duality); rename the key",
                    self.id
                )));
            }
            self.validate_external_rows()?;
            self.validate_tool_rows()?;
            self.validate_minted_rows()?;
            self.validate_pipeline_tables()?;
            self.validate_sink()?;
            self.validate_exclude_paths()?;
            // The key modifier's own obligations (CLOUD-446). Both here rather than
            // in the column census for the reason stated below it: the census is a
            // per-kind const, and these depend on a value inside the row.
            if let Some(expression) = self.requires_key.as_deref() {
                // Without a range there is nothing to read commit subjects over, so
                // the row would fall back to the branch name alone — a narrowing
                // nobody wrote, arrived at by omission.
                if self.base.is_none() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `requires_key` requires `base` — the rev its commit evidence is read since",
                        self.id
                    )));
                }
                // Compiled at load, like `regex` and `exclude`: an expression the
                // matcher cannot parse must name its row. Left to adjudication it
                // would fail open on every call, which is a gate that reads as
                // present and denies nothing.
                Regex::new(expression).map_err(|err| {
                    UsageError::raise(format!(
                        "rule {}: `requires_key` is not valid: {err}",
                        self.id
                    ))
                })?;
            }
            self.validate_admission_columns()?;
            self.validate_conserves()?;
            // Extracted for `validate_policy_source`'s reason, and it is the same
            // class of obligation: which columns a receipt row owes depends on a
            // value inside it, which the per-kind census cannot say.
            self.validate_shape_columns()?;
            self.validate_polarity()?;
            self.validate_receipt_columns()?;
            // Extracted rather than inlined, because `validate` is at its line ceiling
            // and a per-kind block is what it should shed first: the census above is
            // the general mechanism, and these are the three things a flat column
            // list structurally cannot say about one kind.
            self.validate_policy_source()?;
            self.validate_ask_disposition()?;
            for column in self.kind.requires() {
                let present = self
                    .columns()
                    .into_iter()
                    .any(|(name, present)| name == *column && present);
                if !present {
                    return Err(UsageError::raise(format!(
                        "rule {}: kind \"{kind}\" requires `{column}`",
                        self.id
                    )));
                }
            }
            for (name, present) in self.columns() {
                if present && !self.kind.permits().contains(&name) {
                    return Err(UsageError::raise(format!(
                        "rule {}: `{name}` is not valid for kind \"{kind}\"",
                        self.id
                    )));
                }
            }
            // Scope routes a rule to the surface that evaluates it, so a pairing the
            // engine cannot honour must be refused rather than accepted and never
            // run. An inert rule reads as coverage.
            if !self.kind.scopes().contains(&self.scope) {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"{kind}\" does not evaluate over scope \"{}\"",
                    self.id,
                    self.scope.as_str()
                )));
            }
            if self.glob.as_deref().is_some_and(str::is_empty) {
                return Err(UsageError::raise(format!(
                    "rule {}: `glob` must not be empty",
                    self.id
                )));
            }
            // Compiled at load, like `regex` and `exclude` above it (CLOUD-214): a
            // pattern the matcher cannot parse must name the row that carries it,
            // rather than becoming a rule that selects nothing and reads as a gate
            // that found nothing wrong.
            if let Some(glob) = self.glob.as_deref() {
                Selector::new(glob)
                    .map_err(|err| UsageError::raise(format!("rule {}: {err}", self.id)))?;
            }
            self.validate_command_pattern()?;
            self.validate_forbid_predicate()?;
            self.validate_document_predicate()?;
            self.validate_remediation()
        }
    }

    impl Located<'_> {
        /// `<source>:<line>` for the row declaring `id`, or `<source>` where the
        /// declaration cannot be located.
        ///
        /// A literal search for the `id` key rather than a second TOML parse: the
        /// pointer is a courtesy on an error path, and a parser here would be a
        /// second reader of the file the loader already read.
        pub(crate) fn pointer(self, id: &str) -> String {
            let needle = format!("id = \"{id}\"");
            for (index, line) in self.text.lines().enumerate() {
                if line.trim_start().starts_with(&needle) {
                    return format!("{}:{}", self.source, index + 1);
                }
            }
            self.source.to_owned()
        }
    }

    impl Rule {
        /// The obligation [`RuleKind::permits`] cannot express (CLOUD-758).
        ///
        /// # Errors
        ///
        /// A [`UsageError`] (→ exit `1`) for a shape row carrying neither column, or
        /// both, or a `content` expression the matcher cannot compile.
        ///
        /// A shape row is keyed on a command or on content — exactly one (CLOUD-758).
        ///
        /// The "one of" `forbid`'s `pattern`/`regex` pair carries, and for the same
        /// reason: a row with NEITHER loads, matches every mediated call, and turns
        /// a ban into a universal gate; a row with BOTH is two predicates where the
        /// reader can see one, and a precedence rule nobody can read is worse than a
        /// refusal.
        ///
        /// # Errors
        ///
        pub(crate) fn validate_shape_columns(&self) -> anyhow::Result<()> {
            if self.kind != RuleKind::Shape {
                return Ok(());
            }
            // CLOUD-2669: compiled at load, anchored as the matcher anchors them, so
            // an unparseable word expression never reaches adjudication.
            for (field, shape) in [("word", &self.word), ("unless_word", &self.unless_word)] {
                if let Some(shape) = shape.as_deref() {
                    Regex::new(&format!("^(?:{shape})$")).map_err(|err| {
                        UsageError::raise(format!(
                            "rule {}: `{field}` is not a valid regular expression: {err}",
                            self.id
                        ))
                    })?;
                }
            }
            // THREE KEYING COLUMNS NOW, EXACTLY ONE OF WHICH A ROW CARRIES
            // (CLOUD-924). Counted rather than matched as a tuple: a 2x2 match was
            // already at its readable limit and a 2x2x2 one would spell six
            // impossible arms to reach the two that matter.
            let keys: Vec<&str> = [
                ("pattern", self.pattern.is_some()),
                ("content", self.content.is_some()),
                ("tool", self.tool.is_some()),
                ("on", self.on.is_some()),
            ]
            .into_iter()
            .filter_map(|(name, present)| present.then_some(name))
            .collect();
            if keys.len() > 1 {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"shape\" carries {}; a row is keyed on a command \
                     (`pattern`), on written content (`content`), or on the tool a call names \
                     (`tool`) — never on more than one",
                    self.id,
                    keys.join(" and ")
                )));
            }
            if self.on.is_some() {
                self.validate_on_columns()?;
                return self.validate_ceiling();
            }
            if let Some(selector) = self.tool.as_deref() {
                // Refused at load rather than at adjudication, where an empty
                // selector would match the empty final segment of every name ending
                // in `__` — a row that reads as naming one tool and selects a family.
                if selector.is_empty() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `tool` is empty; name the tool this row is about",
                        self.id
                    )));
                }
                // The same command-only modifiers `content` refuses below, refused
                // for the same reason one column over: a structured call carries no
                // argv either, so each would read as configured and narrow nothing.
                self.refuse_command_modifiers("tool")?;
                return self.validate_ceiling();
            }
            match (self.pattern.is_some(), self.content.as_deref()) {
                (true, None) => self.validate_ceiling(),
                // Compiled at load, the way `regex`, `exclude` and `requires_key`
                // already are. Left to adjudication an unparseable expression is
                // skipped on every mediated call, which is a gate that reads as
                // configured in the file and denies nothing — the one failure this
                // kind's whole validation surface exists to close.
                (false, Some(expression)) => {
                    Regex::new(expression).map_err(|err| {
                        UsageError::raise(format!(
                            "rule {}: `content` is not a valid regular expression: {err}",
                            self.id
                        ))
                    })?;
                    // AND THE COMMAND-ONLY MODIFIERS ARE REFUSED HERE, because the
                    // column census permits them on this kind and `adjudicate`
                    // evaluates only `content` for a content-keyed row. Left to load
                    // they are accepted, ignored on every call, and the row denies
                    // writes the configuration appears to narrow — a rule that reads
                    // as scoped and is not, which is the same inert-coverage failure
                    // the `content` compile above closes one column over.
                    //
                    self.refuse_command_modifiers("content")?;
                    self.validate_ceiling()
                }
                (false, None) => Err(UsageError::raise(format!(
                    "rule {}: kind \"shape\" requires `pattern` (a command line), `content` (a \
                     regex over what a write would land), or `tool` (the tool a call names)",
                    self.id
                ))),
                // Unreachable: the count above refuses every row carrying more than
                // one keying column, and this is one of those. Kept as an arm rather
                // than wildcarded so a fourth keying column has to come back here and
                // be decided (non-negotiable rule 6's shape, applied to a match).
                (true, Some(_)) => Err(UsageError::raise(format!(
                    "rule {}: kind \"shape\" carries both `pattern` and `content`; a row is keyed \
                     on a command or on written content, never on both",
                    self.id
                ))),
            }
        }

        /// The three ceiling columns travel together, or none of them does
        /// (CLOUD-925).
        ///
        /// A value inside the row decides the obligation, so the per-kind census
        /// structurally cannot state it — the same reason `receipt`'s
        /// trigger-dependent columns and `policy`'s one-of-three source live here.
        ///
        /// Each partial row is a distinct silent failure and that is why all three
        /// are refused rather than defaulted: a `max` with no `measures` caps
        /// something unnamed, a `measures` with no `max` measures and decides
        /// nothing, and a pair with no `counts` cannot say whether 6000 means tokens
        /// or artifacts — which is a cap off by three orders of magnitude, in the
        /// permissive direction.
        ///
        /// # Errors
        ///
        /// A [`UsageError`] (→ exit `1`) naming the columns a partial row is missing.
        /// The two polarity modifiers may not name the same projection (CLOUD-987).
        ///
        /// A row asking for one key to be both absent and present can never fire, so
        /// it loads, matches nothing, and reads from the file as a narrowing — the
        /// inert-coverage failure this whole validation surface refuses. Naming
        /// *different* projections is legitimate and is what row 3 wants.
        ///
        /// # Errors
        ///
        /// A [`UsageError`] (→ exit `1`) naming the projection asked for twice.
        pub(crate) fn validate_polarity(&self) -> anyhow::Result<()> {
            if let (Some(absent), Some(present)) = (self.when_absent, self.when_present)
                && absent == present
            {
                return Err(UsageError::raise(format!(
                    "rule {}: `when_absent` and `when_present` both name the same projection, so \
                     this row can never fire; name different ones or drop one",
                    self.id
                )));
            }
            // THE VALUE QUALIFIER TRAVELS WITH ITS PROJECTION (CLOUD-312 row 3), and
            // both directions are refused because each is a different silent failure.
            //
            // A value with no `when_present` names nothing to read it out of, so the
            // row compares against a projection it never took — a column that reads as
            // a narrowing and performs none.
            //
            // **HERE RATHER THAN IN `validate_receipt_columns`**, which is where these
            // two were written first and where they were half-dead: `when_value` is
            // permitted on `shape` as well as `receipt`, and that function returns
            // early for every other kind — so a `shape` row carrying the column with
            // no projection loaded clean and narrowed nothing. Caught in review on
            // #680. Every kind that can carry the column reaches this function.
            if self.when_value.is_some() && self.when_present.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `when_value` qualifies `when_present` — name the projection whose value \
                     this is, or the row compares against nothing and narrows nothing",
                    self.id
                )));
            }
            // EMPTY **AFTER FOLDING**, not before, and the difference is the whole
            // check. The comparison drops spaces, underscores and hyphens, so `"___"`
            // and `"---"` fold to nothing and then compare equal to any value made
            // only of separators — a match nobody intended. Testing the raw string for
            // emptiness caught `""` and let the other two through, which is the defect
            // the previous version of this comment described without covering.
            if self
                .when_value
                .as_deref()
                .is_some_and(|value| crate::config_model::comparable(value).is_empty())
            {
                return Err(UsageError::raise(format!(
                    "rule {}: `when_value` folds to nothing, so it matches any value made only of \
                     spaces, underscores or hyphens; name the value this row is about",
                    self.id
                )));
            }
            Ok(())
        }

        /// Refuse the command-only modifiers on a row keyed by `keyed_on`, a column
        /// that names no command line.
        ///
        /// Shared by the `content` and `tool` arms of [`Rule::validate_shape_columns`]
        /// because the argument is identical one column over, and stating it twice is
        /// how the two would drift when an eighth modifier lands. Each of the seven
        /// names a COMMAND: `contains` and `unless_contains` are substring tests over
        /// an argv in the two polarities, `word` and `unless_word` the same over its
        /// whole words, `require_via` is a via-shape test over the
        /// same argv, `requires_key` asks whether the work is keyed before a
        /// command may run, and `base` exists only to tell `requires_key` which
        /// commits to read. A write and a structured call carry no argv for any of
        /// them to read, so left to load they are accepted, ignored on every call,
        /// and the row narrows nothing the configuration appears to narrow.
        ///
        /// # Errors
        ///
        /// A [`UsageError`] (→ exit `1`) naming the first modifier present.
        pub(crate) fn refuse_command_modifiers(&self, keyed_on: &str) -> anyhow::Result<()> {
            self.refuse_argv_modifiers(keyed_on)?;
            for (field, present) in [
                ("requires_key", self.requires_key.is_some()),
                ("base", self.base.is_some()),
            ] {
                if present {
                    return Err(self.modifier_refused(keyed_on, field));
                }
            }
            Ok(())
        }

        /// Refuse a `pattern` the command matcher cannot honour (CLOUD-401).
        ///
        /// The empty-operand fix closed one row that loaded into silence; this
        /// closes the **class**. `hook::matching_shape_rows` and
        /// `hook::matching_receipt_rows` compare a pattern against a command that
        /// has already been normalised two ways — `effective_program` has stepped
        /// past env assignments and look-through wrappers, and the operand words
        /// have had every flag dropped — so a pattern naming what that
        /// normalisation removes is a row that can never fire. It loads clean,
        /// gates nothing, and reads as coverage, which is the exact defect
        /// [`validate`]'s doc comment is written against.
        ///
        /// Refused here rather than in the per-kind column census because the
        /// census is a const list of column NAMES: this depends on the value inside
        /// the column. Both surfaces that key on a command line are covered — a
        /// `shape` row's ban and a `receipt` row's trigger read the same pattern
        /// through the same matcher (`Rule::trigger`), so a rule inert on one is
        /// inert on the other.
        ///
        /// A program-only pattern is **valid**, and that is the point: it is the
        /// reading `Rule::pattern`'s doc comment already invites, and the one this
        /// validator must not take back.
        pub(crate) fn validate_command_pattern(&self) -> anyhow::Result<()> {
            // The kinds that key on a command line. A `write`-triggered receipt row
            // is refused a `pattern` outright above, so it never reaches here.
            let keys_on_a_command = self.kind == RuleKind::Shape
                || (self.kind == RuleKind::Receipt
                    && self.receipt_trigger() == ReceiptTrigger::Command);
            if !keys_on_a_command {
                return Ok(());
            }
            if self.pattern.is_none() {
                return Ok(());
            }
            // `trigger()` yields nothing for a pattern with no word in it, and a
            // row it cannot read is a row the matcher skips.
            let Some((program, wanted)) = self.trigger() else {
                return Err(UsageError::raise(format!(
                    "rule {}: `pattern` names no program; a pattern of only whitespace matches no command",
                    self.id
                )));
            };
            if crate::config_model::is_lookthrough_wrapper(program) {
                return Err(UsageError::raise(format!(
                    "rule {}: `pattern` names the wrapper `{program}`, which the matcher looks THROUGH to judge the program it wraps; name that program instead",
                    self.id
                )));
            }
            if crate::config_model::is_env_assignment(program) {
                return Err(UsageError::raise(format!(
                    "rule {}: `pattern` starts with the environment assignment `{program}`, which the matcher steps past; name the program instead",
                    self.id
                )));
            }
            if let Some(flag) = wanted.iter().find(|word| word.starts_with('-')) {
                return Err(UsageError::raise(format!(
                    "rule {}: `pattern` requires the flag `{flag}`, and the matcher compares operand words with flags already dropped; use `contains` for a flag",
                    self.id
                )));
            }
            Ok(())
        }

        /// The value-dependent obligations on the two ratchet admission columns,
        /// [`Rule::retires_with`] and [`Rule::admits_with`].
        ///
        /// Extracted from [`Rule::validate`] for `validate_conserves`'s reason — the
        /// per-kind census sees a present column and nothing about what is inside it
        /// — and the two are here together because they are the same three refusals
        /// mirrored, so a reader comparing them should not have to hold two screens.
        ///
        /// Each column admits ONE direction of change, and all three refusals close
        /// the same failure: a column that reads as a configured permission and
        /// decides nothing.
        ///
        /// * **`base` must be there.** Each column asks a question about another
        ///   tree — was this subject alive, was this file absent — and there is no
        ///   such tree without it. The ratchet kind already requires `base`, but the
        ///   obligation is on the VALUE, so a future kind taking either column
        ///   inherits the refusal rather than the omission.
        /// * **The token must not be blank.** An empty prefix matches at the start of
        ///   every line, so every file would "declare" whatever its first line
        ///   happens to say. That is `requires_key`'s compile-at-load failure in the
        ///   one form these columns can take it.
        /// * **The direction must be the one the column governs.** This is the blank
        ///   token's failure reached by the other axis, and it is the sharper of the
        ///   two because the column is not merely inert on the wrong row — it
        ///   switches the row OFF. `retires_with`'s block inspects only the files
        ///   whose count FELL, so on a `non_increasing` row it collects no subject,
        ///   leaves the blocker set empty, and the evaluator returns clean over every
        ///   increase. `undeclared_growth` is the mirror: it inspects only the files
        ///   that ROSE, so on a `non_decreasing` row every decrease is admitted in
        ///   silence. Found by review of #694 on `admits_with`; the sibling had
        ///   carried it latent since CLOUD-807.
        pub(crate) fn validate_admission_columns(&self) -> anyhow::Result<()> {
            for (name, token, wanted, wanted_name, base_reason) in [
                (
                    "retires_with",
                    self.retires_with.as_deref(),
                    Direction::NonDecreasing,
                    "DECREASE",
                    "the rev a subject must have been alive at",
                ),
                (
                    "admits_with",
                    self.admits_with.as_deref(),
                    Direction::NonIncreasing,
                    "INCREASE",
                    "an increase is only decidable against the tree a file was absent from",
                ),
            ] {
                let Some(token) = token else {
                    continue;
                };
                if self.base.is_none() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `{name}` requires `base` — {base_reason}",
                        self.id
                    )));
                }
                if token.trim().is_empty() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `{name}` cannot be blank — it is the line prefix a declaration is read after, and an empty one matches every line",
                        self.id
                    )));
                }
                if self.direction != Some(wanted) {
                    return Err(UsageError::raise(format!(
                        "rule {}: `{name}` requires `direction = \"{}\"` — it admits a {wanted_name}, and on a row that refuses the other direction it switches the row off instead of refining it",
                        self.id,
                        wanted.as_str(),
                    )));
                }
            }
            Ok(())
        }

        /// Every token in a [`Conserves`] decides something, so a blank one is a
        /// configured admission (CLOUD-908).
        ///
        /// The obligations, and each closes a way the mapping could read as present
        /// and decide nothing:
        ///
        /// * **`retires_with` must be there.** This column refines that admission. A
        ///   ratchet that never permits a decrease has no deletion to map, so the
        ///   mapping would be inert — and inert coverage is what the whole row is
        ///   about.
        /// * **No token may be blank.** An empty prefix matches at the start of every
        ///   line, so every line would "declare" a case or claim one. The same
        ///   reading `retires_with` takes over its own token.
        /// * **The three arms must be distinct.** Two arms spelled alike make "exactly
        ///   one arm" undecidable: one line would claim a case twice, and the refusal
        ///   for a double claim would fire on every correct mapping instead.
        /// * **`declared_in` must compile.** A glob `globset` cannot parse selects
        ///   nothing, and a mapping read over nothing admits every deletion.
        pub(crate) fn validate_conserves(&self) -> anyhow::Result<()> {
            let Some(conserves) = self.conserves.as_ref() else {
                return Ok(());
            };
            if self.retires_with.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `conserves` requires `retires_with` — it obliges a mapping INSIDE that column's admission, and a ratchet that admits no decrease has no deletion to map",
                    self.id
                )));
            }
            for (name, token) in [
                ("case", &conserves.case),
                ("close", &conserves.close),
                ("carried", &conserves.carried),
                ("subsumed", &conserves.subsumed),
                ("changed", &conserves.changed),
                ("declared_in", &conserves.declared_in),
            ] {
                if token.trim().is_empty() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `conserves.{name}` cannot be blank — every token here decides something, and an empty one matches every line",
                        self.id
                    )));
                }
            }
            // Blank is refused for the optional arm too, where it is DECLARED: an
            // empty token matches every line, so `withdrawn = ""` would claim every
            // case in the ledger. Absent and blank are different answers, and only the
            // first one means "this row has three arms".
            for (name, token) in [
                ("withdrawn", conserves.withdrawn.as_deref()),
                ("ported", conserves.ported.as_deref()),
            ] {
                if let Some(token) = token
                    && token.trim().is_empty()
                {
                    return Err(UsageError::raise(format!(
                        "rule {}: `conserves.{name}` is declared but blank — an empty token matches every line, which would claim every case. Remove the key to leave the arm undeclared.",
                        self.id
                    )));
                }
            }
            let arms: Vec<&String> = [
                Some(&conserves.carried),
                Some(&conserves.subsumed),
                Some(&conserves.changed),
                conserves.withdrawn.as_ref(),
                conserves.ported.as_ref(),
            ]
            .into_iter()
            .flatten()
            .collect();
            for (index, arm) in arms.iter().enumerate() {
                if arms[index + 1..].contains(arm) {
                    return Err(UsageError::raise(format!(
                        "rule {}: `conserves` spells two arms alike, so \"exactly one arm\" cannot be decided — one line would claim a case twice",
                        self.id
                    )));
                }
            }
            Selector::new(&conserves.declared_in)?;
            Ok(())
        }

        pub(crate) fn validate_remediation(&self) -> anyhow::Result<()> {
            if let Some(why) =
                crate::remedy::malformed(self.fix.as_deref(), self.no_fix_reason.as_deref())
            {
                return Err(UsageError::raise(format!("rule {}: {why}", self.id)));
            }
            // `no_retry_reason` WITHOUT a repair says why something that never runs
            // does not hand back — a sentence about nothing (CLOUD-1639). The
            // converse (a `fix` with no `no_retry_reason`) is legal and is the
            // ordinary `retry` row; what makes it owed is the CLASS declaring
            // `silent`, which is a cross-table question and lives in
            // `crate::policy::check_repairs_are_applicable`.
            if self.no_retry_reason.is_some() && self.fix.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `no_retry_reason` says why a repair does not hand the call back, and \
                     this row declares no `fix` to repair with",
                    self.id
                )));
            }
            Ok(())
        }
    }

    impl Rule {
        pub(crate) fn validate_ceiling(&self) -> anyhow::Result<()> {
            let declared: Vec<&str> = [
                ("measures", self.measures.is_some()),
                ("counts", self.counts.is_some()),
                ("max", self.max.is_some()),
            ]
            .into_iter()
            .filter_map(|(name, present)| present.then_some(name))
            .collect();
            if declared.is_empty() {
                // A rewrite table with no ceiling to serve rewrites nothing, and
                // reads from the file as though it narrowed a count.
                if !self.resolves.is_empty() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `resolves` needs a `counts = \"tracked-artifacts\"` ceiling to \
                         serve; on its own it rewrites nothing",
                        self.id
                    )));
                }
                return Ok(());
            }
            if declared.len() != 3 {
                return Err(UsageError::raise(format!(
                    "rule {}: a per-call ceiling needs `measures`, `counts` and `max` together; \
                     this row carries only {}. A partial ceiling measures something it cannot \
                     decide over, or caps a number whose unit is unstated",
                    self.id,
                    declared.join(" and ")
                )));
            }
            // TOOL-KEYED ONLY, and narrower than the column census can say.
            //
            // A ceiling is a modifier over a selection, and the only selection it has
            // a consumer for is a tool: CLOUD-312's row 6 is `fanout-guard`, which
            // fires on `Task`. Admitting it on a `pattern` row would ship a
            // combination with no test behind it and no caller asking for it, and
            // `rules/rust.md`'s reading is that the cheap default is the one
            // direction the mistake is expensive in. Widening this is one line plus
            // the cases that prove it.
            if self.tool.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: a per-call ceiling is keyed on `tool` — the ceiling decides whether \
                     that selection refuses, and a command-keyed one has no consumer yet",
                    self.id
                )));
            }
            // A lint count measures a file, not a call: it has nothing to read on an
            // envelope.
            if self.counts == Some(CeilingUnit::LintEscapes) {
                return Err(UsageError::raise(format!(
                    "rule {}: `lint_escapes` is a ratchet's file measure; a per-call ceiling \
                     counts `tokens` or `tracked_artifacts`",
                    self.id
                )));
            }
            // A rewrite table only means something to the unit that resolves paths.
            // On a token ceiling it would load, rewrite nothing, and read as a
            // narrowing — the inert-coverage failure this whole surface refuses.
            if !self.resolves.is_empty() && self.counts != Some(CeilingUnit::TrackedArtifacts) {
                return Err(UsageError::raise(format!(
                    "rule {}: `resolves` belongs to `counts = \"tracked-artifacts\"`; a token \
                     ceiling resolves no paths",
                    self.id
                )));
            }
            // Compiled at load, the way `regex`, `exclude` and `content` are: left to
            // adjudication an unparseable expression is skipped on every call, which
            // makes the ceiling count LESS than it should — the permissive direction,
            // and silent.
            for rewrite in &self.resolves {
                Regex::new(&rewrite.reference).map_err(|err| {
                    UsageError::raise(format!(
                        "rule {}: `resolves.reference` is not a valid regular expression: {err}",
                        self.id
                    ))
                })?;
            }
            Ok(())
        }

        /// The modifiers that read the command's ARGV (CLOUD-2662): refused on a
        /// row keyed by anything that names none, which an `on` row does not either,
        /// since its routes include structured calls.
        pub(crate) fn refuse_argv_modifiers(&self, keyed_on: &str) -> anyhow::Result<()> {
            for (field, present) in [
                ("contains", self.contains.is_some()),
                ("unless_contains", self.unless_contains.is_some()),
                ("word", self.word.is_some()), // the argv's own words
                ("unless_word", self.unless_word.is_some()), // the argv's own words, exempting
                ("require_via", self.require_via.is_some()),
            ] {
                if present {
                    return Err(self.modifier_refused(keyed_on, field));
                }
            }
            Ok(())
        }

        pub(crate) fn modifier_refused(&self, keyed_on: &str, field: &str) -> anyhow::Error {
            UsageError::raise(format!(
                "rule {}: kind \"{}\" keyed on `{keyed_on}` cannot carry `{field}`; \
                 that column narrows a command line, and this row names none",
                self.id,
                self.kind.as_str()
            ))
        }

        /// The columns an `on` row may not carry (CLOUD-2662): the argv modifiers,
        /// and the per-call projections, which differ per route (`input-draft` is
        /// absent on every shell call) and so would silently drop whole routes.
        /// `requires_key`, `base` and the branch modifiers read the branch, which
        /// every route has, and stay.
        pub(crate) fn validate_on_columns(&self) -> anyhow::Result<()> {
            self.refuse_argv_modifiers("on")?;
            for (field, present) in [
                ("when_absent", self.when_absent.is_some()),
                ("when_present", self.when_present.is_some()),
                ("when_value", self.when_value.is_some()),
            ] {
                if present {
                    return Err(self.modifier_refused("on", field));
                }
            }
            Ok(())
        }

        /// The obligations a receipt row carries that [`RuleKind::permits`] cannot
        /// express (CLOUD-444).
        ///
        /// Which columns a receipt row owes depends on its `trigger`, a value inside
        /// the row — so the per-kind census cannot state it, exactly as it cannot
        /// state a policy row's one-of-three source. Both refusals have the same
        /// reasoning: a column that reads as configured and decides nothing is the
        /// defect this kind was added to close.
        ///
        /// # Errors
        ///
        /// A [`UsageError`] (→ exit `1`) for a command-triggered row with no
        /// `pattern`, for a write-triggered row carrying either command column, and
        /// for an empty `checks` list.
        /// The `delta` key and its base travel together (CLOUD-1547).
        ///
        /// Refused in BOTH directions, for the reason `key_from`'s pair is and with
        /// the same pair of silent failures one keying over.
        ///
        /// A `delta` key with no base has no second side to diff against, so it has
        /// no identity at all and would read no file for any call — which reads as
        /// *never reviewed* and denies everything. That is the direction that gets a
        /// guard switched off rather than satisfied, and it is worse than the
        /// permissive one here precisely because it looks like the gate working. A
        /// base on any other key is the mirror: a column that reads as configured and
        /// is never consulted.
        ///
        /// **Its own function rather than a fourth arm inside
        /// [`Rule::validate_receipt_columns`]**, which clippy's line ceiling forced
        /// and which is the right shape anyway: that one decides what a `trigger`
        /// owes, and this decides what a `key` owes.
        ///
        /// # Errors
        ///
        /// A [`UsageError`] (→ exit `1`) for `key = "delta"` with no `key_base`, and
        /// for a `key_base` on any other keying.
        pub(crate) fn validate_delta_base(&self) -> anyhow::Result<()> {
            match (self.receipt_key(), self.key_base.as_deref()) {
                (ReceiptKey::Delta, None) => Err(UsageError::raise(format!(
                    "rule {}: `key = \"delta\"` requires `key_base` — the ref the identity is taken \
                     against. Without one the change has no second side to diff, so the receipt \
                     would be keyed on nothing and no call could ever satisfy it",
                    self.id
                ))),
                (key, Some(_)) if key != ReceiptKey::Delta => Err(UsageError::raise(format!(
                    "rule {}: `key_base` belongs to `key = \"delta\"`; a {} receipt is keyed on a ref \
                     or a value rather than on a diff, so there is nothing to take a base against",
                    self.id,
                    match key {
                        ReceiptKey::Head => "head-keyed",
                        ReceiptKey::Branch => "branch-keyed",
                        ReceiptKey::Named => "named-keyed",
                        ReceiptKey::Delta => unreachable!("guarded by the arm above"),
                    }
                ))),
                _ => Ok(()),
            }
        }

        /// A receipt row's selectors (CLOUD-2662): exactly one of `pattern`, `tool`
        /// and `on` on a command-triggered row, and no command selector on a
        /// write-triggered one. Split from [`Rule::validate_receipt_columns`], whose
        /// line budget the third selector spent.
        pub(crate) fn validate_receipt_selectors(&self) -> anyhow::Result<()> {
            match self.receipt_trigger() {
                // A command-triggered row selecting on NOTHING matches every
                // mediated call, turning a precondition into a universal gate.
                // `tool` satisfies the obligation as well as `pattern` does
                // (CLOUD-924): both name what the row is about, one by command line
                // and one by the tool a structured call names — and CLOUD-312's rows
                // 1-3 are precisely the second shape.
                ReceiptTrigger::Command
                    if self.pattern.is_none() && self.tool.is_none() && self.on.is_none() =>
                {
                    return Err(UsageError::raise(format!(
                        "rule {}: kind \"receipt\" with `trigger = \"command\"` (the default) requires `pattern` (the command whose precondition this is) or `tool` (the tool a structured call names)",
                        self.id
                    )));
                }
                // Both columns key on one call, and a row carrying both is two
                // selectors where a reader can see one — `validate_shape_columns`'
                // argument, on the kind that shares the columns.
                ReceiptTrigger::Command
                    if [
                        self.pattern.is_some(),
                        self.tool.is_some(),
                        self.on.is_some(),
                    ]
                    .into_iter()
                    .filter(|present| *present)
                    .count()
                        > 1 =>
                {
                    return Err(UsageError::raise(format!(
                        "rule {}: kind \"receipt\" carries both `pattern` and `tool`; a row is keyed on a command line or on the tool a call names, never on both",
                        self.id
                    )));
                }
                // A write carries no command line, so either column would sit there
                // matching nothing while reading as a narrowing. `tool` is NOT
                // refused here: a write tool has a name, and keying a write-triggered
                // row to one is how a precondition narrows from every write to the
                // writes a particular tool makes.
                ReceiptTrigger::Write if self.on.is_some() => {
                    return Err(UsageError::raise(format!(
                        "rule {}: kind \"receipt\" with `trigger = \"write\"` cannot carry `on`; the event is a call, not a write",
                        self.id
                    )));
                }
                ReceiptTrigger::Write if self.pattern.is_some() || self.contains.is_some() => {
                    return Err(UsageError::raise(format!(
                        "rule {}: kind \"receipt\" with `trigger = \"write\"` takes neither `pattern` nor `contains` — a write has no command line for either to match",
                        self.id
                    )));
                }
                _ => {}
            }
            if self.on.is_some() {
                self.validate_on_columns()?;
            }
            Ok(())
        }

        pub(crate) fn validate_receipt_columns(&self) -> anyhow::Result<()> {
            if self.kind != RuleKind::Receipt {
                return Ok(());
            }
            // `key = "branch"` was refused from this same spot until the
            // branch-keyed store existed; every refusal here has that one's
            // reasoning — a column that reads as configured and decides nothing is
            // the defect this kind was added to close.
            self.validate_receipt_selectors()?;
            // THE `named` KEY AND ITS PROJECTION TRAVEL TOGETHER (CLOUD-987), and
            // both halves are refused because each is a different silent failure.
            //
            // A `named` key with no projection has no subject, so it would read one
            // file for every call — `ReceiptKey::Branch` under another name, and the
            // collapse that variant's doc refuses. A projection with some other key
            // is a column that reads as configured and is never consulted.
            match (self.receipt_key(), self.key_from) {
                (ReceiptKey::Named, None) => {
                    return Err(UsageError::raise(format!(
                        "rule {}: `key = \"named\"` requires `key_from` — the projection that supplies \
                         the subject. Without one the receipt would be keyed on nothing and read the \
                         same file for every call",
                        self.id
                    )));
                }
                (key, Some(_)) if key != ReceiptKey::Named => {
                    return Err(UsageError::raise(format!(
                        "rule {}: `key_from` belongs to `key = \"named\"`; a {} receipt takes its \
                         subject from the checkout, not from the call",
                        self.id,
                        match key {
                            ReceiptKey::Head => "head-keyed",
                            ReceiptKey::Branch => "branch-keyed",
                            ReceiptKey::Named => unreachable!("guarded by the arm above"),
                            ReceiptKey::Delta => "delta-keyed",
                        }
                    )));
                }
                _ => {}
            }
            self.validate_delta_base()?;
            // COMPILED AT LOAD, for the reason `resolves.reference` is and with the
            // failure running the same direction: left to adjudication an unparseable
            // expression is discarded per call, the subject resolves to absent,
            // `verdicts` reads that as could-not-look, and the call is ALLOWED. So a
            // typo silently disables the row it was meant to qualify — the permissive
            // direction, and invisible.
            //
            // This clause is here because the column shipped without it while its own
            // doc comment claimed it: caught in review on #680, and the comment was
            // the worse half, because a stated invariant is what stops the next reader
            // checking.
            if let Some(shape) = self.key_shape.as_deref() {
                Regex::new(shape).map_err(|err| {
                    UsageError::raise(format!(
                        "rule {}: `key_shape` is not a valid regular expression: {err}",
                        self.id
                    ))
                })?;
            }
            // A zero bound expires a receipt the instant it is written, so the row
            // refuses every call it selects while reading from the file as though it
            // permitted a fresh one. Same shape as the empty-`checks` refusal below:
            // a column whose value makes the row unsatisfiable is a config error, not
            // a very strict policy.
            if self.max_age == Some(0) {
                return Err(UsageError::raise(format!(
                    "rule {}: `max_age = 0` expires every receipt the moment it is written, so no call \
                     can satisfy this row; name the number of seconds a receipt stays good for",
                    self.id
                )));
            }
            // Refused for `validate_shape_columns`' reason, on the kind that shares
            // the column: an empty selector would match the empty final segment of
            // every name ending in `__`.
            if self.tool.as_deref().is_some_and(str::is_empty) {
                return Err(UsageError::raise(format!(
                    "rule {}: `tool` is empty; name the tool this row is about",
                    self.id
                )));
            }
            // Both halves of the field bound are refused for the reason `max_age = 0`
            // is: a value that makes the column decide nothing reads from the file as
            // though it decided something. `at = 0` names no field under 1-indexed
            // counting, so it can never match and the row would satisfy every call
            // through the absent-is-could-not-look arm; an empty `is` would be
            // satisfied only by a receipt field that is itself empty, which the
            // whitespace split cannot produce.
            if let Some(bound) = self.requires_field.as_ref() {
                if bound.at == 0 {
                    return Err(UsageError::raise(format!(
                        "rule {}: `requires_field.at = 0` names no field — receipt fields are counted \
                         from 1, as every reader of these receipts already counts them",
                        self.id
                    )));
                }
                if bound.is.is_empty() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `requires_field.is` is empty, so no receipt field can ever match it \
                         and the row would decide nothing; name the value that satisfies this row",
                        self.id
                    )));
                }
            }
            self.validate_receipt_names()?;
            self.validate_marker()
        }

        /// A `while_marker` must name a family that landing sweeps (CLOUD-1390).
        ///
        /// **A REFUSAL NEEDS A SPEND, and this is the only thing that supplies one.**
        /// The column's whole contract is *fires while the marker exists*; what makes
        /// that finite is [`crate::land::retire_branch`] deleting the file. Name a
        /// family outside [`crate::config_model::BRANCH_KEYED_RECEIPTS`] and the row is a
        /// deny nothing clears — the work lands, the marker survives the retirement,
        /// and the next piece of work to reuse the branch name is refused for a punt
        /// somebody else took. That is CLOUD-774's inherited-suppression defect in the
        /// refusing direction, which is strictly worse than the advisory one.
        ///
        /// Asserted at load rather than documented, because the doc on
        /// [`Rule::while_marker`] said exactly this and a sentence in a doc comment
        /// stops nobody (non-negotiable rule 2). The pair can now only drift by
        /// failing.
        ///
        /// # Errors
        ///
        /// A [`UsageError`] (→ exit `1`) naming the row and the marker. Pointer-only:
        /// the two ids and the permitted list, never a path from the receipt store.
        pub(crate) fn validate_marker(&self) -> anyhow::Result<()> {
            let Some(marker) = self.while_marker.as_deref() else {
                return Ok(());
            };
            if crate::config_model::BRANCH_KEYED_RECEIPTS.contains(&marker) {
                return Ok(());
            }
            Err(UsageError::raise(format!(
                "rule {}: `while_marker = \"{marker}\"` names no branch-keyed receipt family, so \
                 landing would not clear it and the row would deny forever — including on the next \
                 piece of work to reuse the branch name. Name one of: {}",
                self.id,
                crate::config_model::BRANCH_KEYED_RECEIPTS.join(", ")
            )))
        }

        /// The three refusals over a receipt row's two name columns (CLOUD-1297).
        ///
        /// Split out of [`Rule::validate_receipt_columns`] because that function
        /// crossed the 100-line bound when the alternation arrived, and this is the
        /// half that comes out whole: every arm here is about WHICH RECEIPTS the row
        /// names, where everything left behind is about the trigger and the columns
        /// it implies.
        ///
        /// # Errors
        ///
        /// A [`UsageError`] (→ exit `1`) for an empty `checks` list, an empty
        /// `checks_any` list, or a row naming neither column.
        pub(crate) fn validate_receipt_names(&self) -> anyhow::Result<()> {
            // A row naming an empty `checks` list gates its trigger on nothing and
            // allows every call, which reads as coverage from the file.
            if self.checks.as_ref().is_some_and(Vec::is_empty) {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"receipt\" requires at least one entry in `checks`; an empty list gates nothing",
                    self.id
                )));
            }
            // The same refusal for the alternation, and it is worth its own arm
            // rather than folding into the one above: an empty ALTERNATION is
            // satisfied by nothing, so a row carrying one can never allow a call at
            // all. That fails in the opposite direction to an empty conjunction —
            // one gates nothing, the other gates everything — and a reader handed a
            // single message would be told the wrong thing about their row.
            if self.checks_any.as_ref().is_some_and(Vec::is_empty) {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"receipt\" requires at least one entry in `checks_any`; an empty alternation is satisfied by no receipt, so the row could never allow a call",
                    self.id
                )));
            }
            // CLOUD-1297's conditional requirement, standing in for the `checks`
            // entry `RuleKind::permits` used to carry. A row naming NEITHER column
            // gates its trigger on nothing and allows every call — the same defect
            // the empty-`checks` arm above refuses, arrived at by omission rather
            // than by an empty list, and the census cannot express "one of these
            // two".
            if self.checks.is_none() && self.checks_any.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"receipt\" requires `checks` (every named receipt must be valid) or `checks_any` (any one of them), or both; a row naming neither gates its trigger on nothing",
                    self.id
                )));
            }
            Ok(())
        }

        /// `ask` is a MEDIATED-CALL disposition, and both refusals below are config
        /// faults rather than silent downgrades (CLOUD-340).
        ///
        /// Extracted for the reason its neighbours are: `validate` is at its line
        /// ceiling, and this is a question about a value INSIDE the row — a
        /// severity, not a kind — which the per-kind census structurally cannot ask.
        ///
        /// # Errors
        ///
        /// A [`UsageError`] (→ exit `1`) when a non-`mediated_call` row declares
        /// `ask`, or when an `ask` row carries no `reason`.
        pub(crate) fn validate_ask_disposition(&self) -> anyhow::Result<()> {
            // A tree-scoped rule has no caller to ask: `batten check` walks a
            // repository and answers to whoever ran it, so there is no in-band
            // decision channel and no call to hold open. Accepting `ask` there and
            // rendering it as a deny would be a downgrade nobody wrote down — the
            // shape this repository refuses everywhere else — so it is exit 1 here.
            //
            // The `reason` requirement is the same one a deny carries and for a
            // sharper version of the same purpose: an escalation reaches a HUMAN as
            // the entire explanation, with none of the surrounding output a check
            // run has. A refusal that reads "denied by rule 7" is poor; an escalation
            // that reads that way is unanswerable.
            if self.severity == Some(crate::severity::RuleSeverity::Ask) {
                if self.scope != RuleScope::MediatedCall {
                    return Err(UsageError::raise(format!(
                        "rule {}: `severity = \"ask\"` hands the decision to a human, and a \
                         `scope = \"{}\"` rule has no caller to hand it to — a repository walk \
                         answers to whoever ran it. Use `deny`, or move the row to \
                         `scope = \"mediated_call\"`",
                        self.id,
                        self.scope.as_str(),
                    )));
                }
                if self.reason.as_ref().is_none_or(|it| it.trim().is_empty()) {
                    return Err(UsageError::raise(format!(
                        "rule {}: `severity = \"ask\"` requires a `reason` — it reaches a person \
                         as the whole explanation, with none of the output a check run carries \
                         around it",
                        self.id,
                    )));
                }
            }
            Ok(())
        }

        /// The load-time refusals the three repository-state columns owe
        /// (CLOUD-843).
        ///
        /// Each refuses a declaration the acquisition could only answer wrongly: an
        /// empty tag glob lists nothing, a config key git cannot address resolves to
        /// a permanent `unset`, and a `:`-magic pathspec read as a literal selects
        /// nothing. Every one would load, acquire, and hand its module an answer to a
        /// question nobody asked — CLOUD-845's dead gate by way of a typo — so each is
        /// named here with the column and the entry.
        ///
        /// # Errors
        ///
        /// A [`UsageError`] (→ exit `1`) naming the first offending entry.
        pub(crate) fn validate_repository_state(&self) -> anyhow::Result<()> {
            if self.tags.iter().any(String::is_empty) {
                return Err(UsageError::raise(format!(
                    "rule {}: `tags` carries an empty glob, which lists no tag and would read as \
                     a repository that has none",
                    self.id
                )));
            }
            if let Some(key) = self
                .git_config
                .iter()
                .find(|key| !crate::git::config_key_parses(key))
            {
                return Err(UsageError::raise(format!(
                    "rule {}: `git_config` key `{key}` is not one git can address — a key is \
                     `section.name` or `section.subsection.name`, and this one would read as unset \
                     forever",
                    self.id
                )));
            }
            if let Some(spec) = self
                .index
                .iter()
                .find(|spec| !crate::git::pathspec_is_supported(spec))
            {
                return Err(UsageError::raise(format!(
                    "rule {}: `index` pathspec `{spec}` is empty or uses pathspec magic, which this \
                     build does not implement; read as a literal it would select nothing",
                    self.id
                )));
            }
            Ok(())
        }

        /// The three obligations a policy row carries that [`RuleKind::permits`]
        /// cannot express (CLOUD-833, CLOUD-836).
        ///
        /// All three depend on a value INSIDE the row rather than on its kind, which
        /// is what a flat per-kind column list structurally cannot say — the same
        /// reason `forbid`'s `pattern`/`regex` pair and `receipt`'s trigger-dependent
        /// columns live in `validate` rather than in the census.
        ///
        /// # Errors
        ///
        /// A [`UsageError`] (→ exit `1`) when the row names no source or more than
        /// one, when a mediated-call row declares `documents`, or when a tree-scoped
        /// row declares none.
        pub(crate) fn validate_policy_source(&self) -> anyhow::Result<()> {
            // A QUALIFIER WITH NOTHING TO QUALIFY IS THE DEAD COLUMN THIS ROW EXISTS
            // TO END (CLOUD-1625). `provider` selects among a preset's modules and is
            // read nowhere else, so a row declaring it without `preset` — on this kind
            // or any other — parses, loads, and has the key read by nothing, which is
            // exactly the silence `columns()`'s census refuses one layer over. Checked
            // BEFORE the kind guard, because the wrong kind is the case where the
            // silence is total.
            if self.provider.is_some() && self.preset.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `provider` qualifies `preset`, and this row names no preset; \
                     nothing reads the column, so it would declare a CI provider that \
                     selects nothing",
                    self.id
                )));
            }
            // `except` qualifies `preset` exactly as `provider` does (CLOUD-2290).
            if !self.except.is_empty() && self.preset.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `except` names modules of a preset to skip, and this row names \
                     no preset; nothing reads the column, so it would skip nothing",
                    self.id
                )));
            }
            if self.kind != RuleKind::Policy {
                return Ok(());
            }
            // A policy row names exactly one source, and `permits` cannot say so —
            // a flat column list has no "one of" (CLOUD-833). Same split
            // `Document`'s `pattern`/`reads` pair already carries, and the same
            // reason: a row with both is a load error rather than a precedence rule
            // nobody can read.
            let sources = [
                self.module.as_deref().map(|_| "module"),
                self.bundle.as_deref().map(|_| "bundle"),
                self.preset.as_deref().map(|_| "preset"),
            ];
            let named: Vec<&str> = sources.into_iter().flatten().collect();
            match named.len() {
                0 => {
                    return Err(UsageError::raise(format!(
                        "rule {}: kind \"policy\" requires one of `module` (one file), \
                             `bundle` (a folder) or `preset` (a vendored bundle); a row naming \
                             none enables no policy and could only ever decide nothing",
                        self.id
                    )));
                }
                1 => {}
                _ => {
                    return Err(UsageError::raise(format!(
                        "rule {}: kind \"policy\" takes exactly one of `module`, `bundle` or \
                             `preset`, and this names {}; two sources for one row is a precedence \
                             question nobody should have to answer",
                        self.id,
                        named.join(" and ")
                    )));
                }
            }
            // THE COLUMN REFUSAL IS DERIVED (CLOUD-1282). Six hand-written blocks
            // stood here — `documents`, `sources`, `lines`, `line_sources`, `uses`,
            // `invocations` — and the second one's own comment recorded how the list
            // grew: "`sources` and `lines` are tree columns for the same reason
            // `documents` is, and they were added to `permits` without this."
            //
            // So the list was already KNOWN to lag the struct, and it still did:
            // `git`, `refs`, `ranges`, `commits`, `staged`, `history`, `state`,
            // `forge`, `tools`, `captured`, `landing`, `delta_sources`, `external`
            // and `symbols` were all declarable on a mediated row, and each parsed,
            // loaded, was never acquired for that scope, and left the module reading
            // the corresponding `input.tree.*` key deciding nothing — CLOUD-845's
            // dead-gate class one layer up.
            //
            // Adding fourteen more names is the wrong fix and is the mechanism that
            // produced the gap. `COLUMN_CENSUS` says which FACT each column
            // declares, `Fact::class().surface` says where that fact resolves, and
            // the two together answer for a column added tomorrow with no edit here.
            if self.scope == RuleScope::MediatedCall
                && let Some(column) = self.tree_only_column()
            {
                return Err(UsageError::raise(format!(
                    "rule {}: `{}` declares `{}`, a fact resolvable only on the {} surface, and this \
                     row is `scope = \"mediated_call\"` — the column would parse, load, and never be \
                     acquired, leaving a module that reads it deciding nothing",
                    self.id,
                    column.field,
                    column.fact.as_str(),
                    column.fact.class().surface.as_str(),
                )));
            }
            // A MALFORMED SELECTOR IS A CONFIG FAULT, REFUSED HERE. `acquire_declared`
            // and `policy_rule` both discard the error `declared_documents` returns —
            // deliberately, because by then the run is under way — so without this the
            // row would be SILENTLY SKIPPED under `check` while `policy test` (which
            // propagates it) hard-failed. A bad pattern disabling a gate quietly is
            // the exact failure CLOUD-845 and CLOUD-850 exist to close, and adding a
            // column without this check reopened it for the new field.
            for pattern in &self.sources {
                Selector::new(pattern).map_err(|err| {
                    UsageError::raise(format!(
                        "rule {}: `sources` pattern `{pattern}` is not valid: {err}",
                        self.id
                    ))
                })?;
            }
            // CLOUD-843, for the reason the selector check above states: a
            // declaration the acquisition could only ever answer wrongly is a config
            // fault at load, never a gate that quietly decides over nothing.
            self.validate_repository_state()?;
            // A DECLARED DOCUMENT THIS BUILD CAN NEVER PARSE IS A CONFIG FAULT, not
            // a verdict (CLOUD-845). It used to be neither: `tree_document` checked
            // the extension BEFORE any I/O and dropped the path into `missing`, so
            // `policy_rule` skipped the whole rule — silently, green, without the
            // file ever being opened. A row declaring a prose, script or
            // configuration-language path this build parses none of therefore looked
            // exactly like a row whose document was absent, and a migrated gate could
            // go dead by declaring the wrong extension just as surely as by naming a
            // field the engine never emits.
            //
            // The split is what §5's exit-1 attaches to: no state of the filesystem
            // makes an unparseable extension parseable, so reporting it as
            // could-not-look would report a permanent authoring error as a transient
            // one. Absent, unreadable and unparsed stay verdicts; this one is caught
            // at load, where a config error belongs.
            for path in &self.documents {
                if crate::facts::Format::for_path(path).is_none() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `documents` names `{path}`, whose extension this build has no \
                         parser for — the row would skip silently rather than decide. Parseable \
                         extensions are {}",
                        self.id,
                        crate::facts::parseable_extensions()
                    )));
                }
            }
            self.validate_declared_format_matches_glob()?;
            // THE CONVERSE WAS A REFUSAL AND IS NOT ONE ANY MORE (CLOUD-845). It
            // read: a tree row with no declared documents "is handed an empty tree
            // and decides nothing about the repository", so refusing it was better
            // than letting it read as a configured gate.
            //
            // That reasoning was exactly right while `documents` was the ONLY thing
            // the tree document carried. It is not any more: `tracked` is emitted on
            // every tree evaluation, from the walk the run already did, so a row
            // declaring no documents is handed the checkout's path list and can
            // decide plenty about the repository — `no-docs-tree`-shaped predicates
            // over *which files exist* are precisely that row, and CLOUD-846 counts
            // three of the twenty tree-scoped gates that read no file literals at
            // all.
            //
            // The bound the old refusal protected still holds and is unweakened,
            // because it was a bound on CONTENT: a row still reads no file it did
            // not name. `tracked` is paths, costs nothing per rule, and cannot carry
            // a byte of any file — which is why widening here does not widen what a
            // module may see of a file's insides.
            Ok(())
        }

        /// Refuse a `document` row whose declared `format` contradicts the extension
        /// its glob names (CLOUD-1787).
        ///
        /// # The trap this closes
        ///
        /// `format` is declared and never inferred, which is right — a `.json` file
        /// that is really JSON5 must be declarable as JSON5. But nothing checked the
        /// declaration against the paths it would meet, and one pairing is actively
        /// dangerous rather than merely wrong: `format = "yaml"` over `*.md`
        /// **appears to work**, because `---` is YAML's document-start marker, so a
        /// markdown file's frontmatter is document 1 of the stream and gets read.
        /// Document 2 is the body, which is only accidentally valid YAML. Measured
        /// in CLOUD-1787: with identical correct frontmatter, prose and `**bold**`
        /// passed while a table, a task list and a block quote failed — the verdict
        /// decided by the prose, not the data.
        ///
        /// A row whose correctness depends on whether prose happens to lex is not a
        /// gate, and it fails silently in both directions, so it is refused at load
        /// where a config error costs a config error.
        ///
        /// # Why the literal suffix and not the glob
        ///
        /// Deciding what an arbitrary glob *can* match needs a glob engine and
        /// answers "possibly" for most inputs. The extension a glob ENDS in is a
        /// string, it is what every real row writes (`*.md`, `**/*.md`,
        /// `notes/*.md`), and it is exactly the case above. A computed or
        /// extensionless glob is not caught here and the message says so rather than
        /// implying a totality this does not have.
        pub(crate) fn validate_declared_format_matches_glob(&self) -> anyhow::Result<()> {
            let (Some(declared), Some(glob)) = (self.format, self.glob.as_deref()) else {
                return Ok(());
            };
            let Some(named) = crate::facts::Format::for_path(glob) else {
                return Ok(());
            };
            if named == declared {
                return Ok(());
            }
            Err(UsageError::raise(format!(
                "rule {}: `glob` is `{glob}`, whose extension names {}, but `format` says {} — one \
                 of the two is wrong, and the pairing is admitted by neither. Declare `format = \
                 \"{}\"` to read the file as its extension says. (Checked on the literal extension \
                 a glob ends in; a computed glob is not checked.)",
                self.id,
                named.as_str(),
                declared.as_str(),
                named.as_str()
            )))
        }

        /// Validate that the per-kind fields present match the declared `kind`.
        ///
        /// The struct is flat (a `#[serde(flatten)]` enum would silently defeat
        /// `deny_unknown_fields`), so the kind/field agreement that a tagged enum
        /// would give for free is asserted here instead — and a field belonging to
        /// another kind is an *error*, never ignored, so a rule can never half-apply.
        /// Every optional column, paired with whether this rule carries it.
        ///
        /// The census is what keeps [`Rule::validate`] total. The previous version
        /// hand-wrote one match arm per kind naming one required and one forbidden
        /// field, which was correct for two kinds and two columns and goes stale
        /// silently the moment either grows: a new column simply appears in no arm,
        /// so every kind accepts it. Listing the columns once and asking each kind
        /// about all of them makes that failure impossible, and
        /// [`tests::every_optional_rule_field_is_classified_by_every_kind`] fails if
        /// a column is added here without being placed.
        pub(crate) fn columns(&self) -> [(&'static str, bool); 63] {
            [
                // In the census because it is now per-kind, which is what makes
                // "required by every kind but the judge" a fact the existing
                // machinery decides rather than a special case anyone maintains.
                ("severity", self.severity.is_some()),
                ("criteria", self.criteria.is_some()),
                ("tier", self.tier.is_some()),
                ("no_fix_reason", self.no_fix_reason.is_some()),
                ("no_retry_reason", self.no_retry_reason.is_some()),
                ("glob", self.glob.is_some()),
                ("pattern", self.pattern.is_some()),
                ("regex", self.regex.is_some()),
                ("exclude", self.exclude.is_some()),
                ("content", self.content.is_some()),
                ("tool", self.tool.is_some()),
                ("measures", self.measures.is_some()),
                ("counts", self.counts.is_some()),
                ("max", self.max.is_some()),
                ("resolves", !self.resolves.is_empty()),
                ("when_absent", self.when_absent.is_some()),
                ("when_present", self.when_present.is_some()),
                ("when_value", self.when_value.is_some()),
                ("key_from", self.key_from.is_some()),
                ("key_base", self.key_base.is_some()),
                ("key_shape", self.key_shape.is_some()),
                ("max_age", self.max_age.is_some()),
                ("requires_field", self.requires_field.is_some()),
                ("check", self.check.is_some()),
                ("fix", self.fix.is_some()),
                ("contains", self.contains.is_some()),
                ("unless_contains", self.unless_contains.is_some()),
                ("word", self.word.is_some()),
                ("unless_word", self.unless_word.is_some()),
                ("on", self.on.is_some()),
                ("require_via", self.require_via.is_some()),
                ("requires_key", self.requires_key.is_some()),
                ("reason", self.reason.is_some()),
                ("policy_url", self.policy_url.is_some()),
                ("bypass_env", self.bypass_env.is_some()),
                ("verbatim", self.verbatim.is_some()),
                ("identity_key", self.identity_key.is_some()),
                ("direction", self.direction.is_some()),
                ("base", self.base.is_some()),
                ("retires_with", self.retires_with.is_some()),
                ("conserves", self.conserves.is_some()),
                ("admits_with", self.admits_with.is_some()),
                ("per_file", self.per_file),
                ("format", self.format.is_some()),
                ("node", self.node.is_some()),
                ("derives", self.derives.is_some()),
                ("cites", self.cites.is_some()),
                ("reads", self.reads.is_some()),
                ("module", self.module.is_some()),
                ("checks", self.checks.is_some()),
                ("checks_any", self.checks_any.is_some()),
                ("key", self.key.is_some()),
                ("trigger", self.trigger.is_some()),
                ("verdict", self.verdict.is_some()),
                ("filters", self.filters.is_some()),
                ("substitutes", self.substitutes.is_some()),
                ("interprets", self.interprets.is_some()),
                // CLOUD-2291: a `native` row's whole predicate is which gate.
                ("gate", self.gate.is_some()),
                // `landing` is NOT here, and neither are `git`, `refs` or `ranges`
                // (CLOUD-880, following CLOUD-907). The census drives the per-kind
                // permit/require validation, and a column in it owes an entry in some
                // kind's `permits()` — `every_optional_rule_field_is_classified_by_
                // every_kind` is the gate, and it caught this column the first time it
                // was added here. The four git-family columns are declared reads
                // rather than per-kind capabilities, so they follow their siblings
                // rather than inventing a fifth classification for one of them.
                ("line_sources", !self.line_sources.is_empty()),
                ("invocations", !self.invocations.is_empty()),
                ("invocation_sources", !self.invocation_sources.is_empty()),
                ("uses", !self.uses.is_empty()),
                ("use_sources", !self.use_sources.is_empty()),
            ]
        }

        /// What makes this row fire, with the pinned default applied — the one place
        /// absence is resolved, so no call site reads it a second way.
        #[must_use]
        pub fn receipt_trigger(&self) -> ReceiptTrigger {
            self.trigger.unwrap_or_default()
        }

        /// Which git fact this row's receipts are keyed to, default applied.
        #[must_use]
        pub fn receipt_key(&self) -> ReceiptKey {
            self.key.unwrap_or_default()
        }

        /// The pipeline row's own tables (CLOUD-443).
        ///
        /// Refused for the reason everything in [`Rule::validate`] is refused: a
        /// list that narrows nothing, or a row whose conditions contradict, loads
        /// clean and decides nothing. Extracted rather than inlined so `validate`
        /// stays under the line limit as columns accumulate — the census below it
        /// is the part that must stay whole.
        pub(crate) fn validate_pipeline_tables(&self) -> anyhow::Result<()> {
            if self.kind != RuleKind::Pipeline {
                return Ok(());
            }
            for entry in self.verdict.iter().flatten() {
                entry.validate(&self.id)?;
            }
            if self.verdict.as_ref().is_some_and(Vec::is_empty) {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"pipeline\" requires at least one `verdict` entry; with none it judges no command",
                    self.id
                )));
            }
            if self.filters.as_ref().is_some_and(Vec::is_empty) {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"pipeline\" requires at least one `filters` entry; with none it cannot recognise the substitution it refuses",
                    self.id
                )));
            }
            if self.substitutes.as_ref().is_some_and(Vec::is_empty) {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"pipeline\" requires at least one `substitutes` entry; with none it recognises no substitution",
                    self.id
                )));
            }
            if self.interprets.as_ref().is_some_and(Vec::is_empty) {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"pipeline\" requires at least one `interprets` entry; with none it recognises no interpreter",
                    self.id
                )));
            }
            // ONE of the two families, whole (CLOUD-864). The per-kind required
            // table cannot express this — it is a disjunction over sibling columns,
            // and that table is a flat list — so the obligation lands here, which is
            // the same place `Receipt`'s conditional `pattern` requirement lives.
            //
            // Stated as a disjunction rather than as "at least one column set" on
            // purpose: a row carrying `verdict` and no `filters` recognises a
            // verdict-bearing command and nothing that could discard it, which
            // matches and decides nothing. Half a family is the inert row, not a
            // narrower gate.
            let discard_family = self.verdict.is_some() && self.filters.is_some();
            let substitution_family = self.substitutes.is_some() || self.interprets.is_some();
            if !discard_family && !substitution_family {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"pipeline\" needs either `verdict` AND `filters` (the discard family) or `substitutes` or `interprets` (the substitution family); with neither it matches nothing",
                    self.id
                )));
            }
            Ok(())
        }

        /// `fix` and `no_fix_reason` are alternatives, never both (CLOUD-81).
        ///
        /// Not expressible in [`RuleKind::requires`] for the same reason
        /// `pattern`-xor-`regex` is not: that list is columns that must *all* be
        /// present. [`RuleKind::permits`] carries the other half — a `shape` row is
        /// refused both columns there, because it is adjudicated per mediated call
        /// and never reaches the store, the same reasoning that already denies it
        /// `identity_key`.
        ///
        /// **Carrying neither is refused at ingest, not here** (§5). A rule with no
        /// remediation still loads and still gates: `check` and `enforce` render its
        /// findings and exit on them exactly as before. What it cannot do is put one
        /// in the store, because a *stored* finding is one something later has to
        /// close. Refusing at load would instead make an un-actionable rule
        /// un-runnable, which turns a store-shaped requirement into a gate outage
        /// for every consumer whose config predates this field.
        /// The out-of-root bound's own obligations, refused at LOAD (CLOUD-1167).
        ///
        /// Its own function rather than a block inside `validate` for
        /// [`Rule::validate_tool_rows`]' reason: that function is at its 100-line
        /// ceiling, and every declared-read family adds a paragraph to it.
        ///
        /// # Errors
        ///
        /// Returns a [`UsageError`] (→ exit `1`) for a row missing an `id` or a
        /// `root`, one whose `path` can leave the root it named, or one id declared
        /// twice over different files.
        pub(crate) fn validate_external_rows(&self) -> anyhow::Result<()> {
            // THE OUT-OF-ROOT BOUND, REFUSED AT LOAD (CLOUD-1167). Both halves are
            // config faults rather than verdicts: no state of the filesystem makes
            // either admissible, so reporting them as could-not-look would present a
            // permanent authoring error as a transient one — the choice
            // `NotAcquired::UnknownFormat` already makes one layer down.
            //
            // Checked before the kind gate below so it binds every kind that may
            // carry the column, and stated here rather than in the per-kind census
            // because the census is a flat list of column NAMES and this is a
            // property of a column's CONTENTS.
            let mut seen_external: BTreeMap<&str, (&str, &str)> = BTreeMap::new();
            for row in &self.external {
                if row.id.trim().is_empty() {
                    return Err(UsageError::raise(format!(
                        "rule {}: an `external` row needs a non-empty `id`; it is the key the file is projected under and a module has no other way to name it",
                        self.id
                    )));
                }
                if row.root.trim().is_empty() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `external` row {:?} needs a non-empty `root`; it is the NAME of the environment variable the path resolves beneath, and an empty one would resolve against the process's working directory",
                        self.id, row.id
                    )));
                }
                // THE ANTI-ESCAPE HALF. A declaration that can walk back out of the
                // root it named is a scanner with extra steps, and this is the one
                // place it can be refused for good rather than per run.
                if row.path.trim().is_empty() || row.escapes() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `external` row {:?} needs a `path` that is relative and stays beneath its root; an absolute path or a `..` component would read outside the root the row declared, which is the bound this column exists to hold",
                        self.id, row.id
                    )));
                }
                // THE ONE-ID-ONE-FILE HALF. Acquisition caches by id across the whole
                // rule set, so two rows declaring one id differently would resolve by
                // whichever row the loop reached first — a silent precedence rule
                // over which file a module actually reads. `Wanted` records the same
                // lesson one family over, where keying a cache on the path alone
                // starved the losing row.
                if let Some((root, path)) = seen_external.insert(&row.id, (&row.root, &row.path))
                    && (root != row.root || path != row.path)
                {
                    return Err(UsageError::raise(format!(
                        "rule {}: `external` id {:?} is declared twice with different roots or paths; one id names one file, or which file a module reads depends on rule order",
                        self.id, row.id
                    )));
                }
            }
            Ok(())
        }

        /// The tool-verdict key's own obligations, refused at LOAD (CLOUD-1171).
        ///
        /// Its own function rather than another block inside `validate` for the
        /// reason `validate_sink` is one: that function is at its line ceiling and
        /// every declared-read family adds a paragraph to it.
        ///
        /// Every refusal here is a CONFIG FAULT rather than a verdict, which is the
        /// choice `NotAcquired::UnknownFormat` already makes: no state of the
        /// filesystem makes an empty tool name or a separator inside a version
        /// admissible, so reporting either as could-not-look would present a
        /// permanent authoring error as a transient one.
        ///
        /// # Errors
        ///
        /// Returns a [`UsageError`] (→ exit `1`) for a row whose key cannot be
        /// composed unambiguously, or for one id declared twice over different keys.
        pub(crate) fn validate_tool_rows(&self) -> anyhow::Result<()> {
            let mut seen: BTreeMap<&str, &crate::facts::ToolQuery> = BTreeMap::new();
            for row in &self.tools {
                if row.id.trim().is_empty() || row.input.trim().is_empty() {
                    return Err(UsageError::raise(format!(
                        "rule {}: a `tools` row needs a non-empty `id` and `input`; the id is the key the verdict is projected under, and the input is the file whose digest keys the record",
                        self.id
                    )));
                }
                // THE AMBIGUOUS-KEY HALF. The three components are joined into one
                // record name, so a component carrying the separator or a path
                // component would let two different declarations compose the same
                // key — two questions with one answer, decided by whichever producer
                // wrote last.
                if row.malformed() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `tools` row {:?} needs a `tool` and `version` that are non-empty and carry no `{}` or path separator; all three key components are joined into one record name, and a separator inside one would let two declarations compose the same key",
                        self.id,
                        row.id,
                        crate::facts::KEY_SEPARATOR
                    )));
                }
                // THE ONE-ID-ONE-KEY HALF, for `external`'s reason: acquisition keys
                // by id, so two rows declaring one id differently would resolve by
                // whichever the loop reached first — a silent precedence rule over
                // which verdict a module actually reads.
                if let Some(first) = seen.insert(&row.id, row)
                    && (first.tool != row.tool
                        || first.version != row.version
                        || first.input != row.input)
                {
                    return Err(UsageError::raise(format!(
                        "rule {}: `tools` id {:?} is declared twice with different keys; one id names one verdict, or which record a module reads depends on rule order",
                        self.id, row.id
                    )));
                }
            }
            Ok(())
        }

        /// Refuse a `[[rule.minted]]` row that cannot address a receipt, or an id
        /// declared twice over different questions (CLOUD-1310).
        ///
        /// **The mint NAME is not resolved against the mint table, and that is
        /// deliberate.** A mint that has never fired leaves no receipts, which is
        /// could-not-look and is the ordinary state on any fresh clone — so refusing
        /// the row at load would refuse the common case rather than an authoring
        /// error. What is refused here is only what no state of the filesystem could
        /// make admissible.
        ///
        /// # Errors
        ///
        /// Returns a [`UsageError`] (→ exit `1`) for a row naming an unusable mint or
        /// id, for a row whose two column indices are the same, and for one id
        /// declared twice over different questions.
        pub(crate) fn validate_minted_rows(&self) -> anyhow::Result<()> {
            let mut seen: BTreeMap<&str, &crate::facts::MintedQuery> = BTreeMap::new();
            for row in &self.minted {
                if row.malformed() {
                    return Err(UsageError::raise(format!(
                        "rule {}: a `minted` row needs a non-empty `id` and a `mint` that is non-empty and carries no path separator; the mint names the receipt files this reads and a separator would send it outside the store",
                        self.id
                    )));
                }
                // THE TWO-COLUMNS-ARE-DIFFERENT HALF. The value and the time it was
                // read are different columns of one line; declaring them the same
                // index projects the timestamp as the value while the bound compares
                // the timestamp against itself, so the row is always fresh and always
                // answers with a clock. It reads as a working gate.
                if row.field == row.recency {
                    return Err(UsageError::raise(format!(
                        "rule {}: `minted` row {:?} declares `field` and `recency` at the same index {}; the value and the time it was read are different columns, and collapsing them projects the timestamp as the value while the age bound compares it against itself",
                        self.id, row.id, row.field
                    )));
                }
                // THE ONE-ID-ONE-QUESTION HALF, for `tools`' reason one function up:
                // acquisition keys by id, so two rows declaring one id differently
                // would resolve by whichever the loop reached first.
                if let Some(first) = seen.insert(&row.id, row)
                    && (first.mint != row.mint
                        || first.field != row.field
                        || first.recency != row.recency
                        || first.max_age_days != row.max_age_days)
                {
                    return Err(UsageError::raise(format!(
                        "rule {}: `minted` id {:?} is declared twice with different questions; one id names one field of one mint at one bound, or which reading a module gets depends on rule order",
                        self.id, row.id
                    )));
                }
            }
            Ok(())
        }

        /// A declared sink must be on a kind that can actually request one
        /// (CLOUD-851).
        ///
        /// The request set is built from a [`Scan`], which only the TREE surface
        /// produces: `adjudicate` returns a decision about one call and has no
        /// findings vector to digest. So a `produces` on a `mediated_call`-only kind
        /// would parse, read as configured, and write nothing on every call — the
        /// inert-coverage failure `validate_shape_columns` and
        /// `validate_receipt_columns` each close one column over, and the same one
        /// `Rule::fix`'s refusal states rather than pretends about.
        ///
        /// Refused at LOAD rather than skipped at run time, because a skip is
        /// invisible: the run reports its findings and the record simply is not
        /// there, which looks exactly like a run that had nothing to produce.
        pub(crate) fn validate_sink(&self) -> anyhow::Result<()> {
            if self.produces.is_none() {
                return Ok(());
            }
            // THE ROW'S OWN SCOPE, not the kind's CAPABILITY, and the difference is a
            // real hole the first version left. `RuleKind::Policy` scopes to BOTH
            // surfaces, so `kind.scopes().contains(&Tree)` is true for a policy row
            // configured `scope = "mediated_call"` — it passed validation, the tree
            // runner skipped it as another surface's business, `requested_sinks`
            // excluded it as not-evaluated, and the declared record was never
            // written. Exactly the inert-coverage failure this function exists to
            // refuse, reached through the one kind that spans both scopes.
            if self.scope != RuleScope::Tree {
                return Err(UsageError::raise(format!(
                    "rule {}: `produces` on a `{}`-scoped row, which is decided by `adjudicate` \
                     rather than by a findings scan; there is nothing for a sink to summarise \
                     and the record would never be written",
                    self.id,
                    self.scope.as_str()
                )));
            }
            Ok(())
        }

        /// `exclude_paths` has to be honoured by everything that reads the rule's
        /// selection, and two shapes cannot honour it (CLOUD-883).
        ///
        /// **No `glob`.** The column subtracts from an include set, so with nothing to
        /// subtract from it narrows nothing while reading as a narrowing — the
        /// inert-coverage failure `validate_sink` and `validate_shape_columns` each
        /// close one column over.
        ///
        /// **A ratchet.** Its verdict compares the working tree against a count taken
        /// at the base rev by `git::count_at_rev`, which globs on its own and knows
        /// nothing of this column. The two sides would select different sets, and the
        /// direction is the dangerous one CLOUD-328 measured: a working side narrowed
        /// below a base that counted everything sits permanently under its baseline,
        /// so no addition could ever push it over and **the gate cannot fail**.
        /// Refused rather than half-implemented, because a ratchet that cannot fail
        /// reads exactly like one that is passing.
        pub(crate) fn validate_exclude_paths(&self) -> anyhow::Result<()> {
            if self.exclude_paths.is_empty() {
                return Ok(());
            }
            if self.glob.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `exclude_paths` subtracts from `glob`, and this row declares none — \
                     it would narrow nothing while reading as a narrowing",
                    self.id
                )));
            }
            if self.kind == RuleKind::Ratchet {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"ratchet\" counts the base rev with its own glob, which cannot \
                     read `exclude_paths`; the two sides would select different sets and the \
                     working side could never rise above the base, so the gate could not fail",
                    self.id
                )));
            }
            Ok(())
        }

        /// The `pattern`-xor-`regex` rule, and the regexes' own well-formedness.
        ///
        /// Not expressible in [`RuleKind::requires`], which is a flat list of
        /// columns that must all be present — "exactly one of these two" needs a
        /// check of its own (CLOUD-283). Refusing a row that carries both is what
        /// keeps this a *choice* rather than a precedence rule a reader has to know.
        ///
        /// Each expression is compiled here, at load, so a bad one is a config error
        /// naming the row rather than a failure part-way through a scan.
        /// A document row's predicate: exactly one of `pattern` or `reads`.
        ///
        /// The same "one of" the forbid predicate carries and for the same reason —
        /// a flat column list cannot express it, so it lives here where the pair is
        /// in scope. A row with neither loads, matches a document, and asks nothing
        /// of it; a row with both declares two answers to one comparison.
        pub(crate) fn validate_document_predicate(&self) -> anyhow::Result<()> {
            if self.kind != RuleKind::Document {
                return Ok(());
            }
            match (self.pattern.is_some(), self.reads.is_some()) {
                (true, true) => Err(UsageError::raise(format!(
                    "rule {}: `pattern` and `reads` are alternatives; a row carries exactly one, \
                     never both",
                    self.id
                ))),
                (false, false) => Err(UsageError::raise(format!(
                    "rule {}: kind \"document\" requires `pattern` (a literal) or `reads` (another \
                     rule's derived value)",
                    self.id
                ))),
                _ => Ok(()),
            }
        }

        /// A ratchet's `counts` and `per_file` columns (CLOUD-2663).
        pub(crate) fn validate_ratchet_measure(&self) -> anyhow::Result<()> {
            if self.kind != RuleKind::Ratchet {
                return Ok(());
            }
            if let Some(unit) = self.counts {
                // A LINT COUNT NAMES ITS LINT IN `pattern`, and is the one measure
                // that takes it: the lint is the counter's subject, not a token.
                if unit == CeilingUnit::LintEscapes {
                    if self.pattern.is_none() || self.regex.is_some() {
                        return Err(UsageError::raise(format!(
                            "rule {}: `counts = \"lint_escapes\"` names its lint in `pattern` \
                             (`clippy::disallowed_types`), and takes no `regex`",
                            self.id
                        )));
                    }
                    return Ok(());
                }
                if unit != CeilingUnit::Tokens {
                    return Err(UsageError::raise(format!(
                        "rule {}: a ratchet counts `tokens`, `lint_escapes` or a literal; \
                         `counts = {unit:?}` measures a call, not a file",
                        self.id
                    )));
                }
                if self.pattern.is_some() || self.regex.is_some() {
                    return Err(UsageError::raise(format!(
                        "rule {}: `counts`, `pattern` and `regex` are alternatives; a ratchet \
                         counts exactly one",
                        self.id
                    )));
                }
            }
            if self.per_file && (self.retires_with.is_some() || self.conserves.is_some()) {
                return Err(UsageError::raise(format!(
                    "rule {}: `per_file` judges each file on its own, and `retires_with` and \
                     `conserves` buy an aggregate decrease a per-file row does not have",
                    self.id
                )));
            }
            Ok(())
        }

        pub(crate) fn validate_forbid_predicate(&self) -> anyhow::Result<()> {
            if !matches!(self.kind, RuleKind::Forbid | RuleKind::Ratchet) {
                return Ok(());
            }
            self.validate_ratchet_measure()?;
            if self.kind == RuleKind::Ratchet && self.counts.is_some() {
                // The token measure stands in for both literal columns, and
                // `validate_ratchet_measure` has refused it beside either.
                return Ok(());
            }
            match (self.pattern.is_some(), self.regex.is_some()) {
                (true, true) => {
                    return Err(UsageError::raise(format!(
                        "rule {}: `pattern` and `regex` are alternatives; a row carries exactly one, \
                         never both",
                        self.id
                    )));
                }
                (false, false) => {
                    return Err(UsageError::raise(format!(
                        "rule {}: kind \"{}\" requires `pattern` (a literal) or `regex` (a shape)",
                        self.id,
                        self.kind.as_str()
                    )));
                }
                _ => {}
            }
            for (column, expression) in [("regex", &self.regex), ("exclude", &self.exclude)] {
                if let Some(expression) = expression {
                    Regex::new(expression).map_err(|err| {
                        UsageError::raise(format!(
                            "rule {}: `{column}` is not valid: {err}",
                            self.id
                        ))
                    })?;
                }
            }
            Ok(())
        }

        /// The first column this row declares whose fact the mediated call cannot
        /// resolve (CLOUD-1282).
        ///
        /// Derived rather than listed: [`COLUMN_CENSUS`] says which fact each column
        /// declares and [`crate::facts::Fact::class`] says where that fact resolves,
        /// so a column added to this struct is covered the day it lands — and a fact
        /// RECLASSIFIED onto the hook surface stops being refused here without an
        /// edit, which a list could not manage in either direction.
        ///
        /// `Surface::Hook` is the NARROWEST surface a fact may be resolved on, so it
        /// is the one value that reaches the mediated call; every other means the
        /// column would parse, load and never be acquired.
        ///
        /// Census order decides which column a multi-column row is refused for,
        /// which is declaration order in the struct — the same tie-break every other
        /// table here uses, and the one a reviewer reading top to bottom expects.
        #[must_use]
        pub fn tree_only_column(&self) -> Option<TreeOnlyColumn> {
            COLUMN_CENSUS
                .iter()
                .find_map(|column| match column.declares {
                    Declares::Fact(fact, declared)
                        if fact.class().surface != crate::facts::Surface::Hook
                            && declared(self) =>
                    {
                        Some(TreeOnlyColumn {
                            field: column.field,
                            fact,
                        })
                    }
                    Declares::Fact(..) | Declares::NotFactBearing(_) => None,
                })
        }
    }

    impl VerdictProgram {
        /// Reject a row that cannot mean anything.
        ///
        /// # Errors
        ///
        /// Returns a [`UsageError`] (→ exit `1`) for an empty `program`, an empty
        /// list in any column, a `nested` with no `subcommands`, a row carrying both
        /// `subcommands` and `except`, an `any_argument` beside either of them, and a
        /// row declaring no column at all. Every one of those either matches nothing
        /// or contradicts itself, and both read as coverage from the file.
        pub(crate) fn validate(&self, rule: &str) -> anyhow::Result<()> {
            let refuse = |detail: &str| {
                Err(UsageError::raise(format!(
                    "rule {rule}: verdict {}: {detail}",
                    self.program
                )))
            };
            if self.program.trim().is_empty() || self.program.split_whitespace().count() != 1 {
                return Err(UsageError::raise(format!(
                    "rule {rule}: a verdict entry names one program, not {:?}",
                    self.program
                )));
            }
            for (name, list) in [
                ("subcommands", self.subcommands.as_deref()),
                ("nested", self.nested.as_deref()),
                ("except", self.except.as_deref()),
            ] {
                if list.is_some_and(<[String]>::is_empty) {
                    return refuse(&format!("`{name}` is empty, so it narrows nothing"));
                }
            }
            if self.subcommands.is_some() && self.except.is_some() {
                return refuse(
                    "`subcommands` and `except` are opposite readings of the same position",
                );
            }
            if self.nested.is_some() && self.subcommands.is_none() {
                return refuse(
                    "`nested` needs `subcommands` — a second word with no first names nothing",
                );
            }
            let any = self.any_argument.unwrap_or_default();
            if any && (self.subcommands.is_some() || self.except.is_some()) {
                return refuse(
                    "`any_argument` already admits every word, so it cannot be narrowed",
                );
            }
            if !any && self.subcommands.is_none() && self.except.is_none() {
                return refuse("declares no condition, so it never matches");
            }
            Ok(())
        }
    }

    /// One `Rule` column and what the fact model says about it (CLOUD-1282).
    ///
    /// # Why a census rather than a list of tree-only columns
    ///
    /// A list of the columns to refuse is exactly what stood here before, and its
    /// own comment recorded it lagging the struct. A census answers for EVERY field,
    /// so a column added to `Rule` fails
    /// [`tests::every_rule_column_carries_a_fact_verdict`] until somebody decides
    /// what it declares — the same shape [`crate::trust::CENSUS`] uses, and for the
    /// same reason: the field list is read off the struct's own source, so the table
    /// cannot silently fall behind it.
    #[derive(Debug, Clone, Copy)]
    pub struct ColumnCensus {
        /// The column, spelled as `Rule` declares it.
        pub field: &'static str,
        /// What it says about fact acquisition.
        pub declares: Declares,
    }

    /// A column's verdict in [`COLUMN_CENSUS`]: it declares a fact, or it does not.
    #[derive(Debug, Clone, Copy)]
    pub enum Declares {
        /// The column declares acquisition of this fact, and the closure answers
        /// whether a given row actually declared anything in it.
        ///
        /// The closure is what makes the derivation possible at all: a census of
        /// names could say WHICH columns are tree-only and not whether THIS row
        /// declared one, and the refusal has to name a column the author wrote.
        Fact(crate::facts::Fact, fn(&Rule) -> bool),
        /// The column acquires no fact, with the reason — a selector, a remedy, a
        /// severity, a shape. Recorded rather than omitted, because "not covered"
        /// and "considered and not fact-bearing" are the two readings a silent
        /// absence cannot be told apart from.
        NotFactBearing(&'static str),
    }

    /// One column named as declaring a fact that this scope cannot resolve.
    #[derive(Debug, Clone, Copy)]
    pub struct TreeOnlyColumn {
        /// The column the author wrote.
        pub field: &'static str,
        /// The fact it declares.
        pub fact: crate::facts::Fact,
    }

    /// Every `Rule` column, with what it declares.
    ///
    /// **Read the surface off the fact, never off this table.** A row names a
    /// [`crate::facts::Fact`] and nothing else; whether that fact reaches the
    /// mediated call is `Fact::class().surface`'s answer, so reclassifying a fact
    /// moves this refusal with it and cannot leave the two disagreeing.
    pub const COLUMN_CENSUS: &[ColumnCensus] = &[
        ColumnCensus {
            field: "id",
            declares: Declares::NotFactBearing("the row's own name"),
        },
        ColumnCensus {
            field: "kind",
            declares: Declares::NotFactBearing("which predicate decides the row"),
        },
        ColumnCensus {
            field: "glob",
            declares: Declares::NotFactBearing(
                "selects files; the tree walk is the engine's, not a declared fact",
            ),
        },
        ColumnCensus {
            field: "severity",
            declares: Declares::NotFactBearing("the exit contract"),
        },
        ColumnCensus {
            field: "scope",
            declares: Declares::NotFactBearing(
                "the surface this row is judged on — the question, never an answer to it",
            ),
        },
        ColumnCensus {
            field: "pattern",
            declares: Declares::NotFactBearing("a literal the predicate matches"),
        },
        ColumnCensus {
            field: "regex",
            declares: Declares::NotFactBearing("a pattern the predicate matches"),
        },
        ColumnCensus {
            field: "exclude",
            declares: Declares::NotFactBearing("narrows a match"),
        },
        ColumnCensus {
            field: "content",
            declares: Declares::NotFactBearing("a literal the predicate matches"),
        },
        ColumnCensus {
            field: "tool",
            declares: Declares::NotFactBearing(
                "selects on the call's own tool name, which the envelope carries",
            ),
        },
        ColumnCensus {
            field: "when_absent",
            declares: Declares::NotFactBearing("a condition over a fact another column declared"),
        },
        ColumnCensus {
            field: "key_from",
            declares: Declares::NotFactBearing("names where a receipt's key comes from"),
        },
        ColumnCensus {
            field: "key_base",
            declares: Declares::NotFactBearing(
                "names the ref a delta-keyed receipt's identity is taken against",
            ),
        },
        ColumnCensus {
            field: "when_value",
            declares: Declares::NotFactBearing("a condition over a fact another column declared"),
        },
        ColumnCensus {
            field: "key_shape",
            declares: Declares::NotFactBearing("the shape a key must have"),
        },
        ColumnCensus {
            field: "max_age",
            declares: Declares::NotFactBearing("a bound on a receipt another column declared"),
        },
        ColumnCensus {
            field: "requires_field",
            declares: Declares::NotFactBearing("a condition over the call's own payload"),
        },
        ColumnCensus {
            field: "when_present",
            declares: Declares::NotFactBearing("a condition over a fact another column declared"),
        },
        ColumnCensus {
            field: "while_marker",
            // NOT `Fact::Receipts`, and the distinction is the reason this column can
            // exist at all (CLOUD-1390). That fact is the boundary RESOLVING receipt
            // verdicts — validity, staleness, the key it was filed under — and every
            // one of those questions costs the resolution `checks` pays for. This
            // column asks whether one path exists. A marker carries no conclusion, so
            // there is nothing to resolve and nothing that could come back stale.
            //
            // Declaring the fact anyway would not be a harmless over-statement: it
            // would put receipt resolution on the acquisition list for every row
            // carrying this column, which is CLOUD-460's regression — a resolution
            // paid for by `ls` and by every file edit — and the whole economy of
            // `modifier_admits` reaching the filesystem only for a row that asked.
            declares: Declares::NotFactBearing(
                "a branch-keyed marker's PRESENCE, which is a path test rather than a \
                 receipt verdict — nothing is resolved, so nothing is acquired",
            ),
        },
        ColumnCensus {
            field: "while_unpushed",
            declares: Declares::NotFactBearing(
                "whether HEAD is on a remote-tracking ref, walked by the modifier that \
                 asked — no receipt is resolved, so nothing is acquired",
            ),
        },
        ColumnCensus {
            field: "measures",
            declares: Declares::NotFactBearing(
                "names a projection of the call, which the envelope carries",
            ),
        },
        ColumnCensus {
            field: "counts",
            declares: Declares::NotFactBearing("a condition over a fact another column declared"),
        },
        ColumnCensus {
            field: "max",
            declares: Declares::NotFactBearing("a ceiling on a measurement"),
        },
        ColumnCensus {
            field: "resolves",
            declares: Declares::NotFactBearing("a condition over a fact another column declared"),
        },
        ColumnCensus {
            field: "contains",
            declares: Declares::NotFactBearing("a condition over a fact another column declared"),
        },
        ColumnCensus {
            field: "unless_contains",
            declares: Declares::NotFactBearing(
                "a condition over a fact another column declared, in the exempting polarity",
            ),
        },
        ColumnCensus {
            field: "word",
            declares: Declares::NotFactBearing("a condition over a fact another column declared"),
        },
        ColumnCensus {
            field: "unless_word",
            declares: Declares::NotFactBearing(
                "a condition over a fact another column declared, in the exempting polarity",
            ),
        },
        ColumnCensus {
            field: "on",
            declares: Declares::NotFactBearing("selects by an event the engine resolves"),
        },
        ColumnCensus {
            field: "require_via",
            declares: Declares::NotFactBearing("narrows how a requirement may be met"),
        },
        ColumnCensus {
            field: "requires_key",
            // Hook-surface: the boundary already resolves the key evidence for the
            // typed rule table, so a mediated row declaring it is asking for
            // something it is handed.
            declares: Declares::Fact(crate::facts::Fact::Keys, |rule| rule.requires_key.is_some()),
        },
        ColumnCensus {
            field: "reason",
            declares: Declares::NotFactBearing("the consumer's remedy prose"),
        },
        ColumnCensus {
            field: "policy_url",
            declares: Declares::NotFactBearing("a pointer a refusal carries"),
        },
        ColumnCensus {
            field: "bypass_env",
            declares: Declares::NotFactBearing("names this row's hatch"),
        },
        ColumnCensus {
            field: "check",
            declares: Declares::NotFactBearing(
                "the command a `command` row runs; a spawn, which no mediated kind may do",
            ),
        },
        ColumnCensus {
            field: "fix",
            declares: Declares::NotFactBearing("the command a `command` row repairs with"),
        },
        ColumnCensus {
            field: "produces",
            declares: Declares::Fact(crate::facts::Fact::Produced, |rule| rule.produces.is_some()),
        },
        ColumnCensus {
            field: "exclude_paths",
            declares: Declares::NotFactBearing("narrows `glob`"),
        },
        ColumnCensus {
            field: "run",
            declares: Declares::NotFactBearing("the command a row runs"),
        },
        ColumnCensus {
            field: "verbatim",
            declares: Declares::NotFactBearing("normalisation of a hashed span"),
        },
        ColumnCensus {
            field: "identity_key",
            declares: Declares::NotFactBearing("how a finding is identified across runs"),
        },
        ColumnCensus {
            field: "direction",
            declares: Declares::NotFactBearing("which way a ratchet turns"),
        },
        ColumnCensus {
            field: "base",
            declares: Declares::NotFactBearing("names the ref a ratchet compares against"),
        },
        ColumnCensus {
            field: "retires_with",
            declares: Declares::NotFactBearing("an admission's shape"),
        },
        ColumnCensus {
            field: "conserves",
            declares: Declares::NotFactBearing("an obligation inside an admission"),
        },
        ColumnCensus {
            field: "admits_with",
            declares: Declares::NotFactBearing(
                "an admission's shape on the other side of the count",
            ),
        },
        ColumnCensus {
            field: "per_file",
            declares: Declares::NotFactBearing("the grain a ratchet's count is judged at"),
        },
        ColumnCensus {
            field: "format",
            declares: Declares::NotFactBearing(
                "how a declared document is parsed, not whether one is acquired",
            ),
        },
        ColumnCensus {
            field: "node",
            declares: Declares::NotFactBearing(
                "addresses inside a document another column declared",
            ),
        },
        ColumnCensus {
            field: "derives",
            declares: Declares::NotFactBearing(
                "how a value is computed from a fact another column declared",
            ),
        },
        ColumnCensus {
            field: "cites",
            declares: Declares::NotFactBearing(
                "which declared register a reference row resolves against, and how it cites; the \
                 files read are the register's own declared paths, never a fact",
            ),
        },
        ColumnCensus {
            field: "reads",
            declares: Declares::NotFactBearing("addresses inside a fact another column declared"),
        },
        ColumnCensus {
            field: "predicate_severity",
            declares: Declares::NotFactBearing("per-predicate exit contract"),
        },
        ColumnCensus {
            field: "preset",
            declares: Declares::NotFactBearing(
                "names a vendored module; the facts are that module's own declarations",
            ),
        },
        ColumnCensus {
            field: "provider",
            declares: Declares::NotFactBearing(
                "qualifies `preset`, selecting which of its modules compile; the facts stay \
                 those modules' own declarations (CLOUD-1625)",
            ),
        },
        ColumnCensus {
            field: "gate",
            declares: Declares::NotFactBearing(
                "names one of the engine's compiled gates; the facts are the gate's own (CLOUD-2291)",
            ),
        },
        ColumnCensus {
            field: "except",
            declares: Declares::NotFactBearing(
                "qualifies `preset`, naming modules it does not compile; the facts stay the \
                 remaining modules' own declarations (CLOUD-2290)",
            ),
        },
        ColumnCensus {
            field: "bundle",
            declares: Declares::NotFactBearing("names a vendored bundle, as `preset` does"),
        },
        ColumnCensus {
            field: "documents",
            declares: Declares::Fact(crate::facts::Fact::Document, |rule| {
                !rule.documents.is_empty()
            }),
        },
        ColumnCensus {
            field: "requires_path",
            // A `try_exists` per entry — no glob expansion, no read, nothing
            // spawned — and permitted on every kind by design. It is a filesystem
            // question and NOT a `Fact`, so the derivation does not reach it. Named
            // here rather than left silent, because "the census does not cover it"
            // and "the census considered it" are the two readings an omission
            // cannot be told apart from.
            declares: Declares::NotFactBearing(
                "a `try_exists` per declared entry, permitted on every kind and acquiring no fact",
            ),
        },
        ColumnCensus {
            field: "sources",
            declares: Declares::Fact(crate::facts::Fact::Document, |rule| {
                !rule.sources.is_empty()
            }),
        },
        ColumnCensus {
            field: "lines",
            declares: Declares::Fact(crate::facts::Fact::Lines, |rule| !rule.lines.is_empty()),
        },
        ColumnCensus {
            field: "line_sources",
            declares: Declares::Fact(crate::facts::Fact::Lines, |rule| {
                !rule.line_sources.is_empty()
            }),
        },
        ColumnCensus {
            field: "invocations",
            declares: Declares::Fact(crate::facts::Fact::Invocations, |rule| {
                !rule.invocations.is_empty()
            }),
        },
        ColumnCensus {
            field: "invocation_sources",
            declares: Declares::Fact(crate::facts::Fact::Invocations, |rule| {
                !rule.invocation_sources.is_empty()
            }),
        },
        ColumnCensus {
            field: "uses",
            declares: Declares::Fact(crate::facts::Fact::Uses, |rule| !rule.uses.is_empty()),
        },
        ColumnCensus {
            field: "use_sources",
            declares: Declares::Fact(crate::facts::Fact::Uses, |rule| {
                !rule.use_sources.is_empty()
            }),
        },
        ColumnCensus {
            field: "git",
            // The head/status/remote/worktrees family. All four are
            // `Surface::Check`, so the column is tree-only whichever read a row
            // asked for and one fact answers for it.
            declares: Declares::Fact(crate::facts::Fact::GitHead, |rule| !rule.git.is_empty()),
        },
        ColumnCensus {
            field: "symbols",
            declares: Declares::Fact(crate::facts::Fact::Symbols, |rule| rule.symbols),
        },
        ColumnCensus {
            field: "review",
            declares: Declares::Fact(crate::facts::Fact::Review, |rule| !rule.review.is_empty()),
        },
        ColumnCensus {
            field: "refs",
            declares: Declares::Fact(crate::facts::Fact::GitRef, |rule| !rule.refs.is_empty()),
        },
        ColumnCensus {
            field: "ranges",
            declares: Declares::Fact(crate::facts::Fact::GitRange, |rule| !rule.ranges.is_empty()),
        },
        ColumnCensus {
            field: "commits",
            declares: Declares::Fact(crate::facts::Fact::CommitMeta, |rule| {
                !rule.commits.is_empty()
            }),
        },
        ColumnCensus {
            field: "staged",
            declares: Declares::Fact(crate::facts::Fact::Staged, |rule| !rule.staged.is_empty()),
        },
        ColumnCensus {
            field: "history",
            declares: Declares::Fact(crate::facts::Fact::GitHistory, |rule| {
                !rule.history.is_empty()
            }),
        },
        ColumnCensus {
            field: "tags",
            declares: Declares::Fact(crate::facts::Fact::GitTags, |rule| !rule.tags.is_empty()),
        },
        ColumnCensus {
            field: "git_config",
            declares: Declares::Fact(crate::facts::Fact::GitConfig, |rule| {
                !rule.git_config.is_empty()
            }),
        },
        ColumnCensus {
            field: "index",
            declares: Declares::Fact(crate::facts::Fact::GitIndex, |rule| !rule.index.is_empty()),
        },
        ColumnCensus {
            field: "state",
            declares: Declares::Fact(crate::facts::Fact::State, |rule| !rule.state.is_empty()),
        },
        ColumnCensus {
            field: "forge",
            declares: Declares::Fact(crate::facts::Fact::Forge, |rule| !rule.forge.is_empty()),
        },
        ColumnCensus {
            field: "tools",
            declares: Declares::Fact(crate::facts::Fact::ToolVerdict, |rule| {
                !rule.tools.is_empty()
            }),
        },
        ColumnCensus {
            field: "plan",
            declares: Declares::Fact(crate::facts::Fact::Plan, |rule| !rule.plan.is_empty()),
        },
        ColumnCensus {
            field: "minted",
            declares: Declares::Fact(crate::facts::Fact::Minted, |rule| !rule.minted.is_empty()),
        },
        ColumnCensus {
            field: "captured",
            declares: Declares::Fact(crate::facts::Fact::Captured, |rule| {
                !rule.captured.is_empty()
            }),
        },
        ColumnCensus {
            field: "tasks",
            // Hook-surface (CLOUD-856): read from a receipt minted at session start,
            // so the mediated path parses no manifest. A mediated row declaring it
            // is asking for something this surface can answer.
            declares: Declares::Fact(crate::facts::Fact::Tasks, |rule| !rule.tasks.is_empty()),
        },
        ColumnCensus {
            field: "extract",
            // Hook-surface (CLOUD-1172): a declared extractor's COUNT over this
            // session's transcript, an integer over typed events.
            declares: Declares::Fact(crate::facts::Fact::Extracted, |rule| {
                !rule.extract.is_empty()
            }),
        },
        ColumnCensus {
            field: "landing",
            declares: Declares::Fact(crate::facts::Fact::Landing, |rule| !rule.landing.is_empty()),
        },
        ColumnCensus {
            field: "delta_sources",
            declares: Declares::Fact(crate::facts::Fact::BaseDelta, |rule| {
                !rule.delta_sources.is_empty()
            }),
        },
        ColumnCensus {
            field: "external",
            declares: Declares::Fact(crate::facts::Fact::External, |rule| {
                !rule.external.is_empty()
            }),
        },
        ColumnCensus {
            field: "module",
            declares: Declares::NotFactBearing(
                "names the module file; the facts are that module's own declarations",
            ),
        },
        ColumnCensus {
            field: "no_fix_reason",
            declares: Declares::NotFactBearing("states why a row declares no fix"),
        },
        ColumnCensus {
            field: "no_retry_reason",
            declares: Declares::NotFactBearing(
                "states why a repaired call has nothing to re-issue, so the row's \
                 class may be `silent` rather than `retry` (CLOUD-1639)",
            ),
        },
        ColumnCensus {
            field: "checks",
            // Hook-surface: the boundary already resolves receipt verdicts for the
            // typed rule table, which is what makes `ready-guard` a mediated row.
            declares: Declares::Fact(crate::facts::Fact::Receipts, |rule| rule.checks.is_some()),
        },
        ColumnCensus {
            field: "checks_any",
            // THE SAME FACT AS `checks`, and that is the whole of the entry: the two
            // columns differ in how they are ADJUDICATED — all of one, any of the
            // other — and not at all in what has to be resolved to adjudicate them.
            // A row naming three receipts in an alternation needs all three verdicts
            // resolved, because "any one is valid" cannot be answered without asking
            // about each; the alternation is applied to the answers, never to which
            // questions get asked.
            //
            // So this entry is what makes `Rule::receipt_names` honest at the
            // acquisition layer, the same way that helper makes it honest at every
            // resolution site: a column declaring no fact here would say the
            // alternation's names need not be resolved, which is the dead gate
            // CLOUD-1297 exists to have avoided.
            declares: Declares::Fact(crate::facts::Fact::Receipts, |rule| {
                rule.checks_any.is_some()
            }),
        },
        ColumnCensus {
            field: "key",
            declares: Declares::NotFactBearing(
                "which git fact a receipt is keyed to, not a fact itself",
            ),
        },
        ColumnCensus {
            field: "trigger",
            declares: Declares::NotFactBearing("what makes a receipt row fire"),
        },
        ColumnCensus {
            field: "verdict",
            declares: Declares::NotFactBearing("the verdict-bearing programs a pipeline row knows"),
        },
        ColumnCensus {
            field: "filters",
            declares: Declares::NotFactBearing("the filter programs a pipeline row knows"),
        },
        ColumnCensus {
            field: "substitutes",
            declares: Declares::NotFactBearing("the utilities a pipeline row redirects"),
        },
        ColumnCensus {
            field: "interprets",
            declares: Declares::NotFactBearing("the interpreters a pipeline row contains"),
        },
        ColumnCensus {
            field: "criteria",
            declares: Declares::NotFactBearing("what a judge row asks a model"),
        },
        ColumnCensus {
            field: "tier",
            declares: Declares::NotFactBearing("a judge finding's advisory tier"),
        },
    ];
}

pub mod startup {

    use crate::config_model::Startup;
    use crate::error::UsageError;
    use anyhow::Result;

    /// Refuse a row the engine cannot act on, at LOAD rather than at the first run.
    ///
    /// An empty `check` is the one that matters: [`ran_clean`] would answer
    /// could-not-look forever, so the row would report a failure nobody can fix and
    /// its repair would never run. Refusing it at load says which row and why, once,
    /// instead of once per session — the same direction `[[pattern]]`'s load-time
    /// refusal takes one surface over.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] naming the offending row's id.
    pub fn validate(rows: &[Startup]) -> Result<()> {
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for row in rows {
            if row.check.is_empty() {
                return Err(UsageError::raise(format!(
                    "[[startup]] {}: `check` is empty, so the row could never decide anything",
                    row.id
                )));
            }
            if row.repair.as_ref().is_some_and(Vec::is_empty) {
                return Err(UsageError::raise(format!(
                    "[[startup]] {}: `repair` is present and empty — omit the key for a \
                     diagnose-only row rather than declaring a repair that runs nothing",
                    row.id
                )));
            }
            if row.gloss.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "[[startup]] {}: `gloss` is empty, and the report is pointer-only — this is \
                     the one place the row's meaning can be written down",
                    row.id
                )));
            }
            if !seen.insert(row.id.as_str()) {
                return Err(UsageError::raise(format!(
                    "[[startup]] {}: declared twice — one id, one row, or a report names a \
                     verdict a reader cannot trace back",
                    row.id
                )));
            }
        }
        Ok(())
    }
}

pub mod transcript {
    use crate::config_model::TranscriptConfig;
    use crate::error::UsageError;

    use anyhow::Result;

    /// Validate the table at load, the way every other config table is.
    ///
    /// Takes an `Option` to match [`crate::config_check::budget::validate`]'s signature: `[budget]`
    /// and `[transcript]` are both tables rather than lists, so neither is reached by
    /// the `Vec<T>` census in `config.rs`, and both are called explicitly from
    /// `parse_ungated` for that reason.
    ///
    /// # Errors
    ///
    /// [`UsageError`] when a declared path is empty — a key present and blank is a
    /// different claim from a key absent, and the blank one is a mistake rather than
    /// a repository opting out. Left unchecked it would join to the repository root
    /// and be read as a directory, which surfaces as "undecodable transcript".
    pub fn validate(config: Option<&TranscriptConfig>) -> Result<()> {
        let Some(config) = config else {
            return Ok(());
        };
        if config.path.as_deref().is_some_and(str::is_empty) {
            return Err(UsageError::raise(
                "transcript.path: declared but empty; omit the key to opt out".to_owned(),
            ));
        }
        Ok(())
    }
}

pub mod waiver {
    use crate::config_model::Waiver;
    use crate::error::UsageError;

    use anyhow::Result;

    /// Refuse a malformed waiver table at load, so a typo cannot sit inert.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty rule id, an empty reason,
    /// an unparseable expiry, or the same rule-and-path waived twice.
    pub fn validate(table: &[Waiver]) -> Result<()> {
        for (index, waiver) in table.iter().enumerate() {
            if waiver.rule.trim().is_empty() {
                return Err(UsageError::raise(
                    "waiver: rule must not be empty — a waiver that names no rule suppresses nothing",
                ));
            }
            if waiver.reason.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "waiver {}: reason is required — an unjustified waiver is exactly the hatch this \
                     table exists to replace",
                    waiver.rule
                )));
            }
            waiver.expiry()?;
            if table[..index]
                .iter()
                .any(|prior| prior.key() == waiver.key())
            {
                return Err(UsageError::raise(format!(
                    "{}: declared twice",
                    waiver.key()
                )));
            }
        }
        Ok(())
    }
}

pub mod preset {
    use crate::config_check::verdict::declared_from;

    use crate::preset_catalog::MANIFESTS;

    use crate::config_model::DeclaredVerdict;

    /// Every verdict row the vendored presets declare, as the registry carries them.
    ///
    /// Chained onto the native rows by [`vendored`]. Derived rather
    /// than declared a second time: before this, adding a preset class meant editing
    /// a table in another module under a comment, and nothing tied the two together.
    #[must_use]
    pub fn verdict_rows() -> Vec<DeclaredVerdict> {
        MANIFESTS
            .iter()
            .flat_map(|manifest| manifest.verdicts.iter())
            .map(declared_from)
            .collect()
    }
}

pub mod verdict {
    #![allow(unused_imports)]
    use crate::config_model::{DeclaredVerdict, Route, Vocabulary, VocabularyWord};
    use crate::error::UsageError;
    use crate::preset_catalog::{Applicability, RouteKind};
    use crate::preset_catalog::{VendoredRoute, VendoredVerdict};
    use crate::preset_catalog::{admit, read, run};
    use serde::Serialize;
    use std::collections::BTreeSet;

    /// CLOUD-1823's route, shared by the two receipt classes a `turn mint ahead`
    /// deadlock can carry (CLOUD-1977) so the precondition is written once.
    pub(crate) const STALE_RECEIPT_ROUTE: VendoredRoute = admit(
        "articulate the stale receipt",
        "the check this receipt names is red on this head for a reason only a write can repair, so \
    re-running it cannot change its answer, and the work the receipt was taken about is already \
    pushed",
    );

    /// CLOUD-1806's route: the recorded way through every plain `shape` row.
    pub(crate) const SHAPE_ADMIT_ROUTE: VendoredRoute = admit(
        "articulate the call",
        "the remedy `batten policy explain` prints for this row cannot perform the change this call \
    makes, and you can name what the call changes and where a reviewer will see its effect",
    );

    /// Every class the BINARY ships: the native ones and the vendored presets'.
    ///
    /// # Why the presets' vocabulary ships with the presets
    ///
    /// A preset reaches a consumer who never wrote a `[[verdict]]` row, so holding
    /// it to the consumer's registry would make an enabled preset unloadable with no
    /// fix available — the wrongly-refusing gate AGENTS.md calls a defect, and the
    /// identical argument `policy::check_no_inline_regex` already records for a
    /// preset's patterns. The supply-chain claim is unchanged: `include_str!` at
    /// build time, no network, no registry, the same checksum as the rest of the
    /// binary.
    ///
    /// Non-negotiable rule 1 reaches this table exactly as it reaches the presets
    /// themselves: a class here may describe a PRACTICE and may never name a path, a
    /// task, a tracker key or an entity. `presets_are_inside_the_rule_one_glob`
    /// covers this file, because it is under `crates/**`.
    pub(crate) const VENDORED: &[VendoredVerdict] = &[
        // ── native ──────────────────────────────────────────────────────────────
        VendoredVerdict {
            id: "path write refused",
            gloss: "a mutating verb was aimed at a path the config protects",
            class: "The path is in the `protected` set, so a write to it is refused before it \
    happens rather than reported after. The set is the consumer's own declaration; what is \
    protected is a question about their repository, and the engine only enforces it. A \
    narrower remedy may be declared per path class through `[[redirect]]`, which is what the \
    refusal names when one exists.",
            routes: &[
                read("config read first", "batten.toml"),
                run("patch run first", "git restore"),
                // THE CLASS COULD NOT BE OVERRIDDEN, AND THAT LEFT ONLY THE PASSWORD.
                //
                // The two routes above are real and are the right first answers, but
                // neither reaches a path whose owning surface IS the protected file —
                // registering a rule, adding a redirect, retiring a gate onto a config
                // row. For that class of change `config read first` names the
                // file being refused, so the remedy is the thing denied.
                //
                // With no override route, `admission::questions_for` returns `None` and
                // `batten override request` answers "declares no `override` route, so
                // it cannot be overridden". The only remaining exit was the general
                // hatch (since retired) — a knowable string the guarded party could
                // set, which recorded nothing and stopped nobody. This repository already ruled
                // on that shape for `issue file same`: *the point of the admission
                // mechanism is that the bare variable stops working*.
                //
                // The precondition is what the asker must be ABLE TO STATE, never a
                // judgement the gate makes (non-negotiable rule 3). It names the owning
                // surface deliberately, so the first question forces the asker to say
                // why the route they were already given does not reach.
                admit(
                    "articulate the write",
                    "the surface this class names cannot express the change, so writing the \
    protected path directly is the only route left, and the write is one a reviewer will see \
    in the diff it lands in",
                ),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "program name unknown",
            gloss: "the boundary cannot classify this program, so it will not guess at a protected path",
            class: "This is an ADMISSION rather than an accusation: nothing here says the \
    command mutates. The program appears in neither `[[verb]]`, whose rows encode a program's \
    argv grammar, nor `protected_readers`, which declares a program to only read — so what it \
    would do to an operand is unknown, and the operand is a protected path. Silence used to \
    mean allow, and an allowlist-by-omission's omissions were holes: an interpreter writing a \
    protected path went unrefused while a redirect to the same path was denied. The direction \
    is inverted, which makes a forgotten reader a false refusal somebody fixes in a minute \
    rather than a silent hole. A compiled floor of programs that only ever read their operands \
    is consulted first, so the ordinary read tools never reach this class — and note that a \
    protected path may be DERIVED rather than declared: registering a policy module protects \
    it, so this can fire in a repository whose `protected` set is empty.",
            routes: &[
                read("config read first", "batten.toml"),
                run("readers declared", "batten config show"),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "rule read missing",
            gloss: "a config row changed by a context that has not read why it exists",
            class: "A rule's reasons live in the comment block above its row, its class \
    paragraph and the commits that shaped it, and nothing checked that a context changing the \
    row had read any of them -- which is how a gate's prose decays into a gloss nobody can act \
    on. So a write to a `[[rule]]` or `[[verdict]]` row of the committed authority needs this \
    context to have read that row's history, as it stands at HEAD: a commit to the row voids \
    the read, and so does a compaction, because what was read left the window with it. A new \
    row has no history and needs none.",
            routes: &[
                run("rule read first", "batten policy explain '<id>' --history"),
                admit(
                    "articulate the sweep",
                    "the write is one mechanical change applied across many rows, named in full, \
    whose every row would need the same history read for no different decision",
                ),
            ],
            applicability: Applicability::Advice,
        },
        // CLOUD-2290. Raised by `rules::ejected_behind`, never by a module.
        VendoredVerdict {
            id: "module pin stale",
            gloss: "a module ejected from a preset was copied at an older preset version than this binary ships",
            class: "`batten preset eject` copies a vendored module into this repository and records \
    the preset version it copied, so the copy stops changing when the binary does. That is the \
    point of ejecting, and it is also how a copy quietly misses a fix the preset shipped later. \
    This is a WARNING and a pointer, never a diff: what changed is the release notes' to say, and \
    whether to take it is this repository's call. Take it by hand and raise the recorded version, \
    or raise the version alone to say the change was read and declined.",
            routes: &[run("module read first", "batten preset eject --help")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "task run twice",
            gloss: "a live process in this clone already holds this task's lock",
            class: "Some tasks are one-per-clone: a second copy does not do the work \
    twice, it races the first over the same refs, the same lock and the same remote. The \
    task itself refuses a second copy, and this is the same refusal arriving before a \
    process starts rather than a fraction of a second after. A lock naming a DEAD pid is \
    not this class -- that is a corpse the acquiring path reclaims. A lock naming NOTHING \
    READABLE is this class: a holder caught between its create and its write is a holder, \
    which is the reading the acquiring path already takes, and a gate disagreeing with it \
    would allow a start that path then refuses.",
            routes: &[read("holder inspected", "batten task alive")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "history drop unpushed",
            gloss: "the reset would discard commits that exist in no other clone",
            class: "`git reset --hard` moves the branch and discards the working tree \
    and the index together, with none of the \"you have unstaged changes\" refusals that \
    stop git's other destructive verbs. Where every commit in the discarded range is on a \
    remote that is the ordinary undo and nothing is lost. Where one is not, the only copy \
    of that work is the commit being removed, and it is unreferenced the moment the reflog \
    expires. The class fires on the second case only: the verb is not the defect, \
    reachability is.",
            routes: &[
                // The two verbs that reach the same outcome without discarding a
                // commit. Named as the FIRST route because a caller who wanted to
                // drop a change usually wanted to drop a change, not a commit.
                //
                // The first draft named the set-aside verb `no_gix_gap_primitive_survives`
                // refuses anywhere in this tree: the primitives built on it retired with
                // the spawn they required (CLOUD-780), and a route naming a retired
                // concept is a remedy nobody here can follow. `--soft` is the better
                // answer anyway — it moves the same ref and leaves both the tree and the
                // index where they were.
                // THE RECOVERY LEADS, per the row's §5: a caller who reads this has
                // not lost anything yet, and what they need first is that the commit
                // is still reachable. It was a `Fix::Run` string at the deny site
                // (`hook::history_drop_refusal`) for its whole life, which rendered
                // only while `Fix` led the routes clause; CLOUD-1637 stopped
                // rendering `Fix`, so the recovery is declared here — on the class,
                // once, beside the other ways out — rather than smuggled through one
                // call site.
                run("commits still reachable", "git reflog"),
                // `run` RATHER THAN `read`, AND THE KIND WAS WRONG BEFORE
                // (CLOUD-1637). Both targets are commands and both were declared
                // `read`, which was inert while `command_routes` filtered the clause:
                // a `document` route rendered nowhere, so nothing read the kind and
                // nothing caught it. Now the kind decides the verb a reader is given,
                // and "read `git reset --soft`" is an instruction nobody can follow.
                run("ref moved, work kept", "git reset --soft"),
                run("file reverted", "git checkout -- <path>"),
                // The way through that leaves a record, which is what keeps this a
                // gate rather than a wall. Its precondition also makes the class
                // non-suppressible by any hatch (CLOUD-1357), which is
                // right for a verb whose subject is gone by the time anyone reads
                // the refusal.
                admit(
                    "articulate the loss",
                    "the commits this discards are ones you have read and intend to lose, and \
    you can name what they contained without consulting them",
                ),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "config write refused",
            gloss: "`init` will not overwrite the committed authority",
            class: "House style §8 gives a repository ONE committed authority, and `init` \
    writes it. Overwriting an existing one would replace a reviewed policy with a default \
    set, silently, in a verb whose whole purpose is that there was nothing there before. \
    Edit the file that exists, or move it aside deliberately.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "outcome table refused",
            gloss: "an `[[outcome]]` row could not mean anything",
            class: "A post-tool signature names the class it establishes, the exit code that \
    anchors it, and the OS family it applies to. A row naming a class the engine cannot resolve, \
    a family nobody surveyed, or a code a second row already claims is an arm that fires on \
    nothing — and a declared-but-dead arm is worse than an absent one, because it reads as \
    coverage while its route has never been walked. The refusal names the row and the key.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "plan read stale",
            gloss: "the committed plan projection no longer matches the pinned runner",
            class: "An adopted runner decides which steps a gate runs, in what order, under \
    which profiles and in which parallel group, and the committed projection is the reviewed \
    answer to that. A live plan that differs means the gate now enforces something nobody \
    read a diff of. Regenerate the projection and review the diff — the difference is the \
    decision, and absorbing it silently is what this refuses.",
            routes: &[run("contract run first", "batten hk contract")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "handler answer denied",
            gloss: "a configured hook handler denied the call",
            class: "The refusal is the handler's, not the engine's: a `[hook.handler]` row \
    names a program, the program answered deny, and this carries that answer through. The \
    handler's own reason is free text the consumer configured, so no remedy is invented here \
    — the handler is where a remedy would have to be declared.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "scanner pin missing",
            gloss: "a `secrets` rule needs its scanner pinned and none is declared",
            class: "A `secrets` rule delegates to an external scanner, and which scanner \
    decides what the rule means. An unpinned one would resolve to whatever is ambient, so a \
    green run would say nothing about the tree — the same defect a bare `cargo` has against \
    a pinned toolchain. Declare the scanner as a `[[provision]]` entry.",
            routes: &[
                run("check run first", "batten provision"),
                read("config read first", "batten.toml"),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "scanner install missing",
            gloss: "the pinned scanner is not in the provision cache, so nothing was scanned",
            class: "The scanner is declared and absent. This is could-not-look rather than a \
    clean tree, and it is reported as a refusal precisely so the two are not spelled the \
    same way: a secrets rule that scanned no file and reported nothing is the vacuous pass \
    this engine argues against everywhere.",
            routes: &[run("check run first", "batten provision")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "spawn run refused",
            gloss: "this rule kind runs a configured command, which a read-effect verb will not do",
            class: "The effect model (house style §5) puts every verb in one class and holds \
    it there. A rule kind that spawns is `Effect`, and `check` is `Read`, so reaching one \
    through the other would make the read-only allowlist a claim nobody could rely on. The \
    rule is not wrong; the verb is.",
            routes: &[run("check run first", "batten enforce")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "turn finish unmet",
            gloss: "the end-of-turn facts do not permit stopping",
            class: "A stop is a completion signal, and this engine's whole subject is keeping \
    that signal aligned with landed-and-verified work. The facts the turn ended on say it is \
    not, and the refusal names which. Each has its own route; the shared one is to finish \
    the thing rather than to re-declare that it is finished.",
            routes: &[
                run("task run first", "mise run land"),
                read("config read first", "batten.toml"),
            ],
            applicability: Applicability::Advice,
        },
        // ── the mediated composers' classes (CLOUD-1285) ────────────────────────
        //
        // The cause each of these carries used to be a hardcoded `format!` in
        // `hook.rs` that `Refusal::new` then dropped the class for. Moving the prose
        // here is what makes it dereferenceable: `batten policy explain <token>`
        // answers with the `class` below, so the hot path can carry the token and the
        // pointers and stop repeating the paragraph on every firing.
        VendoredVerdict {
            id: "receipt read missing",
            gloss: "a declared receipt does not attest the commit this call is made against",
            class: "A `receipt` row names checks whose verdict must already exist for this \
    commit, in this checkout. The receipt is missing, older than the row allows, recorded \
    against a different head, or records something the row does not accept -- and the refusal \
    names which, because the four call for different repairs. Re-running the check is the \
    remedy for a missing one and useless for a refuted one.",
            // CLOUD-1823's route, declared where the refusal lands (CLOUD-1977). A red
            // check writes no receipt, so `turn mint ahead` over a red head refuses as
            // MISSING, never as `receipt read other`. The route there alone was
            // unreachable from the deadlock it was written for: `admit_mediated` binds
            // to the class the refusal carries.
            routes: &[
                read("config read first", "batten.toml"),
                STALE_RECEIPT_ROUTE,
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "receipt read late",
            gloss: "the receipt exists and is older than the row allows",
            class: "The step RAN, and not recently enough for its verdict to still be evidence. \
    That is a different repair from a missing receipt and is why it is a different class: \
    re-run the check. A row declaring a `max_age` is saying the world can move underneath the \
    answer, so an old verdict is could-not-look rather than a pass.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "receipt carry other",
            gloss: "the receipt records something this row does not accept",
            class: "The step ran and what it recorded is not what the row requires. This is the \
    one receipt class that is a statement about what was READ rather than about the read, so \
    re-running the check changes nothing until the thing it reports is fixed. An ABSENT field \
    is could-not-look and is not this class.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "receipt read other",
            gloss: "an amend or a rebase replaced the bytes this receipt validated",
            class: "The receipt is keyed to a commit this branch no longer carries. Its verdict \
    covered the bytes it read and nothing later, so it is not evidence about this head. Re-run \
    the check against what is here now. Kept apart from the trunk case because the two name \
    different things that moved, and a refusal that says the wrong one sends the reader after \
    the wrong repair.",
            routes: &[
                read("config read first", "batten.toml"),
                // THE RE-RUN IS THE RIGHT FIRST ANSWER AND SOMETIMES CANNOT BE TAKEN
                // (CLOUD-1823), which is the same hole `path write refused` had:
                // a class whose only route is the thing the refusal blocks.
                //
                // Measured twice. `turn mint ahead` is keyed to the head and triggers
                // on WRITE, so where the named check is red for reasons only a write
                // can repair, "re-run the check" prescribes a run that cannot change
                // its answer, and the write that would is the call being refused. The
                // branch has no exit: every edit is denied, and the denial is
                // discharged only by the edits. With no override route
                // `admission::questions_for` returns `None`, so the sole remaining way
                // through was the general hook hatch — a knowable string that records
                // nothing, which this repository already ruled on for `issue file
                // same`: *the point of the admission mechanism is that the bare
                // variable stops working*. The hatch is retired engine-wide now, and
                // `admit_mediated` (`lib.rs`) is what consumes a spent admission.
                //
                // THE ROUTE IS HEAD-BOUND, SO IT IS NOT THE EXIT FOR A LONG EDIT
                // (CLOUD-843): an admission binds `Anchor::Call { head }`, and every
                // commit voids it. `turn mint ahead` escapes the wedge through
                // `while_unpushed` instead — a pushed head is the harm the row names
                // being absent — and this route stays for a head that cannot be pushed.
                //
                // The precondition is what the asker must be ABLE TO STATE, never a
                // judgement the gate makes (non-negotiable rule 3). Both halves are
                // checkable by a reader: whether the check is red on this head, and
                // whether the work the receipt was about is on a remote. The second
                // half is the one that matters — it is the harm the refusing row
                // actually guards, and an asker who cannot state it is being stopped
                // for the right reason.
                STALE_RECEIPT_ROUTE,
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "receipt read stale",
            gloss: "the receipt was taken against a trunk this branch has moved off",
            class: "The branch MOVED FORWARD off the base the receipt was taken against -- \
    `git checkout -B <name> origin/main` after a merge, which repoints the name at a new base \
    and discards the commits that were the branch, while the receipt survives keyed by that \
    name. Re-take the evidence on the branch as it now stands. Distinct from the amend case: \
    there the branch's own bytes changed, here the branch is a different branch wearing the \
    same name. THE DIRECTION IS THE PREDICATE (CLOUD-1091): a branch merely BEHIND the trunk \
    keeps its receipt, because the receipt is then more current than the branch and no amount \
    of re-taking it can help -- this text said the opposite for its whole life and prescribed \
    the one action guaranteed not to work.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "tool run loose",
            gloss: "a shell text utility stood in for the structured file surface",
            class: "The call reaches for a text utility over a path this repository CONTAINS, as \
    its FIRST stage, to answer a question the structured surface answers directly and better: \
    a range of one file's contents, a pattern across the tree, paths by glob, or what a name \
    resolves to. Which instruments a session carries varies, so the refusal names the question \
    classes rather than a product. The same utility DOWNSTREAM of a pipe is untouched, because \
    filtering another command's output is not standing in for anything. CONTAINMENT, never the \
    INDEX (CLOUD-1109): the boundary resolves the operand against the call's own working \
    directory and asks whether the repository contains the result. It does not ask git, because \
    a `git ls-files` per mediated call is a spawn `RuleKind::scopes` forbids on this kind and \
    `perf-assert` prices out. This text said 'tracks' for its whole life and nothing ever \
    checked it -- a class a reader believes is worse than one they cannot look up.",
            routes: &[read("rule read first", "rules/scanning.md")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "path read routed",
            gloss: "this path declares its own read route, named after it",
            class: "A structured READ of a path whose `[[redirect]]` row declares a `read` \
    remedy (CLOUD-1258). The row exists because a path read couples the caller to the tree \
    layout, and the named tool survives a move of that tree where a hardcoded path does not. \
    The refusal names the path and then the declared route, so the way out is on the line \
    itself; the tool that read it is the envelope's own and is not repeated, which keeps the \
    longest committed memory name within `[refusal] max_tokens`. A row declaring no `read` refuses nothing, \
    which is how a consumer whose session does not carry the tool says so. Not `tool run \
    loose` (CLOUD-1929): no shell utility was involved, and that class's route sent a memory \
    reader to the scanning rules instead of to the tool its own row names.",
            routes: &[run(
                "rule explain first",
                "batten policy explain protected-mutation",
            )],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "verdict read dropped",
            gloss: "piping a verdict-bearing command into a pager or filter discards its status",
            class: "The pipeline exits with the FILTER's status, which is 0 whether the command \
    passed or failed. A verdict is read from the harness, never inferred from output. Background \
    the command and read the exit code the notification carries; a pager over a FILE is fine, a \
    pager over a live task is not. DO NOT REDIRECT INSTEAD -- this text prescribed `> file 2>&1` \
    for its whole life, and `redirect write unread` now refuses exactly that, because the harness \
    already captures a backgrounded task's output where the human watches.",
            routes: &[read("rule read first", "rules/toolchain.md")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "verdict carry other",
            gloss: "a verdict-bearing command followed by `;`, `||` or a newline has its status replaced",
            class: "Only the last element's status survives, so the compound reports the wrong \
    command's verdict. This is the laundered shape: it reads as correct, and backgrounded it is \
    worse than a misread, because the completion notification then carries the compound's \
    status. `&&` is fine -- it short-circuits, so a failure still propagates.",
            routes: &[read("rule read first", "rules/toolchain.md")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "turn watch dropped",
            gloss: "detaching a command orphans it from the tool call",
            class: "`nohup` or a trailing `&` returns the call at once, the harness records it \
    complete, and the session loses the wake-up it would get when the work actually exits. \
    Backgrounding the tool call is the supported shape and keeps the notification; detaching \
    inside the call throws it away.",
            routes: &[read("rule read first", "rules/toolchain.md")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "call count over",
            gloss: "this call measures over a ceiling the config declares",
            class: "A `ceiling` row counts something about the call and refuses above a declared \
    maximum. The count and the maximum are the whole finding -- what was counted is the row's \
    subject, and the refusal carries neither the measured content nor the call text, which is \
    non-negotiable rule 4 decided at the composer rather than at the report.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "call name refused",
            gloss: "the mediated call matches a command shape the config refuses",
            class: "A `shape` row declares a command spelling that is refused outright. The \
    refusal names the row rather than echoing the command, because the command is the caller's \
    own text and could carry anything. What to run instead is the row's declared remedy, which \
    `batten policy explain` prints; where that remedy cannot perform the change, the class is \
    admissible through a recorded admission bound to the row id at the current commit.",
            routes: &[
                run("rule read first", crate::grammar::RULE_HOP_PLACEHOLDER),
                SHAPE_ADMIT_ROUTE,
            ],
            applicability: Applicability::Advice,
        },
        // ─── the repaired arms (CLOUD-1639) ──────────────────────────────────────
        //
        // The two classes that say the boundary ACTED rather than advised. Both are
        // vendored rather than consumer-declared for the reason every `Native` class
        // is: the engine raises them from its own code, so a consumer could not
        // decline to declare one without making a refusal site unable to speak.
        //
        // THEIR OWN `applicability` IS `advice`, WHICH IS NOT A CONTRADICTION. The
        // column says what the boundary may do about THIS class, and there is
        // nothing left to repair — the repair already happened and these are how it
        // is reported. A `retry` here would mean "repair the report", which is not
        // a thing.
        VendoredVerdict {
            id: "call retry now",
            gloss: "the boundary repaired what it refused; re-issue the identical call",
            class: "A rule declared a repair for the shape it refuses, the boundary ran it, and it \
    succeeded. The call as made did not happen, so this is a refusal rather than an allow — but the \
    condition that caused it is gone, and the same call issued again is expected to pass. Nothing \
    needs deciding: the token IS the instruction. Re-issuing a call the boundary has just repaired \
    for is the one retry that is not a guess, which is why this is its own class rather than the \
    original refusal read a second time and puzzled over.",
            routes: &[run("call issue again", "the identical call, unchanged")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "call fix silent",
            gloss: "the boundary repaired the call and let it through, and this is the record",
            class: "A rule declared a repair, the boundary ran it, and the class it raises declares \
    that the call proceeds rather than being re-issued. The call was ALLOWED; this is the record that \
    something changed underneath it, which is the half no surveyed system omits — a mutating \
    admission controller applies silently and still writes an audit annotation. A repair nobody is \
    told about leaves a tree that no longer matches what its author last read, and that cost is \
    measured rather than assumed. The row owes `no_retry_reason`, so proceeding without a re-issue is \
    somebody's stated decision.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "input write refused",
            gloss: "the content this call would write matches a refused shape",
            class: "A `content` row judges what a write would PUT somewhere rather than which \
    path it targets, so it fires before the bytes land. The refusal names the row and the \
    destination and never the matched content -- this rule reads exactly the text somebody \
    wanted checked, which is the likeliest place in the surface for a secret to appear.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "issue name missing",
            gloss: "the work this call publishes names no tracker key",
            class: "A `requires_key` row narrows a refusal from \"this command is banned\" to \
    \"this command is banned unless the work is keyed\". Three evidence sources are read and any \
    one of them allows: the command itself, the branch name, and the commit subjects on the \
    range the row declares. None carried a key, so nothing on the published work says which row \
    it serves.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        // ── the config loader's classes (CLOUD-1313) ────────────────────────────
        //
        // One per `VALIDATED_AT_LOAD` table plus the remedy resolver. Each `class`
        // says what the table is FOR and what a refusal from it therefore means,
        // because the message the loader already carries says which row and key
        // failed and repeating that here would be the payload rule 4 refuses.
        //
        // Every route is the config itself, which is not a placeholder: a config
        // fault is edited in exactly one file, and a `command` route would have to
        // name a task that can run over a config that does not load.
        VendoredVerdict {
            id: "config read refused",
            gloss: "the declaration is not TOML, so no rule in it could be read",
            class: "Every other config fault leaves the rest of the file deciding -- an unknown key \
    costs its own row, a table whose validator refuses names that table, and a version this build \
    is too old for still says so. Each of those keeps a working gate surface and an agent that can \
    be told to repair the broken part. This one has no partial function to preserve: the bytes are \
    not TOML, so zero rows are readable and nothing is enforced. That is why it is the one class \
    the mediated boundary refuses a call under, rather than reporting and proceeding -- a gate that \
    fails open is inert, and an inert gate over an unreadable authority is the false green this \
    engine exists to catch.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "verb declare refused",
            gloss: "the verb table would not load",
            class: "`[[verb]]` is how a consumer names the commands their harness mediates and \
    what effect each carries. A row that is inert -- declared twice, or read-effect in a table \
    named for mutation -- reads as covered while matching nothing, so the table is proven at \
    load rather than at the call it would have decided.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "pattern declare refused",
            gloss: "the named-pattern registry would not load",
            class: "`[[pattern]]` gives one concept one spelling, so a module cannot inline a \
    regex and duplication becomes unwritable rather than merely detectable. A malformed \
    expression here is a config fault, and refusing it at load is what stops a mediated call \
    discovering it at adjudication -- the worst moment and the wrong exit class.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "traversal declare refused",
            gloss: "the declared-walk registry would not load",
            class: "`[[traversal]]` is where a graph walk is DECLARED rather than written into a \
    module, which is what keeps a consumer's edge vocabulary out of the core and what BOUNDS the \
    walk -- the engine cannot traverse what no row asked for. A malformed row here is a config \
    fault: a half-declared stop condition would walk to exhaustion while reading as a stop, and a \
    zero bound would decide nothing while loading clean. Refusing at load is what stops a gate \
    discovering either at adjudication.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "register declare refused",
            gloss: "the declared-key-set registry would not load",
            class: "`[[register]]` is where a key set a `reference` row resolves against is \
    DECLARED -- which file, which column, which node -- so a consumer's vocabulary stays out of \
    the core and the engine owns the one table grammar. A malformed row here is a config fault: \
    a key column past the declared width, or a blank key node, would build a set that answers \
    about the wrong cells while loading clean. Refusing at load is what stops a gate discovering \
    it at adjudication.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "verdict declare refused",
            gloss: "the refusal vocabulary would not load",
            class: "`[[verdict]]` is the registry every other class in this table belongs to: a \
    token's arity, a gloss that is one line, a route list that is not an override alone, a \
    tombstone chain that terminates. Each clause is a property of the table, so it is knowable \
    without a tree and belongs where a config fault is reported.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "redirect declare refused",
            gloss: "the redirect table would not load",
            class: "`[[redirect]]` changes what a refusal SAYS for a class of path, never \
    whether it fires -- which is why it needs no raise-only clamp and why a redefinition is \
    refused for coherence with the other append-only tables rather than because it lowers a \
    bar.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "deferral declare refused",
            gloss: "the deferral table would not load",
            class: "A `[[deferral]]` row whose `reaches` is not a version could never be \
    compared, so it would read as a watched condition while nothing watched it -- which is the \
    defect the table exists to close, arriving through the table itself. Refused at load rather \
    than at evaluation, because a row that can never fire is a config fault and not a finding.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "remedy resolve missing",
            gloss: "a declared remedy names a command that does not exist",
            class: "A refusal whose remedy points at a verb that was renamed away is worse than \
    one carrying no remedy: the reader spends the round finding out. This is the one clause \
    needing a THIRD table -- the rule ids -- so it lives at the load rather than inside either \
    remedy table's own validator, where a checker reaching past its argument would quietly \
    become the config's.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "marker declare refused",
            gloss: "the marker table would not load",
            class: "`[[marker]]` declares the tokens a scan treats as significant. An empty \
    `token` matches every line of every file, which loads clean and reads as coverage, so the \
    table is proven at load.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "rule declare refused",
            gloss: "the rule table would not load",
            class: "`[[rule]]` is the policy surface itself, and it used to be validated only by \
    whichever runner happened to evaluate it. That was defensible with one runner; with a tree \
    engine and a mediation boundary, a malformed mediated-call row validated only by the tree \
    engine is a row that loads, matches nothing at the mediation channel, and reads as \
    coverage.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "output declare refused",
            gloss: "the exec output-predicate table would not load",
            class: "`[[exec_pattern]]` is how a wrapped command's OUTPUT becomes a decidable \
    object rather than something a reader skims. A duplicate id makes two predicates \
    indistinguishable in the record they write.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "environment declare refused",
            gloss: "the verify-environment classifier table would not load",
            class: "`[[verify_environment_pattern]]` is what tells a gate refusal caused by the \
    MACHINE from one caused by this tree, so a malformed row does not fail loudly — it classifies \
    nothing and reads as a consumer who declared no classifier at all, and every refusal goes back \
    to being reported as a defect to reproduce. A SECOND class over the same type as \
    `output declare refused` rather than a shared one, because a refusal has to name which of the \
    two tables to edit.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "waiver declare refused",
            gloss: "the waiver table would not load",
            class: "The stakes here are inverted from every other table: a malformed rule fails \
    to gate, but a malformed WAIVER is a hatch whose expiry nobody could read. Refusing at load \
    is what makes \"every waiver carries an expiry\" true of the resolved config rather than \
    aspirational.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "fact declare refused",
            gloss: "the fact table would not load",
            class: "`[[fact]]` declares what the boundary resolves about a call before any rule \
    reads it. A row naming a fact the engine cannot produce is a gate that evaluates, reads \
    undefined, and refuses nothing -- the silent dead gate, decided at load instead.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "mint declare refused",
            gloss: "the mint table would not load",
            class: "`[[mint]]` declares what a receipt records and how long it answers for. A \
    malformed row is a receipt nothing can satisfy or one that answers forever, and both are \
    decidable from the table alone.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "recorder declare refused",
            gloss: "the recorder table would not load",
            class: "`[[recorder]]` binds a captured section to a named pattern. It is validated \
    AFTER the pattern registry, because a refusal for a missing pattern id is only honest once \
    the ids are known to be well formed themselves.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "record declare refused",
            gloss: "the record table would not load",
            class: "`[[record]]` declares a family a producer fills with `batten record named`, so \
    that a module may read its store at all. A row whose name could never be written, or whose \
    writer is unnamed, is a family that can only ever answer could-not-look -- and the moment to \
    say so is at load, not after a green run nobody questioned.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "provision declare refused",
            gloss: "the provision table would not load",
            class: "`[[provision]]` is how a pinned tool reaches the cache a rule will look for \
    it in. A row that cannot resolve is a rule that will report a missing scanner at the moment \
    it was supposed to decide something.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "startup declare refused",
            gloss: "the startup table would not load",
            class: "`[[startup]]` is how a repository states what its container must be and how that is repaired. A row that could never decide -- an empty check, a repair that runs nothing, an id declared twice -- is a precondition reported as broken every session with no repair reachable, so it is refused here rather than once per session, where the failure would read as a broken container instead of a typo in this file.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "step declare refused",
            gloss: "the step table would not load",
            class: "`[[step]]` declares what keys a step's receipt: the pathspecs whose index \
    entries it hashes and the tool argvs whose answers it hashes. A row with no inputs keys no \
    file and would answer for any tree; a row with no tools lets a receipt outlive the toolchain \
    that earned it; a `:`-magic pathspec selects nothing and reads as a clean set. Each is a \
    receipt attesting bytes nobody checked, so it is refused at load rather than trusted at the \
    first hit.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        // ── commit-msg channel ──────────────────────────────────────────────────
        VendoredVerdict {
            id: "commit spelling wrong",
            gloss: "the commit subject does not match the repository's declared commit convention",
            class: "`[commit] subject_pattern` is the one expression every non-merge commit's \
    subject must match. A repository that lands by fast-forward derives its changelog and its \
    version bump from those subjects, so whether a subject is conventional is a rule about what a \
    commit may be. The engine never judges whether a subject is good: it asks whether the \
    configured pattern matches the first line, and the type words and scope shape are the \
    consumer's own. The finding points at the commit and the field and never echoes the subject, \
    which can carry anything its author typed.",
            routes: &[
                read("config read first", "batten.toml"),
                run("commit write now", "git commit -F <path>"),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit name missing",
            gloss: "the commit names no tracker row and no declared exemption covers it",
            class: "`[commit.claims]` asks that every commit in a judged range name the row it \
    serves: a closing keyword or the first key of a reference trailer, read through the \
    consumer's own key grammar. A claim receipt never leaves the clone, so this is the half of a \
    claim a reviewer and a workflow can see. Claiming is stricter than mentioning. An exemption is \
    a property of the commit, never of its wording: every path it changed, and where declared its \
    author address, must match one `unclaimed` row.",
            routes: &[
                run("commit edit now", "git commit --amend -F <path>"),
                read("config read first", "batten.toml"),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit admit missing",
            gloss: "the commit wrote a protected path and carries no articulation block for it",
            class: "An override makes a protected write admissible, and the articulation it cost \
    lives in a store scoped to the container. The block in the commit message is what makes that \
    reasoning durable and readable by every reviewer of the change it justifies. This finding is \
    the honest omission: the commit wrote the path and no block claims it. Issue and spend an \
    admission against the class that refused the write, and carry the block it prints. A path \
    whose writes a redirect sanctions owes no block, because nothing was refused and nothing was \
    issued.",
            routes: &[
                run(
                    "grant ask first",
                    "batten override request --rule protected-mutation --verdict 'path write \
    refused' --subject <path>",
                ),
                run(
                    "grant write now",
                    "batten override spend --admission <address> --rule protected-mutation \
    --verdict 'path write refused' --subject <path>",
                ),
                read("config read first", "batten.toml"),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit admit other",
            gloss: "an articulation block for this path does not hash to the address it names",
            class: "The graver of the two articulation findings, and the opposite of an omission: \
    a block claims this path and does not recompute to the address it carries. Somebody edited the \
    reasoning after it was issued, or assembled a block by hand. The check is a pure function of \
    the block, so it decides identically on a runner that has never seen the admission store. It \
    is still reached on a path a redirect sanctions, because a doctored block is examined even \
    where none was owed. Issue a fresh admission and carry the block it prints verbatim.",
            routes: &[
                run(
                    "grant ask first",
                    "batten override request --rule protected-mutation --verdict 'path write \
    refused' --subject <path>",
                ),
                run(
                    "grant write now",
                    "batten override spend --admission <address> --rule protected-mutation \
    --verdict 'path write refused' --subject <path>",
                ),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit admit same",
            gloss: "the commit adds a conserves-ledger arm and spends it in the same change",
            class: "An optional conserves-ledger arm widens what a deletion may claim, so adding \
    one wants an independent reader. A commit that both introduces the arm and spends it is \
    self-authorizing: the thing that would have refused the deletion was authored by the same \
    change. The remedy is sequencing, not permission. Land the arm, let it be reviewed on its \
    own, then spend it in a later commit. There is deliberately no override, since an admission \
    here would be the author authorizing their own hatch one layer up.",
            routes: &[run("commit ship first", "git restore --staged <path>")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit own refused",
            gloss: "the commit's author or committer is an identity the attribution policy denies",
            class: "`[attribution]` governs what a produced commit may carry about the tooling \
    that made it, and `identity_deny` is the half that reads the author and committer as git \
    stamps them. The committer is judged too, because it is the field a repair reaching only the \
    author leaves behind. The finding names the field and never the identity. The declared \
    repair sets the repository-local identity to the accountable one the table declares, and \
    leaves an identity a contributor set for themselves alone when the policy accepts it.",
            routes: &[run("config fix now", "batten attribution identity")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit carry refused",
            gloss: "the commit carries a trailer the attribution policy denies",
            class: "`[attribution] trailer_deny` names trailer shapes a produced commit may not \
    carry, and `trailer_allow` is the only carve-out: an empty allow list exempts nothing, which \
    is the posture that discloses nothing. The finding names the trailer KEY and never its value, \
    because the value is the payload the policy exists to keep out of history. Rewrite the \
    message without the trailer.",
            routes: &[run("commit write now", "git commit -F <path>")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit state refused",
            gloss: "the commit message body states attribution the policy denies",
            class: "`[attribution] body_deny` names phrasings a produced commit's message may not \
    state about the tooling that made it. The whole message is judged, not only the trailers, \
    because a formula in the body discloses exactly what a refused trailer would. The finding \
    names the field and never the matched text. Rewrite the message without it.",
            routes: &[run("commit write now", "git commit -F <path>")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "tag own refused",
            gloss: "the tag was cut by an identity the attribution policy does not permit",
            class: "`[attribution] tag_identity_allow` is an allow-form: every tagger that is not \
    the declared identity is refused, so a release cut by an unexpected credential is caught \
    whether or not anyone predicted that credential. `identity_deny` is still consulted, and a \
    tagger both permitted and denied is refused. The finding names the tag and never the tagger \
    identity. Delete the tag and cut it again under the accountable identity.",
            routes: &[
                run("tag retire now", "git tag -d <tag>"),
                read("config read first", "batten.toml"),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "tag own unnamed",
            gloss: "the tag carries no tagger identity, so who cut it cannot be judged",
            class: "A lightweight tag is a ref pointing straight at a commit, and an unsigned \
    annotated tag carries no tagger header. Either way there is no identity to hold to \
    `tag_identity_allow`, and reading that absence as accountable is how a release cut by anyone \
    would pass. Replace it with an annotated tag cut under the accountable identity.",
            routes: &[
                run("tag retire now", "git tag -d <tag>"),
                run("tag mint now", "git tag -a <tag>"),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "prose declare refused",
            gloss: "a config column's text is longer than the cap its column declares",
            class: "Batten echoes config prose back -- `batten policy explain` prints a class \
    and a row's reason, and a first sighting renders the reason in full -- \
    so the length of every string a config declares is paid in every reader's context. Each \
    column is held to a cap at load: one line for a gloss, a sentence for a route, a remedy or a \
    note, a paragraph for a class or a reason, and the paragraph ceiling for any column not listed \
    tighter. An over-cap value is refused rather than truncated, because a truncated reason is a \
    remedy missing its second half. The refusal names the column, the row index, the length and \
    the cap, never the text. Shorten the value; provenance and evidence belong in a TOML comment \
    beside the row, which is never parsed or emitted.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        // ── the unclassed emitters' classes (CLOUD-2078) ─────────────────────────
        // One class per emitter FAMILY: the site's own message travels as a subject,
        // so it rides both arms and nothing per-site is withheld.
        VendoredVerdict {
            id: "input parse refused",
            gloss: "the invocation was refused before it ran; the subject says why",
            class: "A verb that refuses its own input -- an unknown flag, a missing argument, a \
    value it cannot use -- has decided nothing about the work. The subject is the verb's own \
    sentence, and `batten --help` lists every verb and flag this build carries.",
            routes: &[run("verb help first", "batten --help")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "verb run broken",
            gloss: "the verb could not complete; the chain is a diagnosis of Batten, not a verdict",
            class: "An internal failure is exit 3: the verb could not look, so it decided \
    nothing. The subjects are the error chain, outermost first. A failure that repeats on an \
    unchanged tree is a defect in Batten to file with that chain; `batten doctor` checks the \
    environment the verb ran in.",
            routes: &[run("doctor run first", "batten doctor")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "issue file refused",
            gloss: "the row a bot pull request implies cannot be derived, so none is filed",
            class: "`pr derive` files the tracker row a bot's pull request stands for, and \
    refuses when the author, the owned manifest or the subject cannot be read as one. The \
    subjects name which.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "layer carry refused",
            gloss: "an ingested layer would replace a committed value it may only tighten",
            class: "Configuration is one committed authority plus raise-only overrides. A layer \
    that would loosen a committed value is refused whole rather than applied in part; the \
    subjects name the first key, the layer and how many keys it touched.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "provision pin other",
            gloss: "the fetched artifact does not match its pin, so nothing was installed",
            class: "A provision is installed only when its bytes hash to the pinned digest. A \
    mismatch means the pin is stale or the source changed under it; nothing was installed, and \
    the subjects carry both digests.",
            routes: &[run("check run first", "batten provision apply")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit ship missing",
            gloss: "the turn declared a stopping point and its commits are not on the landing target",
            class: "Work that is committed and not landed is in no state anyone else can see, \
    and a container reclaim loses whatever is not pushed. The subjects count the commits not on \
    the landing target. This is said once per claim until the operator speaks again: a landing \
    held on purpose is a state, not an omission, and repeating it every turn displaces the \
    operator's own words (CLOUD-2332).",
            routes: &[run("land run first", "batten land lap")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit ship unknown",
            gloss: "the clone is shallow, so where these commits are cannot be computed",
            class: "A shallow clone stops every history walk at its boundary, so whether the \
    turn's commits are on the landing target could not be computed; that is could-not-look, \
    never landed. Said once per claim until the operator speaks again (CLOUD-2655).",
            routes: &[run("unshallow run first", "git fetch --unshallow")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit push missing",
            gloss: "the claim's commits exist only in this clone",
            class: "This repository declares `landed_by = \"person\"`: a person merges what the \
    agent pushed, so the agent's last step is the push. These commits are not on the branch's \
    upstream, or the branch tracks none, and a container reclaim loses them. The second subject \
    names which (CLOUD-2656).",
            routes: &[
                run("push run first", "git push"),
                run("upstream set first", "git push -u <remote> HEAD"),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit merge held",
            gloss: "the work is pushed and a person merges it",
            class: "This repository declares `landed_by = \"person\"`, and the claim's commits \
    are on the branch's upstream: the merge is a person's step, not this session's. Said once; \
    the Stop is not refused (CLOUD-2656).",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "issue list unclear",
            gloss: "every row this branch filed, for a by-number answer: independent, or a punt",
            class: "A row filed while doing a task is either independent work or part of the \
    task deferred. The subjects list every row this branch filed; answer each by number, and \
    close the ones that are this task's here.",
            routes: &[run("ready lint first", "batten ready lint")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "hook report now",
            gloss: "a declared hook handler reported on this call; its words are the subject",
            class: "A `[[hook.handler]]` row dispatches a program on an event, and its report \
    travels as the subject: `hook.handler.<id>` names the row, the rest is what it said. Its row \
    in the config says what it guards.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "hook answer broken",
            gloss: "a declared hook handler broke its contract, so its answer was not used",
            class: "A handler answers by exit status and output within its declared timeout. One \
    that could not spawn, timed out, exited outside its contract, said nothing on a refusal, \
    died on a signal or wrote a host decision document of its own broke that contract; the \
    subjects name the row and which.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "output write missing",
            gloss: "this call's response was not captured; the reason id says why",
            class: "A mediated call's response is captured so a later remedy can hand over its \
    bytes without them entering the context. When the capture is skipped, the subject is the \
    reason id, and the capture is absent for that call only.",
            routes: &[run("doctor run first", "batten doctor")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "workspace state broken",
            gloss: "this environment does not match what the tree declares",
            class: "A failing doctor check or startup row means a program, pin or provision the \
    tree declares is not present or not reachable here, so gates that need it cannot run. The \
    subjects name the check or row and its reason. `batten startup --repair` runs the declared \
    repairs; `batten doctor` reports what is left.",
            routes: &[
                run("doctor run first", "batten doctor"),
                run("startup repair first", "batten startup --repair"),
            ],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "call grant now",
            gloss: "the call was pre-approved by a declared rule or handler",
            class: "A pre-approval tells the host not to prompt for a call the policy already \
    admits. It is never a refusal and never outranks one: a call any gate refuses is not \
    pre-approved. The rule or handler that granted it is on the line.",
            // NO ROUTE: a grant asks nothing of its reader, so a way out would be a
            // pointer with nothing to point the reader at (CLOUD-2145).
            routes: &[],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "commit port blocked",
            gloss: "a replay onto the landing target conflicted and stopped",
            class: "The replay is stateless: nothing is half-replayed, so there is no rebase to \
    continue or abort. Merge each conflicted path in the worktree, then name it to `land \
    replay --resolve`, which re-runs the replay from its base with your bytes for that path.",
            // THE PLAIN REPLAY, NOT ITS `--resolve` SPELLING: a route rides every
            // line, and a pathless conflict has no path to name. The stop's own
            // remedy carries `--resolve <first>` when there is one.
            routes: &[run("replay run first", "batten land replay <base>")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "check run red",
            gloss: "the configured gate refused this head",
            class: "`land` verifies a head before it pushes, with the gate the repository \
    declares. A refusal names its cause; nothing was pushed.",
            routes: &[run("land run first", "batten land lap")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "job run red",
            gloss: "a required CI check failed on this head",
            class: "`land` waits on the required checks of the head it pushed, and stops on the \
    first failure. The subjects name the head and each failing check; the same checks run \
    locally.",
            routes: &[run("land run first", "batten land lap")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "lane run spent",
            gloss: "every lap was spent without a landing",
            class: "`land` bounds its laps so a moving target cannot keep it running forever. \
    The subjects count the laps, the CI matrices they spent and the lease waits among them.",
            routes: &[run("land run first", "batten land lap")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "contract read stale",
            gloss: "a declared contract file moved after this session read it",
            class: "The files a repository declares as a session's contract are read once, at \
    start. A `changed` subject is one this session holds in its old form, an `added` one is new \
    capability it never read, a `removed` one is no longer tracked. A `hook wiring moved` subject \
    means what this session runs may differ from what the tree declares.",
            routes: &[read("config read first", "batten.toml")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "hook run missing",
            gloss: "the engine did not run at this session's start, so earlier calls went unmediated",
            class: "Hosts register the engine by bare name, so a session whose start event found no \
    binary on `PATH` ran every call before this one unmediated. It is a provisioning failure, not a \
    policy one, and which calls preceded this is not answerable from here.",
            routes: &[run("doctor run first", "batten doctor")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "drain fit broken",
            gloss: "a drain's delta did not fit its token budget, so whole rule lines were cut",
            class: "A drain carries what is new since the session was last told, a capped number of \
    locations per rule, so its size follows one turn's work and the budget is a relief valve. A cut \
    means one turn produced more new findings across more rules than that shape holds; the cut lines \
    are in the journal and the subjects count them.",
            routes: &[run("state list first", "batten state list")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "output point now",
            gloss: "a reduced read stored the whole response; each subject is a field and its lines",
            class: "A reduction hands back a few declared fields and stores the response whole. The \
    store is one line of JSON, so the read route is the view: the same document laid out field by \
    field, each subject naming a field, the view lines holding it and its size. Read only the lines \
    you need; the raw connector returns the same bytes into the window again.",
            // THE VIEW, NOT `--field` (CLOUD-2284): `--field` alone prints only a
            // size header, and a spilled leaf is no JSON document at all, so the
            // command never reached the content the note pointed at.
            routes: &[read("output read first", "the view the note names")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "cargo retire now",
            gloss: "free space fell below the declared minimum, so cargo units were removed before this call ran",
            class: "Below `[prune] min_free_mb` the hook collects before admitting: superseded units first, \
    then live units least recently used first, until `max_free_mb` is free. A tree a running build holds \
    is never touched, and the engine's own unit survives. The subjects are the bytes freed, the units \
    removed and the free space after. The call was admitted either way; the next build of a removed unit \
    rebuilds it.",
            routes: &[run("space read first", "batten target prune --dry-run")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "call reach loose",
            gloss: "the call acts on a repository other than the session's home, which arms the reach gate",
            class: "A session is homed in the first repository it stood in that carries an authority, and a \
    visit never moves the home (CLOUD-2672). Where the home declares a `repository-reach` native row, a \
    call whose targets (a structured call's path; a shell call's directories, `cd`/`pushd` operands and \
    `git -C`/`--git-dir`/`--work-tree` operands) place in another repository is refused, and so is one \
    whose targets cannot be placed at all. A directory in no repository passes. The subjects are the \
    home and the root reached, never a file's contents.",
            routes: &[run(
                "override request first",
                "batten override request --rule repository-reach",
            )],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "script run loose",
            gloss: "a script interpreter ran a script file that lives outside the repository",
            class: "A call to an interpreter the row's `interprets` column declares whose script operand \
    resolves OUTSIDE the repository (CLOUD-2304). The edit guards are bound to the host's edit tools and to \
    the command line, and a script file carries its writes in its own body, where neither looks: \
    a protected path, an unrefined filed row, every Edit/Write handler is walked around by moving \
    the edit into a scratch script. A script the repository holds is reviewed code and runs; so \
    does the same interpreter downstream of a pipe, and an inline `-c`/`-e` program, whose text \
    the protected-path scan already reads. CONTAINMENT, never the INDEX, for `tool run loose`'s \
    reason: the operand is resolved against the call's own working directory and the repository \
    asked whether it holds the result.",
            routes: &[run(
                "edit run first",
                "make the edit with the host's Edit/Write tools; a reusable program is a tracked file under review",
            )],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "issue grade refused",
            gloss: "the issue fails a checkable Ready clause, named in the subject beside its line",
            class: "`ready lint` holds an issue's description to the checkable half of the Definition \
    of Ready. Each subject is the issue, the description line, and the clause it fails; the line is \
    where the edit goes. Nothing the issue says is echoed.",
            routes: &[run("ready lint first", "batten ready lint")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "issue grade partial",
            gloss: "the issue's relations were not in the fetch, so its citations could not be judged",
            class: "A citation is judged against the issue's relations. A payload fetched without \
    them cannot be judged either way, which is could-not-look rather than a pass; the subject is \
    the first citation that hit the gap.",
            routes: &[run("ready lint first", "batten ready lint")],
            applicability: Applicability::Advice,
        },
        VendoredVerdict {
            id: "claim mint refused",
            gloss: "the claim was not minted: the issue is held by another, or was not refined first",
            class: "`claim check` mints the claim receipt only for an issue nobody else holds and \
    whose refinement came before this session. The subject is the issue and the reason: a holder \
    (`assigned`, a competing branch or PR) or the refinement sequence (`not-ready`).",
            routes: &[run("claim check first", "batten claim check")],
            applicability: Applicability::Advice,
        },
    ];

    /// Every class the binary ships, as the registry carries them.
    ///
    /// Unioned with the consumer's `[[verdict]]` rows by `policy::load`. A collision
    /// between the two is refused there rather than here: which side is at fault is
    /// a question about the pair, and this function knows only one of them.
    #[must_use]
    pub fn vendored() -> Vec<DeclaredVerdict> {
        // Native rows here, preset rows from their own manifests (CLOUD-1181). The
        // presets' half used to sit in this same table under a comment, so a preset
        // class and the preset that raises it were declared in different modules
        // with nothing tying them together.
        VENDORED
            .iter()
            .map(declared_from)
            .chain(crate::config_check::preset::verdict_rows())
            .collect()
    }

    /// One vendored row, as the registry carries it.
    ///
    /// Shared with [`crate::preset`] so the two halves of the vendored registry
    /// cannot be projected differently — which is the same "one authority per fact"
    /// reason the manifests exist at all.
    #[must_use]
    pub fn declared_from(entry: &VendoredVerdict) -> DeclaredVerdict {
        DeclaredVerdict {
            id: entry.id.to_owned(),
            gloss: entry.gloss.to_owned(),
            // Joined by id from the one doc table (CLOUD-2143), so the vendored and
            // preset halves are documented in one place.
            doc: crate::doc::vendored(entry.id),
            class: entry.class.to_owned(),
            // Carried rather than defaulted (CLOUD-1639): this is the one projection
            // between the two tables, so a vendored class that declares a repairing
            // posture would silently become `advice` here if the field were dropped
            // — and the arm that reads it is at the boundary, far from this line.
            applicability: entry.applicability,
            routes: entry
                .routes
                .iter()
                .map(|route| Route {
                    id: route.id.to_owned(),
                    kind: route.kind,
                    target: route.target.to_owned(),
                    precondition: route.precondition.map(str::to_owned),
                })
                .collect(),
            successor: None,
            withdrawn: None,
        }
    }
}
