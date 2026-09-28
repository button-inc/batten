//! Declared forge reads, recorded for a module to decide over (CLOUD-843).
//!
//! # What this is, and the line it holds
//!
//! A `[[forge.query]]` row ([`crate::rest::Query`]) names a paginated REST read:
//! an endpoint template, where the rows sit in the body, a page size and budget,
//! an optional trailing time window, and the fields to keep. `batten record query
//! <id>` walks it through [`crate::forge::window_until`] over [`crate::rest::get`]
//! — the ETag-cached, `total_count`-checked walk that already existed for exactly
//! this — reduces each row to the declared fields, and writes the result as the
//! record family `<id>` through [`crate::record::store_named`], which is the
//! store `Fact::Records` projects onto `input.tree.records.<id>`.
//!
//! **It fetches, reduces and writes; it DECIDES NOTHING.** Whether a window is
//! healthy is the module that reads the family, in `policy/*.rego` or a preset.
//! The eleven shell bodies this facility exists to absorb each fused the three —
//! a `gh api --paginate`, a `jq` projection and a threshold in one string — which
//! is why none of their decisions could be tested apart from a network.
//!
//! # Mechanism only, and the consumer's facts stay the consumer's
//!
//! Nothing here names an endpoint, a workflow, a field or a window: every one of
//! those is a row in the consumer's `batten.toml` (non-negotiable rule 1). What
//! the engine owns is the grammar of a row, the walk, the clock, and the record's
//! shape.
//!
//! # The record's shape
//!
//! One `row<TAB><json>` line per kept row — the declared fields and nothing else,
//! as a compact JSON object, so a value holding a tab or a newline cannot tear a
//! line — then ONE closing line:
//!
//! ```text
//! window<TAB>state=whole<TAB>read=<n><TAB>kept=<n>[<TAB>since=<rfc3339>]
//! window<TAB>state=truncated<TAB>read=<n><TAB>kept=<n><TAB>total=<n|-><TAB>pages=<n>[<TAB>since=<rfc3339>]
//! ```
//!
//! The closing line is last on `timeout-drift`'s reasoning: a record present
//! without exactly one of it is torn, and a module can say so. `kept` restates
//! the row count for the same reason.
//!
//! # Three answers, kept apart
//!
//! * **whole** — the walk reached the end of the collection, or of the declared
//!   window on a collection the consumer says is ordered.
//! * **truncated** — the page budget ran out first. The PREFIX is recorded with
//!   the state saying so, because deciding what a partial window means is the
//!   module's job and a producer that discarded the prefix would leave it
//!   nothing to decide over. The exit is still 0: the record is the answer.
//! * **could not look** — no remote to name the repository, no clock, a forge
//!   that refused or answered something unparseable, or a row with no readable
//!   instant in its declared `since` field. The record is REMOVED rather than
//!   left, because a module cannot tell a stale window from a fresh one (the
//!   clock is not on its surface), and the verb exits 3 with a pointer.
//!
//! # Pointer-only
//!
//! A refusal names the query, an endpoint template, a placeholder, a status or a
//! row NUMBER — never a byte of a response body (rule 4). The rows themselves go
//! only into the store, reduced to what the consumer declared.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use anyhow::Result;

use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::forge::{self, Shape, Transport, Window};
use crate::rest::Query;

// THE PRODUCER'S OWN DISCRIMINATION (CLOUD-843), each over the compiled binary so
// the mutation has to survive the whole path a consumer depends on: the row
// loads, the walk runs against the fixture forge, the record lands, and a module
// decides over it. Each row restores one failure the header names.
//MUTANT-SUITE crates/batten/tests/it/forge_query.rs
//MUTANT stale-record-survives-could-not-look|s@^            crate::record::clear_named(VERB, .query.id)?;$@@|a_refusing_forge_is_could_not_look_and_removes_the_stale_record
//MUTANT since-window-keeps-everything|s@^            if at < cutoff {$@            if false {@|the_since_window_keeps_recent_rows_and_drops_old_ones
//MUTANT truncation-recorded-as-whole|s@^            "truncated",$@            "whole",@|a_truncated_window_reaches_the_module_as_truncated
//MUTANT unprojected-family-loads|s@^        if !families.iter().any(.family. family.record == id) {$@        if false {@|a_query_whose_family_no_record_row_declares_is_refused_at_load
//MUTANT reduction-keeps-the-whole-row|s@^        body.push_str(.reduce(row, .query.select).to_string());$@        body.push_str(row.to_string().as_str());@|a_declared_query_is_walked_reduced_and_decided_over
//MUTANT unread-input-ignored|s@^        if !named.contains(key.as_str()) {$@        if false {@|an_input_the_query_does_not_read_is_a_usage_error

/// The leaf this module answers for, as a refusal names it.
const VERB: &str = "record query";

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
const RESERVED: [&str; 3] = ["owner", "repo", "since"];

// --- the row grammar ------------------------------------------------------------

/// One piece of a template: literal text, or a `{name}` to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Piece<'a> {
    Literal(&'a str),
    Name(&'a str),
}

/// A placeholder name: ASCII letters, digits, `_` and `-`.
fn is_name(name: &str) -> bool {
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
fn pieces(template: &str) -> std::result::Result<Vec<Piece<'_>>, String> {
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
fn placeholders(query: &Query) -> std::collections::BTreeSet<&str> {
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
fn segments(path: &str) -> Option<Vec<&str>> {
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
pub fn validate(queries: &[Query], families: &[crate::record::Declared]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for query in queries {
        let id = query.id.as_str();
        crate::record::safe_component("`[[forge.query]]` id", id)?;
        let refuse = |why: String| UsageError::raise(format!("forge query `{id}`: {why}"));
        if !seen.insert(id) {
            return Err(refuse(String::from(
                "is declared twice; one query writes one family",
            )));
        }
        validate_endpoint(&query.endpoint).map_err(|why| refuse(format!("`endpoint` {why}")))?;
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
    }
    Ok(())
}

/// An endpoint template's own rules, beyond the placeholder grammar.
///
/// API-relative and path-only, for [`crate::rest::get`]'s contract: a leading
/// slash doubles and 404s, and a query string belongs in `params`, where it is
/// encoded. The literal text is held to a path's safe characters so nothing the
/// transport would have to escape can hide in it.
fn validate_endpoint(endpoint: &str) -> std::result::Result<(), String> {
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
fn validate_select(select: &[String]) -> std::result::Result<(), String> {
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

// --- binding --------------------------------------------------------------------

/// Percent-encode everything but RFC 3986's unreserved characters.
///
/// Applied to every BOUND value and to every parameter, so a branch name with a
/// slash, an instant with colons or an operator like `>=` reaches the forge as
/// one parameter value rather than as syntax the URI parser rejects or splits.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// How much of a rendered template is percent-encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    /// Only the bound values: a PATH, whose literal text `validate_endpoint`
    /// already held to a path's safe characters, and whose `/` separators must
    /// survive as separators.
    Values,
    /// The whole rendered value: a query PARAMETER, whose literal text may carry
    /// an operator like `>=` that the URI parser rejects unencoded.
    Whole,
}

// The unit tier's own row: a parameter's LITERAL text left unencoded is the
// defect this split was written to close, and only a template carrying an
// operator can see it.
//MUTANT-SUITE crates/batten/src/forge_query.rs
//MUTANT param-literal-unencoded|s@^        Encoding::Whole => encode(.out),$@        Encoding::Whole => out,@|binding_resolves_the_slug_the_inputs_and_encodes_every_value
/// Render one template with its placeholders bound, encoded as `encoding` says.
fn render(
    template: &str,
    values: &BTreeMap<&str, String>,
    encoding: Encoding,
) -> std::result::Result<String, String> {
    let mut out = String::new();
    for piece in pieces(template)? {
        match piece {
            Piece::Literal(text) => out.push_str(text),
            Piece::Name(name) => {
                let Some(value) = values.get(name) else {
                    return Err(format!(
                        "names `{{{name}}}`, and nothing bound it — pass `--input {name}=<value>`"
                    ));
                };
                match encoding {
                    Encoding::Values => out.push_str(&encode(value)),
                    Encoding::Whole => out.push_str(value),
                }
            }
        }
    }
    Ok(match encoding {
        Encoding::Values => out,
        Encoding::Whole => encode(&out),
    })
}

/// A row's request, bound: the API-relative path and the encoded parameters,
/// `per_page` included.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    /// The endpoint, placeholders bound.
    path: String,
    /// The query-string parameters, keys and values encoded, `per_page` last.
    params: Vec<(String, String)>,
}

/// What a producer run concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Produced {
    /// The record body to write: the reduced rows and the closing line.
    Recorded(String),
    /// The forge, the remote or the clock could not be asked. A POINTER — an
    /// endpoint, a status, a row number — never a body.
    CouldNotLook(String),
}

/// Why a run did not produce a record: the caller's fault or the world's.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    /// The invocation cannot run as written → exit 1.
    Usage(String),
    /// The invocation is fine and the world did not answer → exit 3.
    CouldNotLook(String),
}

/// Bind a row's templates to the caller's inputs, the remote's slug and the
/// window's cut-off.
fn bind(
    query: &Query,
    inputs: &BTreeMap<String, String>,
    slug: Option<&str>,
    since: Option<&str>,
) -> std::result::Result<Request, Refusal> {
    let named = placeholders(query);
    let mut values: BTreeMap<&str, String> = BTreeMap::new();
    for (key, value) in inputs {
        if RESERVED.contains(&key.as_str()) {
            return Err(Refusal::Usage(format!(
                "`--input {key}` is bound by the engine — `owner`/`repo` from the forge remote, \
                 `since` from the declared window — and cannot be supplied"
            )));
        }
        // A KEY NOBODY READS IS A USAGE ERROR, `record derive`'s rule: a caller
        // who misspelled one would otherwise get a clean record of a read that
        // ran on something else.
        if !named.contains(key.as_str()) {
            return Err(Refusal::Usage(format!(
                "query `{}` names no placeholder `{{{key}}}`",
                query.id
            )));
        }
        values.insert(key.as_str(), value.clone());
    }
    if named.contains("owner") || named.contains("repo") {
        // COULD NOT LOOK, not a usage error: the invocation is right and the
        // checkout names no repository this can derive a slug from.
        let Some((owner, repo)) = slug.and_then(|slug| slug.split_once('/')) else {
            return Err(Refusal::CouldNotLook(String::from(
                "no forge remote names the repository `{owner}/{repo}` is about",
            )));
        };
        values.insert("owner", owner.to_owned());
        values.insert("repo", repo.to_owned());
    }
    if let Some(since) = since {
        values.insert("since", since.to_owned());
    }
    let path = render(&query.endpoint, &values, Encoding::Values)
        .map_err(|why| Refusal::Usage(format!("`endpoint` {why}")))?;
    let mut params = Vec::with_capacity(query.params.len() + 1);
    for (key, template) in &query.params {
        let value = render(template, &values, Encoding::Whole)
            .map_err(|why| Refusal::Usage(format!("`params.{key}` {why}")))?;
        params.push((encode(key), value));
    }
    params.push((String::from("per_page"), query.per_page.to_string()));
    Ok(Request { path, params })
}

// --- the reduction ----------------------------------------------------------------

/// One field path's value in a row, or `None` where the path leads nowhere.
///
/// A numeric segment indexes an array; any other segment reads an object key.
fn field<'a>(row: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut at = row;
    for segment in segments(path)? {
        at = match at {
            serde_json::Value::Object(map) => map.get(segment)?,
            serde_json::Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(at)
}

/// A row reduced to the declared fields, each path a key, `null` where it led
/// nowhere — so every recorded row has every key.
fn reduce(row: &serde_json::Value, select: &[String]) -> serde_json::Value {
    let mut kept = serde_json::Map::new();
    for path in select {
        kept.insert(
            path.clone(),
            field(row, path).cloned().unwrap_or(serde_json::Value::Null),
        );
    }
    serde_json::Value::Object(kept)
}

/// The instant a row carries in its declared `since` field, in epoch seconds.
fn dated(row: &serde_json::Value, path: &str) -> Option<i64> {
    field(row, path)
        .and_then(serde_json::Value::as_str)
        .and_then(crate::landed::second_of)
}

/// Compose the record body from a walk's answer.
fn compose(
    query: &Query,
    window: Window,
    cutoff: Option<(i64, &str)>,
) -> std::result::Result<String, Refusal> {
    let (state, rows, tail) = match window {
        Window::Whole(rows) => ("whole", rows, String::new()),
        Window::Truncated {
            rows, total, pages, ..
        } => (
            "truncated",
            rows,
            format!(
                "\ttotal={}\tpages={pages}",
                total.map_or_else(|| String::from("-"), |count| count.to_string())
            ),
        ),
        Window::CouldNotLook { endpoint, status } => {
            return Err(Refusal::CouldNotLook(format!(
                "the forge did not answer for {endpoint} (status {})",
                status.map_or_else(|| String::from("none"), |code| code.to_string())
            )));
        }
    };
    let mut body = String::new();
    let mut kept = 0_usize;
    for (index, row) in rows.iter().enumerate() {
        if let (Some((cutoff, _)), Some(since)) = (cutoff, &query.since) {
            // AN UNDATED ROW IS COULD-NOT-LOOK, never "outside the window". A
            // misspelled `since.field` would otherwise drop every row and record
            // an empty window over a collection that was full — the vacuous pass
            // CLOUD-251 names, arriving from the declaration side.
            let Some(at) = dated(row, &since.field) else {
                return Err(Refusal::CouldNotLook(format!(
                    "row {} carries no RFC 3339 instant at `{}`",
                    index + 1,
                    since.field
                )));
            };
            if at < cutoff {
                continue;
            }
        }
        body.push_str("row\t");
        body.push_str(&reduce(row, &query.select).to_string());
        body.push('\n');
        kept += 1;
    }
    let since = cutoff.map_or_else(String::new, |(_, text)| format!("\tsince={text}"));
    {
        use std::fmt::Write as _;
        // `write!` to a String cannot fail; bound rather than dropped for
        // `forge::window_over`'s reason.
        let _ = writeln!(
            body,
            "window\tstate={state}\tread={}\tkept={kept}{tail}{since}",
            rows.len()
        );
    }
    Ok(body)
}

/// Run one declared query over a transport: bind, walk, reduce, compose.
///
/// Everything a run needs is an argument — the slug, the instant, the git
/// directory, the transport — so the whole of it is testable without a
/// network, a clock or a remote, and [`run`] is this with the live ones bound.
///
/// # Errors
///
/// A [`UsageError`] when the invocation cannot run as written: an input the row
/// names no placeholder for, a reserved one, or a placeholder nothing bound.
pub fn produce(
    query: &Query,
    inputs: &BTreeMap<String, String>,
    slug: Option<&str>,
    now: u64,
    git_dir: &Path,
    fetch: Transport<'_>,
) -> Result<Produced> {
    let refused = |refusal: Refusal| -> Result<Produced> {
        match refusal {
            Refusal::Usage(why) => Err(UsageError::raise(format!("{VERB} {}: {why}", query.id))),
            Refusal::CouldNotLook(why) => Ok(Produced::CouldNotLook(why)),
        }
    };
    let cutoff = match &query.since {
        None => None,
        // A CLOCK THAT DID NOT READ IS NOT AN INSTANT, `rest::backoff_of`'s rule:
        // `now_unix` answers 0 on failure, and a window measured back from the
        // epoch would keep nothing and record that as the reading.
        Some(_) if now == 0 => {
            return Ok(Produced::CouldNotLook(String::from(
                "the clock did not read, so the window has no end to measure back from",
            )));
        }
        Some(since) => {
            let back = i64::try_from(since.seconds).unwrap_or(i64::MAX);
            let cutoff = i64::try_from(now).unwrap_or(i64::MAX).saturating_sub(back);
            let text = crate::receipt::rfc3339_utc(u64::try_from(cutoff).unwrap_or(0));
            Some((cutoff, text))
        }
    };
    let request = match bind(
        query,
        inputs,
        slug,
        cutoff.as_ref().map(|(_, text)| text.as_str()),
    ) {
        Ok(request) => request,
        Err(refusal) => return refused(refusal),
    };
    let shape = match &query.rows {
        Some(key) => Shape::Wrapped(key),
        None => Shape::Bare,
    };
    let params: Vec<(&str, &str)> = request
        .params
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    // THE STOP IS THE CONSUMER'S ORDER CLAIM, passed only where it was made. An
    // undated row never stops the walk: the reduction below refuses it, and a
    // stop on it would end the walk at the very row that is could-not-look.
    let stop_at = match (&query.since, &cutoff) {
        (Some(since), Some((cutoff, _))) if since.stop => Some((since.field.as_str(), *cutoff)),
        _ => None,
    };
    let stop = move |row: &serde_json::Value| {
        stop_at.is_some_and(|(path, cutoff)| dated(row, path).is_some_and(|at| at < cutoff))
    };
    let window = forge::window_until(
        git_dir,
        &request.path,
        &params,
        shape,
        query.max_pages,
        stop_at.is_some().then_some(&stop as forge::Stop<'_>),
        fetch,
    );
    match compose(
        query,
        window,
        cutoff.as_ref().map(|(at, text)| (*at, text.as_str())),
    ) {
        Ok(body) => Ok(Produced::Recorded(body)),
        Err(refusal) => refused(refusal),
    }
}

/// `batten record query <id>`: run a declared query and write its family.
///
/// # Errors
///
/// A [`UsageError`] when no `[[forge.query]]` row declares `id`, when an input
/// is malformed or unread, or when the checkout has no branch to key the record
/// on. An internal error when the store cannot be written. Could-not-look is not
/// an error: it removes any stale record, names what could not be asked on
/// `err`, and answers [`ExitCode::Internal`].
pub fn run(
    id: &str,
    inputs: &[String],
    overrides: &crate::resolve::Overrides,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let config = crate::resolve::committed(Path::new("."), overrides)?;
    let Some(query) = config
        .forge
        .as_ref()
        .and_then(|forge| forge.query.iter().find(|query| query.id == id))
    else {
        return Err(UsageError::raise(format!(
            "{VERB}: no `[[forge.query]]` row declares the id `{id}`"
        )));
    };
    let inputs = crate::record::inputs_of(VERB, inputs)?;
    let root = Path::new(".");
    let git_dir = crate::git::git_dir(root)?;
    let slug = crate::repo_slug(root);
    let produced = produce(
        query,
        &inputs,
        slug.as_deref(),
        crate::now_unix(),
        &git_dir,
        &|path, etag| crate::rest::get(path, etag),
    )?;
    match produced {
        Produced::Recorded(body) => {
            crate::record::store_named(VERB, &query.id, &body)?;
            Ok(ExitCode::Success)
        }
        Produced::CouldNotLook(why) => {
            crate::record::clear_named(VERB, &query.id)?;
            writeln!(err, "batten: {VERB} {}: could not look: {why}", query.id)?;
            Ok(ExitCode::Internal)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::rest::{Answer, Since};

    fn query(endpoint: &str) -> Query {
        Query {
            id: String::from("runs"),
            endpoint: endpoint.to_owned(),
            rows: Some(String::from("workflow_runs")),
            params: BTreeMap::new(),
            per_page: 2,
            max_pages: 3,
            since: None,
            select: vec![String::from("id"), String::from("conclusion")],
        }
    }

    fn family(name: &str) -> crate::record::Declared {
        crate::record::Declared {
            record: name.to_owned(),
            writer: format!("batten record query {name}"),
        }
    }

    fn page(body: &str) -> Answer {
        Answer {
            status: 200,
            etag: None,
            poll_floor: None,
            backoff: None,
            body: body.to_owned(),
            headers: BTreeMap::new(),
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("batten-forge-query-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Serve `pages` in order, recording each request path.
    fn served<'a>(
        pages: &'a [&'a str],
        asked: &'a std::cell::RefCell<Vec<String>>,
    ) -> impl Fn(&str, Option<&str>) -> Option<Answer> + 'a {
        move |path, _| {
            let mut asked = asked.borrow_mut();
            let body = pages.get(asked.len())?;
            asked.push(path.to_owned());
            Some(page(body))
        }
    }

    fn recorded(produced: Produced) -> String {
        match produced {
            Produced::Recorded(body) => body,
            other @ Produced::CouldNotLook(_) => panic!("expected a record, got {other:?}"),
        }
    }

    #[test]
    fn a_template_splits_into_literals_and_names_and_refuses_a_broken_brace() {
        assert_eq!(
            pieces("repos/{owner}/{repo}/runs").unwrap(),
            vec![
                Piece::Literal("repos/"),
                Piece::Name("owner"),
                Piece::Literal("/"),
                Piece::Name("repo"),
                Piece::Literal("/runs"),
            ]
        );
        for broken in ["repos/{owner", "repos/owner}", "repos/{}/x", "repos/{a b}"] {
            assert!(pieces(broken).is_err(), "{broken:?} is not a template");
        }
    }

    #[test]
    fn a_well_formed_row_with_a_declared_family_validates() {
        // THE ANTI-VACUITY HALF: every refusal below would also pass over a
        // validator that refused everything.
        assert!(
            validate(
                &[query("repos/{owner}/{repo}/actions/runs")],
                &[family("runs")]
            )
            .is_ok()
        );
    }

    #[test]
    fn a_row_that_could_never_run_as_written_is_refused_at_load() {
        let families = [family("runs")];
        let refused = |row: Query| {
            let err = validate(&[row], &families).unwrap_err();
            assert!(err.downcast_ref::<UsageError>().is_some(), "{err}");
        };
        refused(query("/repos/{owner}/{repo}/runs"));
        refused(query("repos/{owner}/{repo}/runs?status=done"));
        refused(query("repos/{owner/runs"));
        refused(Query {
            per_page: 0,
            ..query("repos/x")
        });
        refused(Query {
            per_page: MAX_PER_PAGE + 1,
            ..query("repos/x")
        });
        refused(Query {
            max_pages: 0,
            ..query("repos/x")
        });
        refused(Query {
            select: Vec::new(),
            ..query("repos/x")
        });
        refused(Query {
            select: vec![String::from("a..b")],
            ..query("repos/x")
        });
        refused(Query {
            select: vec![String::from("id"), String::from("id")],
            ..query("repos/x")
        });
        refused(Query {
            rows: Some(String::new()),
            ..query("repos/x")
        });
        refused(Query {
            params: BTreeMap::from([(String::from("page"), String::from("2"))]),
            ..query("repos/x")
        });
        refused(Query {
            params: BTreeMap::from([(String::from("created"), String::from(">={since}"))]),
            ..query("repos/x")
        });
        refused(Query {
            since: Some(Since {
                field: String::from("created_at"),
                seconds: 0,
                stop: false,
            }),
            ..query("repos/x")
        });
        refused(Query {
            id: String::from("../escape"),
            ..query("repos/x")
        });
        // Twice, and a family nobody declares.
        assert!(validate(&[query("repos/x"), query("repos/y")], &families).is_err());
        assert!(validate(&[query("repos/x")], &[family("other")]).is_err());
    }

    #[test]
    fn binding_resolves_the_slug_the_inputs_and_encodes_every_value() {
        let row = Query {
            params: BTreeMap::from([
                (String::from("branch"), String::from("{branch}")),
                (String::from("created"), String::from(">={since}")),
            ]),
            since: Some(Since {
                field: String::from("created_at"),
                seconds: 60,
                stop: false,
            }),
            ..query("repos/{owner}/{repo}/actions/workflows/{workflow}/runs")
        };
        let inputs = BTreeMap::from([
            (String::from("workflow"), String::from("land.yml")),
            (String::from("branch"), String::from("feature/x y")),
        ]);
        let bound = bind(
            &row,
            &inputs,
            Some("acme/widgets"),
            Some("2026-08-29T10:40:00Z"),
        )
        .unwrap();
        assert_eq!(
            bound.path,
            "repos/acme/widgets/actions/workflows/land.yml/runs"
        );
        assert_eq!(
            bound.params,
            vec![
                (String::from("branch"), String::from("feature%2Fx%20y")),
                (
                    String::from("created"),
                    String::from("%3E%3D2026-08-29T10%3A40%3A00Z")
                ),
                (String::from("per_page"), String::from("2")),
            ]
        );
    }

    #[test]
    fn an_unread_input_a_reserved_one_and_a_missing_one_are_usage_and_no_slug_is_could_not_look() {
        let row = query("repos/{owner}/{repo}/actions/workflows/{workflow}/runs");
        let one = |key: &str| BTreeMap::from([(key.to_owned(), String::from("v"))]);
        assert!(matches!(
            bind(&row, &one("typo"), Some("o/r"), None),
            Err(Refusal::Usage(_))
        ));
        assert!(matches!(
            bind(&row, &one("owner"), Some("o/r"), None),
            Err(Refusal::Usage(_))
        ));
        assert!(matches!(
            bind(&row, &BTreeMap::new(), Some("o/r"), None),
            Err(Refusal::Usage(_))
        ));
        assert!(matches!(
            bind(&row, &one("workflow"), None, None),
            Err(Refusal::CouldNotLook(_))
        ));
        assert!(bind(&row, &one("workflow"), Some("o/r"), None).is_ok());
    }

    #[test]
    fn a_whole_walk_records_every_row_reduced_and_closes_the_window() {
        let git = scratch("whole");
        let asked = std::cell::RefCell::new(Vec::new());
        let pages = [
            r#"{"total_count": 3, "workflow_runs": [{"id": 1, "conclusion": "success", "title": "secret"}, {"id": 2, "conclusion": null}]}"#,
            r#"{"total_count": 3, "workflow_runs": [{"id": 3}]}"#,
        ];
        let body = recorded(
            produce(
                &query("repos/{owner}/{repo}/actions/runs"),
                &BTreeMap::new(),
                Some("o/r"),
                1_788_000_000,
                &git,
                &served(&pages, &asked),
            )
            .unwrap(),
        );
        assert_eq!(
            body,
            "row\t{\"conclusion\":\"success\",\"id\":1}\n\
             row\t{\"conclusion\":null,\"id\":2}\n\
             row\t{\"conclusion\":null,\"id\":3}\n\
             window\tstate=whole\tread=3\tkept=3\n"
        );
        assert!(
            !body.contains("secret"),
            "the reduction keeps only what it declared"
        );
        assert_eq!(
            asked.borrow().first().map(String::as_str),
            Some("repos/o/r/actions/runs?page=1&per_page=2")
        );
    }

    #[test]
    fn a_truncated_walk_records_its_prefix_and_says_it_is_one() {
        // THE DISCRIMINATING CASE: the prefix is kept AND labelled. A producer
        // that dropped it would leave a module nothing to decide over; one that
        // recorded it as `whole` would report a window as a population.
        let git = scratch("truncated");
        let asked = std::cell::RefCell::new(Vec::new());
        let pages = [r#"{"total_count": 9, "workflow_runs": [{"id": 1}, {"id": 2}]}"#];
        let body = recorded(
            produce(
                &Query {
                    max_pages: 1,
                    ..query("repos/x/runs")
                },
                &BTreeMap::new(),
                None,
                1_788_000_000,
                &git,
                &served(&pages, &asked),
            )
            .unwrap(),
        );
        assert!(
            body.contains("row\t{\"conclusion\":null,\"id\":1}\n"),
            "{body}"
        );
        assert!(
            body.ends_with("window\tstate=truncated\tread=2\tkept=2\ttotal=9\tpages=1\n"),
            "{body}"
        );
    }

    #[test]
    fn the_since_window_keeps_the_recent_rows_and_the_stop_spares_the_next_page() {
        // `total_count` says 40 and the budget is ten pages, so without the stop
        // the walk would read on. The first page already holds a row older than
        // the cut-off, and the collection is declared newest-first, so the
        // window is whole after ONE request.
        let git = scratch("since");
        let asked = std::cell::RefCell::new(Vec::new());
        let pages = [
            r#"{"total_count": 40, "workflow_runs": [{"id": 1, "created_at": "2026-08-29T10:39:30Z"}, {"id": 2, "created_at": "2026-08-29T10:30:00Z"}]}"#,
            r#"{"total_count": 40, "workflow_runs": [{"id": 3, "created_at": "2026-08-29T10:00:00Z"}]}"#,
        ];
        let row = Query {
            max_pages: 10,
            since: Some(Since {
                field: String::from("created_at"),
                seconds: 60,
                stop: true,
            }),
            ..query("repos/x/runs")
        };
        let body = recorded(
            produce(
                &row,
                &BTreeMap::new(),
                None,
                1_788_000_000,
                &git,
                &served(&pages, &asked),
            )
            .unwrap(),
        );
        assert_eq!(asked.borrow().len(), 1, "the stop ended the walk");
        assert_eq!(
            body,
            "row\t{\"conclusion\":null,\"id\":1}\n\
             window\tstate=whole\tread=2\tkept=1\tsince=2026-08-29T10:39:00Z\n"
        );

        // AND WITHOUT THE ORDER CLAIM the same collection is walked to the end
        // of the budget: `stop` is the consumer's to make, never inferred.
        let asked = std::cell::RefCell::new(Vec::new());
        let unordered = Query {
            max_pages: 2,
            since: Some(Since {
                field: String::from("created_at"),
                seconds: 60,
                stop: false,
            }),
            ..query("repos/x/runs")
        };
        let body = recorded(
            produce(
                &unordered,
                &BTreeMap::new(),
                None,
                1_788_000_000,
                &scratch("since-unordered"),
                &served(&pages, &asked),
            )
            .unwrap(),
        );
        assert_eq!(asked.borrow().len(), 2);
        assert!(body.contains("state=truncated"), "{body}");
    }

    #[test]
    fn an_undated_row_is_could_not_look_rather_than_outside_the_window() {
        // A misspelled `since.field` would otherwise drop every row and record an
        // empty window over a full collection.
        let asked = std::cell::RefCell::new(Vec::new());
        let pages = [r#"{"workflow_runs": [{"id": 1, "created": "2026-08-29T10:39:30Z"}]}"#];
        let row = Query {
            since: Some(Since {
                field: String::from("created_at"),
                seconds: 60,
                stop: false,
            }),
            ..query("repos/x/runs")
        };
        let produced = produce(
            &row,
            &BTreeMap::new(),
            None,
            1_788_000_000,
            &scratch("undated"),
            &served(&pages, &asked),
        )
        .unwrap();
        assert!(
            matches!(produced, Produced::CouldNotLook(_)),
            "{produced:?}"
        );
        // And a clock that did not read is not an instant either.
        assert!(matches!(
            produce(
                &row,
                &BTreeMap::new(),
                None,
                0,
                &scratch("undated-clock"),
                &served(&pages, &asked),
            )
            .unwrap(),
            Produced::CouldNotLook(_)
        ));
    }

    #[test]
    fn a_refusing_forge_is_could_not_look_and_names_no_body() {
        let refusing = |_: &str, _: Option<&str>| {
            Some(Answer {
                status: 403,
                ..page(r#"{"message": "Resource not accessible by integration"}"#)
            })
        };
        let produced = produce(
            &query("repos/x/runs"),
            &BTreeMap::new(),
            None,
            1_788_000_000,
            &scratch("refused"),
            &refusing,
        )
        .unwrap();
        match produced {
            Produced::CouldNotLook(why) => {
                assert!(why.contains("403"), "{why}");
                assert!(!why.contains("Resource"), "rule 4: {why}");
            }
            other @ Produced::Recorded(_) => panic!("a 403 is could-not-look, got {other:?}"),
        }
    }

    #[test]
    fn a_field_path_reads_through_objects_and_arrays_and_null_marks_nowhere() {
        let row = serde_json::json!({"a": {"b": [{"c": 7}]}, "d": "x"});
        let reduced = reduce(
            &row,
            &[
                String::from("a.b.0.c"),
                String::from("d"),
                String::from("a.b.9.c"),
                String::from("d.e"),
            ],
        );
        assert_eq!(
            reduced,
            serde_json::json!({"a.b.0.c": 7, "d": "x", "a.b.9.c": null, "d.e": null})
        );
    }
}
