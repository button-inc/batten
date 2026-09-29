//! `batten doctor forge`: which claims this repository's tasks need from the
//! forge credential, answered by the forge itself (CLOUD-843, retiring
//! `gh-preflight`).
//!
//! # Why this exists
//!
//! An under-scoped or proxy-substituted token otherwise surfaces as an unrelated
//! 403 at whichever task runs first, each looking like its own denial rather
//! than one missing claim. A 403 carries the header naming the claim the forge
//! wanted, so the consumer's table is checked AGAINST the forge: a named claim
//! the table does not declare marks the TABLE stale. A 404 can be an empty
//! repository, so it is reported and never counted.
//!
//! # Read-only by construction
//!
//! Only GET is issued, through [`crate::rest::get`] — the one client and the one
//! credential reader. A row the consumer declares with `probe = false` is
//! reported as declared and never probed: a write cannot be tested without
//! performing it.
//!
//! # Everything the consumer knows is a `[[forge.probe]]` row
//!
//! Which endpoints, which claims and which tasks need them are the consumer's
//! (non-negotiable rule 1). What stays here is the walk and the one forge fact a
//! refusal carries: the header that names the claim.

use std::io::Write;

use anyhow::Result;

use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::rest::{Answer, Probe};

/// The header a forge refusal names the missing claim in.
const ACCEPTED_PERMISSIONS: &str = "x-accepted-github-permissions";

/// The two placeholders a probe endpoint may carry.
const PLACEHOLDERS: [&str; 2] = ["{owner}", "{repo}"];

/// Refuse a probe table that cannot mean one thing.
///
/// # Errors
///
/// [`UsageError`] for an empty table, a blank endpoint or claim, an endpoint
/// with a leading `/`, or a placeholder other than `{owner}` and `{repo}`.
pub fn validate(probes: &[Probe]) -> Result<()> {
    if probes.is_empty() {
        return Err(UsageError::raise(
            "doctor forge: no `[[forge.probe]]` row is declared, so there is nothing to probe",
        ));
    }
    for probe in probes {
        if probe.endpoint.trim().is_empty() || probe.claim.trim().is_empty() {
            return Err(UsageError::raise(
                "doctor forge: a `[[forge.probe]]` row needs a non-empty `endpoint` and `claim`",
            ));
        }
        if probe.endpoint.starts_with('/') {
            return Err(UsageError::raise(format!(
                "doctor forge: the endpoint {:?} is API-relative and carries no leading `/`",
                probe.endpoint
            )));
        }
        let mut rest = probe.endpoint.clone();
        for placeholder in PLACEHOLDERS {
            rest = rest.replace(placeholder, "");
        }
        if rest.contains('{') || rest.contains('}') {
            return Err(UsageError::raise(format!(
                "doctor forge: the endpoint {:?} names a placeholder other than {{owner}} and \
                 {{repo}}; nothing binds it, and a literal brace on the wire 404s",
                probe.endpoint
            )));
        }
    }
    Ok(())
}

/// What one probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Found {
    /// A 2xx: the claim is held.
    Held,
    /// A 403, with the claim the forge named, if it named one.
    Missing(Option<String>),
    /// Any other status, or no answer: reported and never counted.
    Other(Option<u16>),
    /// Declared and never called.
    Declared,
}

/// What a GET answered, classified.
fn classify(answer: Option<&Answer>) -> Found {
    match answer {
        Some(answer) if (200..300).contains(&answer.status) => Found::Held,
        Some(answer) if answer.status == 403 => Found::Missing(
            answer
                .header(ACCEPTED_PERMISSIONS)
                .map(str::trim)
                .filter(|named| !named.is_empty())
                .map(str::to_owned),
        ),
        Some(answer) => Found::Other(Some(answer.status)),
        None => Found::Other(None),
    }
}

/// `batten doctor forge`, over the declared rows, for the repository `slug`
/// names, through `get`.
///
/// Diagnoses on `out`, one pointer line per row, and answers on `doctor`'s
/// contract: exit 0 every probed read answered, exit 1 a read claim is missing
/// or no forge remote names the repository. It renders no policy verdict, so it
/// cannot mint a `2`.
///
/// # Errors
///
/// A malformed table (see [`validate`]) and a failed write.
//MUTANT-SUITE crates/batten/tests/it/gh_preflight.rs
//MUTANT forbidden-read-passes|s@^        Some(answer) if answer.status == 403 => Found::Missing(@        Some(answer) if answer.status == 499 => Found::Missing(@|a_forbidden_read_is_missing_and_named
//MUTANT stale-table-unseen|s@^                if named != probe.claim {@                if false {@|a_claim_the_forge_names_that_the_table_does_not_marks_it_stale
//MUTANT write-probed|s@^        let found = if probe.probe {$@        let found = if true {@|the_declared_only_claims_are_never_probed
pub fn run(
    probes: &[Probe],
    slug: Option<&str>,
    get: &dyn Fn(&str) -> Option<Answer>,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    validate(probes)?;
    let Some((owner, repo)) = slug.and_then(|slug| slug.split_once('/')) else {
        writeln!(
            out,
            "doctor forge: could not resolve owner/repo — no forge remote names this repository"
        )?;
        return Ok(ExitCode::Usage);
    };
    writeln!(out, "doctor forge: {owner}/{repo}")?;
    // A REPO-SCOPED OR PROXY-INJECTED TOKEN READS THE REPOSITORY WHILE THE
    // IDENTITY ENDPOINT REFUSES, so a missing identity is reported and never
    // counted: it says which kind of token this is, not that a claim is missing.
    let login = get("user")
        .filter(Answer::is_reading)
        .and_then(|answer| serde_json::from_str::<serde_json::Value>(&answer.body).ok())
        .and_then(|user| user.get("login")?.as_str().map(str::to_owned));
    match login {
        Some(login) => writeln!(out, "token   present, authenticated as {login}")?,
        None => writeln!(
            out,
            "token   no user identity (a repo-scoped or proxy-injected token does this)"
        )?,
    }
    let mut missing: Vec<&str> = Vec::new();
    let mut stale: Vec<String> = Vec::new();
    for probe in probes {
        let path = probe
            .endpoint
            .replace("{owner}", owner)
            .replace("{repo}", repo);
        let found = if probe.probe {
            classify(get(&path).as_ref())
        } else {
            Found::Declared
        };
        let claim = &probe.claim;
        match found {
            Found::Held => writeln!(out, "ok   {claim:<20} {path}")?,
            Found::Declared => {
                writeln!(out, "decl {claim:<20} {path}  (declared, never probed)")?;
            }
            Found::Other(status) => {
                let status = status.map_or_else(
                    || String::from("no response"),
                    |code| format!("HTTP {code}"),
                );
                writeln!(out, "?    {claim:<20} {path}  ({status})")?;
            }
            Found::Missing(named) => {
                writeln!(out, "MISS {claim:<20} {path}")?;
                writeln!(out, "     {:<20} needed by: {}", "", probe.used_by)?;
                missing.push(claim);
                if let Some(named) = named {
                    writeln!(out, "     {:<20} the forge names: {named}", "")?;
                    if named != probe.claim {
                        stale.push(format!(
                            "{path} -> the forge wants {named}, the table declares {claim}"
                        ));
                    }
                }
            }
        }
    }
    if !stale.is_empty() {
        writeln!(
            out,
            "doctor forge: the probe table is STALE — the forge asked for a claim it does not declare:"
        )?;
        for line in &stale {
            writeln!(out, "  {line}")?;
        }
    }
    if missing.is_empty() {
        writeln!(
            out,
            "doctor forge: every probed read endpoint answered. The declared-only claims are not \
             tested — a write cannot be probed without performing it."
        )?;
        return Ok(ExitCode::Success);
    }
    writeln!(
        out,
        "doctor forge: missing {} read claim(s): {}. These are permissions, not egress policy: \
         plain repository reads succeed while these do not.",
        missing.len(),
        missing.join(" ")
    )?;
    Ok(ExitCode::Usage)
}
