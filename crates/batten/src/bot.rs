//! Turn a bot's pull request into a refined tracker row (CLOUD-1295).
//!
//! `mise-tasks/bot-issue.sh`, ported. Two halves, kept apart inside one module
//! for CLOUD-346's reason: the PREDICATES below decide — is this PR one of the
//! lane's, which manifests it touched, what Conventional type its subject
//! declares, whether a body still closes a key — and every one of them is a pure
//! function testable with no network at all. The [`forge`] half underneath is the
//! only thing that talks to anybody, through the same client [`crate::pr_watch`]
//! reads check runs with.
//!
//! # Why the forge's own client rather than this crate's HTTP transport
//!
//! [`crate::fetch`] could send these requests, and sending them would put
//! credential resolution into `crates/batten` — where no config row declares a
//! forge credential and where the token would then have to be read from an
//! environment this crate does not otherwise consult. `gh` resolves it outside,
//! which is the standing CLOUD-1143 already gave the check-run read, and it is
//! also byte-for-byte the call the retired program made.
//!
//! # Why a bot row can be mechanical, which is the honest part
//!
//! A bump has no design question to refine: the source of truth is the manifest,
//! the predicate is "CI green on the bump", the effect is none, and the type
//! follows the one the bot's own config already decided. That is exactly why this
//! must NOT reuse the agent refinement path, where a human judgement is the thing
//! being attested — the two attest different things, and CLOUD-431 exists to keep
//! them apart.
//!
//! # Every consumer fact is config, and that is non-negotiable rule 1
//!
//! Which repository, which bot logins, which manifests a lane owns, which markers
//! tie a row to its PR — all of it is the consumer's, and none of it is spelled
//! here. `[bot_lane]` in `batten.toml` carries the answers; this module carries
//! the matcher. A grep of `crates/batten` for a bot's name or a manifest path
//! returns nothing, which is the same standing `[attribution]` has.
//!
//! # Pointer-only per non-negotiable rule 4
//!
//! Every refusal names a PR number, an issue key, a login or a path. Never a diff
//! body, never a version, never the PR body — a bot PR carries a release-notes
//! dump, and echoing it would put that in the log of every landing.

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;

/// The `[bot_lane]` table: which proposals this repository will file a row for.
///
/// Absent means the repository runs no bot lane, and the verbs say so rather than
/// filing against defaults — a lane assembled from engine literals would be a row
/// asserting a bump nobody configured, which is the CLOUD-198 class with a new
/// author.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BotLane {
    /// The forge repository, `owner/name`, that the lane's pull requests live in.
    pub repo: String,
    /// The logins whose pull requests earn a row.
    ///
    /// A list rather than a pattern: a login is a literal the forge assigns, and
    /// a regex over it would admit a neighbour nobody meant to trust.
    pub bots: Vec<String>,
    /// The manifests this lane owns, as globs. A PR touching none of them is
    /// refused rather than given an invented row.
    pub owned_manifests: Vec<String>,
    /// The hidden marker that ties a mirror issue to the pull request it was
    /// filed for.
    ///
    /// A comment rather than a label or a title convention: it survives an edit,
    /// it is invisible rendered, and it is what makes `ensure` idempotent across
    /// the window where the row exists and the PR body does not yet name it.
    pub marker_prefix: String,
    /// What the tracker's own sync leaves on the issue once it has mirrored it.
    /// The key is read from a comment carrying this, never from the issue body —
    /// that body is this lane's own text, so a key named there would be one we
    /// wrote rather than one the tracker assigned.
    pub linkback_marker: String,
    /// The tracker's key prefix, which a key is this followed by digits.
    ///
    /// The consumer's vocabulary, exactly as the Ready grammar's `[[pattern]]`
    /// rows are: a tracker's key shape in `crates/batten` is non-negotiable rule
    /// 1's violation.
    pub key_prefix: String,
    /// The branch prefix a bot receipt may be keyed to. A branch outside it is
    /// refused onto the agent claim receipt, which attests something else.
    pub branch_prefix: String,
    /// The path of the file whose text is the derived row's body, with
    /// `{{...}}` placeholders substituted.
    ///
    /// A tracked file rather than a string in the config: the body is a page of
    /// consumer prose carrying a Ready block, and a page of markdown inside a
    /// TOML value is unreviewable. It is also what keeps `ready-lint`'s grammar
    /// and the text it judges in one place a human edits.
    pub body_template: String,
}

/// The placeholders [`BotLane::body_template`] may carry.
///
/// A closed set, checked at substitution: a template naming one this engine does
/// not fill would render the literal `{{...}}` into a tracker row, and a row
/// carrying a template artifact reads as a lane that half-ran.
pub const PLACEHOLDERS: &[&str] = &["pr", "branch", "login", "manifests", "type"];

/// Whether `login` is one of the lane's bots.
///
/// Exact, case-sensitively: a forge login is a literal, and `renovate` is not
/// `Renovate` to the API that assigned it.
#[must_use]
pub fn is_lane_bot(login: &str, bots: &[String]) -> bool {
    bots.iter().any(|bot| bot == login)
}

/// The subset of `files` this lane owns, in the order given.
///
/// The glob is the same matcher every other path row in this engine is decided
/// by, so a lane cannot grow a second opinion about what a recursive pattern
/// means. Which globs a lane declares is the consumer's, in `[bot_lane]`, and
/// non-negotiable rule 1 is why not one of them is named here — not even as an
/// example, which is what `document_facts` caught in the first draft of this
/// comment.
///
/// # Errors
///
/// [`UsageError`] when a declared glob will not compile — a lane whose pattern
/// cannot be read must refuse rather than silently own nothing.
pub fn owned<'a>(files: &'a [String], globs: &[String]) -> Result<Vec<&'a String>> {
    let mut builder = globset::GlobSetBuilder::new();
    for glob in globs {
        builder.add(globset::Glob::new(glob).map_err(|err| {
            UsageError::raise(format!(
                "bot lane: owned_manifests glob {glob} will not compile: {err}"
            ))
        })?);
    }
    let set = builder
        .build()
        .map_err(|err| UsageError::raise(format!("bot lane: owned_manifests: {err}")))?;
    Ok(files.iter().filter(|path| set.is_match(path)).collect())
}

/// The Conventional type a subject declares, or `None` where it declares none.
///
/// READ rather than chosen: the bot's own config already decided it, and
/// re-deciding here would be a second authority for one fact. A subject with no
/// prefix is a lane defect, not something to paper over — the commit gate would
/// refuse it anyway, so the caller says so instead of inventing a type.
#[must_use]
pub fn conventional_type(subject: &str) -> Option<&str> {
    let head = subject.split(':').next()?;
    if head == subject {
        // No colon at all, so nothing was split and there is no prefix.
        return None;
    }
    let word = head
        .split_once('(')
        .map_or_else(|| head.trim_end_matches('!'), |(before, _)| before);
    let word = word.trim_end_matches('!');
    (!word.is_empty() && word.chars().all(|ch| ch.is_ascii_lowercase())).then_some(word)
}

/// The closing verbs a body may use to move a row, as the board reads them.
const CLOSING_VERBS: &[&str] = &[
    "close", "closes", "closed", "fix", "fixes", "fixed", "resolve", "resolves", "resolved",
];

/// The first tracker key `body` **closes**, or `None`.
///
/// The predicate is the board gate's, verbatim, and deliberately not a narrower
/// one matching only what this lane writes: a body a human edited to say
/// "Fixes CLOUD-767" closes the row just as well, and a gate that refused it
/// would be wrong about the one thing it exists to decide.
///
/// A key merely NAMED does not count, which is the whole failure being caught: a
/// bot regenerates its body on every rebase and the closing line goes with it,
/// leaving a body that still mentions the key and moves nothing.
#[must_use]
pub fn closing_key(body: &str, prefix: &str) -> Option<String> {
    let lowered = body.to_lowercase();
    let mut best: Option<(usize, String)> = None;
    for (at, _) in lowered.match_indices(&prefix.to_lowercase()) {
        let Some(key) = key_at(body, at, prefix) else {
            continue;
        };
        // The word before the key, skipping the separators a body may put between
        // them: whitespace, a colon, and the `#` some forges want.
        let before = lowered[..at].trim_end_matches(['#', ':', ' ', '\t', '\n', '\r']);
        let verb = before
            .rsplit(|ch: char| !(ch.is_ascii_alphabetic()))
            .next()
            .unwrap_or_default();
        // `DO-NOT-CLOSE CLOUD-388` ends in a closing verb and is the one marker
        // that must not read as a close, so the character before the verb decides:
        // a hyphen means the verb is part of a longer token.
        let joined = before
            .strip_suffix(verb)
            .is_some_and(|rest| rest.ends_with('-'));
        if !joined && CLOSING_VERBS.contains(&verb) && best.is_none() {
            best = Some((at, key));
        }
    }
    best.map(|(_, key)| key)
}

/// The first tracker key `body` NAMES, closing or not.
///
/// What idempotence keys on: a body already carrying any key has had its row
/// filed, and filing a second one is the failure a per-tick call must not have.
#[must_use]
pub fn named_key(body: &str, prefix: &str) -> Option<String> {
    body.match_indices(prefix)
        .find_map(|(at, _)| key_at(body, at, prefix))
}

/// The whole `<prefix><digits>` token starting at `at`, or `None` where the
/// prefix is not followed by at least one digit.
fn key_at(body: &str, at: usize, prefix: &str) -> Option<String> {
    let rest = body.get(at + prefix.len()..)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    (!digits.is_empty()).then(|| format!("{}{digits}", &body[at..at + prefix.len()]))
}

/// The derived row's body: the template with every placeholder substituted.
///
/// # Errors
///
/// [`UsageError`] when the template names a placeholder this engine does not
/// fill. Refusing is the safe direction — the alternative is a tracker row
/// carrying a literal `{{...}}`, which reads as a lane that half-ran and which
/// nobody would notice until a human opened the row.
pub fn render(template: &str, values: &[(&str, String)]) -> Result<String> {
    let mut body = template.to_owned();
    for (name, value) in values {
        body = body.replace(&format!("{{{{{name}}}}}"), value);
    }
    if let Some(at) = body.find("{{") {
        let rest = &body[at..];
        let name: String = rest
            .trim_start_matches('{')
            .chars()
            .take_while(|ch| *ch != '}')
            .collect();
        return Err(UsageError::raise(format!(
            "bot lane: the body template names placeholder {{{{{name}}}}}, which nothing fills — \
             the declared set is {}",
            PLACEHOLDERS.join(", ")
        )));
    }
    Ok(body)
}

/// The file name the bot receipt is keyed to.
///
/// Keyed by BRANCH, like the agent claim and for the same reason: it attests a
/// decision about the pull request that every commit on the branch continues to
/// serve, where a SHA-keyed one would demand a re-claim per commit. A slash is
/// the one character a file name cannot carry, so it is spelled out.
#[must_use]
pub fn receipt_name(branch: &str) -> String {
    format!("bot.{}", branch.replace('/', "-"))
}

/// Write the bot receipt.
///
/// **Pointer-only**: the key, the login, the pull request number, a timestamp and
/// the base commit. Never the body, never a version.
///
/// The `base` line gives this receipt CLOUD-516's staleness rule: a branch
/// restarted out from under its receipt is void rather than silently trusted.
///
/// # Errors
///
/// [`UsageError`] when the receipt cannot be written.
pub fn mint(
    receipts: &std::path::Path,
    branch: &str,
    attested: &Attested,
    base: Option<&str>,
    at: &str,
) -> Result<std::path::PathBuf> {
    use std::fmt::Write as _;

    let mut body = String::new();
    writeln!(body, "{}", attested.key)?;
    writeln!(body, "bot {}", attested.login)?;
    writeln!(body, "pr {}", attested.pr)?;
    writeln!(body, "derived-at {at}")?;
    writeln!(body, "base {}", base.unwrap_or("-"))?;

    std::fs::create_dir_all(receipts).map_err(|err| {
        UsageError::raise(format!(
            "claim bot: cannot create {}: {err}",
            receipts.display()
        ))
    })?;
    let path = receipts.join(receipt_name(branch));
    std::fs::write(&path, body).map_err(|err| {
        UsageError::raise(format!("claim bot: cannot write {}: {err}", path.display()))
    })?;
    Ok(path)
}

/// The facts a bot receipt records, once every one of them holds.
///
/// A struct rather than three loose arguments so a caller cannot mint one with a
/// key it never checked: the only way to build it is to have read all three.
#[derive(Debug, Clone)]
pub struct Attested {
    /// The tracker key the pull request's body names.
    pub key: String,
    /// The login that opened it.
    pub login: String,
    /// The pull request number.
    pub pr: String,
}

/// What a pull request is, as far as this lane is concerned.
///
/// The fields the predicates above read and nothing else. Notably NOT the body's
/// prose: a bot PR carries a release-notes dump, and a struct with a place to put
/// it is a struct a report can leak it from.
#[derive(Debug, Clone)]
pub struct Pull {
    /// The number, as given.
    pub number: String,
    /// The subject, which is also the derived row's title.
    pub title: String,
    /// The body, read for the keys it names and never emitted.
    pub body: String,
    /// The login that opened it.
    pub login: String,
    /// The head branch.
    pub head: String,
}

/// The forge half: every call this lane makes, and nothing that decides anything.
pub mod forge {
    use anyhow::Result;

    use super::Pull;
    use crate::error::UsageError;

    /// The client every call goes through, for [`crate::pr_watch`]'s reason.
    const CLIENT: &str = "gh";

    /// Run `gh` with `args` and hand back stdout, or a could-not-look.
    ///
    /// Pointer-only on the failure path: the endpoint and the status, never the
    /// response body — a forge error can echo a header dump back, and a token
    /// with it.
    ///
    /// # Errors
    ///
    /// Anything but a clean exit is an internal error (→ exit `3`): a lane that
    /// cannot read the pull request must not report that it filed nothing.
    fn run(args: &[&str]) -> Result<String> {
        run_with(args, None)
    }

    /// As [`run`], with `stdin` handed to the child where there is one.
    ///
    /// The two writes send their body **on stdin** (`-F body=@-`) rather than
    /// through a temporary file. A body is a page of markdown carrying newlines
    /// and backticks; a file would put that page on disk under a path this
    /// process then has to remember to remove, and a write that fails between
    /// those two steps leaves a tracker row's text lying in the world. Stdin has
    /// no such window.
    fn run_with(args: &[&str], stdin: Option<&str>) -> Result<String> {
        #[expect(
            clippy::disallowed_types,
            reason = "stays: the forge's own client IS the call, and it resolves the credential outside this crate — the standing CLOUD-1143 gave the check-run read (CLOUD-1295)"
        )]
        let output = crate::rules::spawn_resolving(
            Some(std::path::Path::new(".")),
            CLIENT,
            |program, extra| {
                let mut command = std::process::Command::new(program);
                command
                    .args(extra)
                    .args(args)
                    .stderr(std::process::Stdio::null());
                let Some(body) = stdin else {
                    return command.output();
                };
                command
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped());
                let mut child = command.spawn()?;
                if let Some(pipe) = child.stdin.as_mut() {
                    std::io::Write::write_all(pipe, body.as_bytes())?;
                }
                drop(child.stdin.take());
                child.wait_with_output()
            },
        );
        let output = output.map_err(|err| {
            anyhow::anyhow!("bot lane: cannot run {CLIENT}: {err} — nothing is written")
        })?;
        if !output.status.success() {
            // The endpoint, which is the first argument, and nothing else.
            let endpoint = args.get(1).copied().unwrap_or("<none>");
            return Err(anyhow::anyhow!(
                "bot lane: {CLIENT} refused {endpoint} — cannot read the pull request, so nothing \
                 is written"
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// One `--jq` read against an endpoint.
    fn read(endpoint: &str, jq: &str) -> Result<String> {
        Ok(run(&["api", endpoint, "--jq", jq])?.trim().to_owned())
    }

    /// The pull request, as [`Pull`].
    ///
    /// # Errors
    ///
    /// As [`run`], plus a [`UsageError`] where the answer carries no title: the
    /// derived row's title IS the PR's, so there is nothing to file.
    pub fn pull(repo: &str, number: &str) -> Result<Pull> {
        let raw = read(
            &format!("repos/{repo}/pulls/{number}"),
            "[.title, .body // \"\", .user.login, .head.ref] | @tsv",
        )?;
        let mut fields = raw.split('\t');
        let title = fields.next().unwrap_or_default().to_owned();
        if title.is_empty() {
            return Err(UsageError::raise(format!(
                "bot lane: #{number} has no title, and the row's title is the pull request's — so \
                 there is nothing to file"
            )));
        }
        Ok(Pull {
            number: number.to_owned(),
            title,
            body: fields.next().unwrap_or_default().to_owned(),
            login: fields.next().unwrap_or_default().to_owned(),
            head: fields.next().unwrap_or_default().to_owned(),
        })
    }

    /// The paths the pull request changed, capped at one page.
    ///
    /// A bump touches two files; a PR touching more than a page is not a bump,
    /// and the cap refusing it is the safe direction rather than a truncation
    /// nobody sees.
    ///
    /// # Errors
    ///
    /// As [`run`].
    pub fn files(repo: &str, number: &str) -> Result<Vec<String>> {
        Ok(read(
            &format!("repos/{repo}/pulls/{number}/files?per_page=100"),
            ".[].filename",
        )?
        .lines()
        .map(str::to_owned)
        .filter(|line| !line.is_empty())
        .collect())
    }

    /// The mirror issue this pull request already has, if any.
    ///
    /// LISTED rather than searched: the search API's indexing lag is measured in
    /// tens of seconds, and a tick running inside that window would file a second
    /// row for the same pull request.
    ///
    /// # Errors
    ///
    /// As [`run`].
    pub fn mirror(repo: &str, number: &str, marker_prefix: &str) -> Result<Option<String>> {
        let marker = format!("{marker_prefix}{number} -->");
        let found = read(
            &format!("repos/{repo}/issues?state=all&per_page=100"),
            &format!(
                "[.[] | select((.pull_request // null) == null) | select((.body // \"\") | \
                 contains(\"{marker}\"))] | .[0].number // empty"
            ),
        )?;
        Ok((!found.is_empty()).then_some(found))
    }

    /// The tracker's linkback comment on `issue`, or empty while the sync has not
    /// run yet.
    ///
    /// Read from the comment alone: the issue BODY is this lane's own text, so a
    /// key named there would be one we wrote rather than one the tracker
    /// assigned.
    ///
    /// # Errors
    ///
    /// As [`run`].
    pub fn linkback(repo: &str, issue: &str, marker: &str) -> Result<String> {
        read(
            &format!("repos/{repo}/issues/{issue}/comments?per_page=100"),
            &format!(
                "[.[] | select((.body // \"\") | contains(\"{marker}\"))] | .[0].body // empty"
            ),
        )
    }

    /// Open the mirror issue and answer with its number.
    ///
    /// The body travels on STDIN rather than on the command line: it is a page of
    /// markdown carrying newlines and backticks, and an argument of that shape is
    /// a quoting bug waiting for the first template edit.
    ///
    /// # Errors
    ///
    /// As [`run`], plus an internal error where the forge accepted the issue and
    /// named no number — no row exists then, and none is invented.
    pub fn open_issue(repo: &str, title: &str, body: &str) -> Result<String> {
        let created = run_with(
            &[
                "api",
                "-X",
                "POST",
                &format!("repos/{repo}/issues"),
                "-f",
                &format!("title={title}"),
                "-F",
                "body=@-",
                "--jq",
                ".number",
            ],
            Some(body),
        )?
        .trim()
        .to_owned();
        if created.is_empty() {
            return Err(anyhow::anyhow!(
                "bot lane: the mirror issue was accepted and named no number, so no row exists \
                 and none is invented"
            ));
        }
        Ok(created)
    }

    /// Replace the pull request's body.
    ///
    /// # Errors
    ///
    /// As [`run`]: a body that could not be written means the row exists and the
    /// merge would not move it, which is a failure rather than a quiet skip.
    pub fn set_body(repo: &str, number: &str, body: &str) -> Result<()> {
        run_with(
            &[
                "api",
                "-X",
                "PATCH",
                &format!("repos/{repo}/pulls/{number}"),
                "-F",
                "body=@-",
            ],
            Some(body),
        )
        .map(|_| ())
    }

    /// The number of the open pull request whose head is `branch`, if any.
    ///
    /// # Errors
    ///
    /// As [`run`].
    pub fn open_for(repo: &str, branch: &str) -> Result<Option<String>> {
        let found = read(
            &format!("repos/{repo}/pulls?state=open&per_page=100"),
            &format!("[.[] | select(.head.ref == \"{branch}\")] | .[0].number // empty"),
        )?;
        Ok((!found.is_empty()).then_some(found))
    }
}

#[cfg(test)]
// Panicking on a refusal the case does not expect is the idiomatic way for a
// test to fail loudly.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The key prefix the cases below use. A literal here rather than the
    /// consumer's, because these are assertions about the MATCHER.
    const KEY: &str = "CLOUD-";

    #[test]
    fn a_listed_login_is_the_lane_and_a_neighbour_is_not() {
        let bots = vec!["renovate[bot]".to_owned()];
        assert!(is_lane_bot("renovate[bot]", &bots));
        // The retired sibling: a row filed for a bot that cannot open a PR would
        // be a claim about a lane this repository does not have.
        assert!(!is_lane_bot("dependabot[bot]", &bots));
        // Case is the forge's, not ours to normalise.
        assert!(!is_lane_bot("Renovate[bot]", &bots));
    }

    #[test]
    fn only_the_declared_manifests_are_owned() {
        // Neutral names for rule 1's reason: a consumer's artifact path may not
        // reach `crates/batten`, and a unit test is still `crates/batten`.
        let files = vec![
            "manifest.toml".to_owned(),
            "src/main.rs".to_owned(),
            "lane/nested/one.yml".to_owned(),
        ];
        let globs = vec!["manifest.toml".to_owned(), "lane/**".to_owned()];
        let owned = owned(&files, &globs).unwrap();
        assert_eq!(owned.len(), 2);
        assert!(owned.iter().all(|path| *path != "src/main.rs"));
    }

    #[test]
    fn a_glob_that_will_not_compile_refuses_rather_than_owning_nothing() {
        let files = vec!["manifest.toml".to_owned()];
        assert!(owned(&files, &["[".to_owned()]).is_err());
    }

    #[test]
    fn the_type_is_read_from_the_subject_and_a_bare_one_has_none() {
        assert_eq!(
            conventional_type("build(deps): update cargo"),
            Some("build")
        );
        assert_eq!(conventional_type("ci: bump the action"), Some("ci"));
        assert_eq!(conventional_type("feat!: a breaking change"), Some("feat"));
        assert_eq!(conventional_type("update cargo"), None);
        // Not a Conventional prefix: a capitalised word is not a type word, and
        // reading it as one would let a subject the commit gate refuses through.
        assert_eq!(conventional_type("Update: cargo"), None);
    }

    #[test]
    fn a_closing_verb_closes_and_a_bare_key_does_not() {
        assert_eq!(
            closing_key("Closes CLOUD-700", KEY).as_deref(),
            Some("CLOUD-700")
        );
        assert_eq!(
            closing_key("Fixes #CLOUD-701", KEY).as_deref(),
            Some("CLOUD-701")
        );
        assert_eq!(
            closing_key("resolved: CLOUD-702", KEY).as_deref(),
            Some("CLOUD-702")
        );
        // THE WHOLE FAILURE BEING CAUGHT: a rebase leaves the key named and the
        // closing line gone, and a merge on that body moves nothing.
        assert_eq!(closing_key("See CLOUD-703 for context", KEY), None);
        assert_eq!(closing_key("nothing here", KEY), None);
    }

    #[test]
    fn the_do_not_close_marker_does_not_read_as_a_close() {
        // It ends in a closing verb, which is exactly why the character before
        // the verb has to decide rather than the verb alone.
        assert_eq!(closing_key("DO-NOT-CLOSE CLOUD-388", KEY), None);
    }

    #[test]
    fn a_named_key_is_found_whether_or_not_it_closes() {
        assert_eq!(
            named_key("See CLOUD-703 for context", KEY).as_deref(),
            Some("CLOUD-703")
        );
        // A prefix with no digits is not a key, so a body discussing "CLOUD-"
        // as a string does not read as one already filed.
        assert_eq!(named_key("the CLOUD- prefix", KEY), None);
    }

    #[test]
    fn a_template_naming_an_unfilled_placeholder_refuses() {
        let filled = render("pr {{pr}}", &[("pr", "7".to_owned())]).unwrap();
        assert_eq!(filled, "pr 7");
        let refused = render("pr {{pr}} by {{whoever}}", &[("pr", "7".to_owned())]);
        assert!(refused.is_err(), "an unfilled placeholder must refuse");
    }
}
