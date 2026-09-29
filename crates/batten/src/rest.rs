//! The forge's REST tier, IN PROCESS — one client, one credential reader, no
//! spawn (CLOUD-1338).
//!
//! **Named `rest` rather than `forge`, and the near-miss is worth the line.**
//! [`crate::forge`] is a different subject entirely: it reads a VERDICT RECORD a
//! producer wrote outside the engine, keyed by sha, off disk. Drafting this as
//! `forge.rs` overwrote it wholesale — the two nouns are one word apart and the
//! subjects share nothing, which is exactly when a name collision is silent.
//!
//! # This module exists because four sites claimed a client that was already here
//!
//! Every spawn it replaces carried the same `#[expect(clippy::disallowed_types)]`
//! reason: *"this crate carries no HTTP client that resolves a forge
//! credential — so the forge's own client IS the call."* That sentence was
//! **false when it was written, four times**, and one of the four was written in
//! `lease.rs`, eighty lines from the credential reader [`credential`] is —
//! a function that resolves the token and attaches `Authorization: Bearer` to a
//! [`crate::fetch`] call. (It named two variables outright when that was written;
//! since CLOUD-1622 the consumer declares them, because naming them here was the
//! same rule-1 defect one layer down.)
//!
//! [`crate::fetch`] is hyper plus hyper-rustls, vendored under CLOUD-745, with
//! explicit connect and total timeouts, a typed status, lowercased response
//! headers and a scoped current-thread runtime. It is strictly better than a
//! child process for every one of these reads, and it was in the crate the whole
//! time.
//!
//! **The escapes were the tell and nothing caught them.** `spawn-adapters` is the
//! gate over WHERE a spawn may appear, and it is answered by adding a word to a
//! Rego set — which is what happened: two placements went in, each with a
//! justification in a comment no gate reads. A branch whose whole subject is
//! *removing shell* added five annotated spawns and widened the placement table
//! twice, and every sensor stayed green.
//!
//! # What is NOT here
//!
//! The git smart-HTTP transport. [`crate::lease`] speaks that directly for the
//! lease ref's compare-and-swap — a different protocol over a different endpoint
//! family, and folding the two would put a ref-advertisement parser behind a REST
//! helper. What moved here is the credential reader the two share.

use crate::fetch::{self, Call};

/// Where the REST tier lives.
///
/// A constant rather than a config key: a consumer pointing this at another host
/// is asking for a different client, not a different value, and a key nobody sets
/// is a surface with no reader.
const API: &str = "https://api.github.com";

/// What the API is asked to send back.
const ACCEPT: &str = "application/vnd.github+json";

/// Which forge this repository is hosted on, in the parts the engine cannot
/// derive (CLOUD-1622).
///
/// **Only what a consumer can actually answer.** The REST base stays the constant
/// above: pointing this tier at another host asks for a different CLIENT, not a
/// different value, and that reasoning is unchanged by this table. What a
/// consumer genuinely knows, and what the engine had no way to be told, is which
/// environment variables carry the token.
///
/// **IT IS NOT THE FORGE'S CONVENTIONAL NAMES, and the first revision of this
/// type said it was.** That revision argued a CI provider injects a job token
/// under its own name and so those names are what a REST read should present.
/// Measured, the opposite holds on this class of host: the injected value is a
/// substitutable PLACEHOLDER — batten's own provisioning carries a
/// `reject_prefix` to refuse it — and the credential the consumer holds lives
/// under a name only they can state. Reading a conventional spelling as a
/// credential is the same rule-1 defect as hard-coding it, one level of
/// indirection along.
#[derive(
    Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema, PartialEq, Eq,
)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Forge {
    /// The environment variables that may carry the forge credential, in
    /// precedence order.
    ///
    /// Ordered rather than a set, and the order is the consumer's: which of
    /// several wins is a fact about that consumer's host, and the emptiness rule
    /// below means a name that is exported but blank falls THROUGH to the next
    /// rather than committing the read to the first that exists.
    ///
    /// **An empty list is could-not-look, never "no credential needed."** A
    /// public repository genuinely needs none, so an unauthenticated read is a
    /// legitimate state — but it is one a consumer DECLARES by naming no
    /// variables, rather than one the engine infers by finding none of the two
    /// spellings it used to carry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_names: Vec<String>,
    /// The paginated reads this consumer declares, each recorded by
    /// `batten record query <id>` (CLOUD-843).
    ///
    /// **Declared HERE, interpreted in [`crate::forge_query`]**, and the split is
    /// the layering rather than a filing accident: this table is the `[forge]`
    /// section and this module is its owner, while the template grammar, the
    /// walk and the reduction reach `git`, `forge` and `record` — edges this
    /// module, which reaches `fetch` alone, must not grow. So the rows are plain
    /// data here and every reading of them is that module's.
    ///
    /// **No weakening comparison in `trust.rs`, and the absence is argued.**
    /// Deleting a row is LOUD rather than silent: the `[[record]]` row that
    /// declares its family still names `record query <id>` as the writer, and
    /// that invocation then exits 1 on an id nothing declares. Editing a row's
    /// endpoint, window or reduction changes WHAT is measured, and none of those
    /// has a monotone reading a raise-only clamp could order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query: Vec<Query>,
    /// The claims this consumer's tasks need from the credential, each with the
    /// read endpoint that proves it, which `batten doctor forge` probes
    /// (CLOUD-843, retiring `gh-preflight`).
    ///
    /// **Declared HERE, interpreted in [`crate::preflight`]**, for `query`'s
    /// reason directly above: which endpoints a consumer calls and which claim
    /// each needs are the consumer's facts, and walking them is mechanism.
    ///
    /// **No weakening comparison in `trust.rs`, and the absence is argued.** A
    /// probe row is a DIAGNOSIS, not a gate: dropping one makes the report
    /// shorter and refuses nothing it refused before, because no verdict any rule
    /// renders reads it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probe: Vec<Probe>,
}

/// One `[[forge.probe]]` row: a claim the credential must carry, and the
/// endpoint that proves it (CLOUD-843).
///
/// **Read-only by construction.** A row whose `probe` is `false` is DECLARED and
/// reported as never probed — a write cannot be tested without performing it,
/// and an endpoint that needs an existing object may answer 404 for want of one.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    /// The API-relative endpoint, no leading slash, with `{owner}` and `{repo}`
    /// resolved from the checkout's forge remote. A query string is allowed:
    /// a probe asks for one row, not a collection.
    pub endpoint: String,
    /// The claim the endpoint needs, as the forge names it in a refusal —
    /// `checks=read`, `pull_requests=write`.
    pub claim: String,
    /// Which of the consumer's tasks need the claim, for the report.
    pub used_by: String,
    /// Whether the endpoint is probed. `false` declares the claim and never
    /// calls the endpoint.
    #[serde(default = "probed")]
    pub probe: bool,
}

/// A probe row is probed unless it says otherwise.
const fn probed() -> bool {
    true
}

/// One `[[forge.query]]` row: a declared, paginated REST read and the reduction
/// a producer records from it (CLOUD-843).
///
/// # Why a row rather than a verb per measurement
///
/// Eleven shell bodies each re-derived the same four things — an endpoint with
/// the repository spliced in, a pagination walk, a date cut-off and a `jq`
/// projection — and three of them got the truncation wrong three different ways
/// ([`crate::forge`]'s header). One declared row per read puts the consumer's
/// facts (which endpoint, which fields, which window) in the committed authority
/// and leaves the mechanism in the engine, which is non-negotiable rule 1's split
/// exactly: nothing here names an endpoint, and nothing in `batten.toml` walks a
/// page.
///
/// The row's `id` is also the RECORD FAMILY it writes, and a `[[record]]` row
/// must declare that family — a query nothing projects would write a store no
/// module can read, which is CLOUD-1810's dead gate one table over, refused at
/// load rather than discovered as a green run.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Query {
    /// The query's name, which `record query` takes and which is also the record
    /// family it writes. One path component.
    pub id: String,
    /// The API-relative endpoint, with no leading slash and no query string,
    /// e.g. `repos/{owner}/{repo}/actions/runs`.
    ///
    /// `{owner}` and `{repo}` are resolved from the checkout's forge remote;
    /// `{since}` is the window's cut-off instant where `since` is declared; any
    /// other `{name}` is bound by `record query --input name=value`. A
    /// placeholder nobody binds is a usage error, never a literal brace on the
    /// wire — the forge client this replaces expanded `{owner}/{repo}` itself,
    /// and a port that inherited the spelling without the expansion 404'd on
    /// every call (`land_forge_reads.rs`).
    pub endpoint: String,
    /// Where the rows are in the response body: absent means the body IS the
    /// array; a key names the array an object wraps, e.g. `workflow_runs`.
    ///
    /// Named rather than sniffed, for [`crate::forge::Shape`]'s reason. A wrong
    /// answer is loud rather than silent: an object read as bare is not an array,
    /// which the walk reports as could-not-look.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<String>,
    /// Further query-string parameters, as `name = "template"`. Values take the
    /// same placeholders as `endpoint` and are percent-encoded after binding.
    ///
    /// `page` and `per_page` are the walk's own and are refused here.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub params: std::collections::BTreeMap<String, String>,
    /// Rows asked for per page, `1..=100`.
    ///
    /// Required, because it is also the walk's END-OF-COLLECTION signal where
    /// the endpoint states no count: a page shorter than this is the last. The
    /// forge silently clamps above 100, so a larger value would make every full
    /// page look short and end the walk after one page reporting it whole.
    pub per_page: u32,
    /// The page budget. Required and at least 1, for [`crate::forge::window`]'s
    /// reason: every caller that took a default took a different one.
    pub max_pages: u32,
    /// A trailing time window over the rows, and whether it may end the walk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<Since>,
    /// The reduction: which fields of each row are recorded, as dot-separated
    /// paths (`head_commit.id`, `pull_requests.0.number`).
    ///
    /// Required and non-empty. The whole row is NEVER recorded — a forge row
    /// carries titles, bodies and URLs, and non-negotiable rule 4 is decided
    /// here, at the declaration, rather than hoped for at every reader. A path
    /// that resolves to nothing records `null`, so every row has every key.
    pub select: Vec<String>,
    /// Walk this row once per value another row's record holds (CLOUD-843).
    ///
    /// **The fan-out a single endpoint cannot express**: a run's jobs, a
    /// branch's tip commit. The shell bodies this absorbs looped `gh api` over the
    /// ids an earlier `gh api` printed; declaring the loop names which family the
    /// members come from, so the walk is the engine's and the members are a
    /// record a module can also read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub each: Option<Each>,
    /// Durations derived from the instants a row carries (CLOUD-843).
    ///
    /// Arithmetic over instants is the one reduction a module cannot make — no
    /// clock and no date parser reach the policy surface — so it is declared
    /// here and computed by the producer, beside the fields it reads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub span: Vec<Span>,
}

/// A `[[forge.query]]` row's fan-out: one walk per distinct value at `field`
/// in the rows of the family `query` recorded, bound to the placeholder
/// `input` (CLOUD-843).
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Each {
    /// The `[[forge.query]]` id whose recorded rows supply the members.
    pub query: String,
    /// Which of the source row's `select` paths holds a member's value, spelled
    /// exactly as that row declares it.
    ///
    /// A recorded row carries each selected path as ONE flat key — `commit.sha`
    /// is a key, not an object — so this is looked up whole rather than walked,
    /// and a path the source never selected is refused at load, where it can be
    /// fixed, rather than read as could-not-look on every run.
    pub field: String,
    /// The placeholder each member binds, and the key it is recorded under on
    /// every row its walk kept.
    pub input: String,
}

/// One duration a `[[forge.query]]` row derives from its instants (CLOUD-843).
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Span {
    /// The key the duration is recorded under. A placeholder-shaped name, so it
    /// can never be mistaken for a dotted `select` path.
    pub name: String,
    /// The dot-separated path of the RFC 3339 instant the span starts at.
    pub from: String,
    /// The dot-separated path of the instant it ends at; absent is the
    /// producer's clock, which is how an AGE is declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// What the duration counts.
    #[serde(default)]
    pub unit: SpanUnit,
}

/// What a [`Span`] counts.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum SpanUnit {
    /// Whole seconds between the two instants.
    #[default]
    Seconds,
    /// UTC calendar days between the two instants' dates — a civil-day count,
    /// so an instant at 23:59 and one at 00:01 the next day are one day apart.
    Days,
}

/// A `[[forge.query]]` row's time window: keep the rows whose `field` is an
/// RFC 3339 instant no older than `seconds` before the producer's clock.
///
/// The clock is the PRODUCER's (house style §5): a module sees the rows already
/// windowed and the cut-off as a token in the record, and `Fact::Instant` stays
/// `null` on every policy surface.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Since {
    /// The row field carrying the instant, as a dot-separated path.
    pub field: String,
    /// The window's length, back from now, in seconds. At least 1.
    pub seconds: u64,
    /// The collection is ordered newest-first on `field`, so the first row older
    /// than the cut-off ends the walk.
    ///
    /// **A claim only the consumer can make**, which is why it defaults off: a
    /// walk that stopped on a collection that was NOT so ordered would report a
    /// prefix as the whole window ([`crate::forge::Stop`]).
    #[serde(default)]
    pub stop: bool,
}

/// What the loaded config declared about the forge, set once per process.
///
/// **A process-scoped declaration rather than a threaded parameter, and the
/// choice is argued rather than convenient.** Fifteen call sites across six
/// modules reach [`get`], [`post`] and [`post_json`], and most sit in functions
/// with no `Config` in scope — threading one would change signatures up six call
/// chains to deliver a value that is the same for every one of them, since a
/// process runs against exactly one repository. That is the shape [`FIXTURE`]
/// below already takes for the same reason.
///
/// **One writer, one reader.** [`declare`] is called from the config loader and
/// nowhere else, and [`credential`] is the only thing that reads it — so this is
/// not a second authority over "which variable holds the credential", which is
/// the property the module header insists on.
///
/// Unset reads as `None`, which is could-not-look: a caller reaching the REST
/// tier before any config was loaded gets an unauthenticated request and the
/// 401/403 its callers already report, never a token borrowed from a default.
static DECLARED: std::sync::OnceLock<Forge> = std::sync::OnceLock::new();

/// Record what the consumer declared, once.
///
/// Later calls are ignored rather than refused: a process loads one config, and a
/// second load of the same file must not be able to change the credential a
/// request in flight would use.
pub(crate) fn declare(forge: Forge) {
    let _ = DECLARED.set(forge);
}

/// [`credential`] against what this process was told, for the one caller outside
/// this module that needs the token rather than a built header.
///
/// [`crate::lease`] speaks git's smart-HTTP transport directly, so it builds its
/// own `Authorization` line over a different endpoint family — but it reads the
/// credential through here, which is what keeps one answer to "which variable
/// holds it" rather than two.
pub(crate) fn declared_credential() -> Option<String> {
    credential(DECLARED.get())
}

/// The bearer token this forge needs, or `None`.
///
/// **Resolved here and returned to nobody outside this module.** It is
/// deliberately not a field of any value: a token in a struct is a token in that
/// struct's `Debug`, and non-negotiable rule 4 makes every report in this crate a
/// pointer. Keeping it inside the request builder means there is no value a
/// caller could print by accident.
///
/// **The names come from the consumer now** (CLOUD-1622). They were two
/// forge-shaped literals in the engine, which is the mechanism half of
/// non-negotiable rule 1: on a consumer whose host injects under a third name
/// neither exists, no `Authorization` header is attached, the remote answers
/// 401/403, and every caller reports could-not-look — so a landing says "no
/// in-flight runs" at exit 0 while knowing nothing. A dead path and a clean
/// answer, byte-identical from outside.
///
/// **AND A DECLARED NAME CAN STILL BE THE WRONG ONE, which is why the row is the
/// consumer's to get right rather than a spelling to copy.** Measured while
/// landing this seam: naming the forge's conventional variables resolved to a
/// substitutable placeholder in a bare shell and to a real token under the task
/// runner, because the runner re-exports the same name. A key whose meaning
/// depends on who launched the process is the coupling this rule removes, wearing
/// a config row as a disguise — so the emptiness fall-through below is load
/// bearing, and a consumer names the variable that holds THEIR credential.
///
/// **Naming none yields none, and there is deliberately no fallback to the old
/// pair.** A fallback is exactly how this stayed invisible: it worked in this
/// repository, on this forge, and returned a safe-looking nothing everywhere
/// else. A consumer that declares no names has said "read unauthenticated",
/// which is legitimate for a public repository and now a DECLARATION rather than
/// an inference.
///
/// **This is still the one reader**, promoted rather than copied — a second would
/// be a second answer to "which variable holds the credential", and the four
/// spawns this module replaces existed because nobody looked for the first.
pub(crate) fn credential(forge: Option<&Forge>) -> Option<String> {
    // **THE EMPTINESS TEST IS INSIDE THE CLOSURE, and outside it the fallback
    // above was a sentence the code did not implement** (review of #848).
    // `find_map` commits to the first variable that EXISTS, so a trailing
    // `.filter` judged only the already-chosen value: an exported-but-EMPTY
    // `GH_TOKEN` yielded `None` rather than falling through to `GITHUB_TOKEN`.
    //
    // That is the ordinary shape rather than a corner: a forge's own CI
    // substitutes the empty string for an unset secret, so a job naming a
    // personal token that was never configured exports an empty one beside a
    // perfectly good job token — and a task runner that resolves the variable
    // from a chain of fallbacks emits an empty one when the chain runs out. Every
    // REST read then goes out unauthenticated, and every caller reads the
    // resulting 403/404 as could-not-look, so a landing reports "no in-flight
    // runs" at exit 0 while knowing nothing at all.
    pick(forge?, |name| std::env::var(name).ok())
}

/// [`credential`]'s choice, with the environment handed in.
///
/// Split out so the rule above is testable at all: this crate forbids `unsafe`,
/// `std::env::set_var` is unsafe, and a test that mutated the process environment
/// would be untestable AND shared with every other test in the binary. The
/// lookup is the only impure part, so it is the only part that stays outside.
fn pick(forge: &Forge, lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    forge
        .credential_names
        .iter()
        .find_map(|name| lookup(name).filter(|token| !token.is_empty()))
}

/// The request headers for one exchange.
///
/// **An absent credential is not an error.** A public repository needs none, and
/// a private one answers `401` — which every caller here already reports as
/// could-not-look rather than as a verdict about the work.
fn headers(conditional: Option<&str>, json_body: bool) -> Vec<(String, String)> {
    let mut headers = vec![
        (String::from("Accept"), ACCEPT.to_owned()),
        // **REQUIRED, AND ITS ABSENCE IS A 403 ON EVERY CALL.** The forge
        // documents it: *"All API requests MUST include a valid User-Agent
        // header. Requests with no User-Agent header will be rejected."* The
        // client this tier replaced sent one for free, so nothing in the port
        // noticed it was gone — and the failure does not look like a missing
        // header. It looks like a permission problem, which is where a reader
        // goes first: measured on this repository with a token whose
        // `pull_requests=read` claim `gh-preflight` reports as `ok`, the same
        // request answered `200` from `curl` and `403` from here, and the only
        // difference was this line.
        //
        // A NAME AND A VERSION, which is what the forge asks for and what makes
        // a rate-limit conversation possible at all. No URL and nothing about
        // the consumer: a header is sent on every request, so it is the last
        // place a repository's identity should leak (non-negotiable rule 1).
        (
            String::from("User-Agent"),
            format!("batten/{}", env!("CARGO_PKG_VERSION")),
        ),
    ];
    if json_body {
        headers.push((
            String::from("Content-Type"),
            String::from("application/json"),
        ));
    }
    if let Some(etag) = conditional {
        headers.push((String::from("If-None-Match"), etag.to_owned()));
    }
    if let Some(token) = credential(DECLARED.get()) {
        headers.push((String::from("Authorization"), format!("Bearer {token}")));
    }
    headers
}

/// One answer from the REST tier.
///
/// `PartialEq` without `Eq`, because [`Answer::poll_floor`] is an `f64` and no
/// float is `Eq`. That is the right way round rather than a concession: a
/// fractional floor is CLOUD-390's whole defect, so the field cannot be an
/// integer, and a total-equality bound on a value carrying one would be a claim
/// this type has no business making.
///
/// **Typed at the boundary, which is the half the spawn could not give.** A child
/// process hands back bytes, so every caller had to re-parse a status line and a
/// header block out of `gh api -i` output. `pr_watch` carried the parser three
/// modules shared to undo that framing; with the last spawn gone the transport
/// has already read them, and that second parser is **retired** rather than left
/// standing beside this one. Two readings of one status line is the disagreement
/// class, not a duplication to tidy up later.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    /// The HTTP status. `304` is the reading that did not change.
    pub status: u16,
    /// The validator to send with the next request, where one was sent.
    pub etag: Option<String>,
    /// The interval the server asked to be polled at, in seconds.
    ///
    /// `f64` rather than an integer, which is CLOUD-390's defect and the reason
    /// this field is not a `u64`: the predecessor compared with `-gt`, so a
    /// fractional value read as *the server asked for no floor* — byte-identical
    /// to an absent header, and silently faster than the endpoint allows.
    pub poll_floor: Option<f64>,
    /// How long the forge asked the caller to back off for, in seconds.
    ///
    /// **A DIFFERENT HEADER ANSWERING A DIFFERENT QUESTION from
    /// [`Answer::poll_floor`]**, and conflating them is what made the
    /// predecessor's loop respond to being rate-limited by generating more of
    /// the request that had just been refused. `X-Poll-Interval` is *how often
    /// to ask*; this is *stop asking until*. A poll honouring only the first
    /// keeps its polite cadence straight into a secondary limit.
    ///
    /// Resolved from `Retry-After` where the forge states one, and otherwise
    /// from `X-RateLimit-Reset` — but only once `X-RateLimit-Remaining` is `0`,
    /// because a reset instant is always present and reading it as a backoff
    /// would pause on every successful call.
    pub backoff: Option<u64>,
    /// The response body, as text.
    pub body: String,
    /// Every header the response carried, keyed by LOWERCASE name.
    ///
    /// **The four typed fields above are readings this tier makes; this is the
    /// rest of what it already read.** `fetch::Response` holds the whole block
    /// and `canned` parses the whole block, so before this field the transport
    /// was discarding headers it had in hand — which is why `gh-preflight` still
    /// shelled out to `gh api -i` to read `X-Accepted-GitHub-Permissions` off a
    /// 403. That is the second header parser this module's own header says the
    /// typed boundary retired, standing again one endpoint over.
    ///
    /// Lowercase because `fetch::Response` lowercases every name it read, and
    /// matching a mixed-case literal against that map finds nothing and reads as
    /// *the header was absent* — the three-valued mistake CLOUD-390 records.
    /// [`Answer::header`] folds the case so no caller has to remember.
    pub headers: std::collections::BTreeMap<String, String>,
}

impl Answer {
    /// Whether this answer's body is a READING, rather than the forge declining.
    ///
    /// # `Some(Answer)` is not the same claim as *the forge answered the question*
    ///
    /// [`get`] answers `None` only where the exchange could not happen at all. A
    /// `401`, a `403`, a `404` or a `5xx` is a completed exchange carrying a
    /// refusal, so it arrives as `Some` — and its body is an error document
    /// rather than the collection a caller parses. A caller that reads the body
    /// without reading the status therefore gets an EMPTY parse, which is
    /// byte-identical on the decision surface to a genuinely empty collection.
    ///
    /// Measured on this crate (PR #848's review): the lap's ready step read the
    /// head's check-runs without this test, so a forge blip parsed as zero runs,
    /// `checks_green::decide` answered *unregistered*, `land::buys_a_matrix` read
    /// that as `Refire`, and the lap re-drafted and re-readied the pull request —
    /// cancelling the in-flight matrix the arm exists to protect.
    ///
    /// # `304` is deliberately NOT a reading
    ///
    /// A not-modified says *your cached copy still stands*, which is an answer
    /// only to a caller that HAS one. A one-shot read sends no validator and holds
    /// no cache, so treating it as a reading would report the empty cache as the
    /// forge's answer — the same defect one status along. A polling caller does
    /// not use this: [`crate::pr_watch::Poll::absorb`] keeps its own runs across a
    /// `304` precisely because it is the one that has something to keep.
    #[must_use]
    pub const fn is_reading(&self) -> bool {
        self.status == 200
    }

    /// Did the server answer NORMALLY — a reading, or a not-modified?
    ///
    /// **The sibling of [`Answer::is_reading`], and the distinction is what a
    /// RATE-LIMIT WINDOW turns on** (review of #848). A conditional poll's
    /// ordinary success is `304`, which `is_reading` deliberately excludes
    /// because it carries no body to read. But a `304` is still the forge
    /// answering rather than refusing, so it retires a `Retry-After` the way a
    /// `200` does — and a poll that retired the window only on `200` re-armed a
    /// stale one on every unchanged answer and wedged itself for the rest of the
    /// run.
    ///
    /// So: `is_reading` asks *did I get a body*, and this asks *did the server
    /// serve me*. Two questions, and the same status separates them differently.
    #[must_use]
    pub const fn answered(&self) -> bool {
        self.status == 200 || self.status == 304
    }

    /// One header by name, case-insensitively, or `None` where it was absent.
    ///
    /// **Works on a REFUSAL as well as a reading, and that is the point rather
    /// than a side effect.** The caller this exists for reads
    /// `X-Accepted-GitHub-Permissions` off a `403` to name the claim a token is
    /// missing — a status [`Answer::is_reading`] excludes and
    /// [`Answer::answered`] excludes too. Gating header access on either would
    /// leave exactly the case that needs it unable to ask.
    ///
    /// `None` is *the response did not carry this header*. It is not
    /// could-not-look: an [`Answer`] exists only where the exchange completed,
    /// and the could-not-look channel is [`get`] returning `None`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

/// One GET against the REST tier, or `None` where it could not be reached.
///
/// **`None` is could-not-look and never a verdict.** Every caller here polls in a
/// loop that must survive an unreachable forge: a lap that concluded "trunk
/// moved" from a failed request would decide about the network rather than about
/// the work, and it would cost a whole CI run each time.
///
/// `path` is API-relative and carries no leading slash — `repos/{owner}/{repo}/…`
/// — which is the spelling the forge's own client takes, so a call site moving
/// here keeps its endpoint string byte for byte.
#[must_use]
pub fn get(path: &str, etag: Option<&str>) -> Option<Answer> {
    exchange(path, etag, None, false)
}

/// One POST against the REST tier, with no body.
///
/// `false` where the call did not succeed, on the same could-not-look posture
/// [`get`] takes: the one caller cancels a run it is standing in, and a guard
/// that could not stop a run must not also fail the job it is standing in.
#[must_use]
pub fn post(path: &str) -> bool {
    exchange(path, None, Some(&[]), false).is_some_and(|answer| (200..300).contains(&answer.status))
}

/// One POST carrying a JSON body.
///
/// **The ANSWER comes back rather than a boolean**, because the one caller needs
/// the created object's id: the join key a lap waits on is minted from it, so a
/// call reporting only success would leave the lap with nothing to match. The
/// predecessor reached the same conclusion and said so — it used the API rather
/// than the client's comment porcelain precisely because the porcelain does not
/// return the object.
#[must_use]
pub fn post_json(path: &str, body: &serde_json::Value) -> Option<Answer> {
    let encoded = serde_json::to_vec(body).ok()?;
    exchange(path, None, Some(&encoded), false)
}

/// One asset's BYTES, from an API-relative asset path, or `None` where the
/// exchange could not happen at all (CLOUD-843, retiring `[tasks.checksums]`).
///
/// **The one read here that is not JSON, and the reason it is a separate door.**
/// A release asset is served by the same endpoint family as its metadata, told
/// apart only by `Accept: application/octet-stream`, and the forge answers it
/// with a redirect to a storage host. [`crate::fetch`] follows that redirect and
/// DROPS `Authorization` when the host changes, so the credential never reaches
/// the storage host — the property `fetch::exchange` records being added for
/// exactly "the next asset or download endpoint added here".
///
/// Bytes rather than an [`Answer`], because an [`Answer`] carries its body as
/// text and a lossy decode of an archive would hash to something the release
/// never published. A non-200 status travels with the (empty or error) body so
/// the caller decides; it is never read as the asset.
///
/// Under [`FIXTURE`] the canned response's body is served as the bytes, so a
/// suite's assets are text files it wrote — which is all a hash needs.
#[must_use]
pub fn download(path: &str) -> Option<(u16, Vec<u8>)> {
    let url = format!("{API}/{path}");
    if let Some(dir) = std::env::var_os(FIXTURE) {
        let answer = from_fixture(
            std::path::Path::new(&dir),
            &Request {
                method: "GET",
                url: &url,
                body: None,
            },
            None,
            crate::now_unix(),
        )?;
        return Some((answer.status, answer.body.into_bytes()));
    }
    let mut headers = headers(None, false);
    for (name, value) in &mut headers {
        if name.eq_ignore_ascii_case("accept") {
            *value = String::from("application/octet-stream");
        }
    }
    let response = fetch::get(&url, &headers).ok()?;
    Some((response.status, response.body))
}

/// One PATCH carrying a JSON body — [`post_json`]'s twin for an update the forge
/// takes only as a `PATCH`, such as rewriting a pull request's body (CLOUD-1924).
#[must_use]
pub fn patch_json(path: &str, body: &serde_json::Value) -> Option<Answer> {
    let encoded = serde_json::to_vec(body).ok()?;
    exchange(path, None, Some(&encoded), true)
}

/// Where a SUITE may put canned responses instead of the forge.
///
/// **A test seam, and it is here because retiring a spawn retired a tier.** The
/// suites over `pr watch` and its siblings drove the engine by putting a stubbed
/// `gh` on `PATH`: the program was the seam, so a case could hand the poll a
/// `304`, a rate-limit header or a green body and count the calls. Moving the
/// read in-process removed that seam and left those cases with no way to answer,
/// so `pr watch`'s unbounded loop polled a forge it could not reach — measured at
/// 46 minutes on two cases before the run was killed.
///
/// The alternative was to leave the spawn, and that is the wrong trade: a
/// compiled-binary tier is what proves the ENGINE builds what the caller reads,
/// and losing it is exactly the class `.claude/rules/policy-modules.md` names.
/// So the seam moves to the boundary the read moved to.
///
/// **`LEASE_FROM_REF`'s standing, in the same words**: overridable only so the
/// suite can point it at a fixture. It is read once, here, at the one exchange
/// every verb in this module goes through — so there is no second route and
/// nothing a consumer gains by setting it except responses they wrote
/// themselves.
const FIXTURE: &str = "BATTEN_REST_FIXTURE";

/// One request as the fixture seam sees it.
struct Request<'a> {
    method: &'a str,
    url: &'a str,
    body: Option<&'a [u8]>,
}

/// Serve one response from the fixture directory, counting the call.
///
/// The protocol is the stubbed program's, conserved exactly so the cases that
/// read it back need no rewrite: `resp.<n>` for the n-th call and `resp.last`
/// once they run out, the count in `calls`, and the request appended to `args`.
///
/// **ROUTED BY ENDPOINT WHERE THE FIXTURE SAYS SO** (CLOUD-1924). A lane that
/// asks several endpoints answers by WHICH endpoint, not by call order, which is
/// what its retired `gh` stub dispatched on. A `routes` file holds
/// `<needle>\t<file>` lines; the first needle contained in `<METHOD> <url>`
/// answers from `<file>`, and a request body is kept beside it as
/// `<file>.request` so a case asserts what the forge was ASKED to store. No
/// `routes` file, or no line matching, falls through to the call-order protocol.
fn from_fixture(
    dir: &std::path::Path,
    request: &Request<'_>,
    etag: Option<&str>,
    now: u64,
) -> Option<Answer> {
    let url = request.url;
    if let Ok(routes) = std::fs::read_to_string(dir.join("routes")) {
        let line = format!("{} {url}", request.method);
        let routed = routes.lines().find_map(|route| {
            let (needle, file) = route.split_once('\t')?;
            line.contains(needle).then(|| file.trim().to_owned())
        });
        if let Some(file) = routed {
            let _ = crate::durable::append(&dir.join("args"), &line);
            if let Some(body) = request.body {
                let _ = crate::durable::replace(dir.join(format!("{file}.request")), body);
            }
            let raw = std::fs::read_to_string(dir.join(&file)).ok()?;
            return Some(canned(&raw, now));
        }
    }
    let calls = dir.join("calls");
    let n = std::fs::read_to_string(&calls)
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .unwrap_or(0)
        + 1;
    let _ = crate::durable::replace(&calls, format!("{n}\n"));
    {
        // THE VALIDATOR IS PART OF THE REQUEST A CASE READS BACK. The stubbed
        // program recorded its whole argv, so `-H "If-None-Match: …"` was
        // visible and the 304 case asserts on it — the conditional poll IS the
        // economy, so a fixture that hid it would let the header go away
        // silently. Written in the client's own spelling, which is what keeps
        // that assertion's bytes unchanged.
        match etag {
            Some(etag) => {
                let _ = crate::durable::append(
                    &dir.join("args"),
                    &format!("{url} -H If-None-Match: {etag}"),
                );
            }
            None => {
                let _ = crate::durable::append(&dir.join("args"), url);
            }
        }
    }
    let raw = std::fs::read_to_string(dir.join(format!("resp.{n}")))
        .or_else(|_| std::fs::read_to_string(dir.join("resp.last")))
        .ok()?;
    Some(canned(&raw, now))
}

/// One `-i`-style response text, as an [`Answer`].
///
/// The fixtures are written in the shape the forge's own client printed, which
/// is what lets a case that predates this seam keep its bytes.
fn canned(raw: &str, now: u64) -> Answer {
    let clean = raw.replace('\r', "");
    let (head, body) = clean.split_once("\n\n").unwrap_or((clean.as_str(), ""));
    let mut lines = head.split('\n');
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let header = |name: &str| {
        lines.clone().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim().eq_ignore_ascii_case(name)).then(|| value.trim().to_owned())
        })
    };
    // THE WHOLE BLOCK, lowercased, so a fixture answers `header` exactly as a
    // live exchange does. A fixture that carried fewer headers than the wire
    // would make the one caller reading an arbitrary header untestable offline,
    // which is the shape of a gate that is only exercised in production.
    let headers = lines
        .clone()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    Answer {
        status,
        headers,
        etag: header("etag"),
        poll_floor: header("x-poll-interval")
            .and_then(|raw| raw.trim().parse::<f64>().ok())
            .filter(|seconds| seconds.is_finite() && *seconds > 0.0),
        backoff: backoff_of(header, now),
        body: body.to_owned(),
    }
}

fn exchange(path: &str, etag: Option<&str>, body: Option<&[u8]>, patching: bool) -> Option<Answer> {
    let now = crate::now_unix();
    let url = format!("{API}/{path}");
    if let Some(dir) = std::env::var_os(FIXTURE) {
        let method = match body {
            Some(_) if patching => "PATCH",
            Some(_) => "POST",
            None => "GET",
        };
        return from_fixture(
            std::path::Path::new(&dir),
            &Request {
                method,
                url: &url,
                body,
            },
            etag,
            now,
        );
    }
    let headers = headers(etag, body.is_some_and(|bytes| !bytes.is_empty()));
    let mut answers = fetch::spend(&[Call {
        url: &url,
        headers: &headers,
        body,
        patch: patching,
        // PROXIED, which is the ordinary path. `direct` exists so a credential
        // can be proved against the forge with the proxy out of the way
        // (`fetch::get_direct`); a forge REST call is not that question, and
        // taking the direct route here would bypass the egress fence for every
        // read this module makes.
        direct: false,
    }])
    .ok()?;
    // ONE call in, one answer out. `spend` returns them in the order given and
    // stops at the first failure, so a non-empty vector here is this call's.
    let response = answers.pop()?;
    Some(Answer {
        status: response.status,
        // ALREADY LOWERCASE off `fetch::Response`; re-folding costs nothing and
        // keeps this side's invariant stated where the map is built.
        headers: response
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect(),
        etag: response.header("etag").map(str::to_owned),
        // LOWERCASE, because `fetch::Response` lowercases every name it read.
        // Matching `X-Poll-Interval` here would find nothing and read as *the
        // server asked for no floor* — the exact three-valued mistake CLOUD-390
        // records, arriving by a different route.
        poll_floor: response
            .header("x-poll-interval")
            .and_then(|raw| raw.trim().parse::<f64>().ok())
            .filter(|seconds| seconds.is_finite() && *seconds > 0.0),
        backoff: backoff_from(&response, now),
        body: String::from_utf8_lossy(&response.body).into_owned(),
    })
}

/// The longest backoff this tier will honour, in seconds.
///
/// **A CEILING ON THE FORGE'S OWN NUMBER, which `MAX_FLOOR` deliberately is
/// not.** That one bounds `X-Poll-Interval` — a cadence — and its doc says so;
/// putting a backoff through it would truncate a genuine rate-limit wait into a
/// retry loop against the refusal that caused it. But unbounded is not the other
/// option: `Retry-After` is a number off the wire and a reset instant is a
/// subtraction, so both can arrive absurd, and the consumer is a `thread::sleep`
/// inside a loop with no wall clock of its own.
///
/// One hour, which is longer than any window this forge resets on, so it clamps
/// nothing a healthy exchange produces — and a landing that has waited an hour
/// has a caller who wants to hear about it rather than a process that should
/// still be asleep.
const MAX_BACKOFF: u64 = 3600;

/// The backoff a response asks for, in seconds, or `None`.
///
/// **`now` is the CALLER'S instant rather than a clock read here**, which is the
/// rule `.claude/rules/policy-modules.md` states for every other comparison in
/// this crate: the clock belongs to the boundary, so one exchange yields one
/// answer whoever asks and whenever they ask again.
fn backoff_from(response: &fetch::Response, now: u64) -> Option<u64> {
    backoff_of(|name| response.header(name).map(str::to_owned), now)
}

/// The backoff a response states, over a header accessor rather than a response.
///
/// **ONE READER FOR BOTH PATHS, and this module's header names the class the
/// split belonged to: two readings of one header block.** The fixture seam
/// parsed `Retry-After` alone, so a fixture stating the RATE-LIMIT headers
/// yielded `backoff: None` — and a case asserting rate-limit backoff passed
/// without exercising the behaviour, which is coverage that has stopped testing
/// the thing it names. Found in review.
fn backoff_of(header: impl Fn(&str) -> Option<String>, now: u64) -> Option<u64> {
    // `Retry-After` FIRST, because a forge that states one has stated it about
    // this exact refusal. The reset instant below is a property of the window.
    if let Some(seconds) = header("retry-after")
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
    {
        return Some(seconds.min(MAX_BACKOFF));
    }
    // ONLY AT ZERO REMAINING. The reset instant rides every response, so reading
    // it unconditionally would back off after each successful call.
    if header("x-ratelimit-remaining").and_then(|raw| raw.trim().parse::<u64>().ok()) != Some(0) {
        return None;
    }
    // **A CLOCK THAT DID NOT READ IS NOT AN INSTANT** (review of #848).
    // `now_unix` answers `0` when `SystemTime::now` fails, and `0` passes the
    // `reset > now` filter — so the subtraction yielded the raw absolute epoch,
    // about 1.79e9 seconds, and `pr_watch::wait_for` deliberately does not clamp
    // a backoff. One failed clock read therefore put a loop this crate documents
    // as unbounded to sleep for roughly fifty-seven years, holding the landing
    // lease and looking exactly like a slow bot.
    if now == 0 {
        return None;
    }
    header("x-ratelimit-reset")
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|reset| *reset > now)
        .map(|reset| (reset - now).min(MAX_BACKOFF))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A REFUSAL IS AN ANSWER THAT ARRIVED, AND IT IS NOT A READING.**
    ///
    /// `get` answers `Some` for every completed exchange, so a `401`, a `403` and
    /// a `5xx` all reach a caller carrying an error document where a collection
    /// was expected. A caller reading the body alone parses that as EMPTY, which
    /// is indistinguishable from a genuinely empty collection — the defect
    /// measured on the lap's ready step, where it re-drafted a pull request over
    /// a forge blip.
    ///
    /// The `200` arm is what keeps this from being satisfied by a predicate that
    /// refuses everything, and the `304` arm pins the deliberate exclusion rather
    /// than leaving it to be re-argued: a one-shot read holds no cache, so
    /// not-modified answers a question it never asked.
    #[test]
    fn only_a_two_hundred_carries_a_reading() {
        let with = |status: u16| Answer {
            headers: std::collections::BTreeMap::new(),
            status,
            etag: None,
            poll_floor: None,
            backoff: None,
            body: String::new(),
        };
        assert!(with(200).is_reading());
        for status in [304, 401, 403, 404, 422, 500, 502] {
            assert!(
                !with(status).is_reading(),
                "{status} is the forge declining, not a reading"
            );
        }
    }

    /// Every endpoint a caller hands over is API-relative.
    ///
    /// A leading slash produces a double one and a `404`, which every caller here
    /// reads as could-not-look — silent, and exactly the dead-gate class this
    /// crate exists to refuse.
    #[test]
    fn an_api_relative_path_keeps_the_forge_clients_own_spelling() {
        for path in [
            "repos/{owner}/{repo}/git/ref/heads/main",
            "repos/o/r/actions/runs/7/cancel",
            "repos/o/r/issues/42/comments",
        ] {
            assert!(
                !path.starts_with('/'),
                "API-relative, never rooted: {path:?}"
            );
            assert!(
                format!("{API}/{path}").starts_with("https://"),
                "and HTTPS, which the connector enforces anyway"
            );
        }
    }

    /// **The names come from the consumer, and naming none yields none**
    /// (CLOUD-1622).
    ///
    /// Driven through [`pick`] with the environment handed in, which is what makes
    /// the rule testable without mutating the process: this crate forbids
    /// `unsafe`, and `set_var` is unsafe. The arm that matters is the one with no
    /// fallback — an undeclared forge must yield `None`, never the pair the engine
    /// used to carry, because a fallback is precisely how this seam stayed
    /// invisible.
    #[test]
    fn an_undeclared_forge_yields_no_credential_rather_than_a_default() {
        let env = |name: &str| match name {
            "TOKEN" => Some(String::from("t0ken")),
            "EMPTY" => Some(String::new()),
            _ => None,
        };

        assert_eq!(
            credential(None),
            None,
            "no declaration is could-not-look, never the engine's old spellings"
        );
        assert_eq!(
            pick(
                &Forge {
                    credential_names: Vec::new(),
                    query: Vec::new(),
                    probe: Vec::new(),
                },
                env
            ),
            None,
            "and naming no variable is the same answer, said out loud"
        );
        assert_eq!(
            pick(
                &Forge {
                    credential_names: vec![String::from("TOKEN")],
                    query: Vec::new(),
                    probe: Vec::new(),
                },
                env
            ),
            Some(String::from("t0ken")),
            "a declared name is read — without this the case above is satisfied \
             by a reader that always answers None"
        );
        // AND THE ENGINE'S OLD SPELLINGS ARE NOT SPECIAL ANY MORE, which is the
        // whole seam: a consumer who does not name them gets nothing from them.
        assert_eq!(
            pick(
                &Forge {
                    credential_names: vec![String::from("TOKEN")],
                    query: Vec::new(),
                    probe: Vec::new(),
                },
                |name| if name == "GH_TOKEN" {
                    Some(String::from("leaked"))
                } else {
                    env(name)
                }
            ),
            Some(String::from("t0ken")),
            "an undeclared variable must not be consulted, however conventional"
        );

        // THE EMPTINESS RULE SURVIVED THE MOVE. An exported-but-empty variable
        // falls THROUGH to the next name rather than committing to the first that
        // exists — the defect review of #848 found, re-asserted here because the
        // list is the consumer's now and a consumer will order it that way.
        assert_eq!(
            pick(
                &Forge {
                    credential_names: vec![String::from("EMPTY"), String::from("TOKEN")],
                    query: Vec::new(),
                    probe: Vec::new(),
                },
                env
            ),
            Some(String::from("t0ken")),
            "an empty first name must not shadow a good second one"
        );
    }

    /// The conditional header is attached only when there is a validator.
    ///
    /// **Asserted on the header LIST rather than on a request**, because building
    /// a request would dial. What this pins is the shape a `304` depends on: an
    /// unconditional poll had to stay slow to stay affordable, so a validator
    /// that never reaches the wire makes the news arrive late.
    #[test]
    fn the_validator_is_attached_only_when_one_was_read() {
        let first = headers(None, false);
        assert!(
            !first.iter().any(|(name, _)| name == "If-None-Match"),
            "nothing to validate against yet: {first:?}"
        );

        let second = headers(Some("W/\"a\""), false);
        assert!(
            second
                .iter()
                .any(|(name, value)| name == "If-None-Match" && value == "W/\"a\""),
            "a 304 is what makes a one-second poll affordable: {second:?}"
        );
    }

    /// A body-bearing call declares its content type and a bodyless one does not.
    ///
    /// The anti-vacuity half matters as much: sending `Content-Type` on a GET is
    /// how a caller learns the header builder ignores its argument.
    #[test]
    fn a_json_body_declares_its_type_and_a_bodyless_call_does_not() {
        assert!(
            headers(None, true)
                .iter()
                .any(|(name, value)| name == "Content-Type" && value == "application/json"),
        );
        assert!(
            !headers(None, false)
                .iter()
                .any(|(name, _)| name == "Content-Type"),
        );
    }

    /// **The credential never reaches a value a caller can print.**
    ///
    /// Non-negotiable rule 4 lands here as a TYPE property rather than as a habit
    /// at each call site: [`Answer`] has no credential field, so no `Debug` of
    /// anything this module returns can carry one.
    #[test]
    fn no_value_this_module_returns_can_carry_the_credential() {
        let answer = Answer {
            headers: std::collections::BTreeMap::new(),
            status: 200,
            etag: Some(String::from("W/\"a\"")),
            poll_floor: Some(2.5),
            backoff: Some(60),
            body: String::from("{}"),
        };
        let rendered = format!("{answer:?}");
        assert!(
            !rendered.contains("Bearer"),
            "the token is not a field and cannot be one: {rendered}"
        );
    }

    fn answered(headers: &[(&str, &str)]) -> fetch::Response {
        fetch::Response {
            status: 200,
            body: Vec::new(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    /// **THE HEADER THE POLL FLOOR IS NOT.** `X-Poll-Interval` says how often to
    /// ask; `Retry-After` says stop asking. The predecessor's loop honoured only
    /// the first, so being rate-limited made it generate more of exactly the
    /// request that had just been refused.
    #[test]
    fn a_stated_retry_after_is_the_backoff_and_wins_over_the_reset() {
        let response = answered(&[
            ("retry-after", "45"),
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", "9000"),
        ]);
        assert_eq!(
            backoff_from(&response, 1000),
            Some(45),
            "a forge stating one has stated it about THIS refusal"
        );
    }

    /// The reset instant answers only once the window is actually spent.
    ///
    /// **The anti-vacuity half is the load-bearing one**: the reset rides every
    /// response, so a reader that did not check `remaining` would back off after
    /// each successful call and turn a healthy poll into a stall.
    #[test]
    fn the_reset_answers_at_zero_remaining_and_never_otherwise() {
        let spent = answered(&[
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", "1060"),
        ]);
        assert_eq!(backoff_from(&spent, 1000), Some(60));

        let healthy = answered(&[
            ("x-ratelimit-remaining", "4999"),
            ("x-ratelimit-reset", "1060"),
        ]);
        assert_eq!(
            backoff_from(&healthy, 1000),
            None,
            "a reset instant is not a backoff while requests remain"
        );
    }

    /// A response stating nothing asks for nothing, and a reset already past is
    /// not a wait.
    #[test]
    fn a_silent_response_and_a_lapsed_reset_both_ask_for_no_backoff() {
        assert_eq!(backoff_from(&answered(&[]), 1000), None);
        assert_eq!(
            backoff_from(
                &answered(&[("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "900")]),
                1000
            ),
            None,
            "the window already reopened"
        );
    }
}
