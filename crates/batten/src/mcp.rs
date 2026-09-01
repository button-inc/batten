//! Dispatch a declared MCP call and hand back a reduction (CLOUD-1260).
//!
//! # Why the engine dispatches at all
//!
//! Measured over one session's own transcript on 2026-08-31: 43.5 MB of tool
//! content, of which tracker round trips were 13.2 MB — **73% of all tool
//! output**, across 973 calls against 208 rows. Bash, Grep and Read together
//! were 1.9 MB. Reading the tree is nearly free; the connector was the entire
//! cost. A whole document moved every time to convey a delta of a couple of
//! kilobytes, which is non-negotiable rule 4 — *output is a pointer, never the
//! payload* — unenforced at the tool boundary.
//!
//! The connector never has to offer a projection. MCP is JSON-RPC 2.0, so Batten
//! can be the **client**: dispatch the request itself, own the response, store it
//! whole, and return a shape the connector does not ship.
//!
//! **This is a client and never a server.** CLOUD-204 declined shipping an MCP
//! server and that record is untouched — it is the opposite direction.
//!
//! # Everything a tracker knows is the consumer's
//!
//! The crate knows exactly two verbs: *dispatch a declared method* and *reduce by
//! a declared projection*. Every identifier that names a tracker — the server id,
//! the method names, the field sets, which reduction each method takes, and where
//! a harness keeps its wiring — is a row in the consumer's `batten.toml`, because
//! a tracker's vocabulary inside `crates/batten` is non-negotiable rule 1's
//! violation. A grep of this crate for a method name, a config filename or a
//! launcher path returns nothing, and that is an acceptance test rather than a
//! habit.
//!
//! Where the wiring lives is **declared, never scanned**, on
//! [`crate::facts::Rooted`]'s own terms: a `root` is the NAME of an environment
//! variable and the engine expands a variable rather than walking a filesystem.
//!
//! # What that bound costs, and the one install it excludes (CLOUD-1251)
//!
//! A path a row cannot name is a server this cannot reach. Every install whose
//! config location can be written down is covered; a Claude Code **remote**
//! session is not, because its launcher mints the file per session — the path is
//! a glob, the match count is not one, and the id a declaration would need cannot
//! be authored for a name that does not yet exist.
//!
//! **The recorded decision is to keep the bound**: a producer resolves such a set
//! outside the engine and a module reads what was written, rather than this
//! family growing a glob. What that does NOT do is unblock dispatch, and the
//! reason is structural rather than a matter of effort — [`crate::facts::Sourced`]
//! states that no byte of a producer's buffer reaches its record, because
//! `rows_in` reduces it to a COUNT at the boundary. A count answers a module
//! deciding a predicate and cannot carry an endpoint and headers, which is what
//! dispatch needs. So the remote case is a known gap with a stated cause, and
//! `batten.toml`'s own `[mcp]` section carries the decision beside the rows it
//! bounds.
//!
//! # The invariant, in its true form
//!
//! **The model has no unreduced route to the payload BY DEFAULT.** The strong
//! form — *no unreduced route* — is false, and it is Batten that falsifies it:
//! `capture show --raw` writes the selected bytes to stdout verbatim, and
//! `--lines`/`--bytes`/`--grep` select from the same store. That route stays,
//! because a deliberate, single-purpose, visible retrieval is not the failure
//! mode; 973 reflexive full-body reads are. What follows is an obligation rather
//! than a caveat, and [`crate::capture::record_escape`] is where it is paid: a
//! spent `--raw` is a **record**, the way an override is a record and never a
//! variable somebody knows.
//!
//! # Three answers, kept apart
//!
//! * **the method is declared** — dispatch, store, and emit the reduction;
//! * **the method is UNDECLARED** — dispatch, store, and emit the response whole.
//!   Byte-identical to no-Batten, which is what keeps the reducer from being a
//!   silent filter (CLOUD-418's mirror);
//! * **no declared source resolves, or one resolves and will not read** — nothing
//!   is dispatched and the run says which, loudly. A reducer that silently
//!   truncated would be a correctness disaster rather than a saving.

use std::path::Path;

use crate::Result;
use crate::error::UsageError;
use crate::facts::{Format, Look, Node, TOKEN_MAX};

/// The `[mcp]` table: where the wiring lives, and what to return instead of a
/// payload.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    /// Where a harness keeps its MCP wiring, in precedence order.
    ///
    /// A LIST rather than one row because one repository is worked in from
    /// several harnesses, and each keeps its wiring somewhere else. The first row
    /// that resolves a server wins, so the order is a statement about which
    /// harness to believe when two are installed.
    #[serde(default, rename = "source", skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<Source>,
    /// What to return instead of a method's full response.
    ///
    /// A method with no row here is dispatched and returned whole.
    #[serde(default, rename = "result", skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<ResultRow>,
}

/// One `[[mcp.source]]` row: a file that carries a server's transport, endpoint
/// and headers.
///
/// The shape is [`crate::facts::Rooted`]'s deliberately — same three-part bound,
/// same reason — with a `node` because a wiring file holds every server the
/// harness knows and the row has to say which subtree is the server map.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// The key this source is named by in a report.
    ///
    /// The id and never the resolved path: a resolved path is a machine's home
    /// directory, and non-negotiable rule 4 keeps one out of every finding.
    pub id: String,
    /// The NAME of the environment variable holding the directory `path`
    /// resolves beneath, or absent for a path relative to the repository root.
    ///
    /// A name, never a value, and never a directory this crate knows. Unset or
    /// empty on this machine is could-not-look, never an absent file: "this host
    /// does not have that root" and "the file is not there" are different
    /// answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// A base this crate knows how to name without an operator's help.
    ///
    /// Mutually exclusive with `root`, and refused at load if both appear. Absent
    /// with `root` absent is the repository root, exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Base>,
    /// The path beneath that root.
    ///
    /// Relative and downward — an absolute path or a `..` component is refused at
    /// load, so a declaration cannot walk back out of the root it named.
    ///
    /// # `${VAR}` expands, and that is what makes a per-session file nameable
    ///
    /// A launcher that mints its wiring per session writes it under a name
    /// carrying the session id, so the FILENAME is not writable in advance even
    /// where the directory is. A row spells the id where it appears:
    ///
    /// ```text
    /// path = "mcp-config-${CLAUDE_CODE_REMOTE_SESSION_ID}.json"
    /// ```
    ///
    /// **Expansion is not a glob, and the difference is the whole reason this is
    /// allowed where a glob was declined (CLOUD-1251).** A glob's three fatal
    /// objections were that the match count is not one, that the engine would have
    /// to walk a filesystem, and that a row's id cannot be authored for a name
    /// that does not exist yet. Expansion has none of them: the result is exactly
    /// one path, the engine expands a variable rather than looking around, and the
    /// id is the row's own. `[[rule.external]]`'s discipline is unchanged — *the
    /// engine expands a variable; it does not scan*.
    ///
    /// Only `${NAME}` is a placeholder. A bare `$NAME` is a literal, because a
    /// path is allowed to contain a `$` and guessing where such a name ends is how
    /// one spelling becomes two.
    pub path: String,
    /// Where the server map sits inside the parsed document, in [`Node::at`]'s
    /// spelling. An empty string is the document itself.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node: String,
    /// The credential this source's servers authenticate with, if they need one.
    ///
    /// **Absent is the default and it is byte-identical to no credential at all**
    /// — a wiring file whose headers already authenticate needs nothing here, and
    /// adding this key must not change what such a source does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<Credential>,
}

/// A directory the crate can name on its own, for a source whose file does not
/// live under the repository or under a directory an operator exports.
///
/// A closed set of ONE, deliberately. Every member has to be a location the
/// platform itself defines, because the alternative is this crate learning a
/// harness's layout — non-negotiable rule 1's violation — and because a member
/// nobody can predict is a scan wearing an enum's clothes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Base {
    /// The OS temporary directory, as the platform defines it.
    ///
    /// **Named rather than spelled `/tmp`**, which is what keeps it portable and
    /// keeps a literal path out of a config. It is where a launcher that mints a
    /// per-session file puts it, and the one location an operator has no variable
    /// for — `TMPDIR` is unset on a great many hosts, so a row naming it as a
    /// `root` silently does not resolve there.
    Temp,
}

/// One `[mcp.source.credential]` table: WHICH credential a source spends, never
/// the credential (CLOUD-1261).
///
/// # The whole point is the indirection
///
/// `batten.toml` is committed, so a value here would be a secret in git. What a
/// row carries is a **name**: the name of an environment variable, or the name of
/// an environment variable whose value is a path. That is `[[rule.external]]`'s
/// root discipline applied to key material — *the engine expands a variable; it
/// does not scan* — and it is what lets a public config say "this server needs
/// the operator's token" without saying what the token is.
///
/// # Every resolved value is a [`Secret`], which has no route to a `String`
///
/// The negative half is the load-bearing one, so it is enforced by type rather
/// than by remembering to redact: [`Secret`] has no `Display`, its `Debug` prints
/// a fixed marker, and the only thing that consumes it is the header list handed
/// to the transport. A failure path cannot render it because there is no method
/// that would.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    /// The header the credential is sent in.
    ///
    /// Declared rather than assumed: `Authorization` is the common answer and the
    /// default, but a session-scoped endpoint may want its own name, and guessing
    /// one produces a 401 that says nothing about why.
    #[serde(default = "authorization")]
    pub header: String,
    /// The scheme prefixed to the value, space-separated. Empty sends the value
    /// alone, which is what a bare token header wants.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scheme: String,
    /// The NAME of an environment variable holding the credential itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// The NAME of an environment variable holding the PATH of a file that holds
    /// the credential.
    ///
    /// The two-hop spelling is deliberate and it is the one a harness actually
    /// offers: a launcher that mints a per-session token writes it to a file and
    /// exports the path, so the path is not writable in advance while the variable
    /// name is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_from: Option<String>,
}

/// The default header a credential is sent in.
fn authorization() -> String {
    "Authorization".to_owned()
}

impl Credential {
    /// The header name and finished value this row sends a resolved value as.
    ///
    /// **A method rather than a closure inside [`credential`]**, so the scheme
    /// folding can be tested without an environment variable: the workspace
    /// forbids `unsafe`, `std::env::set_var` is `unsafe`, and a test that cannot
    /// arrange its own premise ends up asserting the resolution path instead of
    /// the formatting one it means to.
    fn sent(&self, value: &str) -> (String, Secret) {
        (
            self.header.clone(),
            Secret(if self.scheme.is_empty() {
                value.to_owned()
            } else {
                format!("{} {value}", self.scheme)
            }),
        )
    }
}

/// A resolved credential, with no route back to a string.
///
/// [`crate::identity::SecretSpan`]'s shape and for its reason: containment that
/// holds on the failure paths has to be structural, because a redaction somebody
/// has to remember is a redaction that ships working and leaks the first time an
/// error formats something new.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl std::fmt::Debug for Secret {
    /// A fixed marker, so a `{:?}` anywhere — a log line, a panic, a derived
    /// `Debug` on a struct that happens to hold one — cannot print the value.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Secret(<redacted>)")
    }
}

impl Secret {
    /// The finished header value, scheme already folded in.
    ///
    /// The **one** route out, and it goes straight into the transport's header
    /// list. There is deliberately no `as_str`, no `Display` and no `into_inner`:
    /// a caller that wanted the bytes for any other purpose would have to add one,
    /// which is a reviewable change rather than an accident. Named `spend` for the
    /// same reason the row is — this is the verb CLOUD-1261 says the engine lacked.
    fn spend(&self) -> String {
        self.0.clone()
    }
}

/// Resolve a source's credential, if it declares one.
///
/// # The three answers stay apart
///
/// * **no `[mcp.source.credential]`** — `Ok(None)`, and the dispatch is
///   byte-identical to one from before this key existed;
/// * **declared and resolvable** — `Ok(Some(secret))`;
/// * **declared and NOT resolvable** — an error, never a silent unauthenticated
///   call. A call sent without the credential its row demands gets a 401 that
///   reads like the server's fault, which is the wrong bug to hand somebody.
///
/// # Errors
///
/// An internal error (→ exit `3`) when the named variable is unset or empty, or
/// when the file it names will not read. **Every message names the VARIABLE and
/// the source id and nothing else** — never the path it expanded to, which is a
/// machine's home directory, and never a byte of the value.
fn credential(source: &Source) -> Result<Option<(String, Secret)>> {
    let Some(row) = &source.credential else {
        return Ok(None);
    };
    let id = &source.id;
    if let Some(name) = &row.env {
        let value = std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "mcp: source {id} declares a credential in {name}, and {name} is unset or empty"
                )
            })?;
        return Ok(Some(row.sent(&value)));
    }
    let name = row.file_from.as_ref().ok_or_else(|| {
        anyhow::anyhow!("mcp: source {id} declares a credential naming neither env nor file_from")
    })?;
    let at = std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "mcp: source {id} declares a credential file named by {name}, and {name} is unset \
                 or empty"
            )
        })?;
    // POINTER-ONLY IN THE REFUSAL: the io error carries the path it tried, which
    // is an absolute path on somebody's machine, so it is dropped rather than
    // formatted. What a reader needs is which variable to fix.
    let value = std::fs::read_to_string(std::path::PathBuf::from(at))
        .map_err(|_| {
            anyhow::anyhow!("mcp: source {id}'s credential file, named by {name}, will not read")
        })?
        .trim()
        .to_owned();
    if value.is_empty() {
        return Err(anyhow::anyhow!(
            "mcp: source {id}'s credential file, named by {name}, is empty"
        ));
    }
    Ok(Some(row.sent(&value)))
}

/// One `[[mcp.result]]` row: what to hand back instead of a method's response.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ResultRow {
    /// The method this row reduces. The consumer's vocabulary, matched exactly.
    pub method: String,
    /// What to make of the response.
    pub reduce: Reduce,
    /// The fields kept, in the order they are written.
    ///
    /// Top-level keys of the payload the row's `node` reaches. A declared field
    /// the payload does not carry is ABSENT from the reduction rather than
    /// present and null: "the row does not have this" and "the reduction dropped
    /// it" are different answers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// Where the payload sits inside the JSON-RPC result, in [`Node::at`]'s
    /// spelling. An empty string is the result itself.
    ///
    /// Declared rather than known, because how a server frames a payload is the
    /// server's business and this crate holds no opinion about it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node: String,
    /// Whether the node's scalar text is itself a document to parse.
    ///
    /// A server that frames its payload as text carrying JSON is common and is
    /// not something the engine may assume: a row says so, and a row that says so
    /// wrongly gets could-not-look rather than a reduction over the wrong tree.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub embedded: bool,
}

/// How a [`ResultRow`] turns a response into something rule 4 permits.
///
/// A closed set rather than an expression language, for
/// [`crate::facts::Reduction`]'s reason exactly: every member is bounded by
/// construction, so no row can declare a reduction that yields the payload back.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Reduce {
    /// The declared fields, with their values passed through as the payload
    /// carries them.
    ///
    /// The read-side answer. What bounds it is the DECLARATION — a field nobody
    /// named never leaves the store — so a consumer choosing its own field set is
    /// choosing its own cost.
    Project,
    /// The declared fields, each held to a bounded SCALAR.
    ///
    /// The write-side answer (CLOUD-1122), and it differs from [`Reduce::Project`]
    /// in KIND rather than in degree: a field whose value runs past [`TOKEN_MAX`],
    /// or is a container rather than a scalar, is **absent** rather than
    /// truncated, because a prefix of somebody's issue body is still their issue
    /// body. So this arm structurally cannot echo a body however the row is
    /// written, where `project` leaves that to the declaration.
    ///
    /// # Why the bound is length and not [`crate::facts::Reduction::Token`]'s
    ///
    /// That reduction additionally refuses any value carrying whitespace, and it
    /// is right to: its product reaches the POLICY INPUT, where a module could
    /// lift a sentence into a `subjects` pointer, so "is this already a token"
    /// is the question worth asking. This arm's product reaches the CALLER, and
    /// the thing being kept out is a 15k-character description — which the length
    /// bound stops on its own.
    ///
    /// Copying the whitespace clause across was this row's own near-miss,
    /// measured before it shipped: `save_issue` answers `status = "In Progress"`,
    /// so the arm would have silently dropped the one field CLOUD-1122 names in
    /// its remedy — `{id, status, handle}` — while every test still passed. A
    /// bound borrowed from a surface with a different threat model is how a
    /// reduction quietly stops answering the question it was built for.
    Acknowledge,
}

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
fn validate_credential(source: &Source) -> Result<()> {
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
    match (&row.env, &row.file_from) {
        (None, None) => Err(UsageError::raise(format!(
            "mcp: source {id:?} declares a credential naming neither `env` nor `file_from`; a row \
             that names no variable resolves to nothing and would dispatch unauthenticated"
        ))),
        (Some(_), Some(_)) => Err(UsageError::raise(format!(
            "mcp: source {id:?} declares a credential naming both `env` and `file_from`; one row \
             names one variable, or which one the engine spends depends on the order it reads them"
        ))),
        (Some(name), None) | (None, Some(name)) if name.trim().is_empty() => {
            Err(UsageError::raise(format!(
                "mcp: source {id:?} declares a credential naming an empty variable; it is the NAME \
                 of an environment variable, never a value"
            )))
        }
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
        validate_credential(source)?;
        seen.push(&source.id);
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

/// Expand every `${NAME}` in `path` from the environment.
///
/// # Why an unset variable is `None` rather than an empty string
///
/// Substituting empty would turn `mcp-config-${ID}.json` into `mcp-config-.json`
/// — a real path, almost certainly somebody else's, and one the engine would then
/// report as an absent file. "This host does not set that variable" and "the file
/// is not there" are different answers, and this is the same three-valued read the
/// `root` key already keeps apart.
///
/// # Errors
///
/// A malformed placeholder — an unclosed `${`, or a name that is not
/// `[A-Za-z_][A-Za-z0-9_]*` — is a [`UsageError`] (→ exit `1`). It is the
/// caller's typo, and reading it as a literal would resolve a path nobody wrote.
fn expand(path: &str) -> Result<Option<String>> {
    let mut out = String::with_capacity(path.len());
    for part in parts(path)? {
        match part {
            Part::Literal(text) => out.push_str(text),
            Part::Variable(name) => {
                match std::env::var(name).ok().filter(|value| !value.is_empty()) {
                    Some(value) => out.push_str(&value),
                    None => return Ok(None),
                }
            }
        }
    }
    Ok(Some(out))
}

/// One piece of a declared path: text as written, or a variable to expand.
enum Part<'a> {
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
fn placeholders(path: &str) -> Result<()> {
    parts(path).map(|_| ())
}

/// Split a declared path into literals and `${NAME}` placeholders.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for an unclosed `${`, or a name that is not
/// `[A-Za-z_][A-Za-z0-9_]*`. Reading either as a literal would resolve a path
/// nobody wrote, which is the failure this refuses rather than tolerates.
fn parts(path: &str) -> Result<Vec<Part<'_>>> {
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
fn escapes(path: &str) -> bool {
    Path::new(path).components().any(|part| {
        matches!(
            part,
            std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::ParentDir
        )
    })
}

/// A server's transport, endpoint and headers, as a declared source resolved
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wiring {
    /// The source row that answered, by id — never the path it resolved.
    pub source: String,
    /// Where to POST.
    pub endpoint: String,
    /// The headers to send, as the wiring file carries them.
    ///
    /// **These are ROUTING IDENTIFIERS and not, on their own, a credential — a
    /// claim this doc comment used to make the other way round, and it was
    /// wrong.** It read *"these ARE the credential … this dispatches from inside
    /// the session that minted the auth and needs none."* Measured 2026-09-01
    /// against the live endpoint, a dispatch carrying exactly these headers is
    /// answered **401**, and CLOUD-673 had already reached the same result with a
    /// different client. Whether they suffice is the SERVER's business; a source
    /// that needs more says so with a [`Credential`] row.
    pub headers: Vec<(String, String)>,
    /// The credential this source declared, already resolved: the header name it
    /// is sent under, and the value with its scheme folded in.
    ///
    /// `None` is both "no row declared one" and the state every wiring was in
    /// before CLOUD-1261 — which is why absence has to dispatch exactly as it did
    /// then.
    pub credential: Option<(String, Secret)>,
}

/// Why no wiring came back.
///
/// **Three answers, and collapsing any two of them is the vacuous pass.** A
/// launcher that wrote no config and a root this host does not set are different
/// facts about the world, and a file that exists and will not parse is a
/// different fact again — that last one is the one a caller must never read as
/// "the server is not configured".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unresolved {
    /// No `[[mcp.source]]` row is declared at all.
    Undeclared,
    /// Every declared row was looked for and none answered: the root is unset,
    /// the file is absent, or the server is not in it.
    ///
    /// Carries the ids that were tried, never the paths they resolved to.
    NotFound {
        /// The source ids consulted, in declaration order.
        tried: Vec<String>,
    },
    /// A source's file EXISTS and will not parse.
    ///
    /// Could-not-look, and the one arm that must never be reported as an absent
    /// server: a wiring file somebody is halfway through editing would otherwise
    /// read as a connector nobody configured.
    Unreadable {
        /// Which source row, by id.
        source: String,
    },
    /// A source resolved the server AND declares a credential that will not
    /// resolve.
    ///
    /// A **fourth** answer rather than a shade of `Unreadable`, because the fix is
    /// somewhere else entirely: the wiring is fine and an environment variable is
    /// not. Collapsing it into "will not parse" sends a reader to the wrong file.
    CredentialUnusable {
        /// Which source row, by id.
        source: String,
        /// Why, in [`credential`]'s own words — a variable NAME and a cause, never
        /// a path and never a byte of the value.
        why: String,
    },
    /// A source's `path` expanded to something it may not read.
    ///
    /// Either the placeholder is malformed, or a variable's VALUE carried an
    /// upward step and the expanded path left the base the row declared. Both are
    /// refusals rather than skips: a row whose path cannot be trusted must not
    /// fall through to another source's answer, and the second case is the one
    /// that would otherwise turn expansion into a file-read primitive.
    ///
    /// **Carries no path**, expanded or literal — rule 4 applies hardest to the
    /// arm whose whole subject is a path somebody controls.
    PathUnusable {
        /// Which source row, by id.
        source: String,
    },
}

impl Unresolved {
    /// The pointer a report carries for this answer: ids and a cause, never a
    /// path and never a byte of a file.
    #[must_use]
    pub fn pointer(&self) -> String {
        match self {
            Unresolved::Undeclared => {
                "no `[[mcp.source]]` row is declared, so there is nowhere to look for a server's \
                 endpoint"
                    .to_owned()
            }
            Unresolved::NotFound { tried } => format!(
                "no declared source resolves this server (tried: {})",
                tried.join(", ")
            ),
            Unresolved::Unreadable { source } => format!(
                "source {source} is present and will not parse — could-not-look, which is not the \
                 same answer as a server nobody configured"
            ),
            Unresolved::CredentialUnusable { why, .. } => why.clone(),
            Unresolved::PathUnusable { source } => format!(
                "source {source}'s `path` will not expand to a path beneath its base — a \
                 placeholder is malformed, or a variable's value carries an upward step"
            ),
        }
    }
}

/// The two keys a wiring entry is read under.
///
/// Protocol vocabulary rather than a consumer's: every MCP wiring file spells a
/// remote server's address and its headers, whatever harness wrote it. A
/// consumer's SERVER NAME is never here — that arrives as an argument.
const ENDPOINT_KEYS: &[&str] = &["url", "endpoint", "httpUrl"];

/// The key a wiring entry carries its headers under.
const HEADER_KEY: &str = "headers";

/// Resolve one server's wiring out of the declared sources.
///
/// **Declaration order decides**, and the first row that carries the server wins.
/// A row whose root is unset is skipped rather than fatal — that is the whole
/// point of declaring several: a repository worked in from two harnesses names
/// both, and each host sets one of the roots.
///
/// # Errors
///
/// Never. The three could-not-look answers are values rather than errors, because
/// the caller reports them differently and an error would collapse them into one.
pub fn wiring(
    config: &McpConfig,
    repo_root: &Path,
    server: &str,
) -> std::result::Result<Wiring, Unresolved> {
    if config.sources.is_empty() {
        return Err(Unresolved::Undeclared);
    }
    let mut tried = Vec::new();
    for source in &config.sources {
        tried.push(source.id.clone());
        let base = match (&source.base, &source.root) {
            // A BASE THE PLATFORM DEFINES, for the one directory an operator has
            // no variable for. `temp_dir` reads the platform's own answer rather
            // than this crate spelling `/tmp`, which would be wrong on Windows and
            // a literal path in a config either way.
            (Some(Base::Temp), _) => std::env::temp_dir(),
            // A ROOT THIS HOST DOES NOT SET IS NOT AN ABSENT FILE, and empty
            // counts as unset: an empty variable resolves the row against the
            // process's working directory, which is a different file on every
            // invocation.
            (None, Some(name)) => match std::env::var_os(name).filter(|value| !value.is_empty()) {
                Some(dir) => std::path::PathBuf::from(dir),
                None => continue,
            },
            (None, None) => repo_root.to_path_buf(),
        };
        // AN UNSET PLACEHOLDER IS THIS HOST NOT HAVING THE ROW'S SUBJECT, which is
        // the `root` arm's answer one level down: skip to the next source rather
        // than resolving a path nobody wrote.
        let Some(path) = expand(&source.path).map_err(|_| Unresolved::PathUnusable {
            source: source.id.clone(),
        })?
        else {
            continue;
        };
        // THE SECOND ESCAPE CHECK, over runtime input. The load-time one saw
        // `${ID}` and not what `ID` holds, so this is the one that stops a
        // variable's value from walking out of the base the row declared.
        if escapes(&path) {
            return Err(Unresolved::PathUnusable {
                source: source.id.clone(),
            });
        }
        let Ok(text) = std::fs::read_to_string(base.join(&path)) else {
            continue;
        };
        // A FILE THAT EXISTS AND WILL NOT PARSE STOPS THE SEARCH. Falling through
        // to the next source would report the next harness's answer for this
        // one's broken file, which is a wrong answer wearing a right one's shape.
        //
        // THROUGH `rules::parse_node`, the one `Format::read` call in the crate
        // (CLOUD-849): a second call site is a second error mapping, and two
        // mappings over one grammar diverge.
        let Ok(document) = crate::rules::parse_node(Format::Json, &text) else {
            return Err(Unresolved::Unreadable {
                source: source.id.clone(),
            });
        };
        let Look::Is(map) = document.at(&source.node) else {
            continue;
        };
        let Look::Is(entry) = map.at(server) else {
            continue;
        };
        let Some(endpoint) = ENDPOINT_KEYS
            .iter()
            .find_map(|key| match entry.at(key) {
                Look::Is(node) => node.scalar(),
                Look::IsNot | Look::CouldNotLook => None,
            })
            .filter(|endpoint| !endpoint.is_empty())
        else {
            continue;
        };
        return Ok(Wiring {
            source: source.id.clone(),
            endpoint,
            // A DECLARED CREDENTIAL THAT WILL NOT RESOLVE STOPS THE SEARCH, and
            // it is not `Unresolved`: the row was found, so falling through to the
            // next source would answer this server's question with another
            // harness's wiring, and dispatching without the credential would send
            // a call the row said must be authenticated.
            credential: credential(source).map_err(|err| Unresolved::CredentialUnusable {
                source: source.id.clone(),
                why: err.to_string(),
            })?,
            headers: match entry.at(HEADER_KEY) {
                Look::Is(Node::Map(entries)) => entries
                    .iter()
                    .filter_map(|(name, value)| value.scalar().map(|value| (name.clone(), value)))
                    .collect(),
                _ => Vec::new(),
            },
        });
    }
    Err(Unresolved::NotFound { tried })
}

/// The reduction a method's row declares, or `None` where no row declares one.
#[must_use]
pub fn row_for<'a>(config: &'a McpConfig, method: &str) -> Option<&'a ResultRow> {
    config.results.iter().find(|row| row.method == method)
}

/// A dispatched result with the protocol's own framing taken off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// The document to store and to reduce.
    pub value: serde_json::Value,
    /// Whether the framing was recognised and removed.
    ///
    /// Carried so the caller can file the capture under the honest fidelity:
    /// bytes that went through a decode are not a reproduction of the document
    /// the server framed, and [`crate::capture::Fidelity`] has two different
    /// words for that.
    pub unwrapped: bool,
}

/// Take MCP's own content-block framing off a `tools/call` result.
///
/// # This is reading the protocol, not guessing a tracker's schema
///
/// `tools/call` is specified to answer with `content` blocks, and optionally with
/// a `structuredContent` object beside them — that is MCP's vocabulary, exactly as
/// `jsonrpc`, `result` and `initialize` are, and knowing it is not knowing
/// anything about a tracker. Non-negotiable rule 1 draws its line at a CONSUMER's
/// identifiers, and none appear here. A row's `node`/`embedded` stay available for
/// a server that frames differently, and are an override of this rather than the
/// only route to a payload.
///
/// # Why it matters more than tidiness
///
/// **The store has an existing reader and it expects the unwrapped shape.**
/// `capture::find` resolves a stored response by a key at a declared path — `id`
/// by default — and that is how `ready lint --issue`, `claim check --issue` and
/// the board gates reach a payload without its bytes entering anyone's context.
/// Measured against this repository's own store on 2026-08-31: the harness files
/// the DECODED content, `id` at the top level. A dispatch that filed the JSON-RPC
/// envelope instead would put `id` two levels down, every one of those lookups
/// would silently resolve nothing, and the gates would report could-not-look over
/// a store that was full — fidelity lost to a framing decision.
///
/// # Three answers, and the third is why this is not an unwrap
///
/// `structuredContent` when the server sent one; else the single text block's
/// document when there is exactly one and it parses; else **the result whole**,
/// with `unwrapped` false. A server whose framing is not recognised keeps its
/// bytes rather than having a shape imposed on them.
#[must_use]
pub fn payload(result: &serde_json::Value) -> Payload {
    if let Some(structured) = result.get("structuredContent") {
        return Payload {
            value: structured.clone(),
            unwrapped: true,
        };
    }
    // EXACTLY ONE BLOCK, deliberately. A multi-block answer is several documents,
    // and picking one of them would be choosing which half of the server's answer
    // to keep — a narrowing nobody declared.
    let single = result
        .get("content")
        .and_then(serde_json::Value::as_array)
        .filter(|blocks| blocks.len() == 1)
        .and_then(|blocks| blocks.first())
        .and_then(|block| block.get("text"))
        .and_then(serde_json::Value::as_str)
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok());
    match single {
        Some(value) => Payload {
            value,
            unwrapped: true,
        },
        None => Payload {
            value: result.clone(),
            unwrapped: false,
        },
    }
}

/// Apply a row's reduction to a payload [`payload`] has already unframed.
///
/// **A row that cannot find its payload yields `None`**, which the caller reports
/// as could-not-look and answers by passing the response through whole. That is
/// the fail-open-loudly half: a reduction that silently emitted `{}` over a node
/// it never reached would be a correctness disaster rather than a saving, because
/// an empty projection and a genuinely empty row are byte-identical on the
/// decision surface.
///
/// The row's `node` and `embedded` are applied INSIDE the unframed payload, so
/// they are an override for a server whose shape [`payload`] did not recognise
/// rather than the ordinary route. Left at their defaults — an empty `node` and
/// `embedded` false — the payload itself is what the fields are read from.
#[must_use]
pub fn reduce(
    row: &ResultRow,
    payload: &serde_json::Value,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    // Through the one parse (CLOUD-849), which is also what keeps the canonical
    // tree the authority here rather than `serde_json`'s value type: a node path
    // means the same thing in this family as in every declared-read family.
    let document = crate::rules::parse_node(Format::Json, &payload.to_string()).ok()?;
    let Look::Is(at) = document.at(&row.node) else {
        return None;
    };
    // A SECOND PARSE ONLY WHERE A ROW ASKED FOR ONE. Guessing that a scalar is a
    // document is how a reduction ends up reading a tree the server never sent.
    let owned;
    let payload = if row.embedded {
        let text = at.scalar()?;
        owned = crate::rules::parse_node(Format::Json, &text).ok()?;
        &owned
    } else {
        at
    };

    let mut kept = serde_json::Map::new();
    for field in &row.fields {
        let Look::Is(node) = payload.at(field) else {
            // ABSENT RATHER THAN NULL. "the payload does not carry this" and
            // "the reduction dropped it" are different answers, and a caller
            // acts on the second.
            continue;
        };
        match row.reduce {
            Reduce::Project => {
                kept.insert(field.clone(), node.to_json());
            }
            Reduce::Acknowledge => {
                // REFUSED RATHER THAN TRUNCATED, and this is the line that makes
                // the write-side arm differ in kind rather than in degree. A
                // container is refused with it: a list or a map is a shape whose
                // size the caller did not bound, and `scalar` returning `None` is
                // exactly that answer.
                let Some(text) = node.scalar() else { continue };
                if text.is_empty() || text.len() > TOKEN_MAX {
                    continue;
                }
                kept.insert(field.clone(), serde_json::Value::String(text));
            }
        }
    }
    Some(kept)
}

/// The JSON-RPC version every request carries.
const JSONRPC: &str = "2.0";

/// The protocol revision this client negotiates.
///
/// A pinned literal rather than "whatever the server offers": a client that
/// accepted any revision would be claiming to implement one it has never seen.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// The content types a response may arrive in.
///
/// Both, because a streamable-HTTP server chooses per request and a client that
/// accepted only one gets a 406 from the other kind.
const ACCEPT: &str = "application/json, text/event-stream";

/// The header a session-bearing server establishes its session in.
const SESSION_HEADER: &str = "mcp-session-id";

/// Dispatch one call and return the JSON-RPC `result` it answered with.
///
/// **MCP is stateful, so this is three requests and not one.** `initialize`
/// negotiates the protocol revision and may mint a session; the initialized
/// notification tells the server the handshake is done; and the call itself
/// carries the session back. All three run on ONE runtime and one connection pool
/// ([`crate::fetch::spend`]), which is what makes the handshake affordable.
///
/// # Errors
///
/// An internal error (→ exit `3`) when the exchange cannot complete, when the
/// server answers with a non-2xx status, when the answer is not a JSON-RPC
/// envelope, or when the envelope carries an `error`. A server's refusal is a
/// fact about the call rather than a verdict about the repository, so it never
/// reaches the policy code — see `crate::exit`'s table.
pub fn dispatch(
    wiring: &Wiring,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value> {
    let handshake = serde_json::json!({
        "jsonrpc": JSONRPC,
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "batten", "version": env!("CARGO_PKG_VERSION")},
        },
    });
    let opened = post(wiring, &handshake, None)?;
    let session = opened
        .header(SESSION_HEADER)
        .map(str::to_owned)
        .filter(|value| !value.is_empty());
    envelope(&opened, "initialize")?;

    // THE REMAINING TWO GO TOGETHER, on one runtime and one connection pool. They
    // could not be batched with `initialize` — that is what mints the session id
    // these two carry back — but they can be batched with each other, which is the
    // whole of what `post_all` exists for.
    //
    // The notification carries no id, so the server answers 202 with no body. Its
    // status is still read: a handshake the server rejected must not be followed
    // by a call that pretends it succeeded.
    let ready = serde_json::json!({
        "jsonrpc": JSONRPC,
        "method": "notifications/initialized",
    });
    let call = serde_json::json!({
        "jsonrpc": JSONRPC,
        "id": 2,
        "method": "tools/call",
        "params": {"name": method, "arguments": params},
    });
    let answers = post_all(wiring, &[ready, call], session.as_deref())?;
    let [acknowledged, answered] = answers.as_slice() else {
        return Err(anyhow::anyhow!(
            "mcp: the session exchange returned {} answers rather than two",
            answers.len()
        ));
    };
    if !(200..300).contains(&acknowledged.status) {
        return Err(anyhow::anyhow!(
            "mcp: the server refused the initialized notification with status {}",
            acknowledged.status
        ));
    }
    envelope(answered, method)
}

/// POST one JSON-RPC document to the endpoint.
///
/// # Errors
///
/// As [`crate::fetch::spend`].
fn post(
    wiring: &Wiring,
    document: &serde_json::Value,
    session: Option<&str>,
) -> Result<crate::fetch::Response> {
    post_all(wiring, std::slice::from_ref(document), session)?
        .pop()
        .ok_or_else(|| anyhow::anyhow!("mcp: the exchange returned no answer"))
}

/// POST several JSON-RPC documents in order, on **one** runtime and one
/// connection pool.
///
/// # Why this exists rather than a loop over [`post`]
///
/// Each [`crate::fetch::spend`] builds a runtime and drops it with the exchange.
/// That is the right shape for a one-shot fetch and the wrong one for a protocol
/// whose smallest useful unit is several requests: a loop would pay the
/// construction cost per hop and open a fresh connection each time, for a session
/// the server believes is one conversation.
///
/// **The handshake cannot be one batch, and that bound is the protocol's rather
/// than this function's.** `initialize` is what MINTS the session id, and the two
/// requests after it must carry that id back — so the first exchange has to
/// complete before the rest can even be addressed. What is batchable is
/// everything downstream of it, which is what [`dispatch`] sends here.
///
/// # Errors
///
/// As [`crate::fetch::spend`]. The sequence stops at the first failure, because a
/// notification the server rejected says nothing about the call that would have
/// followed it.
fn post_all(
    wiring: &Wiring,
    documents: &[serde_json::Value],
    session: Option<&str>,
) -> Result<Vec<crate::fetch::Response>> {
    let mut headers = wiring.headers.clone();
    headers.push(("content-type".to_owned(), "application/json".to_owned()));
    headers.push(("accept".to_owned(), ACCEPT.to_owned()));
    // THE ONE PLACE A `Secret` IS SPENT. It goes from the resolved credential
    // straight into the header list the transport sends, and `header_value` is the
    // only method that yields its bytes — so this line is the whole audit.
    if let Some((name, secret)) = wiring.credential.as_ref() {
        headers.push((name.clone(), secret.spend()));
    }
    if let Some(session) = session {
        headers.push((SESSION_HEADER.to_owned(), session.to_owned()));
    }
    let bodies = documents
        .iter()
        .map(|document| {
            serde_json::to_vec(document)
                .map_err(|err| anyhow::anyhow!("mcp: the request will not render: {err}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let calls: Vec<crate::fetch::Call<'_>> = bodies
        .iter()
        .map(|body| crate::fetch::Call {
            url: &wiring.endpoint,
            headers: &headers,
            payload: crate::fetch::Payload::Create(body),
        })
        .collect();
    crate::fetch::spend(&calls)
}

/// The `result` member of a JSON-RPC answer.
///
/// # Errors
///
/// An internal error (→ exit `3`) on a non-2xx status, an unreadable envelope, or
/// an envelope carrying `error`.
///
/// **Pointer-only in every refusal.** A server's error body is content from
/// somewhere the operator did not choose, so what travels is the status, the
/// method and the JSON-RPC error CODE — never a message and never a body.
fn envelope(response: &crate::fetch::Response, method: &str) -> Result<serde_json::Value> {
    if !(200..300).contains(&response.status) {
        return Err(match challenge(response) {
            Some(scheme) => anyhow::anyhow!(
                "mcp: {method} answered with status {} and challenges {scheme} — the endpoint wants \
                 a credential this source does not send; declare one with \
                 `[mcp.source.credential]`",
                response.status
            ),
            None => anyhow::anyhow!("mcp: {method} answered with status {}", response.status),
        });
    }
    let text = String::from_utf8(response.body.clone())
        .map_err(|_| anyhow::anyhow!("mcp: {method} answered with bytes that are not UTF-8"))?;
    let document: serde_json::Value = serde_json::from_str(&frame(&text)).map_err(|_| {
        anyhow::anyhow!("mcp: {method} answered with no readable JSON-RPC envelope")
    })?;
    if let Some(code) = document.get("error").and_then(|error| error.get("code")) {
        return Err(anyhow::anyhow!(
            "mcp: {method} was refused by the server, JSON-RPC error code {code}"
        ));
    }
    document.get("result").cloned().ok_or_else(|| {
        anyhow::anyhow!("mcp: {method} answered with an envelope carrying no result")
    })
}

/// The authentication SCHEME a refusal challenges with, if it names one.
///
/// # Why a refusal gets to say this much and no more
///
/// A 401 with no cause is the least actionable error in the protocol, and it cost
/// this feature a whole round: CLOUD-673 concluded from a bare 401 that the
/// endpoint's headers "are not authorization", and CLOUD-1260 then concluded the
/// opposite from no new evidence. A server that publishes `WWW-Authenticate` is
/// telling every client what to send, so relaying it turns a guess into a fact.
///
/// **The SCHEME TOKEN only** — the first word, uppercased for byte-stability, and
/// nothing after it. The parameters that follow can carry a realm, a resource URI
/// and an error description, which are the server operator's content and not
/// something rule 4 lets into a finding. So `Bearer realm="https://…"` reports
/// `BEARER`.
fn challenge(response: &crate::fetch::Response) -> Option<String> {
    response
        .header("www-authenticate")
        .and_then(|value| value.split_whitespace().next())
        .filter(|scheme| {
            !scheme.is_empty()
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        .map(str::to_uppercase)
}

/// The JSON document inside whatever framing the server chose.
///
/// A streamable-HTTP server may answer a POST as `application/json` — in which
/// case the body IS the document — or as an event stream, where the document is
/// the last `data:` field. **The LAST rather than the first**: a server is free
/// to send progress notifications ahead of the answer, and taking the first would
/// read a progress event as the result.
fn frame(text: &str) -> String {
    let mut last: Option<String> = None;
    let mut saw_data = false;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            saw_data = true;
            last = Some(rest.trim().to_owned());
        }
    }
    if saw_data {
        return last.unwrap_or_default();
    }
    text.to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn row(reduce: Reduce, fields: &[&str]) -> ResultRow {
        ResultRow {
            method: "m".to_owned(),
            reduce,
            fields: fields.iter().map(|f| (*f).to_owned()).collect(),
            node: String::new(),
            embedded: false,
        }
    }

    fn source_with(credential: Option<Credential>) -> Source {
        Source {
            id: "s".to_owned(),
            root: None,
            base: None,
            path: "w.json".to_owned(),
            node: String::new(),
            credential,
        }
    }

    fn declared(env: Option<&str>, file_from: Option<&str>, scheme: &str) -> Credential {
        Credential {
            header: authorization(),
            scheme: scheme.to_owned(),
            env: env.map(str::to_owned),
            file_from: file_from.map(str::to_owned),
        }
    }

    #[test]
    fn a_path_with_no_placeholder_expands_to_itself() {
        // The allow half, and the compatibility one: every landed row is this
        // shape, so expansion must be a no-op over all of them.
        assert_eq!(
            expand("wiring.json").unwrap(),
            Some("wiring.json".to_owned())
        );
        assert_eq!(
            expand(".hidden/w.json").unwrap(),
            Some(".hidden/w.json".to_owned())
        );
    }

    #[test]
    fn a_bare_dollar_is_a_literal_rather_than_a_placeholder() {
        // Only `${NAME}` is a placeholder. A path may contain a `$`, and guessing
        // where a bare `$NAME` ends is how one spelling becomes two.
        assert_eq!(expand("a$B.json").unwrap(), Some("a$B.json".to_owned()));
    }

    #[test]
    fn an_unclosed_or_misnamed_placeholder_is_refused_rather_than_read_as_text() {
        // Reading either as a literal resolves a path nobody wrote — and would do
        // it silently, which is the shape this repository refuses everywhere.
        assert!(placeholders("mcp-${ID.json").is_err(), "an unclosed `${{`");
        assert!(
            placeholders("${1BAD}.json").is_err(),
            "a name starting with a digit"
        );
        assert!(placeholders("${}.json").is_err(), "an empty name");
        assert!(placeholders("${A-B}.json").is_err(), "a name with a hyphen");
        assert!(
            placeholders("mcp-config-${CLAUDE_CODE_REMOTE_SESSION_ID}.json").is_ok(),
            "the shape this feature exists for must load"
        );
    }

    #[test]
    fn an_unset_placeholder_is_could_not_look_and_never_an_empty_substitution() {
        // Substituting empty turns `mcp-config-${ID}.json` into
        // `mcp-config-.json` — a real path, almost certainly somebody else's, that
        // the engine would then report as an absent file. Two different answers,
        // and the wrong one sends a reader to look for a file that never existed.
        let name = "BATTEN_TEST_SESSION_ID_DEFINITELY_UNSET";
        assert!(
            std::env::var_os(name).is_none(),
            "this case needs {name} unset to mean anything"
        );
        assert_eq!(
            expand(&format!("mcp-config-${{{name}}}.json")).unwrap(),
            None
        );
    }

    #[test]
    fn an_expanded_path_is_checked_for_escape_a_second_time() {
        // THE CASE THAT KEEPS EXPANSION FROM BEING A FILE-READ PRIMITIVE. The
        // load-time check sees `${ID}` and not what `ID` holds, so a value
        // carrying an upward step would otherwise walk out of the declared base.
        // Asserted over `escapes` directly, which is what `wiring` runs over the
        // expanded string — the environment cannot be arranged here, because the
        // workspace forbids the `unsafe` that `set_var` requires.
        assert!(
            !escapes("mcp-config-cse_01ABC.json"),
            "an ordinary expansion stays beneath its base"
        );
        assert!(
            escapes("mcp-config-../../etc/passwd.json"),
            "a value carrying an upward step must be caught by the second check"
        );
        assert!(
            escapes("/etc/passwd"),
            "and so must one that expanded to a rooted path"
        );
    }

    #[test]
    fn a_source_declaring_no_credential_resolves_to_none() {
        // The byte-identical arm. Without it, adding this key would change what
        // every source that does not use it sends — the silent behaviour change
        // CLOUD-1261's acceptance refuses by name.
        assert_eq!(credential(&source_with(None)).unwrap(), None);
    }

    #[test]
    fn a_credential_row_naming_neither_variable_is_refused_at_load() {
        let err = validate_credential(&source_with(Some(declared(None, None, ""))))
            .expect_err("a row naming no variable resolves to nothing and must not load");
        assert!(
            err.to_string().contains("neither `env` nor `file_from`"),
            "the refusal names which keys are missing: {err}"
        );
    }

    #[test]
    fn a_credential_row_naming_both_variables_is_refused_at_load() {
        // Two answers to one question. Left to dispatch, which one is spent would
        // depend on the order this file happens to read them in.
        let err = validate_credential(&source_with(Some(declared(Some("A"), Some("B"), ""))))
            .expect_err("a row naming two variables has no single meaning");
        assert!(
            err.to_string().contains("both `env` and `file_from`"),
            "the refusal names the conflict: {err}"
        );
    }

    #[test]
    fn an_unset_variable_is_an_error_rather_than_an_unauthenticated_call() {
        // The case that matters: falling through to a header-less dispatch would
        // produce a 401 that reads as the server's fault, sending whoever debugs
        // it to the wrong system entirely.
        let name = "BATTEN_TEST_CREDENTIAL_DEFINITELY_UNSET";
        // SAFETY-ADJACENT: assert the premise rather than assume it, per
        // `.claude/rules/rust.md` — a test whose precondition was never created
        // asserts its own premise before its conclusion.
        assert!(
            std::env::var_os(name).is_none(),
            "this case needs {name} unset to mean anything"
        );
        let err = credential(&source_with(Some(declared(Some(name), None, ""))))
            .expect_err("a declared credential that will not resolve must not dispatch");
        assert!(
            err.to_string().contains(name),
            "the refusal names the VARIABLE to fix: {err}"
        );
    }

    #[test]
    fn a_secret_has_no_debug_rendering_of_its_value() {
        // The negative half, and it is asserted over the formatter every accidental
        // leak goes through: a `{:?}` in a log line, a panic, or a derived `Debug`
        // on any struct that comes to hold one.
        let secret = Secret("sk-the-actual-value".to_owned());
        let rendered = format!("{secret:?}");
        assert!(
            !rendered.contains("sk-the-actual-value"),
            "a Secret must not render its value under `{{:?}}`, got {rendered}"
        );
        assert_eq!(rendered, "Secret(<redacted>)");
    }

    #[test]
    fn a_wiring_carrying_a_secret_does_not_render_it_either() {
        // `Wiring` derives `Debug`, so the containment has to survive being a
        // FIELD of something derived — which is the shape a leak actually takes.
        let wiring = Wiring {
            source: "s".to_owned(),
            endpoint: "https://example.invalid/mcp".to_owned(),
            headers: Vec::new(),
            credential: Some((authorization(), Secret("sk-the-actual-value".to_owned()))),
        };
        assert!(
            !format!("{wiring:?}").contains("sk-the-actual-value"),
            "a derived Debug over a struct holding a Secret must not reach the value"
        );
    }

    #[test]
    fn a_scheme_is_folded_in_and_an_empty_scheme_sends_the_value_alone() {
        // Both arms, because a bare-token header and a `Bearer` one are different
        // wire bytes and a server accepts exactly one of them. A default header
        // that silently prefixed `Bearer` would put this feature back where the
        // 401 was — sending something the endpoint did not ask for.
        let (header, schemed) = declared(Some("A"), None, "Bearer").sent("tok");
        assert_eq!(header, "Authorization");
        assert_eq!(schemed.spend(), "Bearer tok");
        let (_, bare) = declared(Some("A"), None, "").sent("tok");
        assert_eq!(
            bare.spend(),
            "tok",
            "an empty scheme sends the value alone, which is what a bare-token header wants"
        );
    }

    #[test]
    fn a_credential_header_may_be_named_rather_than_assumed() {
        // The endpoint measured on 2026-09-01 authenticates a SESSION and its
        // wiring names three `X-`-prefixed headers, so `Authorization` is a
        // default rather than a law.
        let row = Credential {
            header: "X-Session-Token".to_owned(),
            scheme: String::new(),
            env: Some("A".to_owned()),
            file_from: None,
        };
        assert_eq!(row.sent("tok").0, "X-Session-Token");
    }

    #[test]
    fn a_challenge_reports_the_scheme_token_and_never_its_parameters() {
        // Rule 4 at the one place a refusal is tempted to quote the server: the
        // parameters carry a realm and an error description, which are the
        // operator's content.
        let response = crate::fetch::Response {
            status: 401,
            body: Vec::new(),
            headers: vec![(
                "www-authenticate".to_owned(),
                r#"Bearer realm="https://api.example.invalid", error="invalid_token""#.to_owned(),
            )],
        };
        assert_eq!(challenge(&response), Some("BEARER".to_owned()));
        let silent = crate::fetch::Response {
            status: 401,
            body: Vec::new(),
            headers: Vec::new(),
        };
        assert_eq!(
            challenge(&silent),
            None,
            "a server that publishes no challenge must not have one invented for it"
        );
    }

    #[test]
    fn a_projection_keeps_the_declared_fields_and_nothing_else() {
        // The allow half. Without it every case below is satisfied by a
        // reduction that returns nothing, which would gate nothing and save
        // everything by dropping the answer.
        let result = serde_json::json!({"id": "K-1", "body": "a long prose body", "n": 3});
        let kept = reduce(&row(Reduce::Project, &["id", "n"]), &result).unwrap();
        assert_eq!(kept.get("id"), Some(&serde_json::json!("K-1")));
        assert_eq!(kept.get("n"), Some(&serde_json::json!(3)));
        assert!(
            !kept.contains_key("body"),
            "a field no row declared must never leave the store"
        );
    }

    #[test]
    fn an_undeclared_field_is_absent_rather_than_null() {
        // "the payload does not carry this" and "the reduction dropped it" are
        // different answers, and a caller acts on the second.
        let kept = reduce(
            &row(Reduce::Project, &["missing"]),
            &serde_json::json!({"id": "K"}),
        )
        .unwrap();
        assert!(kept.is_empty(), "an absent field contributes no key at all");
    }

    #[test]
    fn acknowledge_refuses_a_body_rather_than_truncating_it() {
        // THE DIFFERENCE IN KIND from `project`, and the whole of CLOUD-1122's
        // rule-4 guarantee: a prefix of somebody's issue body is still their
        // issue body, so the arm refuses rather than shortens.
        let long = "x".repeat(TOKEN_MAX + 1);
        let result = serde_json::json!({
            "id": "K-1",
            "status": "In Progress",
            "labels": ["a", "b"],
            "description": long,
        });
        let kept = reduce(
            &row(
                Reduce::Acknowledge,
                &["id", "status", "labels", "description"],
            ),
            &result,
        )
        .unwrap();
        assert_eq!(kept.get("id"), Some(&serde_json::json!("K-1")));
        assert!(
            !kept.contains_key("description"),
            "an over-long value is refused, never truncated"
        );
        assert!(
            !kept.contains_key("labels"),
            "a container is a shape whose size the caller did not bound"
        );

        // THE NEAR-MISS THIS ROW ALMOST SHIPPED, pinned so it cannot come back.
        // An earlier draft copied `facts::Reduction::Token`'s whitespace clause
        // across, which is right for the POLICY INPUT it serves and wrong here:
        // `save_issue` answers `status = "In Progress"`, so the arm would have
        // silently dropped the one field CLOUD-1122's remedy names — `{id,
        // status, handle}` — with every test still green.
        assert_eq!(
            kept.get("status"),
            Some(&serde_json::json!("In Progress")),
            "a short status name is what the caller asked for, not prose to refuse"
        );

        // The same field set under `project` DOES carry the body, which is what
        // makes the refusals above a statement about the arm rather than about
        // the payload.
        let wide = reduce(
            &row(Reduce::Project, &["id", "labels", "description"]),
            &result,
        )
        .unwrap();
        assert!(wide.contains_key("description") && wide.contains_key("labels"));
    }

    #[test]
    fn a_node_the_row_cannot_reach_is_could_not_look_rather_than_an_empty_reduction() {
        // The fail-open-loudly half. An empty projection and a genuinely empty
        // row are byte-identical on the decision surface, so the unreachable
        // node must not answer with `{}`.
        let mut unreachable = row(Reduce::Project, &["id"]);
        unreachable.node = "nowhere.at.all".to_owned();
        assert_eq!(reduce(&unreachable, &serde_json::json!({"id": "K"})), None);

        // And an `embedded` row over a node that is not a document, which is the
        // same answer arrived at down a different path.
        let mut mistaken = row(Reduce::Project, &["id"]);
        mistaken.embedded = true;
        assert_eq!(reduce(&mistaken, &serde_json::json!({"id": "K"})), None);
    }

    #[test]
    fn an_embedded_payload_is_parsed_only_where_a_row_asked() {
        // The OVERRIDE route, for a server whose framing `payload` does not
        // recognise. It reaches inside a document `payload` handed back whole.
        let odd = serde_json::json!({
            "envelope": {"blob": r#"{"id":"K-1","body":"prose"}"#},
        });
        let mut declared = row(Reduce::Project, &["id"]);
        declared.node = "envelope.blob".to_owned();
        declared.embedded = true;
        let kept = reduce(&declared, &odd).unwrap();
        assert_eq!(kept.get("id"), Some(&serde_json::json!("K-1")));
        assert!(!kept.contains_key("body"));
    }

    #[test]
    fn the_protocols_own_framing_comes_off_without_a_row_asking() {
        // READING THE PROTOCOL, not guessing a schema: `tools/call` is specified
        // to answer with content blocks, so an ordinary row needs no override —
        // and the store's existing readers need the unframed shape, because
        // `capture::find` looks for its key at the top level.
        let framed = serde_json::json!({
            "content": [{"type": "text", "text": r#"{"id":"K-1","body":"prose"}"#}],
        });
        let taken = payload(&framed);
        assert!(taken.unwrapped, "a single text block is recognised framing");
        assert_eq!(taken.value.get("id"), Some(&serde_json::json!("K-1")));

        // `structuredContent` wins where a server sends one, because it is the
        // typed answer rather than a rendering of it.
        let both = serde_json::json!({
            "structuredContent": {"id": "K-2"},
            "content": [{"type": "text", "text": r#"{"id":"K-1"}"#}],
        });
        assert_eq!(
            payload(&both).value.get("id"),
            Some(&serde_json::json!("K-2"))
        );
    }

    #[test]
    fn what_is_filed_is_what_the_store_s_reader_resolves() {
        // THE FIDELITY COUPLING, asserted against the actual reader rather than
        // described. `capture::find` locates a stored response by a key at a
        // declared path — `id` by default, read through `mint::scalar` — and that
        // is how `ready lint --issue`, `claim check --issue` and the board gates
        // reach a payload without its bytes entering anyone's context.
        //
        // A dispatch that filed the JSON-RPC envelope would put the key two
        // levels down: every one of those lookups would silently resolve nothing
        // and the gates would report could-not-look over a full store. So this
        // case asks the reader itself, and the negative half below is what makes
        // it discriminate rather than merely pass.
        let framed = serde_json::json!({
            "content": [{"type": "text", "text": r#"{"id":"K-1","description":"a body"}"#}],
        });
        assert_eq!(
            crate::mint::scalar(&payload(&framed).value, "id"),
            Some("K-1".to_owned()),
            "what `mcp call` files must be resolvable by the key the store's reader looks for"
        );
        assert_eq!(
            crate::mint::scalar(&framed, "id"),
            None,
            "and the envelope must NOT be — otherwise this case would pass over either shape"
        );
    }

    #[test]
    fn an_unrecognised_framing_keeps_its_bytes_rather_than_having_a_shape_imposed() {
        // THE THIRD ANSWER, and the reason this is not an unwrap. Without it the
        // two cases above are satisfied by a function that reaches into whatever
        // it finds and returns null when it finds nothing — which would file an
        // empty document under a digest that promises a response.
        for odd in [
            // Several blocks: picking one would be choosing which half of the
            // server's answer to keep, a narrowing nobody declared.
            serde_json::json!({"content": [
                {"type": "text", "text": "{\"id\":\"a\"}"},
                {"type": "text", "text": "{\"id\":\"b\"}"},
            ]}),
            // A block whose text is not a document at all.
            serde_json::json!({"content": [{"type": "text", "text": "plain prose"}]}),
            // No framing this function knows.
            serde_json::json!({"rows": [1, 2, 3]}),
        ] {
            let taken = payload(&odd);
            assert!(!taken.unwrapped, "unrecognised framing must say so");
            assert_eq!(taken.value, odd, "and must hand the bytes back untouched");
        }
    }

    #[test]
    fn an_event_stream_yields_the_last_data_field_and_a_plain_body_is_untouched() {
        // A server may send progress events ahead of the answer, so taking the
        // first `data:` would read a progress notification as the result.
        assert_eq!(
            frame("event: message\ndata: {\"a\":1}\n\nevent: message\ndata: {\"b\":2}\n"),
            "{\"b\":2}"
        );
        assert_eq!(frame("{\"a\":1}"), "{\"a\":1}");
    }

    #[test]
    fn a_root_that_is_not_a_name_and_a_path_that_escapes_are_both_refused_at_load() {
        let mut config = McpConfig::default();
        config.sources.push(Source {
            id: "s".to_owned(),
            root: Some("  ".to_owned()),
            base: None,
            path: "x.json".to_owned(),
            node: String::new(),
            credential: None,
        });
        assert!(validate(&config).is_err(), "an empty root name is refused");

        config.sources[0].root = Some("HOME".to_owned());
        // `/etc/passwd` IS THE PORTABILITY CASE, and it is listed first because
        // it is the one an `is_absolute` predicate lets through. On Windows that
        // path is "relative" — a root with no drive prefix — while `Path::join`
        // still discards the base and yields `C:\etc\passwd`. This shipped once,
        // `verify` passed over it (`cross-check` type-checks the target and runs
        // no test there), and the Windows job in CI is what caught it.
        for path in ["/etc/passwd", "/", "../outside.json", "a/../../b.json"] {
            config.sources[0].path = path.to_owned();
            assert!(
                validate(&config).is_err(),
                "{path} must not be declarable: it leaves the root the row named"
            );
        }
        config.sources[0].path = "under/here.json".to_owned();
        assert!(
            validate(&config).is_ok(),
            "a relative downward path is fine"
        );
    }

    #[test]
    fn a_reduction_over_no_fields_is_refused_at_load() {
        // An empty projection is a dropped payload wearing the costume of a
        // narrower answer, and it is refused where a config fault belongs.
        let mut config = McpConfig::default();
        config.results.push(ResultRow {
            method: "m".to_owned(),
            reduce: Reduce::Project,
            fields: Vec::new(),
            node: String::new(),
            embedded: false,
        });
        assert!(validate(&config).is_err());
    }

    #[test]
    fn an_undeclared_source_set_and_an_unmatched_server_answer_differently() {
        // Non-negotiable: "nowhere to look" and "looked and did not find" are
        // different facts about the world.
        let empty = McpConfig::default();
        assert_eq!(
            wiring(&empty, Path::new("."), "anything"),
            Err(Unresolved::Undeclared)
        );

        let mut declared = McpConfig::default();
        declared.sources.push(Source {
            id: "nowhere".to_owned(),
            root: Some("BATTEN_MCP_ROOT_THAT_IS_NOT_SET".to_owned()),
            base: None,
            path: "wiring.json".to_owned(),
            node: String::new(),
            credential: None,
        });
        assert_eq!(
            wiring(&declared, Path::new("."), "anything"),
            Err(Unresolved::NotFound {
                tried: vec!["nowhere".to_owned()]
            })
        );
    }

    #[test]
    fn no_pointer_carries_a_resolved_path() {
        // Rule 4 where it matters most: a resolved path here is somebody's home
        // directory, which is exactly what keying by id exists to keep out.
        for answer in [
            Unresolved::Undeclared,
            Unresolved::NotFound {
                tried: vec!["a".to_owned()],
            },
            Unresolved::Unreadable {
                source: "a".to_owned(),
            },
        ] {
            let pointer = answer.pointer();
            assert!(!pointer.contains('/'), "{pointer:?} must carry no path");
        }
    }
}
