//! Captured child output, content-addressed in out-of-tree state (CLOUD-162).
//!
//! The shared substrate two capabilities need over the output of a single
//! `batten exec` run: an output predicate that scans it for a pattern meaning
//! "not actually done" (CLOUD-117), and a handle an agent can expand without
//! re-running the command (CLOUD-121). Built once, here, so neither consumer
//! grows its own copy — building the capture twice is the failure the issue
//! exists to prevent.
//!
//! ## What this module is, and is not
//!
//! It is the *storage and addressing* of bytes a child already wrote. It renders
//! no verdict, scans for nothing, and emits nothing: the predicate is CLOUD-117's
//! and the `show` verbs are CLOUD-121's. Keeping it inert is what lets both land
//! on top of it without renegotiating where captures live.
//!
//! ## Addressing reuses the one hashing discipline
//!
//! [`crate::identity::capture_fingerprint`] — a domain tag then each field,
//! length-prefixed, the same construction every finding identity and the config
//! epoch already go through. The digest **is** the key: a capture is stored at
//! `captures/<digest>`, so identical bytes are one record rather than two, and
//! re-running a command whose output did not change writes nothing new.
//!
//! That is also why the record carries no timestamp. A capture keyed by content
//! must be a pure function of that content, and a "captured at" field would make
//! two identical outputs two different records — the byte-stability §6 requires,
//! broken by a field nothing reads.
//!
//! ## Why it lives out of tree
//!
//! [`crate::state::repo_state_dir`] — the same root the receipt store uses, so a
//! checkout stays clean and no new path scheme is invented. A capture is a fact
//! about one run of one command; it is not source, and a repo that accumulated
//! them would have to gitignore its own bookkeeping.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::error::UsageError;
use crate::identity;
use crate::state;

/// Which of a child's two output streams a capture holds.
///
/// A named pair rather than a bare string, so the stored key and the hashed
/// field cannot drift apart, and so a caller cannot invent a third stream the
/// reader will not recognise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stream {
    /// The child's standard output.
    Stdout,
    /// The child's standard error.
    Stderr,
    /// A tool response the harness handed over (CLOUD-918).
    ///
    /// **Appended, never inserted.** `semver` reads a reordered variant as
    /// `enum_no_repr_variant_discriminant_changed`, so declaration order is an
    /// API fact here exactly as it is for [`crate::hook::Capability`].
    ///
    /// Not a child's stream at all, and it rides this enum anyway because
    /// everything downstream of the store key is identical: the handle shape,
    /// [`Handle::parse`], [`list`], [`prune`] and the `<stream>-<digest>`
    /// filename need no new case. A second addressing scheme for the same
    /// question is how two stores come to disagree.
    ///
    /// **Sealed-only**, and that is enforced by [`LiveStream`] rather than
    /// asserted: a response arrives whole, so there is nothing to spool and a
    /// live handle would promise a file that is still growing when nothing is
    /// writing it.
    Response,
}

impl Stream {
    /// Every stream, so anything ranging over them is derived rather than typed
    /// twice.
    pub const ALL: &'static [Stream] = &[Stream::Stdout, Stream::Stderr, Stream::Response];

    /// The stable token used in the store key and in the hashed preimage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Stream::Stdout => "stdout",
            Stream::Stderr => "stderr",
            Stream::Response => "response",
        }
    }
}

/// A stream that can spool: the only thing a live handle can name.
///
/// **Makes sealed-only unrepresentable rather than merely untested.**
/// [`live_handle`] and [`Spool::open`] take this instead of a [`Stream`], so
/// there is no code path that mints a live handle for [`Stream::Response`] and
/// no test standing guard over one. The exhaustive `match` in
/// [`LiveStream::new`] also means a seventh stream cannot land without deciding
/// which side it is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveStream(Stream);

impl LiveStream {
    /// A child's standard output, which spools.
    ///
    /// A const rather than [`LiveStream::new`] plus a handled `None`, because at
    /// every production call site the stream is statically one of these two and
    /// the crate's lints forbid unwrapping a total answer into a reachable panic.
    pub const STDOUT: LiveStream = LiveStream(Stream::Stdout);
    /// A child's standard error, which spools.
    pub const STDERR: LiveStream = LiveStream(Stream::Stderr);

    /// `None` for a stream that is sealed-only.
    ///
    /// A child's pipes grow while it runs and can be read mid-flight; a tool
    /// response is handed over complete, so a watermark would have nothing to
    /// name.
    #[must_use]
    pub const fn new(stream: Stream) -> Option<LiveStream> {
        match stream {
            Stream::Stdout | Stream::Stderr => Some(LiveStream(stream)),
            Stream::Response => None,
        }
    }

    /// The stream this names.
    #[must_use]
    pub const fn stream(self) -> Stream {
        self.0
    }

    /// Whether this is the error stream.
    ///
    /// A boolean rather than leaving callers to `match` the inner [`Stream`]:
    /// there are exactly two spooling streams, so a caller choosing between two
    /// terminal sinks has a total answer here and no third arm to write for a
    /// case [`LiveStream`] already excludes.
    #[must_use]
    pub const fn is_stderr(self) -> bool {
        matches!(self.0, Stream::Stderr)
    }
}

/// How faithfully the bytes a capture holds relate to the bytes the host framed
/// (CLOUD-917).
///
/// Five values, mutually exclusive, and every declared cell carries exactly one.
/// The column this ranges over is [`crate::hook::CaptureCapabilities`], per host
/// and per response shape — a capture that does not say how faithful it is makes
/// every reader guess, and the guesses differ.
///
/// # `byte-perfect` names [`Fidelity::LexicalBytes`] and [`Fidelity::SpillFile`]
///
/// Exactly two of these five may be described that way, and
/// [`Fidelity::is_byte_perfect`] is the only authority on which — no doc comment,
/// output line, record field or test name may say it of any other.
/// `tests/capture_fidelity.rs` scans this module's own docs and this type's
/// rendered output for the term and refuses a mention beside a value that does
/// not answer `true` there.
///
/// The value that makes the rule necessary is [`Fidelity::DecodedContent`]:
/// re-serializing a decoded JSON value normalizes key order, escaping and
/// whitespace, so what comes back out is a different byte string from what
/// arrived. It is exact for the member it decoded and it is not a reproduction
/// of the document, and those are two claims rather than one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fidelity {
    /// The original bytes of the response member, exactly as the host framed
    /// them. A faithful reproduction of the document that arrived.
    LexicalBytes,
    /// The decoded content bytes, with the framing recorded separately.
    ///
    /// Exact for the member it decoded, and **not** a reproduction of the
    /// document the host framed: a decode-then-reserialize round trip
    /// renormalizes key order, escaping and whitespace, so the bytes that come
    /// back out are a different string from the ones that arrived. The framing —
    /// block count, per-block type — lives on the provenance row rather than
    /// interleaved into the bytes, so a reader of the stream gets content and a
    /// reader of the record gets structure.
    DecodedContent,
    /// The bytes of the file the host spilled the response into. A faithful
    /// reproduction: the file is read once and stored as it was read.
    SpillFile,
    /// A leading prefix, plus whatever is known about the whole.
    ///
    /// **Not** a reproduction of the document, and it never claims to be: this
    /// is the value that says so out loud, which is the whole reason a partial
    /// capture does not borrow a completeness claim it cannot support.
    Prefix {
        /// How many bytes were captured.
        captured: u64,
        /// The total the host declared, when it declared one. `None` is a
        /// truncation signal with no total, never a total of zero.
        declared: Option<u64>,
    },
    /// Nothing; the host does not make the bytes reachable here.
    ///
    /// The honest value for an unsurveyed host, and never a guess. A host that
    /// cannot be captured is *knowable* rather than silent, which is the whole
    /// difference between this and having no column at all.
    Unavailable,
}

impl Fidelity {
    /// Every fidelity arm, so a census is derived rather than hand-kept.
    ///
    /// [`Fidelity::Prefix`] carries a payload, so it appears here under one
    /// representative value. The census ranges over **arms**: the payload is a
    /// fact about one capture and is not part of the vocabulary a host declares.
    pub const ALL: &'static [Fidelity] = &[
        Fidelity::LexicalBytes,
        Fidelity::DecodedContent,
        Fidelity::SpillFile,
        Fidelity::Prefix {
            captured: 0,
            declared: None,
        },
        Fidelity::Unavailable,
    ];

    /// The stable token, for byte-stable output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Fidelity::LexicalBytes => "lexical-bytes",
            Fidelity::DecodedContent => "decoded-content",
            Fidelity::SpillFile => "spill-file",
            Fidelity::Prefix { .. } => "prefix",
            Fidelity::Unavailable => "unavailable",
        }
    }

    /// Whether this value may be described as byte-perfect: true for
    /// [`Fidelity::LexicalBytes`] and [`Fidelity::SpillFile`], false for the
    /// other three.
    ///
    /// **The one authority**, so the claim cannot be made in prose by a site
    /// that never consulted it. Only a capture holding the bytes as the host
    /// framed them qualifies: the original member
    /// ([`Fidelity::LexicalBytes`]) or the spilled file
    /// ([`Fidelity::SpillFile`]). A decoded member is exact for what it decoded
    /// and is not this; a prefix does not claim completeness at all.
    #[must_use]
    pub const fn is_byte_perfect(self) -> bool {
        matches!(self, Fidelity::LexicalBytes | Fidelity::SpillFile)
    }

    /// Whether this capture holds the **whole** of what the host handed over:
    /// true for [`Fidelity::LexicalBytes`], [`Fidelity::DecodedContent`] and
    /// [`Fidelity::SpillFile`], false for [`Fidelity::Prefix`] and
    /// [`Fidelity::Unavailable`].
    ///
    /// **A different question from [`Fidelity::is_byte_perfect`], and reaching
    /// for that one instead is the defect this exists to prevent** (CLOUD-1121).
    /// That predicate asks whether the bytes reproduce the document the host
    /// framed, which only the two faithful arms can claim. This one asks whether
    /// anything is MISSING — which is what a consumer parsing the capture as a
    /// document needs, because a decode-then-reserialize round trip renormalizes
    /// key order and escaping and changes no value.
    ///
    /// Measured 2026-08-28: every MCP tool response captured on this host is
    /// [`Fidelity::DecodedContent`], for which `is_byte_perfect` is false. A
    /// resolver filtering on that predicate would reject every payload in the
    /// store and could never return a hit — a gate that cannot fire, which reads
    /// exactly like a clean tree.
    ///
    /// [`Fidelity::Prefix`] is excluded whatever its `captured` count, including
    /// a prefix that happens to hold everything: the arm's whole purpose is that
    /// it does not claim completeness, and inferring one from the numbers would
    /// put the claim back where the type removed it.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(
            self,
            Fidelity::LexicalBytes | Fidelity::DecodedContent | Fidelity::SpillFile
        )
    }

    /// The rendered one-line description, for a `doctor` row or a listing.
    ///
    /// Carries the reserved term for — and only for — the two values
    /// [`Fidelity::is_byte_perfect`] admits, so deleting the claim from the
    /// rendering while leaving it in the type is a red rather than a drift.
    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Fidelity::LexicalBytes => "the response member as the host framed it; byte-perfect",
            Fidelity::SpillFile => "the file the host spilled the response into; byte-perfect",
            Fidelity::DecodedContent => {
                "the decoded content, exact for the member and not the framed document"
            }
            Fidelity::Prefix { .. } => "a leading prefix; completeness is not claimed",
            Fidelity::Unavailable => "the host does not make the bytes reachable here",
        }
    }
}

/// The state root could not be resolved, so there is no store to write into.
///
/// Distinct from [`STORE_UNWRITABLE`] on purpose: two different remedies — fix
/// the repository, or fix the directory — so one id would send the reader to the
/// wrong place. That is `doctor.rs`'s pattern for a reason id, and these inherit
/// its `a_reason_id_never_carries_a_path` gate.
pub const STATE_ROOT_UNRESOLVED: &str = "capture-state-root-unresolved";

/// The store resolved and a record could not be written into it.
pub const STORE_UNWRITABLE: &str = "capture-store-unwritable";

/// The response arrived in a shape no decoder here recognises.
///
/// **Could-not-look, never zero bytes**, which is `facts::rows_in`'s own
/// precedent: an unread shape is not an empty response, and recording it as one
/// would make "the tool said nothing" and "we could not read what it said" the
/// same record.
pub const RESPONSE_SHAPE_UNREADABLE: &str = "capture-response-shape-unreadable";

/// The write-time budget refused the bytes.
pub const BUDGET_EXHAUSTED: &str = "capture-budget-exhausted";

/// The file a host spilled a response into was gone when it was opened.
pub const SPILL_VANISHED: &str = "capture-spill-vanished";

/// A spilled file's length moved between the open and the end of the read.
///
/// **Never a [`Fidelity::Prefix`]**, which would imply the host truncated: a
/// racing writer is a fidelity answer about our read, not a claim about what the
/// host meant to send.
pub const SPILL_RACED: &str = "capture-spill-raced";

/// The host sent no response member at all.
///
/// **The one reason id that is not a failure.** A pre-tool call has no response
/// by construction, and a post-tool call from a host that sends none is the
/// surveyed-`Unavailable` case rather than anything gone wrong. It exists so the
/// row can exist: without a record, "the host sent nothing" and "no call was ever
/// made" are the same absence, which is CLOUD-251's collapse on this surface.
pub const RESPONSE_ABSENT: &str = "capture-response-absent";

/// Every reason id this module can produce, so a census is derived.
pub const REASONS: &[&str] = &[
    STATE_ROOT_UNRESOLVED,
    STORE_UNWRITABLE,
    RESPONSE_ABSENT,
    RESPONSE_SHAPE_UNREADABLE,
    BUDGET_EXHAUSTED,
    SPILL_VANISHED,
    SPILL_RACED,
];

/// What a response member decoded to, plus the framing kept out of the bytes.
///
/// The framing — how many blocks, and of what type — lives here rather than
/// interleaved into [`Decoded::bytes`], which is what makes the bytes replayable:
/// a reader of the stream gets content, and a reader of the provenance row gets
/// structure. Interleaving would make `--raw` return something no host ever
/// sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The decoded content bytes, in the order the host sent them.
    pub bytes: Vec<u8>,
    /// How many blocks were concatenated. One for a bare string or an object.
    pub blocks: usize,
    /// The fidelity this decode achieved.
    pub fidelity: Fidelity,
}

/// The response member's content bytes, or why they could not be read.
///
/// **Always [`Fidelity::DecodedContent`] today, and that is a measurement rather
/// than a choice.** [`crate::hook::decode`] hands the engine an already-parsed
/// `serde_json::Value`, so the member's original lexical bytes are gone before
/// anything here sees it. Reaching [`Fidelity::LexicalBytes`] needs two things
/// that do not exist: `serde_json`'s non-default `raw_value` feature, and a
/// decoder that carries the member's raw span beside the parsed value.
///
/// **Re-serializing is not a substitute and is forbidden.** `to_vec` over the
/// parsed value renormalizes key order, escaping, numbers and whitespace, so the
/// result is a different byte string from what arrived — and describing that as a
/// faithful reproduction of the document is precisely the claim [`Fidelity`]'s
/// reserved word exists to refuse. So this decodes CONTENT and says so.
///
/// Three shapes are recognised, which are the three the corpus carries:
///
/// * an array of `{"type":"text","text":…}` blocks — the MCP content-block shape;
///   each block's decoded text, concatenated in host order.
/// * an object with string members — Claude Code's Bash shape; `stdout` then
///   `stderr`, in that fixed order so the bytes are a function of the value
///   rather than of map iteration.
/// * a bare string.
///
/// Anything else is [`RESPONSE_SHAPE_UNREADABLE`] rather than zero bytes.
///
/// # Errors
///
/// Returns [`RESPONSE_SHAPE_UNREADABLE`] when the member is in none of the three
/// shapes above. **Could-not-look, never zero bytes** — recording an unread shape
/// as an empty response would make "the tool said nothing" and "we could not read
/// what it said" one record, which is `facts::rows_in`'s own distinction.
pub fn decode_response(result: &serde_json::Value) -> Result<Decoded, &'static str> {
    match result {
        serde_json::Value::String(text) => Ok(Decoded {
            bytes: text.as_bytes().to_vec(),
            blocks: 1,
            fidelity: Fidelity::DecodedContent,
        }),
        serde_json::Value::Array(items) => {
            let mut bytes = Vec::new();
            let mut blocks = 0;
            for item in items {
                // A block whose `text` is a string contributes it; anything else
                // in the array is framing this decoder does not claim to read.
                if let Some(text) = item.get("text").and_then(serde_json::Value::as_str) {
                    bytes.extend_from_slice(text.as_bytes());
                    blocks += 1;
                }
            }
            // An EMPTY array is a real response of zero bytes — `[]` is a host
            // saying "nothing", which is not the same as a shape we cannot read.
            if blocks == 0 && !items.is_empty() {
                return Err(RESPONSE_SHAPE_UNREADABLE);
            }
            Ok(Decoded {
                bytes,
                blocks,
                fidelity: Fidelity::DecodedContent,
            })
        }
        serde_json::Value::Object(map) => {
            // A FIXED ORDER, declared here rather than taken from the map: two
            // runs over one value must produce one digest (§6), and iteration
            // order is not a promise a caller can rely on.
            let mut bytes = Vec::new();
            let mut blocks = 0;
            for key in ["stdout", "stderr"] {
                if let Some(text) = map.get(key).and_then(serde_json::Value::as_str) {
                    bytes.extend_from_slice(text.as_bytes());
                    blocks += 1;
                }
            }
            // An empty object is zero bytes, for the empty array's reason. An
            // object with members but none we read is a shape, not an absence.
            if blocks == 0 && !map.is_empty() {
                return Err(RESPONSE_SHAPE_UNREADABLE);
            }
            Ok(Decoded {
                bytes,
                blocks,
                fidelity: Fidelity::DecodedContent,
            })
        }
        // `Null` never reaches here: the caller gates on the member being
        // present, because absent and empty are two records.
        _ => Err(RESPONSE_SHAPE_UNREADABLE),
    }
}

/// A pointer to captured bytes: which stream, how many bytes, and their digest.
///
/// Pointer-only by construction (non-negotiable rule 4) — the record names the
/// bytes and never carries them, which is what lets it be emitted or logged
/// without leaking a program's output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Capture {
    /// The stream these bytes came from.
    pub stream: &'static str,
    /// How many bytes were captured. Zero is a real answer, not an absence.
    pub bytes: u64,
    /// The content digest, lowercase hex — and the key the bytes are stored at.
    pub digest: String,
}

impl Capture {
    /// The handle a consumer addresses this capture by: `<stream>:<digest>`.
    ///
    /// One string rather than two fields at every call site, and the shape
    /// CLOUD-121's `show` and CLOUD-117's predicate both read. A byte range is
    /// appended by the consumer that needs one, never stored here.
    #[must_use]
    pub fn handle(&self) -> String {
        format!("{}:{}", self.stream, self.digest)
    }
}

/// The directory captures live in, under the repository's state root.
fn captures_dir(repo_root: &Path) -> Result<PathBuf> {
    Ok(state::repo_state_dir(repo_root)?.join("captures"))
}

/// The capture store's mode: owner only (CLOUD-918).
///
/// Following [`crate::secrets`]'s `KEY_DIR_MODE`, and a **change from previous
/// behaviour**: the store used to be created with a bare `create_dir_all` and
/// inherited the umask. That was defensible while a capture held only the output
/// of a command the operator themself ran; it is not once the same store can hold
/// a tool response, which is the likeliest thing in an envelope to carry a
/// secret.
///
/// A store written by an earlier binary is **not** retroactively tightened —
/// stated rather than left to be discovered, because the mode is set when a
/// directory is created and nothing here walks an existing one to fix it.
#[cfg(unix)]
const STORE_DIR_MODE: u32 = 0o700;

/// A stored capture's mode: owner read and write.
#[cfg(unix)]
const STORE_FILE_MODE: u32 = 0o600;

/// Create the capture store, owner-only where the platform enforces it.
///
/// `create_dir_all` then `set_permissions`, which is [`crate::secrets`]'s
/// `create_dir_private` idiom and acceptable for its reason: `create_dir_all`
/// takes no mode, and the window between the two holds an EMPTY directory. On
/// Windows the claim is unenforced, the same per-platform arm the state root
/// already carries.
///
/// **Only a store THIS call creates gets its mode set**, which is what makes
/// [`STORE_DIR_MODE`]'s compatibility note true rather than aspirational. Every
/// [`store`] goes through here, so chmod-ing unconditionally would silently
/// tighten a directory an operator may have widened on purpose — and would
/// contradict the promise that an existing store is not retroactively changed.
/// Caught in review on the commit that introduced it.
fn create_store_dir(dir: &Path) -> Result<()> {
    let fresh = !dir.exists();
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create the capture store {}", dir.display()))?;
    #[cfg(unix)]
    if fresh {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(STORE_DIR_MODE))
            .with_context(|| format!("restrict the capture store {}", dir.display()))?;
    }
    // Read only under `unix`, where the mode exists to be set at all.
    #[cfg(not(unix))]
    let _ = fresh;
    Ok(())
}

/// Distinguishes one staging file from another within a process.
///
/// See [`store`]: the pid alone collides when two threads of one `batten` write
/// the same content-addressed record at the same moment.
static STAGING_ATTEMPT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many staging names [`store`] tries before calling it a storage failure.
///
/// The counter restarts per process, so a stale `.tmp` from an interrupted run
/// can collide after pid reuse. A handful of names is plenty to step past one;
/// needing more means the directory itself is the problem.
const STAGING_ATTEMPTS: u32 = 8;

/// Store `bytes` as `stream`'s capture for the repository at `repo_root`.
///
/// Content-addressed and therefore idempotent: storing the same bytes twice
/// leaves one record, and the returned [`Capture`] is identical both times.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or the record cannot
/// be written. **Never a silent skip** — this is the substrate a gate will read,
/// and a capture that quietly did not happen is indistinguishable from a command
/// nobody checked. That is the same posture the receipt store takes, and the
/// reason both are internal errors rather than fail-open allowances.
/// A mutable way to FIND a payload — never a claim about its content
/// (CLOUD-1366).
///
/// # Why this is a type rather than a `String`
///
/// An issue key, a capture handle and a host's spill-file path all discover a
/// candidate, and every one of them can point at different bytes tomorrow: a row
/// is edited, a handle is superseded, a spill file is overwritten in place. A
/// [`identity::ContentAddress`] cannot — it IS the bytes. Carrying both as
/// strings is what let a filename be trusted as content in the first place, so
/// they are separate types with no `From` between them and one named crossing
/// ([`Index::current`]) that has to go through the index.
///
/// **Discovery-only, and the rendering says so.** A locator renders with its kind
/// as a prefix, so a locator that reached a field expecting an address is visible
/// in the bytes rather than merely wrong — and `ContentAddress::parse` refuses
/// every one of these spellings, because none of them is `b3-<version>-<hex>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Locator {
    /// A tracker row. Its payload changes whenever anyone edits the row.
    IssueKey(String),
    /// A capture handle. Ordering selects a current one; the selection moves.
    Handle(String),
    /// A path the host spilled a payload to. Overwritten in place by design.
    SpillPath(String),
}

impl Locator {
    /// The rendered form, kind-prefixed so it can never be read as an address.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Locator::IssueKey(key) => format!("issue:{key}"),
            Locator::Handle(handle) => format!("handle:{handle}"),
            Locator::SpillPath(path) => format!("spill:{path}"),
        }
    }

    /// The kind alone, for a pointer-only diagnostic.
    ///
    /// A spill path is a filesystem path on somebody's machine and an issue key
    /// is a consumer's vocabulary, so a diagnostic that must not carry either
    /// still has something true to say.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Locator::IssueKey(_) => "issue",
            Locator::Handle(_) => "handle",
            Locator::SpillPath(_) => "spill",
        }
    }
}

/// An identity that names a payload and CANNOT be resolved back to it
/// (CLOUD-1366).
///
/// The privacy exemption, as a type. A tool result may be identified — so a gate
/// can say *this is the same answer as last time* — without the bytes being
/// retrievable from the identity. There is deliberately no route from this into
/// [`identity::ContentAddress`] and no resolver that accepts one: a resolvable
/// identity over a payload nobody agreed to store is the leak this exists to
/// make unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueIdentity(String);

impl OpaqueIdentity {
    /// Mint one from a digest a caller already holds.
    #[must_use]
    pub fn new(digest: impl Into<String>) -> OpaqueIdentity {
        OpaqueIdentity(digest.into())
    }

    /// The rendered form, prefixed so it is distinguishable from an address at a
    /// glance and refused by `ContentAddress::parse` at the boundary.
    #[must_use]
    pub fn render(&self) -> String {
        format!("opaque:{}", self.0)
    }
}

/// How a locator's current address compares with the one a caller expected.
///
/// **Aligned with [`crate::store::Resolution`] without duplicating it.** These
/// answer *has the content moved*, where the resolver answers *can these bytes be
/// trusted* — so `Stale` has no resolver counterpart and `Mismatch` has no
/// freshness counterpart. The two vocabularies stay separate because collapsing
/// them would make a moved payload and a corrupt one one word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The index's current address is the expected one.
    Unchanged,
    /// The index names a different current address: the content moved.
    Stale,
    /// The index has no entry for this locator.
    Absent,
    /// The index could not be read; this says nothing about the content.
    Unavailable,
}

impl Freshness {
    /// The stable token used in machine output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Freshness::Unchanged => "unchanged",
            Freshness::Stale => "stale",
            Freshness::Absent => "absent",
            Freshness::Unavailable => "unavailable",
        }
    }
}

/// The Batten-owned map from a locator to the address current for it.
///
/// One line per entry, `<locator>\t<address>`, under the repository's state
/// directory. A flat file rather than a store: the whole point is that a
/// comparison costs a read of THIS file and never a read of a payload.
#[derive(Debug)]
pub struct Index {
    /// Where the index lives.
    at: PathBuf,
}

/// The index file's name inside the state directory.
const INDEX_FILE: &str = "locator-index";

impl Index {
    /// The index for `repo_root`.
    ///
    /// # Errors
    ///
    /// When the repository's state directory cannot be resolved.
    pub fn open(repo_root: &Path) -> Result<Index> {
        Ok(Index {
            at: state::repo_state_dir(repo_root)?.join(INDEX_FILE),
        })
    }

    /// The index at an explicit path, for a caller that already resolved one.
    #[must_use]
    pub fn at(path: PathBuf) -> Index {
        Index { at: path }
    }

    /// Record `address` as current for `locator`, replacing any prior entry.
    ///
    /// # Errors
    ///
    /// When the index cannot be READ, as well as when it cannot be written.
    ///
    /// **The read arm is the one worth stating.** This function rewrites the whole
    /// file from what it read, so a could-not-look folded into "empty" does not
    /// degrade a single answer — it DESTROYS every entry the index held and writes
    /// a one-line file in its place. [`Index::compare`] already reports that case
    /// as [`Freshness::Unavailable`] rather than `Absent`, and a writer that
    /// collapsed the same distinction would make the reader's care pointless:
    /// every prior locator would answer `Absent` afterwards, correctly, about a
    /// mapping this function had just deleted.
    pub fn record(&self, locator: &Locator, address: &identity::ContentAddress) -> Result<()> {
        let Some(existing) = self.lines() else {
            anyhow::bail!(
                "the locator index could not be read, so recording would discard entries it \
                 cannot see"
            );
        };
        let mut kept: Vec<String> = existing
            .into_iter()
            .filter(|line| !line.starts_with(&format!("{}\t", locator.render())))
            .collect();
        kept.push(format!("{}\t{}", locator.render(), address.render()));
        // SORTED, so the file is byte-stable: two runs recording the same set in
        // different orders produce identical bytes, which is what keeps a diff of
        // this file readable and §6's stability claim true of it.
        kept.sort();
        if let Some(parent) = self.at.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.at, kept.join("\n") + "\n")
            .with_context(|| "the locator index could not be written".to_owned())
    }

    /// The address current for `locator`, if the index names one.
    ///
    /// **The one named crossing from a locator to an address.** Nothing converts
    /// between the two types directly, so every route from "how do I find it" to
    /// "what is it" passes through here and is greppable.
    #[must_use]
    pub fn current(&self, locator: &Locator) -> Option<identity::ContentAddress> {
        let prefix = format!("{}\t", locator.render());
        self.lines()?
            .into_iter()
            .find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
            .and_then(|rendered| identity::ContentAddress::parse(&rendered).ok())
    }

    /// Compare what a caller expected against what is current, reading NO payload.
    ///
    /// This is the acceptance clause in one function: the answer comes from the
    /// index file alone, so a store whose payloads are gone still answers, and
    /// deciding freshness never costs the bytes it is deciding about.
    #[must_use]
    pub fn compare(&self, locator: &Locator, expected: &identity::ContentAddress) -> Freshness {
        let Some(lines) = self.lines() else {
            // COULD NOT LOOK, never `Absent`: an unreadable index says nothing
            // about whether an entry exists, and a caller that treats the two
            // alike will re-fetch a payload it already had.
            return Freshness::Unavailable;
        };
        let prefix = format!("{}\t", locator.render());
        match lines
            .into_iter()
            .find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        {
            None => Freshness::Absent,
            Some(rendered) if rendered == expected.render() => Freshness::Unchanged,
            Some(_) => Freshness::Stale,
        }
    }

    /// The index's lines, or `None` where it could not be read.
    ///
    /// An ABSENT index reads as an empty set rather than as could-not-look: a
    /// repository that has recorded nothing yet has an empty index, and calling
    /// that unreadable would make every first comparison `Unavailable`.
    fn lines(&self) -> Option<Vec<String>> {
        match std::fs::read_to_string(&self.at) {
            Ok(text) => Some(text.lines().map(str::to_owned).collect()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Some(Vec::new()),
            Err(_) => None,
        }
    }
}

pub fn store(repo_root: &Path, stream: Stream, bytes: &[u8]) -> Result<Capture> {
    store_in(&captures_dir(repo_root)?, stream, bytes)
}

/// [`store`] into a store directory named outright — [`Spool::open_in`]'s seam,
/// for its reason: resolving the state root reads the OS data directory, which a
/// unit test must not write into.
///
/// # Errors
///
/// As [`store`].
pub fn store_in(dir: &Path, stream: Stream, bytes: &[u8]) -> Result<Capture> {
    let digest = identity::capture_fingerprint(stream.as_str(), bytes).to_hex();
    let dir = dir.to_path_buf();
    create_store_dir(&dir)?;

    // The digest already carries the stream, so the filename does not need to —
    // but it is included so a human listing the directory can tell what they are
    // looking at without hashing anything.
    let path = dir.join(format!("{}-{digest}", stream.as_str()));
    // Write unconditionally rather than skipping an existing file: a truncated
    // record from an interrupted earlier run would otherwise persist forever
    // under a digest that promises different bytes.
    //
    // TEMP-AND-RENAME, pid-suffixed, the idiom `findings.rs` and `journal.rs`
    // already use (CLOUD-430). `File::create` + `write_all` is two observable
    // states, and the first of them is an EMPTY file under a digest that
    // promises bytes — so a concurrent reader, or a second `batten` storing the
    // same content-addressed record at the same moment, could read a record that
    // is real, addressable and torn. `rename` within one directory is atomic, so
    // the only states a reader can see are "absent" and "complete". CLOUD-412's
    // flake is a strong candidate for exactly this.
    //
    // Pid AND a per-process counter. The pid alone is not unique enough: two
    // threads of ONE `batten` storing the same content-addressed record — a
    // bundle whose commands printed the same thing, or two library callers at
    // once — would stage to one path, and the second `rename` would find nothing
    // there. Measured, as `No such file or directory` on the publish.
    // MODE AT CREATION, never a chmod afterwards (`secrets.rs`'s `write_private`
    // idiom, and its reason): a file created world-readable and tightened after
    // the write is world-readable for exactly the window in which the bytes are
    // in it.
    //
    // WHICH FORCES `create_new`, AND `create_new` FORCES THIS RETRY. Setting a
    // mode at creation means `OpenOptions`, and an `OpenOptions` that truncated
    // an existing file would reintroduce the torn-record window the temp-and-
    // rename exists to close. But the staging name is only unique WITHIN a
    // process: the counter restarts at zero every run, so a stale `.tmp` left by
    // an interrupted earlier run collides after pid reuse, and `create_new` then
    // fails a capture that has nothing wrong with it. Minting another attempt is
    // the fix — the loop is bounded, because a directory that refuses every name
    // is a storage failure rather than a collision. Caught in review; the
    // predecessor used `File::create`, which truncated the stale file instead.
    let mut file = None;
    let mut staging = PathBuf::new();
    let mut last: Option<std::io::Error> = None;
    for _ in 0..STAGING_ATTEMPTS {
        let attempt = STAGING_ATTEMPT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        staging = dir.join(format!(
            "{}-{digest}.{}.{attempt}.tmp",
            stream.as_str(),
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(STORE_FILE_MODE);
        }
        match options.open(&staging) {
            Ok(opened) => {
                file = Some(opened);
                break;
            }
            // The one error a different name can fix.
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => last = Some(err),
            Err(err) => {
                return Err(anyhow::Error::from(err))
                    .with_context(|| format!("write the capture {}", staging.display()));
            }
        }
    }
    let Some(mut file) = file else {
        let err = last.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "every staging name was taken",
            )
        });
        return Err(anyhow::Error::from(err))
            .with_context(|| format!("write the capture {}", staging.display()));
    };
    file.write_all(bytes)
        .with_context(|| format!("write the capture {}", staging.display()))?;
    file.sync_all()
        .with_context(|| format!("sync the capture {}", staging.display()))?;
    drop(file);
    std::fs::rename(&staging, &path)
        .with_context(|| format!("publish the capture {}", path.display()))?;

    Ok(Capture {
        stream: stream.as_str(),
        bytes: bytes.len() as u64,
        digest,
    })
}

/// The directory a still-running capture spools into.
fn live_dir(repo_root: &Path) -> Result<PathBuf> {
    Ok(captures_dir(repo_root)?.join("live"))
}

/// The handle a **live** capture is addressed by: `<stream>@<key>`.
///
/// `@` rather than `:`, and that is the whole point: a sealed handle is
/// `<stream>:<digest>` and names bytes that will never change again, while this
/// names a file that is still growing. One separator for each promise means a
/// reader cannot be handed a live handle and treat it as a settled one.
///
/// The `key` is the writing process's pid and the command's index within its
/// bundle, both of which the caller already knows — it spawned the process. That
/// is deliberate: printing the handle would put a pid in Batten's output, and §6
/// byte-stability forbids a field that differs between two identical runs.
/// Takes a [`LiveStream`] rather than a [`Stream`]: [`Stream::Response`] is
/// sealed-only, and the type is what says so.
#[must_use]
pub fn live_handle(stream: LiveStream, key: &str) -> String {
    format!("{}@{key}", stream.stream().as_str())
}

/// What a reader saw when it asked a live capture for bytes.
///
/// `Busy` is an outcome rather than an error, exactly as [`crate::journal`]'s
/// merge treats a lost lock race: losing to an honest writer says nothing about
/// the capture, and the next read gets it. Making it an error would turn a
/// scheduling detail into a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveRead {
    /// The bytes between the requested offset and the watermark.
    Bytes(Vec<u8>),
    /// Another party held the lock; nothing was read.
    Busy,
    /// No spool by that handle — never opened, or already sealed.
    Absent,
}

/// A capture that is still being written, with a committed-length watermark.
///
/// **Forced by the existing design rather than chosen** (CLOUD-430). [`store`]
/// runs after the child is reaped and the digest hashes the *complete* output,
/// so the digest cannot be the key while the stream is open: a mid-run read
/// would either block until exit or return a prefix under a key that promises
/// different bytes. A spool with a watermark is the smallest thing that makes
/// "read what has arrived so far" a well-defined question.
///
/// ## The lock, and why it is `fs4` rather than an in-process primitive
///
/// One writer, N readers — adopted as a **shape**, not as a library. The reason
/// it is a file lock is the property this substrate has to survive: **an OS
/// advisory lock is released by the kernel when its holder dies.** A supervisor
/// `SIGKILL`ed mid-write (CLOUD-427) leaves an in-process lock nowhere and a
/// `flock` released, with the watermark naming exactly how much of the spool is
/// real. `fs4` is already here for [`crate::journal`], so this costs nothing new.
///
/// **Rewritten 2026-08-21 (CLOUD-747).** This section used to argue partly that
/// the crate "links no async runtime and adding one for a lock primitive is a
/// large change to the dependency surface" — a premise that dies the moment
/// CLOUD-745 vendors an HTTP client, while the conclusion does not. The surviving
/// reason is the kernel one above, and it is sufficient on its own. The crate's
/// concurrency posture is `.claude/rules/rust.md`'s to state; this comment is a
/// reader of it, not a second derivation.
///
/// ## What the lock protects, which is less than it looks
///
/// Not the data. The spool has **one** writer, appending, so the bytes need no
/// mutual exclusion; what needs it is the *watermark*, because a reader that saw
/// a torn length would read a range nobody promised. So the discipline is: append
/// the bytes and flush them, then take the lock, publish the new length, release.
/// A reader takes a shared lock, reads the length, and reads only that far — and
/// because the length is published strictly after the bytes it covers, every byte
/// under the watermark is already durable.
///
/// A writer that cannot take the lock **skips the publish** rather than waiting:
/// the watermark then lags by one chunk and the next publish carries both. That
/// is what keeps a reader's contention off the child's critical path.
#[derive(Debug)]
pub struct Spool {
    /// The append-only data file.
    data: std::fs::File,
    /// Where the data file lives, for removal at seal.
    data_path: PathBuf,
    /// The lock file guarding the watermark.
    lock_path: PathBuf,
    /// The published length.
    watermark_path: PathBuf,
    /// How many bytes have been appended, published or not.
    written: u64,
}

impl Spool {
    /// Open (or reopen) the spool for `stream` under `key`.
    ///
    /// # Errors
    ///
    /// Returns an error when the state root cannot be resolved or the spool
    /// cannot be created.
    pub fn open(repo_root: &Path, stream: LiveStream, key: &str) -> Result<Self> {
        Self::open_in(&live_dir(repo_root)?, stream, key)
    }

    /// [`Spool::open`] into a directory named outright.
    ///
    /// The seam a test needs and the one production caller does not: resolving
    /// the state root reads the OS data directory, which a unit test must not
    /// write into. Splitting it keeps that out of the type's contract rather than
    /// putting a test-only branch inside `open`.
    ///
    /// # Errors
    ///
    /// Returns an error when the spool cannot be created.
    pub fn open_in(dir: &Path, stream: LiveStream, key: &str) -> Result<Self> {
        let dir = dir.to_path_buf();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create the live capture directory {}", dir.display()))?;
        let handle = live_handle(stream, key);
        let data_path = dir.join(&handle);
        // Truncating on open, not appending: a pid can be reused, and inheriting
        // a dead run's bytes under a live handle would be worse than losing them.
        let data = std::fs::File::create(&data_path)
            .with_context(|| format!("open the spool {}", data_path.display()))?;
        let watermark_path = dir.join(format!("{handle}.watermark"));
        std::fs::write(&watermark_path, "0\n")
            .with_context(|| format!("open the watermark {}", watermark_path.display()))?;
        Ok(Spool {
            data,
            data_path,
            lock_path: dir.join(format!("{handle}.lock")),
            watermark_path,
            written: 0,
        })
    }

    /// Append `bytes` and publish the new committed length.
    ///
    /// # Errors
    ///
    /// Returns an error when the append fails. A lock the writer could not take
    /// is **not** an error — see the type's docs.
    pub fn commit(&mut self, bytes: &[u8]) -> Result<()> {
        self.data
            .write_all(bytes)
            .with_context(|| format!("append to the spool {}", self.data_path.display()))?;
        self.data
            .flush()
            .with_context(|| format!("flush the spool {}", self.data_path.display()))?;
        self.written += bytes.len() as u64;

        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.lock_path)
            .with_context(|| format!("open the spool lock {}", self.lock_path.display()))?;
        // Fully qualified for `journal.rs`'s reason: `std::fs::File::try_lock`
        // was stabilized under the same name, and an inherent method would
        // silently win over the trait once the MSRV moves.
        match fs4::FileExt::try_lock(&lock) {
            Ok(()) => {}
            // The watermark lags one chunk and the next publish carries both.
            // Waiting here would put a reader's contention on the child's path.
            Err(fs4::TryLockError::WouldBlock) => return Ok(()),
            Err(fs4::TryLockError::Error(err)) => {
                return Err(anyhow::Error::from(err))
                    .with_context(|| format!("take the spool lock {}", self.lock_path.display()));
            }
        }
        let published = std::fs::write(&self.watermark_path, format!("{}\n", self.written));
        drop(lock);
        published
            .with_context(|| format!("publish the watermark {}", self.watermark_path.display()))
    }

    /// A second handle on the same spool, without truncating it.
    ///
    /// For the one case that needs it: a drain that hit its deadline leaves the
    /// tee thread alive holding the shared `Spool`, so the caller cannot take it
    /// by value — and waiting for a thread parked on a pipe a grandchild holds
    /// open is the hang the deadline exists to prevent. Reopening is safe because
    /// a spool's identity is its handle rather than its file descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error when the spool cannot be opened for append.
    pub fn reopen(&self) -> Result<Self> {
        let data = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.data_path)
            .with_context(|| format!("reopen the spool {}", self.data_path.display()))?;
        Ok(Spool {
            data,
            data_path: self.data_path.clone(),
            lock_path: self.lock_path.clone(),
            watermark_path: self.watermark_path.clone(),
            written: self.written,
        })
    }

    /// Seal the spool into its content-addressed record and remove it.
    ///
    /// The sealed record is [`store`]'s, unchanged — which is what makes a
    /// bundled command's capture byte-identical to the same command run alone.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be stored.
    pub fn seal(self, repo_root: &Path, stream: Stream, bytes: &[u8]) -> Result<Capture> {
        let capture = store(repo_root, stream, bytes)?;
        drop(self.data);
        // Best effort: a spool file left behind names a run that ended, and the
        // next run with the same key truncates it. Failing the command because
        // bookkeeping could not be tidied would be the tail wagging the dog.
        drop(std::fs::remove_file(&self.data_path));
        drop(std::fs::remove_file(&self.watermark_path));
        drop(std::fs::remove_file(&self.lock_path));
        Ok(capture)
    }
}

/// Read a live capture from `from`, up to its committed watermark.
///
/// `limit` bounds one read; a reader asking again from where it stopped is
/// idempotent, which is the whole point — "more context" must not require
/// parsing a stream or holding a redirect.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or the spool cannot
/// be read. A lock another party holds is [`LiveRead::Busy`], and an unopened or
/// already-sealed handle is [`LiveRead::Absent`] — neither is an error.
pub fn read_live(
    repo_root: &Path,
    stream: LiveStream,
    key: &str,
    from: u64,
    limit: usize,
) -> Result<LiveRead> {
    read_live_in(&live_dir(repo_root)?, stream, key, from, limit)
}

/// [`read_live`] from a directory named outright — [`Spool::open_in`]'s seam.
///
/// # Errors
///
/// As [`read_live`].
pub fn read_live_in(
    dir: &Path,
    stream: LiveStream,
    key: &str,
    from: u64,
    limit: usize,
) -> Result<LiveRead> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let handle = live_handle(stream, key);
    let data_path = dir.join(&handle);
    let watermark_path = dir.join(format!("{handle}.watermark"));
    let lock_path = dir.join(format!("{handle}.lock"));
    if !data_path.exists() {
        return Ok(LiveRead::Absent);
    }

    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open the spool lock {}", lock_path.display()))?;
    match fs4::FileExt::try_lock_shared(&lock) {
        Ok(()) => {}
        Err(fs4::TryLockError::WouldBlock) => return Ok(LiveRead::Busy),
        Err(fs4::TryLockError::Error(err)) => {
            return Err(anyhow::Error::from(err))
                .with_context(|| format!("take the spool lock {}", lock_path.display()));
        }
    }
    let committed = std::fs::read_to_string(&watermark_path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0);
    drop(lock);

    if from >= committed {
        return Ok(LiveRead::Bytes(Vec::new()));
    }
    let available = committed - from;
    let want = usize::try_from(available).unwrap_or(usize::MAX).min(limit);
    let mut file = std::fs::File::open(&data_path)
        .with_context(|| format!("open the spool {}", data_path.display()))?;
    file.seek(SeekFrom::Start(from))
        .with_context(|| format!("seek the spool {}", data_path.display()))?;
    let mut bytes = vec![0_u8; want];
    // `read_exact`, never `read_to_end`: the file may have grown past the
    // watermark since it was read, and a reader that took those bytes would be
    // reading output the writer has not committed to.
    file.read_exact(&mut bytes)
        .with_context(|| format!("read the spool {}", data_path.display()))?;
    Ok(LiveRead::Bytes(bytes))
}

/// The committed length of a live capture, or `None` if there is no spool.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved.
pub fn live_watermark(repo_root: &Path, stream: LiveStream, key: &str) -> Result<Option<u64>> {
    Ok(live_watermark_in(&live_dir(repo_root)?, stream, key))
}

/// [`live_watermark`] in a directory named outright — [`Spool::open_in`]'s seam.
#[must_use]
pub fn live_watermark_in(dir: &Path, stream: LiveStream, key: &str) -> Option<u64> {
    let path = dir.join(format!("{}.watermark", live_handle(stream, key)));
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
}

/// Read back the bytes a [`Capture`] points at.
///
/// The read half CLOUD-117's predicate and CLOUD-121's `show` both need. It is
/// here rather than in either of them for the same reason the write half is: two
/// readers deriving the path independently is two chances to disagree about it.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or the record cannot
/// be read.
pub fn read(repo_root: &Path, capture: &Capture) -> Result<Vec<u8>> {
    let path = captures_dir(repo_root)?.join(format!("{}-{}", capture.stream, capture.digest));
    std::fs::read(&path).with_context(|| format!("read the capture {}", path.display()))
}

// --- navigation (CLOUD-121) --------------------------------------------------
//
// The half that deletes the re-run. `cmd | tail -N` re-executes a possibly
// non-idempotent command to widen a window the agent had to guess the size of;
// everything below selects against bytes that were captured once and are frozen,
// so widening costs a read and never a second run.

/// A parsed `<stream>:<digest>` handle.
///
/// A type rather than two strings threaded through every call, and parsed rather
/// than trusted: a handle arrives from an agent's argv, so an unknown stream or a
/// non-hex digest is a [`UsageError`] naming the shape it wanted, never a path
/// join that reaches for a file outside the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    /// Which stream the capture holds.
    pub stream: Stream,
    /// The content digest, lowercase hex.
    pub digest: String,
}

impl Handle {
    /// Parse `text` as `<stream>:<digest>`.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a missing separator, a stream
    /// token no [`Stream`] declares, or a digest that is not lowercase hex.
    ///
    /// The digest check is not cosmetic: the digest becomes a path component, so
    /// rejecting anything that is not hex is what stops `..` and a separator from
    /// travelling there. Validating the *shape* rather than sanitising the string
    /// keeps that a property of the parser instead of a habit at each call site.
    pub fn parse(text: &str) -> Result<Self> {
        let Some((stream, digest)) = text.split_once(':') else {
            return Err(UsageError::raise(format!(
                "capture: {text:?} is not a handle — write `<stream>:<digest>`, as `batten capture \
                 list` prints them"
            )));
        };
        let Some(stream) = Stream::ALL.iter().find(|known| known.as_str() == stream) else {
            return Err(UsageError::raise(format!(
                "capture: unknown stream {stream:?} — a capture is one of {}",
                Stream::ALL
                    .iter()
                    .map(|known| known.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        };
        if digest.is_empty() || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(UsageError::raise(format!(
                "capture: {digest:?} is not a digest — it is the lowercase hex `batten capture \
                 list` prints"
            )));
        }
        Ok(Handle {
            stream: *stream,
            digest: digest.to_owned(),
        })
    }
}

impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.stream.as_str(), self.digest)
    }
}

/// What a caller asked to see of a capture.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Selection {
    /// No selection: the pointer alone — stream, digest, byte and line counts.
    ///
    /// The default, and deliberately the cheap one. Content is something a caller
    /// names, so the shape that costs nothing is what an unqualified `show`
    /// returns.
    Summary,
    /// A 1-indexed, inclusive line range, clamped to the capture.
    ///
    /// Clamped rather than refused: widening a window is the whole point, and an
    /// agent that asks for `1:5000` of a 400-line log wants the log, not an error
    /// telling it to guess again. Guessing again is the behaviour this deletes.
    Lines { from: usize, to: usize },
    /// Every line containing a literal substring.
    ///
    /// Literal, not regex, for the reason [`crate::outputs`] states about its own
    /// predicate: a reader should see what would match without evaluating an
    /// expression. `forbid` took the regex decision narrowly (CLOUD-283) and this
    /// is one of the places it was deliberately not taken.
    Grep { needle: String },
    /// A **0-indexed, half-open** byte range, clamped to the capture
    /// (CLOUD-918).
    ///
    /// `from` inclusive, `to` exclusive, both optional; an absent `from` is the
    /// start and an absent `to` is the end. Clamped at both ends for
    /// [`Selection::Lines`]'s reason, and an inverted range selects nothing
    /// rather than panicking.
    ///
    /// **The asymmetry with [`Selection::Lines`] is deliberate rather than
    /// sloppy.** Lines are 1-indexed and inclusive because a human reads a line
    /// number off a rendering that starts at 1, and `grep`'s output feeds
    /// straight back in. Bytes are 0-indexed and half-open because byte ranges
    /// *tile*: `0:N` then `N:M` covers the capture exactly once, with no
    /// off-by-one at the seam, and an absent `to` is the only way to say "to the
    /// end" without first learning the length. Collapsing the two conventions
    /// would make one of them wrong.
    Raw { from: Option<u64>, to: Option<u64> },
}

/// A capture's lines, numbered, as selected.
///
/// Numbered because the number is what makes the next call possible: an agent
/// greps, reads `127`, and asks for `120:135` — navigation, rather than a second
/// guess at a window size.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Line {
    /// The 1-indexed line number within the capture.
    pub number: usize,
    /// The line's text, without its terminator.
    pub text: String,
}

/// The answer to one `capture show`.
///
/// Carries the pointer *and* whatever content was selected, so a `-J` consumer
/// gets the provenance of the bytes in the same document as the bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Selected {
    /// The handle these lines came from.
    pub handle: String,
    /// The capture's total size in bytes.
    pub bytes: u64,
    /// The capture's total line count.
    pub lines: usize,
    /// The selected lines. Empty for [`Selection::Summary`], and empty is also a
    /// real answer for a `--grep` that matched nothing.
    pub selected: Vec<Line>,
    /// Whether decoding the capture replaced anything (CLOUD-918).
    ///
    /// **A property of the whole capture, not of the selection**, and the doc has
    /// to say so or the field lies: the decode is of the whole capture, so
    /// `--lines 1:2` of a log whose byte 4000 is invalid reports `true` even
    /// though every selected line came back clean. What it answers is "is this
    /// view a faithful rendering of the stored bytes", which is a question about
    /// the record.
    ///
    /// Without it a caller cannot tell a capture that decoded cleanly from one
    /// that did not, which is the difference between the line view being a
    /// convenience and being a trap. `--raw` is the operation that gets the bytes
    /// themselves.
    pub lossy: bool,
}

/// The answer to one `capture show --raw`: bytes, and the pointer naming them.
///
/// Separate from [`Selected`] because the two carry different things — one holds
/// decoded lines and the other holds bytes — and a single type with both would
/// invite a caller to read whichever field happened to be populated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSelected {
    /// The handle these bytes came from.
    pub handle: String,
    /// The capture's total size in bytes.
    pub bytes: u64,
    /// The clamped, resolved start offset, inclusive.
    pub from: u64,
    /// The clamped, resolved end offset, exclusive.
    pub to: u64,
    /// The selected bytes, verbatim. Never decoded.
    pub data: Vec<u8>,
}

/// Select a byte range of `bytes`, verbatim.
///
/// **Deliberately not an arm of [`select`].** That function opens with
/// `String::from_utf8_lossy` and every arm reads the decoded view, so a raw arm
/// inside it would sit one refactor away from being decoded too. A separate
/// function is what makes "raw never decodes" a structural property rather than a
/// convention — there is no decoded value in this scope to accidentally read.
#[must_use]
pub fn select_raw(
    handle: &Handle,
    bytes: &[u8],
    from: Option<u64>,
    to: Option<u64>,
) -> RawSelected {
    let len = bytes.len();
    // Clamped at both ends, exactly as `Selection::Lines` is. `try_from`
    // saturating to `usize::MAX` then `min(len)` means a 64-bit offset on a
    // 32-bit target clamps to the end rather than wrapping.
    let start = usize::try_from(from.unwrap_or(0))
        .unwrap_or(usize::MAX)
        .min(len);
    let end = usize::try_from(to.unwrap_or(len as u64))
        .unwrap_or(usize::MAX)
        .min(len);
    // An inverted range selects nothing rather than panicking on the slice.
    let data = bytes.get(start..end).unwrap_or(&[]).to_vec();
    RawSelected {
        handle: handle.to_string(),
        bytes: len as u64,
        from: start as u64,
        to: end.max(start) as u64,
        data,
    }
}

/// Apply `selection` to `bytes`.
///
/// Pure over the bytes, so the arithmetic that decides what a caller sees is
/// testable without a store, a repository, or a spawned child.
///
/// **Lines come from a lossy decode**, and that is the honest reading rather than
/// a shortcut: a capture holds whatever a program wrote, which is not guaranteed
/// to be UTF-8, and refusing an agent line 127 of a build log because byte 4000
/// was invalid would send it back to the re-run. The *bytes* stay exact in the
/// store and are what the digest addresses; only this view is decoded. A trailing
/// newline mints no empty last line — a 400-line log has 400 lines.
#[must_use]
pub fn select(handle: &Handle, bytes: &[u8], selection: &Selection) -> Selected {
    let decoded = String::from_utf8_lossy(bytes);
    // `from_utf8_lossy` returns `Borrowed` if and only if the whole input was
    // valid UTF-8, and `Owned` if and only if it inserted at least one
    // replacement character. That is documented behaviour rather than an
    // allocation optimisation, so the discriminant is a faithful answer to "did
    // the decode replace anything" and costs no second pass.
    let lossy = matches!(decoded, std::borrow::Cow::Owned(_));
    let all: Vec<&str> = decoded.lines().collect();
    let numbered = |index: usize, text: &str| Line {
        number: index + 1,
        text: text.to_owned(),
    };
    let selected = match selection {
        Selection::Lines { from, to } => {
            // Clamped at both ends, and an inverted range selects nothing rather
            // than panicking on the slice — `5:2` is a caller error that costs an
            // empty answer, never a crash on a reachable path.
            let start = from.saturating_sub(1).min(all.len());
            let end = (*to).min(all.len());
            all.get(start..end)
                .unwrap_or(&[])
                .iter()
                .enumerate()
                .map(|(offset, text)| numbered(start + offset, text))
                .collect()
        }
        Selection::Grep { needle } => all
            .iter()
            .enumerate()
            .filter(|(_, text)| text.contains(needle.as_str()))
            .map(|(index, text)| numbered(index, text))
            .collect(),
        // Neither selects a line, for two different reasons that happen to have
        // the same answer: `Summary` is the pointer by definition, and a byte
        // range is not a line view at all — `select_raw` answers that one, and
        // returning the pointer here keeps the two functions from producing two
        // different answers for one request.
        Selection::Summary | Selection::Raw { .. } => Vec::new(),
    };
    Selected {
        handle: handle.to_string(),
        bytes: bytes.len() as u64,
        lines: all.len(),
        selected,
        lossy,
    }
}

/// Every capture in the repository's store, in a fixed order.
///
/// Sorted by handle rather than by mtime, so a listing is byte-stable (§6) and
/// two runs over an unchanged store agree. An mtime order would make the answer a
/// function of when captures happened, which is exactly the kind of field
/// [`store`] refuses to record.
///
/// A store that does not exist yet is an **empty listing, not an error**: a
/// repository where `exec` has never run has honestly captured nothing.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved, or when the store
/// exists and cannot be read.
pub fn list(repo_root: &Path) -> Result<Vec<Capture>> {
    list_in(&captures_dir(repo_root)?)
}

/// [`list`] over a store directory named outright — [`store_in`]'s seam.
///
/// # Errors
///
/// As [`list`].
pub fn list_in(dir: &Path) -> Result<Vec<Capture>> {
    let dir = dir.to_path_buf();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("read the capture store {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("read the capture store {}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // A file the store did not write is skipped rather than reported: the
        // directory is Batten's, but a stray file there is not evidence about any
        // command, and inventing a capture from one would be a fabricated pointer.
        let Some((stream, digest)) = name.split_once('-') else {
            continue;
        };
        if Handle::parse(&format!("{stream}:{digest}")).is_err() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Some(stream) = Stream::ALL.iter().find(|known| known.as_str() == stream) else {
            continue;
        };
        found.push(Capture {
            stream: stream.as_str(),
            bytes: meta.len(),
            digest: digest.to_owned(),
        });
    }
    found.sort_by_key(Capture::handle);
    Ok(found)
}

/// One call's capture outcome — the **invocation** identity (CLOUD-917).
///
/// Two identities, and deduplication may not erase either. The blob is keyed by
/// CONTENT, so identical bytes are one record and the record carries no
/// timestamp; this row is keyed by CALL, so forty calls that produced the same
/// bytes are one blob and forty rows. A session that ran one command repeatedly
/// can still say which call was which, and the timestamp a response genuinely
/// needs lives here — where it is a fact about an invocation — rather than on the
/// blob, where it would break §6 byte-stability.
///
/// **Pointer-only** (non-negotiable rule 4): a digest **or** a reason id, never
/// bytes. [`CallRow::class`] is a path *class* rather than a path, because where
/// a host spilled a response is disk layout and differs per machine.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CallRow {
    /// Monotone within [`CallRow::session`], from zero. **Not a clock**: it is
    /// the count of rows already recorded for this session, read under the same
    /// lock the append takes, so two writers cannot mint one ordinal.
    pub order: u64,
    /// The host's own session id, so ordering is scoped to a conversation.
    pub session: String,
    /// Which surface the bytes came from — a fixed token, never a path.
    pub source: String,
    /// The harness, as [`crate::hook::Harness::as_str`] spells it.
    pub host: String,
    /// The tool the host named.
    pub tool: String,
    /// The event, as [`crate::hook::Event::as_str`] spells it.
    pub event: String,
    /// The fidelity, as [`Fidelity::as_str`] spells it.
    pub fidelity: String,
    /// When the call was seen, RFC3339.
    ///
    /// **This is the timestamp the blob refuses to carry**, and it is legitimate
    /// here for the reason the blob's absence is legitimate there: a capture keyed
    /// by content must be a pure function of that content, while a row keyed by
    /// invocation is a fact about a moment. It is therefore **never rendered** by
    /// `capture list --calls` — a listing that printed it would stop being
    /// byte-stable across runs (§6), which is the property the ordering rule
    /// below exists to protect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seen_at: Option<String>,
    /// For a spilled response, the CLASS of path it came from. Never a path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// The content digest. Exactly one of this and [`CallRow::absent`] is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// A recorded absence: one of this module's reason ids.
    ///
    /// **The key that distinguishes the two three-valued outcomes.** A row with
    /// a digest and a row with an absence differ in which keys EXIST, not in a
    /// count — so "the tool returned nothing" and "nobody looked" cannot collapse
    /// into one record, which is CLOUD-251's vacuous pass on a new surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absent: Option<String>,
}

/// The bound on response captures (CLOUD-918).
///
/// Enforced **at write time**, and the trigger is the write — never a clock,
/// never a schedule, never a background sweeper. That is
/// `.claude/rules/toolchain.md`'s split between a gate and a schedule, and
/// [`prune`]'s own doc already refuses a time-based sweeper on the same grounds.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    /// Total response-capture bytes the store may hold. Absent means the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Response-capture records the store may hold. Absent means the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_records: Option<u64>,
    /// The payload size at which a rendered response switches from carrying the
    /// bytes to carrying an address (CLOUD-1367).
    ///
    /// **An ECONOMIC threshold and nothing else.** A payload at or under it is
    /// cheaper to send than an address plus the round trip to resolve one; over
    /// it, the address wins. Absent means [`DEFAULT_INLINE_MAX_BYTES`].
    ///
    /// It is deliberately NOT a privacy or safety cap. Those refuse to emit
    /// content at all and are their own rows; this one only ever changes the
    /// REPRESENTATION, and both routes carry the same semantic result. Reusing
    /// one number for both would mean a measurement about token cost silently
    /// deciding what may leave the process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_max_bytes: Option<u64>,
}

/// How a response renders: the bytes themselves, or an address for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Small enough that the bytes are cheaper than the address plus a resolve.
    Inline,
    /// Large enough that a fixed-length address wins.
    Addressed,
}

impl Transport {
    /// The stable token used in machine output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Transport::Inline => "inline",
            Transport::Addressed => "addressed",
        }
    }
}

/// The default inline threshold.
///
/// **Derived from the rendered grammar rather than chosen** (CLOUD-1367). An
/// address costs [`identity::ADDRESS_RENDERED_LEN`] characters plus the resolve
/// that follows it; below a few hundred bytes the payload is simply cheaper than
/// its own pointer, and `bench/address-transport/RESULTS.md` is the measurement
/// this number is read off. A round 1 KiB is the smallest declared value the
/// measured curve supports, and the bench is what moves it.
pub const DEFAULT_INLINE_MAX_BYTES: u64 = 1024;

/// Which transport a payload of `len` bytes takes under `config`.
///
/// **At or under the threshold is inline**, so the boundary is inclusive and a
/// payload exactly at the declared size still carries its bytes. That is stated
/// here because an off-by-one is invisible in every other reading — the fixtures
/// sit one byte either side for exactly this reason.
#[must_use]
pub fn transport_for(config: Option<&CaptureConfig>, len: u64) -> Transport {
    let threshold = config
        .and_then(|it| it.inline_max_bytes)
        .unwrap_or(DEFAULT_INLINE_MAX_BYTES);
    if len <= threshold {
        Transport::Inline
    } else {
        Transport::Addressed
    }
}

/// The default byte bound on response captures.
///
/// **Bounded by default, unlike `exec` captures**, because a response arrives per
/// mediated call rather than per distinct command output.
pub const DEFAULT_RESPONSE_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// The default record bound on response captures.
pub const DEFAULT_RESPONSE_MAX_RECORDS: u64 = 1024;

/// Evict oldest response captures until the store is inside `config`.
///
/// **Oldest by the call log's recorded order**, never by mtime: the log is the
/// only thing that knows which call came first, and an mtime order would make
/// eviction a function of when the filesystem happened to touch a file.
///
/// Only [`Stream::Response`] records are candidates. A `stdout` or `stderr`
/// capture is `exec`'s and is never evicted here, which is what keeps today's
/// behaviour byte-identical for that consumer.
///
/// # Errors
///
/// Returns an error when the store cannot be read or a record cannot be removed.
pub fn evict_to_budget(repo_root: &Path, config: Option<&CaptureConfig>) -> Result<usize> {
    evict_to_budget_in(&captures_dir(repo_root)?, config)
}

/// [`evict_to_budget`] over a store directory named outright — [`store_in`]'s
/// seam.
///
/// # Errors
///
/// As [`evict_to_budget`].
pub fn evict_to_budget_in(dir: &Path, config: Option<&CaptureConfig>) -> Result<usize> {
    let max_bytes = config
        .and_then(|held| held.max_bytes)
        .unwrap_or(DEFAULT_RESPONSE_MAX_BYTES);
    let max_records = config
        .and_then(|held| held.max_records)
        .unwrap_or(DEFAULT_RESPONSE_MAX_RECORDS);
    // FIRST, because the blob budget below can be satisfied while the log is
    // not: see `bound_calls`. This is the only trim, and it is unconditional.
    bound_calls(dir, max_records)?;
    let held: Vec<Capture> = list_in(dir)?
        .into_iter()
        .filter(|record| record.stream == Stream::Response.as_str())
        .collect();
    let mut total: u64 = held.iter().map(|record| record.bytes).sum();
    let mut count = held.len() as u64;
    if total <= max_bytes && count <= max_records {
        return Ok(0);
    }
    // THE LOG'S APPEND ORDER, never `calls_in`'s sorted view. That view is sorted
    // by `(session, order)` for §6 byte-stability, and `order` is monotone only
    // WITHIN a session — so across two sessions the sorted view is
    // session-lexicographic, and consuming it would evict every row of the
    // alphabetically-first session before any row of a later-sorting one. A
    // store holding an older `zzz` and a newer `aaa` would then evict its newest
    // responses first. Append order is the only cross-session order the log
    // actually carries. A digest named by no row cannot be ordered at all, so it
    // is evicted last rather than first — guessing an order for it would be
    // inventing provenance.
    let ordered = read_calls(&dir.join("calls"));
    // A digest-keyed lookup and a taken-set, rather than a scan inside a scan.
    // The row count is not bounded by the record count — one row per call, many
    // calls per record — so the nested form is quadratic in the log's length, on
    // a path that runs per tool call. Same order, linear cost.
    let by_digest: std::collections::HashMap<&str, &Capture> = held
        .iter()
        .map(|record| (record.digest.as_str(), record))
        .collect();
    let mut taken: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut candidates: Vec<Capture> = Vec::new();
    for row in &ordered {
        let Some(digest) = row.digest.as_deref() else {
            continue;
        };
        if let Some(found) = by_digest.get(digest)
            && taken.insert(found.digest.as_str())
        {
            candidates.push((*found).clone());
        }
    }
    for record in &held {
        if !taken.contains(record.digest.as_str()) {
            candidates.push(record.clone());
        }
    }
    let mut removed = 0;
    for record in candidates {
        if total <= max_bytes && count <= max_records {
            break;
        }
        let path = dir.join(format!("{}-{}", record.stream, record.digest));
        if std::fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(record.bytes);
            count = count.saturating_sub(1);
            removed += 1;
        }
    }
    Ok(removed)
}

/// The `source` a recorded `--raw` retrieval is filed under.
///
/// A fixed token, never a path, and distinct from every dispatch or harness
/// source so a reader counting escapes cannot mistake one for a call.
pub const RAW_ESCAPE: &str = "raw-escape";

/// Record that a `--raw` retrieval was spent (CLOUD-1260).
///
/// # The invariant this pays for, in its true form
///
/// **The model has no unreduced route to the payload BY DEFAULT.** The strong
/// form — *no unreduced route* — is false, and it is Batten that falsifies it:
/// `capture show --raw` writes the selected bytes to stdout verbatim, and
/// `--lines`/`--bytes`/`--grep` select from the same store. **That route stays**,
/// because a deliberate, single-purpose, visible retrieval is not the failure
/// mode; 973 reflexive full-body reads are.
///
/// What follows is an obligation rather than a caveat. An override in this
/// repository is *"a record, never a variable somebody knows"*, and the same
/// reasoning applies one surface over: an UNRECORDED `--raw` is how a reduction
/// silently stops mattering, because nothing distinguishes a session that spent
/// the escape twice from one that never needed it. So the escape leaves a row,
/// and the acceptance measurement can then say *zero unreduced payloads on the
/// default path, with every retrieval appearing as a recorded escape* — which is
/// a count rather than an assertion.
///
/// **It is a record and never a refusal.** Nothing here decides anything: the
/// bytes are already going to stdout, and a failure to append must not turn a
/// legitimate retrieval into an error. The caller reports and continues.
///
/// **Pointer-only, like every row in this log**: the handle's stream and digest,
/// the byte count selected, and the fixed source token. Never a byte of what was
/// retrieved.
///
/// # Errors
///
/// As [`record_call`] — the caller is expected to report rather than raise.
pub fn record_escape(repo_root: &Path, handle: &Handle, selected: usize) -> Result<()> {
    record_call(
        repo_root,
        &CallRow {
            order: 0,
            session: crate::session::declared()
                .map(|declared| declared.key)
                .unwrap_or_default(),
            source: RAW_ESCAPE.to_owned(),
            host: "batten".to_owned(),
            // The SELECTION is what was spent, and it is a count rather than a
            // range: a reader of this log is answering "how much left the store",
            // not "which bytes".
            tool: format!("{selected}"),
            event: "raw".to_owned(),
            fidelity: Fidelity::LexicalBytes.as_str().to_owned(),
            seen_at: None,
            class: None,
            digest: Some(handle.digest.clone()),
            absent: None,
        },
    )
}

/// How many times [`record_call`] retries a held lock before giving up.
///
/// Bounded rather than unbounded: this runs on the mediated path, where a stuck
/// holder must not block a tool call.
const CALL_LOCK_ATTEMPTS: u32 = 50;

/// How long [`record_call`] waits between attempts.
const CALL_LOCK_BACKOFF: std::time::Duration = std::time::Duration::from_millis(2);

/// Append one call row, minting its per-session order under the lock.
///
/// JSONL, one object per line, and byte-stable because `serde_json` emits a
/// struct's fields in declaration order.
///
/// **A lost lock RETRIES rather than skipping**, which is the opposite of
/// [`Spool::commit`]'s watermark publish and deliberately so. There, a skipped
/// publish costs a reader one stale length and the next publish carries both.
/// Here, a skipped row is a call nobody recorded — precisely what this log
/// exists to prevent — so contention waits instead.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or the log cannot be
/// appended to. The mediated caller does not propagate it: on that surface a
/// storage failure is recorded and reported, never raised.
pub fn record_call(repo_root: &Path, row: &CallRow) -> Result<()> {
    record_call_in(&captures_dir(repo_root)?, row)
}

/// [`record_call`] into a store directory named outright — [`store_in`]'s seam.
///
/// # Errors
///
/// As [`record_call`].
pub fn record_call_in(dir: &Path, row: &CallRow) -> Result<()> {
    let dir = dir.to_path_buf();
    create_store_dir(&dir)?;
    let path = dir.join("calls");
    let Some(lock) = take_call_lock(&dir)? else {
        anyhow::bail!(
            "the call log lock in {} stayed held; the row was not recorded",
            dir.display()
        );
    };
    let order = next_order(&path, &row.session);
    let mut minted = row.clone();
    minted.order = order;
    let line = serde_json::to_string(&minted).context("render a call row")?;
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(STORE_FILE_MODE);
    }
    let appended = options
        .open(&path)
        .and_then(|mut file| writeln!(file, "{line}"));
    drop(lock);
    appended.with_context(|| format!("append to the call log {}", path.display()))?;
    Ok(())
}

/// The call log's exclusive lock, or `None` when the bound was exhausted.
///
/// **One lock, two writers**, which is what makes it worth a function rather
/// than a block: the append in [`record_call_in`] and the whole-file rewrite in
/// [`trim_calls`] contend on the same bytes, and a rewrite that renames a new
/// inode over the old one while an append holds a descriptor on the old one
/// loses that appended row outright — the row this log exists to keep.
///
/// `try_lock` is the same call `Spool::commit` makes; the difference is what
/// each does with a refusal — there it returns, here it waits. Bounded, because
/// an unbounded wait on the mediated path would let a stuck holder block a tool
/// call, and no Batten failure may do that. `None` is the exhausted bound, and
/// the two callers read it differently: an unrecorded row is a failure, an
/// untrimmed log is not.
///
/// # Errors
///
/// Returns an error when the lock file cannot be opened, or when the lock call
/// itself fails for a reason other than contention.
fn take_call_lock(dir: &Path) -> Result<Option<std::fs::File>> {
    let lock_path = dir.join("calls.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open the call log lock {}", lock_path.display()))?;
    for _ in 0..CALL_LOCK_ATTEMPTS {
        match fs4::FileExt::try_lock(&lock) {
            Ok(()) => return Ok(Some(lock)),
            Err(fs4::TryLockError::WouldBlock) => {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "the backoff between `try_lock` attempts, bounded by \
                              `CALL_LOCK_ATTEMPTS`: the loop exits on the lock being taken or on \
                              that count being exhausted, which is the `None` this returns — an \
                              unbounded wait here would let a stuck holder block a mediated call \
                              (CLOUD-1177)"
                )]
                std::thread::sleep(CALL_LOCK_BACKOFF);
            }
            Err(fs4::TryLockError::Error(err)) => {
                return Err(anyhow::Error::from(err))
                    .with_context(|| format!("take the call log lock {}", lock_path.display()));
            }
        }
    }
    Ok(None)
}

/// The smallest number of bytes a rendered [`CallRow`] can occupy.
///
/// A floor, deliberately far below the real minimum, because it is only ever
/// used to decide whether the log is SMALL ENOUGH to skip parsing: a floor that
/// is too low costs an unnecessary parse, while one that is too high skips a
/// trim that was due. `a_rendered_row_never_falls_under_the_row_floor` is the
/// gate on the direction that matters.
const MIN_CALL_ROW_BYTES: u64 = 64;

/// Hold the log inside its bound, ahead of the blob budget.
///
/// **Ahead of it, and that ordering is the whole function.** Response blobs are
/// content-addressed, so a session repeating one response leaves the byte and
/// record counts flat while the log gains a row per call — a store permanently
/// inside its blob budget whose log grows forever. Trimming after the budget
/// check therefore never ran in exactly the state the bound exists for, and
/// [`next_order`]'s cost argument rests on that bound being real.
///
/// **One `stat` on the common path.** The log is read and parsed only when its
/// SIZE could hold more rows than the bound allows, which is what keeps this
/// affordable on the mediated post-tool path: the alternative is a full parse
/// per tool call, which is the cost shape [`next_order`] exists to avoid.
///
/// # Errors
///
/// Returns an error when the log cannot be read, rewritten, or published.
fn bound_calls(dir: &Path, max_records: u64) -> Result<()> {
    let allowed = max_records.saturating_mul(4);
    let path = dir.join("calls");
    let Ok(metadata) = std::fs::metadata(&path) else {
        // No log is not a failure to read one: nothing has been recorded yet.
        return Ok(());
    };
    if metadata.len() <= allowed.saturating_mul(MIN_CALL_ROW_BYTES) {
        return Ok(());
    }
    let Some(lock) = take_call_lock(dir)? else {
        // An untrimmed log is not a failure — the next call tries again, and the
        // holder that refused this lock is itself a writer. Failing here would
        // turn contention into a reported storage error.
        return Ok(());
    };
    // Append order here too, and for a sharper reason than the eviction walk's:
    // `trim_calls` keeps a SUFFIX, so a session-lexicographic order would keep
    // the alphabetically-last session's rows and drop everything recent from
    // every other one.
    let ordered = read_calls(&dir.join("calls"));
    let trimmed = trim_calls(dir, &ordered, max_records);
    drop(lock);
    trimmed
}

/// Drop the oldest rows so the log stays inside `max_records`.
///
/// **Bounded by the same number the blobs are**, rather than a second knob: a
/// row and the record it names are one fact about one call, so keeping rows for
/// records that have been evicted would leave the log describing a store that no
/// longer exists. Rewritten whole under the caller's lock, because a partial
/// rewrite of an append-only log is worse than an oversized one.
///
/// A generous multiple of the record bound, not the bound itself: an ABSENCE row
/// names no record, and those are exactly the rows a reader most wants to keep —
/// "no record" must not come to mean "no calls".
fn trim_calls(dir: &Path, ordered: &[CallRow], max_records: u64) -> Result<()> {
    let allowed = usize::try_from(max_records.saturating_mul(4)).unwrap_or(usize::MAX);
    if ordered.len() <= allowed {
        return Ok(());
    }
    let keep = &ordered[ordered.len() - allowed..];
    let mut rendered = String::new();
    for row in keep {
        let line = serde_json::to_string(row).context("render a call row")?;
        rendered.push_str(&line);
        rendered.push('\n');
    }
    let path = dir.join("calls");
    let staging = dir.join("calls.trim");
    std::fs::write(&staging, rendered)
        .with_context(|| format!("stage the trimmed call log {}", staging.display()))?;
    std::fs::rename(&staging, &path)
        .with_context(|| format!("publish the trimmed call log {}", path.display()))?;
    Ok(())
}

/// The next ordinal for `session`, read from the tail of the log.
///
/// **Backwards, and that is a cost decision rather than a style one.** This runs
/// on the mediated post-tool path — the hottest path in the binary — and the
/// obvious implementation parses every row written so far to count the ones
/// matching this session, which makes the per-call cost grow with the session's
/// own history. That is precisely the shape CLOUD-851 measured: a store
/// acquisition that regressed `check` 2.103x with every test still green,
/// because none of them measured invocation cost. Caught in review, before the
/// bench arm that would have measured it landed.
///
/// Scanning from the end stops at the newest row for this session, which in the
/// common case — a session appending to its own recent rows — is the last line.
/// A session with no rows yet walks the log once and answers zero; the bound on
/// THAT is the log trimming in [`evict_to_budget_in`].
fn next_order(path: &Path, session: &str) -> u64 {
    let Ok(text) = std::fs::read_to_string(path) else {
        return 0;
    };
    for line in text.lines().rev() {
        if let Ok(row) = serde_json::from_str::<CallRow>(line)
            && row.session == session
        {
            return row.order.saturating_add(1);
        }
    }
    0
}

/// Read the log, skipping any line that does not parse.
///
/// A torn or hand-edited line is skipped rather than reported, for [`list`]'s
/// reason: a row nothing wrote is not evidence about a call, and inventing one
/// from it would be a fabricated provenance record.
fn read_calls(path: &Path) -> Vec<CallRow> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| serde_json::from_str::<CallRow>(line).ok())
        .collect()
}

/// Every recorded call, in a fixed order.
///
/// Sorted by `(session, order)` — never by mtime and never by `seen_at`, for
/// [`list`]'s §6 reason: an ordering that is a function of when things happened
/// makes two runs over an unchanged log disagree.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved.
pub fn calls(repo_root: &Path) -> Result<Vec<CallRow>> {
    calls_in(&captures_dir(repo_root)?)
}

/// [`calls`] over a store directory named outright — [`store_in`]'s seam.
///
/// # Errors
///
/// As [`calls`].
pub fn calls_in(dir: &Path) -> Result<Vec<CallRow>> {
    let mut rows = read_calls(&dir.join("calls"));
    rows.sort_by(|left, right| {
        left.session
            .cmp(&right.session)
            .then(left.order.cmp(&right.order))
    });
    Ok(rows)
}

// --- resolution by key (CLOUD-1121) ------------------------------------------
//
// The half that deletes the handle hunt. CLOUD-121 made a captured payload
// recoverable, and CLOUD-990 pointed the board gates' remedies at it — but the
// route still ran `capture list`, eyeballed the listing for the right handle,
// and piped `capture show --raw` into the gate. Finding the handle is itself a
// read, so the remedy for "a payload should not have to enter context" began by
// putting a listing into context. Keying the lookup on the id the gate already
// holds removes the search and the pipe together.

/// What a caller is looking for: a tool's response carrying a key at a path.
#[derive(Debug, Clone)]
pub struct Selector<'a> {
    /// Tool selectors, matched by [`crate::rules::selects_tool_name`] so a row
    /// naming `get_issue` matches `mcp__<server>__get_issue` whatever label the
    /// host has rotated the server under (CLOUD-178).
    ///
    /// Several rather than one, because the newest response carrying a key is
    /// not always a read: a lint run straight after a write must see the body
    /// the write stored, which is CLOUD-1118's defect in the transcript route.
    /// A caller naming both tools gets whichever spoke last.
    pub tools: &'a [String],
    /// The value the selected scalar must equal — an issue key, in practice.
    pub key: &'a str,
    /// The dotted path the key sits at. `id` for a tracker payload.
    pub key_at: &'a str,
}

/// A resolved capture, plus the provenance that chose it.
///
/// **Pointer-only** (non-negotiable rule 4): a handle, a byte count, the tool
/// name and the ordinal. No field a body can occupy, which is what makes the
/// emitted line structurally incapable of carrying one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The capture itself — handle and byte count.
    pub capture: Capture,
    /// The tool whose response this was, as the host named it.
    pub tool: String,
    /// The row's ordinal within its session.
    pub order: u64,
}

/// Whether a recorded fidelity token names a complete capture.
///
/// Resolved through [`Fidelity::ALL`] rather than by matching the token strings
/// here, so an arm added to the vocabulary is classified by
/// [`Fidelity::is_complete`] instead of falling through a list nobody updated.
/// An **unrecognised** token is not complete: a store written by a newer binary
/// may hold an arm this one cannot reason about, and guessing that it is whole
/// is the fail-open direction.
fn token_is_complete(token: &str) -> bool {
    Fidelity::ALL
        .iter()
        .find(|known| known.as_str() == token)
        .is_some_and(|known| known.is_complete())
}

/// Resolve the most recent response matching `selector`.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved, or when the store
/// exists and cannot be read.
pub fn find(repo_root: &Path, selector: &Selector<'_>) -> Result<Option<Resolved>> {
    find_in(&captures_dir(repo_root)?, selector)
}

/// [`find`] over a store directory named outright — [`store_in`]'s seam.
///
/// **Read in the log's APPEND order and taken from the end**, which is the one
/// ordering question this function has to get right. [`calls_in`] sorts by
/// `(session, order)` for §6 byte-stability, and that order is not chronological
/// across sessions — `order` is monotone *within* a session, so a sort by it
/// would let a stale session's row outrank a live one's. The append order is
/// chronological across all of them and is still a pure function of the log's
/// bytes, so recency costs no clock: `seen_at` is never read, and two runs over
/// an unchanged log return the same answer. It is the ordering
/// [`evict_to_budget`] already works in.
///
/// # Errors
///
/// As [`find`].
pub fn find_in(dir: &Path, selector: &Selector<'_>) -> Result<Option<Resolved>> {
    for row in read_calls(&dir.join("calls")).iter().rev() {
        let Some(digest) = row.digest.as_deref() else {
            continue;
        };
        if !token_is_complete(&row.fidelity) {
            continue;
        }
        if !selector
            .tools
            .iter()
            .any(|tool| crate::rules::selects_tool_name(tool, &row.tool))
        {
            continue;
        }
        // A row whose blob has been pruned is skipped rather than reported: the
        // log outlives an evicted capture by design, so a missing file is an
        // ordinary state of the store and not a failure to look.
        let path = dir.join(format!("{}-{digest}", Stream::Response.as_str()));
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if crate::mint::scalar(&value, selector.key_at).as_deref() != Some(selector.key) {
            continue;
        }
        return Ok(Some(Resolved {
            capture: Capture {
                stream: Stream::Response.as_str(),
                bytes: bytes.len() as u64,
                digest: digest.to_owned(),
            },
            tool: row.tool.clone(),
            order: row.order,
        }));
    }
    Ok(None)
}

/// Remove every capture in the repository's store, returning how many went.
///
/// **The whole lifecycle, and that is the design.** A capture is content-addressed
/// and never expires on its own; this is the one removal path. A time-based
/// sweeper would put a property of the world inside a verb — the split
/// `.claude/rules/toolchain.md` draws between a gate and a schedule — and the
/// store is bounded by how many *distinct* outputs a repository produces, not by
/// how often it runs them, because identical bytes are one record.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or a record cannot be
/// removed. A store that does not exist removes nothing and is not an error.
pub fn prune(repo_root: &Path) -> Result<usize> {
    let dir = captures_dir(repo_root)?;
    let mut removed = 0;
    for capture in list(repo_root)? {
        let path = dir.join(format!("{}-{}", capture.stream, capture.digest));
        std::fs::remove_file(&path)
            .with_context(|| format!("remove the capture {}", path.display()))?;
        removed += 1;
    }
    Ok(removed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn every_stream_round_trips_through_its_token() {
        for stream in Stream::ALL {
            let token = stream.as_str();
            assert!(!token.is_empty());
            assert_eq!(
                Stream::ALL
                    .iter()
                    .filter(|other| other.as_str() == token)
                    .count(),
                1,
                "{token} is declared twice"
            );
        }
    }

    // `#[cfg(unix)]`, because the constants it reads exist only there — an
    // ungated test does not compile on Windows, which `cross-check` covers.
    #[cfg(unix)]
    #[test]
    fn the_store_mode_is_decided_by_a_constant_rather_than_by_the_umask() {
        // THE EXTRACTED DECISION, which is what `.claude/rules/rust.md` asks for
        // where the environment cannot produce the failing condition: this sandbox
        // runs as root, so permission bits never bite and a test that tried to
        // assert enforcement would assert its own premise. What is checkable is
        // the value the code decided on, and that it is owner-only.
        assert_eq!(STORE_DIR_MODE, 0o700);
        assert_eq!(STORE_FILE_MODE, 0o600);
        // Beside `secrets.rs`, whose modes these follow: a capture store that can
        // hold a tool response is at least as sensitive as a key store.
        assert_eq!(
            STORE_DIR_MODE & 0o077,
            0,
            "the store is group/other-readable"
        );
        assert_eq!(
            STORE_FILE_MODE & 0o077,
            0,
            "a record is group/other-readable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_stored_capture_and_its_store_are_created_owner_only() {
        // The bits we SET, read back off the filesystem — not enforcement, which
        // root would defeat. This is the half a constant assertion cannot cover:
        // that the decision actually reaches the two `create` calls.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("batten-store-mode-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        let store = dir.join("captures");
        create_store_dir(&store).unwrap();
        assert_eq!(
            std::fs::metadata(&store).unwrap().permissions().mode() & 0o777,
            STORE_DIR_MODE
        );
        // The record's mode is set at creation rather than chmod'ed after, so the
        // bytes are never briefly world-readable. Exercised through the same
        // options the store builds.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(STORE_FILE_MODE);
        }
        let record = store.join("response-deadbeef");
        drop(options.open(&record).unwrap());
        assert_eq!(
            std::fs::metadata(&record).unwrap().permissions().mode() & 0o777,
            STORE_FILE_MODE
        );
        drop(std::fs::remove_dir_all(&dir));
    }

    /// A store directory under this process's own scratch space.
    ///
    /// `*_in` rather than the repo-rooted entry points, for `scratch_live`'s
    /// reason: resolving the state root reads the OS data directory, and a unit
    /// test must not write into a developer's.
    fn scratch_store(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("batten-calls-{}-{name}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        dir
    }

    /// A call row with the fields a test does not care about filled in.
    fn row(session: &str, digest: Option<&str>, absent: Option<&str>) -> CallRow {
        CallRow {
            order: 0,
            session: session.to_owned(),
            source: "response".to_owned(),
            host: "claude-code".to_owned(),
            tool: "Bash".to_owned(),
            event: "post-tool".to_owned(),
            fidelity: Fidelity::DecodedContent.as_str().to_owned(),
            seen_at: None,
            class: None,
            digest: digest.map(str::to_owned),
            absent: absent.map(str::to_owned),
        }
    }

    #[test]
    fn a_recorded_absence_is_a_reason_id_rather_than_a_missing_row() {
        // CLOUD-251's collapse, refused at the record shape: "the tool returned
        // nothing" and "nobody looked" differ in which KEYS EXIST, not in a
        // count, so no reader can conflate them by comparing numbers.
        let captured = serde_json::to_string(&row("s", Some("beef"), None)).unwrap();
        let absent =
            serde_json::to_string(&row("s", None, Some("capture-store-unwritable"))).unwrap();
        assert!(captured.contains("\"digest\""));
        assert!(!captured.contains("\"absent\""));
        assert!(absent.contains("\"absent\""));
        assert!(!absent.contains("\"digest\""));
        assert_ne!(captured, absent);
    }

    #[test]
    fn a_call_row_never_carries_a_path_or_a_byte() {
        // Rule 4 at the record. The spill source is a path CLASS, so even the
        // field that describes where bytes came from cannot name a directory.
        let mut carried = row("s", Some("beef"), None);
        carried.class = Some("host-temp".to_owned());
        let rendered = serde_json::to_string(&carried).unwrap();
        assert!(
            !rendered.contains('/'),
            "a row looks like a path: {rendered}"
        );
        assert!(!rendered.contains("bytes"));
    }

    #[test]
    fn a_call_order_is_monotone_within_a_session_and_scoped_to_it() {
        // Minted from the count of rows already recorded for THIS session, under
        // the lock the append takes — never from a clock, which is what keeps two
        // runs over an unchanged log in agreement (§6).
        let root = scratch_store("call-order");
        for _ in 0..3 {
            record_call_in(&root, &row("alpha", Some("aa"), None)).unwrap();
        }
        record_call_in(&root, &row("beta", Some("bb"), None)).unwrap();
        let recorded = calls_in(&root).unwrap();
        let alpha: Vec<u64> = recorded
            .iter()
            .filter(|held| held.session == "alpha")
            .map(|held| held.order)
            .collect();
        assert_eq!(alpha, vec![0, 1, 2]);
        // A second session starts at zero rather than continuing the first: the
        // ordinal answers "which call within this conversation".
        let beta: Vec<u64> = recorded
            .iter()
            .filter(|held| held.session == "beta")
            .map(|held| held.order)
            .collect();
        assert_eq!(beta, vec![0]);
    }

    #[test]
    fn identical_bytes_are_one_blob_and_two_rows() {
        // The two identities, as the property that makes provenance worth having.
        // Dedup collapses content and must not collapse invocations.
        let root = scratch_store("two-identities");
        let first = store_in(&root, Stream::Response, b"same").unwrap();
        let second = store_in(&root, Stream::Response, b"same").unwrap();
        assert_eq!(first.digest, second.digest);
        record_call_in(&root, &row("s", Some(&first.digest), None)).unwrap();
        record_call_in(&root, &row("s", Some(&second.digest), None)).unwrap();
        let blobs: Vec<Capture> = list_in(&root)
            .unwrap()
            .into_iter()
            .filter(|held| held.stream == Stream::Response.as_str())
            .collect();
        assert_eq!(blobs.len(), 1, "identical bytes became two records");
        assert_eq!(
            calls_in(&root).unwrap().len(),
            2,
            "two calls became one row"
        );
    }

    #[test]
    fn the_call_view_is_byte_stable_across_runs() {
        // §6. Reading twice over an unchanged log must agree, which is what
        // forbids an mtime ordering and forbids rendering `seen_at`.
        let root = scratch_store("call-stable");
        let mut stamped = row("s", Some("cc"), None);
        stamped.seen_at = Some("2026-08-23T00:00:00Z".to_owned());
        record_call_in(&root, &stamped).unwrap();
        record_call_in(&root, &row("s", Some("dd"), None)).unwrap();
        assert_eq!(calls_in(&root).unwrap(), calls_in(&root).unwrap());
    }

    #[test]
    fn an_exec_capture_is_unbounded_because_todays_behaviour_is_unchanged() {
        // The bound is for RESPONSES, whose growth law is per call. `exec`
        // captures grow per DISTINCT output and `prune` is their whole lifecycle,
        // so a bound computed for the other denominator must not reach them.
        let root = scratch_store("exec-unbounded");
        for index in 0..4_u8 {
            store_in(&root, Stream::Stdout, &[index]).unwrap();
        }
        let tight = CaptureConfig {
            inline_max_bytes: None,
            max_bytes: Some(1),
            max_records: Some(1),
        };
        assert_eq!(evict_to_budget_in(&root, Some(&tight)).unwrap(), 0);
        assert_eq!(
            list_in(&root).unwrap().len(),
            4,
            "an exec capture was evicted"
        );
    }

    #[test]
    fn eviction_takes_the_oldest_recorded_call_rather_than_the_newest() {
        // The call log's order is the authority on "oldest", never an mtime. An
        // inverted walk here would drop the capture a caller most likely still
        // wants, which is why the direction is pinned rather than assumed.
        let root = scratch_store("evict-oldest");
        let old = store_in(&root, Stream::Response, b"oldest").unwrap();
        let mid = store_in(&root, Stream::Response, b"middle").unwrap();
        let new = store_in(&root, Stream::Response, b"newest").unwrap();
        for digest in [&old.digest, &mid.digest, &new.digest] {
            record_call_in(&root, &row("s", Some(digest), None)).unwrap();
        }
        let two = CaptureConfig {
            inline_max_bytes: None,
            max_bytes: None,
            max_records: Some(2),
        };
        assert_eq!(evict_to_budget_in(&root, Some(&two)).unwrap(), 1);
        let left: Vec<String> = list_in(&root)
            .unwrap()
            .into_iter()
            .filter(|held| held.stream == Stream::Response.as_str())
            .map(|held| held.digest)
            .collect();
        assert!(!left.contains(&old.digest), "the newest was evicted");
        assert!(left.contains(&new.digest));
    }

    #[test]
    fn an_absent_capture_table_means_the_engine_default_rather_than_unbounded() {
        // Absent is the DEFAULT, not "no bound": response capture is bounded by
        // default because it grows per call, and reading an absent table as
        // unbounded would inherit `exec`'s posture into the surface the bound
        // exists for.
        // The defaults are consts, so asserting they are positive is a
        // tautology clippy rightly refuses. What is checkable is the BEHAVIOUR
        // an absent table produces: bounded by the default, not unbounded.
        let root = scratch_store("evict-default");
        store_in(&root, Stream::Response, b"small").unwrap();
        // Well inside the default, so nothing goes...
        assert_eq!(evict_to_budget_in(&root, None).unwrap(), 0);
        // ...and the default is a real bound rather than "no bound": the same
        // store under a table of one record evicts, which an unbounded reading
        // could never do.
        let one = CaptureConfig {
            inline_max_bytes: None,
            max_bytes: None,
            max_records: Some(0),
        };
        assert_eq!(evict_to_budget_in(&root, Some(&one)).unwrap(), 1);
    }

    #[test]
    fn eviction_crosses_sessions_by_append_order_rather_than_by_session_name() {
        // `order` is monotone only WITHIN a session, so the sorted listing view is
        // session-lexicographic across two of them. Consuming that view evicts by
        // NAME: here the older session sorts last, so a sorted walk would take the
        // newest response first — the exact inversion the oldest-first contract
        // forbids, and one a single-session test cannot see.
        //
        // Red on the defect: put `calls_in(dir)?` back in `evict_to_budget_in` and
        // the newest capture is the one that goes.
        let root = scratch_store("evict-cross-session");
        let old = store_in(&root, Stream::Response, b"older").unwrap();
        let new = store_in(&root, Stream::Response, b"newer").unwrap();
        // The OLDER call belongs to the session whose id sorts LAST.
        record_call_in(&root, &row("zzz", Some(&old.digest), None)).unwrap();
        record_call_in(&root, &row("aaa", Some(&new.digest), None)).unwrap();
        let one = CaptureConfig {
            inline_max_bytes: None,
            max_bytes: None,
            max_records: Some(1),
        };
        assert_eq!(evict_to_budget_in(&root, Some(&one)).unwrap(), 1);
        let left: Vec<String> = list_in(&root)
            .unwrap()
            .into_iter()
            .filter(|held| held.stream == Stream::Response.as_str())
            .map(|held| held.digest)
            .collect();
        assert!(
            left.contains(&new.digest),
            "the newest capture was evicted because its session name sorted first"
        );
        assert!(!left.contains(&old.digest));
    }

    #[test]
    fn a_deduplicated_store_still_bounds_its_call_log() {
        // THE STATE THE BOUND EXISTS FOR, and the one a trim behind the blob
        // budget never reached. Blobs are content-addressed, so a session
        // repeating one response holds the byte and record counts flat while the
        // log gains a row per call: the budget check is satisfied forever and the
        // log grows forever with it. `next_order` walks backwards from the tail,
        // so an unbounded log is an unbounded scan on the mediated path.
        //
        // Red on the defect: move `bound_calls` behind the `total <= max_bytes`
        // return and the log keeps every row.
        let root = scratch_store("bound-dedup");
        let stored = store_in(&root, Stream::Response, b"same").unwrap();
        let one = CaptureConfig {
            inline_max_bytes: None,
            max_bytes: None,
            max_records: Some(1),
        };
        // Well past `max_records * 4` rows, all naming the one deduplicated blob.
        for _ in 0..12 {
            record_call_in(&root, &row("s", Some(&stored.digest), None)).unwrap();
            evict_to_budget_in(&root, Some(&one)).unwrap();
        }
        let rows = calls_in(&root).unwrap();
        assert!(
            rows.len() <= 4,
            "the log kept {} rows against a bound of 4",
            rows.len()
        );
        // The bound keeps the NEWEST rows: a trim that kept the head would make
        // the log describe a prefix of the session and nothing since.
        assert!(
            rows.last().is_some_and(|last| last.order >= 8),
            "the trim kept the head rather than the tail"
        );
    }

    #[test]
    fn a_rendered_row_never_falls_under_the_row_floor() {
        // `bound_calls` skips the parse when the log is too SMALL to hold more
        // rows than the bound allows, which is only sound in one direction: a
        // floor above the real minimum skips a trim that was due. The minimal row
        // — every optional key absent — is the case that would break it.
        let minimal = CallRow {
            order: 0,
            session: String::new(),
            source: String::new(),
            host: String::new(),
            tool: String::new(),
            event: String::new(),
            fidelity: String::new(),
            seen_at: None,
            class: None,
            digest: None,
            absent: None,
        };
        let rendered = serde_json::to_string(&minimal).unwrap();
        assert!(
            rendered.len() as u64 >= MIN_CALL_ROW_BYTES,
            "the minimal row renders in {} bytes, under the {MIN_CALL_ROW_BYTES}-byte floor",
            rendered.len()
        );
    }

    #[test]
    fn every_fidelity_token_is_distinct() {
        // The tokens reach a byte-stable record (§6), where two values sharing
        // one name would make the record ambiguous rather than merely ugly.
        let mut tokens: Vec<&str> = Fidelity::ALL
            .iter()
            .map(|fidelity| fidelity.as_str())
            .collect();
        tokens.sort_unstable();
        let count = tokens.len();
        tokens.dedup();
        assert_eq!(tokens.len(), count, "two fidelity values share a token");
    }

    #[test]
    fn exactly_two_fidelity_values_may_be_called_byte_perfect() {
        // The reserved word, pinned at the type. `is_byte_perfect` is the one
        // authority every other site consults, so widening it is a deliberate
        // edit that reds here and in `tests/capture_fidelity.rs` rather than a
        // claim that spreads through prose.
        let admitted: Vec<&str> = Fidelity::ALL
            .iter()
            .filter(|fidelity| fidelity.is_byte_perfect())
            .map(|fidelity| fidelity.as_str())
            .collect();
        assert_eq!(admitted, vec!["lexical-bytes", "spill-file"]);
    }

    #[test]
    fn a_prefix_fidelity_never_claims_a_declared_length_it_did_not_measure() {
        // Three-valued, and the middle value is the one that would otherwise
        // collapse: a truncation signal with NO declared total is not a total of
        // zero, and reading it as one would let a partial capture answer "you
        // have all zero bytes of it".
        let no_total = Fidelity::Prefix {
            captured: 12,
            declared: None,
        };
        let zero_total = Fidelity::Prefix {
            captured: 12,
            declared: Some(0),
        };
        assert_ne!(no_total, zero_total);
        // And neither claims completeness, which only the two admitted values do.
        assert!(!no_total.is_byte_perfect());
        assert!(!zero_total.is_byte_perfect());
    }

    #[test]
    fn a_decoded_capture_is_exact_for_its_member_and_claims_nothing_wider() {
        // The distinction CLOUD-917 reserves the word for. `DecodedContent` is
        // byte-exact for what it decoded and is not a reproduction of the
        // document the host framed, because a reserialize renormalizes key
        // order, escaping and whitespace.
        assert!(!Fidelity::DecodedContent.is_byte_perfect());
        assert!(Fidelity::LexicalBytes.is_byte_perfect());
        assert_ne!(Fidelity::DecodedContent, Fidelity::LexicalBytes);
    }

    /// A live-capture directory under this process's own scratch space.
    fn scratch_live(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("batten-spool-{}-{name}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        dir
    }

    #[test]
    fn a_live_handle_cannot_be_mistaken_for_a_sealed_one() {
        // One separator per promise: `:` names bytes that will never change,
        // `@` names a file that is still growing. A reader handed the wrong one
        // must be unable to treat it as the other.
        assert_eq!(live_handle(LiveStream::STDOUT, "42.0"), "stdout@42.0");
        assert!(!live_handle(LiveStream::STDOUT, "42.0").contains(':'));
    }

    #[test]
    fn a_reader_never_sees_past_the_watermark() {
        // The property the whole spool exists for, exercised through the one way
        // the file can genuinely run ahead of the watermark: a commit whose
        // publish lost the lock. The bytes land, the length does not, and a
        // reader must see the old length rather than the new bytes.
        let dir = scratch_live("watermark");
        let mut spool = Spool::open_in(&dir, LiveStream::STDOUT, "unit").unwrap();
        spool.commit(b"first").unwrap();

        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("stdout@unit.lock"))
            .unwrap();
        // A second open file description in this same process still conflicts:
        // `flock` locks the description, not the process.
        fs4::FileExt::try_lock(&held).unwrap();

        // A reader that cannot take the shared lock is BUSY, which is an outcome
        // rather than an error — losing a race to an honest writer says nothing
        // about the capture, and the next read gets it.
        assert_eq!(
            read_live_in(&dir, LiveStream::STDOUT, "unit", 0, 4096).unwrap(),
            LiveRead::Busy
        );

        // The commit succeeds and the publish is skipped: waiting here would put
        // a reader's contention on the child's critical path.
        spool.commit(b"-second").unwrap();
        assert!(
            std::fs::metadata(dir.join("stdout@unit")).unwrap().len() > 5,
            "the bytes did land"
        );
        drop(held);

        let LiveRead::Bytes(seen) =
            read_live_in(&dir, LiveStream::STDOUT, "unit", 0, 4096).unwrap()
        else {
            panic!("the lock is free again");
        };
        assert_eq!(
            seen, b"first",
            "the watermark lagged, so the reader must lag with it"
        );
        // IDEMPOTENT: the same range re-read is the same bytes, which is what
        // makes "more context" a repeatable question rather than a stream to
        // parse.
        let LiveRead::Bytes(again) =
            read_live_in(&dir, LiveStream::STDOUT, "unit", 0, 4096).unwrap()
        else {
            panic!("the lock is free again");
        };
        assert_eq!(again, seen);

        // And the next publish carries both chunks, so nothing is lost by lagging.
        spool.commit(b"-third").unwrap();
        let LiveRead::Bytes(all) = read_live_in(&dir, LiveStream::STDOUT, "unit", 0, 4096).unwrap()
        else {
            panic!("the lock is free again");
        };
        assert_eq!(all, b"first-second-third");
        assert_eq!(
            live_watermark_in(&dir, LiveStream::STDOUT, "unit"),
            Some(all.len() as u64)
        );
    }

    #[test]
    fn a_handle_nobody_opened_is_absent_rather_than_an_error() {
        let dir = scratch_live("absent");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            read_live_in(&dir, LiveStream::STDOUT, "never", 0, 16).unwrap(),
            LiveRead::Absent
        );
        assert_eq!(live_watermark_in(&dir, LiveStream::STDOUT, "never"), None);
    }

    #[test]
    fn reopening_a_spool_keeps_what_is_already_in_it() {
        // The one case `reopen` exists for: a drain that hit its deadline leaves
        // the tee thread holding the spool, so the caller takes a second handle
        // instead of waiting. If that handle truncated, a timed-out drain would
        // seal an empty capture over a run that produced output.
        let dir = scratch_live("reopen");
        let mut spool = Spool::open_in(&dir, LiveStream::STDOUT, "unit").unwrap();
        spool.commit(b"kept").unwrap();
        let mut second = spool.reopen().unwrap();
        second.commit(b"-more").unwrap();
        let LiveRead::Bytes(seen) =
            read_live_in(&dir, LiveStream::STDOUT, "unit", 0, 4096).unwrap()
        else {
            panic!("nothing else holds this lock");
        };
        assert_eq!(seen, b"kept-more");
    }

    #[test]
    fn a_handle_names_the_stream_and_the_digest() {
        let capture = Capture {
            stream: "stdout",
            bytes: 3,
            digest: "abc".to_owned(),
        };
        assert_eq!(capture.handle(), "stdout:abc");
    }

    #[test]
    fn the_same_bytes_on_two_streams_are_two_identities() {
        // A program that wrote the same text to both streams must not collapse
        // into one record, or a predicate scoped to stderr would match stdout.
        let out = identity::capture_fingerprint(Stream::Stdout.as_str(), b"same");
        let err = identity::capture_fingerprint(Stream::Stderr.as_str(), b"same");
        assert_ne!(out.to_hex(), err.to_hex());
    }

    #[test]
    fn the_digest_is_a_pure_function_of_the_bytes() {
        let first = identity::capture_fingerprint("stdout", b"hello\n");
        let second = identity::capture_fingerprint("stdout", b"hello\n");
        assert_eq!(first.to_hex(), second.to_hex());
        assert_ne!(
            first.to_hex(),
            identity::capture_fingerprint("stdout", b"hello").to_hex(),
            "a trailing newline is a different output, so it is a different capture"
        );
    }

    // --- navigation (CLOUD-121) ---------------------------------------------

    fn handle() -> Handle {
        Handle {
            stream: Stream::Stdout,
            digest: "abc123".to_owned(),
        }
    }

    /// Four lines, so a clamp has something to clamp against.
    const LOG: &[u8] = b"first\nsecond warning[duplicate] here\nthird\nfourth\n";

    #[test]
    fn a_handle_round_trips_through_its_text() {
        for capture in [Stream::Stdout, Stream::Stderr] {
            let text = format!("{}:deadbeef", capture.as_str());
            let parsed = Handle::parse(&text).expect("a well-formed handle parses");
            assert_eq!(parsed.stream, capture);
            assert_eq!(parsed.to_string(), text);
        }
    }

    #[test]
    fn a_malformed_handle_is_a_usage_error_never_a_path() {
        // The digest becomes a path component, so the parser refusing anything
        // that is not hex is what stops a separator or a `..` travelling there.
        // Shape-checking here rather than sanitising at each call site is what
        // makes that a property instead of a habit.
        for bad in [
            "nocolon",
            "stdin:abc",
            "stdout:",
            "stdout:../../etc/passwd",
            "stdout:not hex",
            ":abc",
        ] {
            let err = Handle::parse(bad).expect_err("{bad} is not a handle");
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "{bad} should be a usage error"
            );
        }
    }

    #[test]
    fn the_default_selection_is_the_pointer_not_the_payload() {
        // Content is something a caller names. An unqualified `show` answers with
        // the shape that costs nothing, which is what keeps the cheap path cheap.
        let answer = select(&handle(), LOG, &Selection::Summary);
        assert!(answer.selected.is_empty());
        assert_eq!(answer.lines, 4);
        assert_eq!(answer.bytes, LOG.len() as u64);
        assert_eq!(answer.handle, "stdout:abc123");
    }

    #[test]
    fn a_line_range_is_one_indexed_and_inclusive() {
        let answer = select(&handle(), LOG, &Selection::Lines { from: 2, to: 3 });
        assert_eq!(
            answer
                .selected
                .iter()
                .map(|line| line.number)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(answer.selected[0].text, "second warning[duplicate] here");
    }

    #[test]
    fn a_range_past_the_end_is_clamped_rather_than_refused() {
        // Widening a window is the whole point of a handle. An agent asking for
        // 1:5000 of a 4-line log wants the log — refusing would send it back to
        // guessing, which is the behaviour this deletes.
        let answer = select(&handle(), LOG, &Selection::Lines { from: 1, to: 5000 });
        assert_eq!(answer.selected.len(), 4);
        assert_eq!(answer.selected[3].number, 4);
    }

    #[test]
    fn an_inverted_range_selects_nothing_rather_than_panicking() {
        // A reachable path, since the range comes from an agent's argv, and the
        // workspace lints forbid panicking on one.
        let answer = select(&handle(), LOG, &Selection::Lines { from: 5, to: 2 });
        assert!(answer.selected.is_empty());
        assert_eq!(answer.lines, 4, "the capture is still described");
    }

    #[test]
    fn grep_numbers_the_lines_it_matched() {
        // The number is what makes the next call possible: grep, read 2, then ask
        // for a window around it — navigation rather than a second guess.
        let answer = select(
            &handle(),
            LOG,
            &Selection::Grep {
                needle: "warning[duplicate]".to_owned(),
            },
        );
        assert_eq!(answer.selected.len(), 1);
        assert_eq!(answer.selected[0].number, 2);
    }

    #[test]
    fn grep_matching_nothing_is_an_answer_not_an_error() {
        let answer = select(
            &handle(),
            LOG,
            &Selection::Grep {
                needle: "absent".to_owned(),
            },
        );
        assert!(answer.selected.is_empty());
        assert_eq!(answer.lines, 4);
    }

    #[test]
    fn a_trailing_newline_mints_no_empty_last_line() {
        assert_eq!(select(&handle(), b"a\nb\n", &Selection::Summary).lines, 2);
        assert_eq!(select(&handle(), b"a\nb", &Selection::Summary).lines, 2);
        assert_eq!(select(&handle(), b"", &Selection::Summary).lines, 0);
    }

    #[test]
    fn invalid_utf8_is_still_navigable() {
        // A capture holds whatever a program wrote. Refusing to show line 2
        // because byte 3 is invalid would send the caller back to re-running.
        let answer = select(&handle(), b"ok\n\xff\xfe bad\ntail\n", &Selection::Summary);
        assert_eq!(answer.lines, 3);
        assert_eq!(answer.bytes, 15);
    }

    #[test]
    fn an_empty_stream_still_has_an_identity() {
        // Zero bytes is a real answer — "the command said nothing" — and it must
        // be distinguishable from a run that was never captured.
        let empty = identity::capture_fingerprint("stdout", b"");
        assert_eq!(empty.to_hex().len(), 64);
        assert_ne!(
            empty.to_hex(),
            identity::capture_fingerprint("stderr", b"").to_hex()
        );
    }
}
