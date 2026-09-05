//! The landing lease's wire half: ref discovery and a compare-and-swap over a
//! remote ref, spoken as git smart-HTTP over [`crate::fetch`] (CLOUD-1274).
//!
//! # Why this module exists at all, and why it is not a library call
//!
//! The landing lease is a **compare-and-swap over a remote ref**, and
//! `mem:workflow/landing-loop` records two properties the design was
//! pressure-tested into, each costing an incident: the lease must live on
//! `refs/heads` (the agent proxy 403s a push elsewhere, and GitHub does not
//! enforce the fast-forward rule off `refs/heads` either — a parentless orphan was
//! ACCEPTED on a custom namespace), and renewal must be a true CAS, which a REST
//! `PATCH` with `force:false` does not give.
//!
//! Every library route to that operation is refused by a gate in this tree, and
//! each refusal was measured rather than assumed:
//!
//! * **gix cannot push.** `gix-protocol` ships `fetch`, `handshake` and `ls_refs`;
//!   the only `push` symbols in gix are `push_url()` configuration setters.
//! * **gix's own HTTP transports** resolve `reqwest` — barred by
//!   `AMBIENT_CRATES` — plus `security-framework` and `core-foundation`, both
//!   `FRAMEWORK_CRATES` names, and `ring`/`aws-lc-sys` `links` crates.
//! * **git2/libgit2** cannot reach HTTPS without its `https` feature, and every
//!   configuration carrying it resolves `openssl-sys` — a `FRAMEWORK_CRATES` name
//!   `macos-link-check` refuses BY NAME, with no vendored exemption.
//!   `vendored-openssl` does not change it. Adopting git2 would mean retiring
//!   `macos-link-check`, which is `governed_at_head` and so cannot be edited.
//!
//! So the protocol is spoken directly over the client this crate already vendored
//! and already bounded. That buys the CAS for **no new dependency, no `links`
//! crate, no Apple framework and no governed gate touched** — and it keeps
//! `git.rs`'s in-process gix reads exactly as they are.
//!
//! # The CAS is the protocol's own, not something layered on top
//!
//! receive-pack takes a command list of `<old-sha> <new-sha> <ref>`, and the
//! server applies it only while the ref still reads `<old-sha>`. That is a
//! genuine CAS decided by the server under its own lock — strictly stronger than
//! `--force-with-lease`, which compares against what the CLIENT last observed and
//! races anything that moved in between.
//!
//! # Where this may be reached from
//!
//! Nowhere on a gate surface. `policy/module-layering.rego` forbids the resolved
//! `use` edge from `hook` and from `check` to this module, for the reason it
//! already forbids `hook -> fetch`: a network round trip on the mediated path is
//! what CLOUD-689's ceiling and CLOUD-747's no-runtime assertion both refuse.

use std::collections::BTreeMap;
use std::path::Path;

use crate::Result;
use crate::fetch::{self, Call};

/// The two smart-HTTP services, named as the wire names them.
///
/// Spelled as an enum rather than passed as a string because the name appears in
/// three places per exchange — the discovery query, the `Content-Type` of the
/// request and the advertisement's own first line — and three spellings of one
/// service is how a transport starts disagreeing with itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// Reading: ref discovery and object fetch.
    UploadPack,
    /// Writing: the ref update this module exists for.
    ReceivePack,
}

impl Service {
    /// The wire name, which is also the path segment and the media-type stem.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Service::UploadPack => "git-upload-pack",
            Service::ReceivePack => "git-receive-pack",
        }
    }
}

/// What the remote said its refs are.
///
/// **A ref ABSENT from this map does not exist on the remote**, which is the
/// distinction the lease turns on: an unheld lease is an absent ref, and creating
/// it is a CAS from the all-zero object id. Collapsing absent into "zero" here
/// would make a caller unable to tell a lease nobody has taken from one this
/// module failed to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    /// Full ref name to object id.
    pub refs: BTreeMap<String, String>,
    /// The capabilities the server offered, as it spelled them.
    pub capabilities: Vec<String>,
}

/// The object id git uses for "this ref does not exist", on both sides of a
/// command.
pub const ZERO: &str = "0000000000000000000000000000000000000000";

impl Advertisement {
    /// The id `name` points at, or [`ZERO`] where the remote does not carry it.
    ///
    /// The CAS's `old` side wants exactly this collapse — creating a ref is a
    /// swap from zero — while [`Advertisement::refs`] keeps the distinction for
    /// every caller that needs to tell absent from unread.
    #[must_use]
    pub fn head_of(&self, name: &str) -> &str {
        self.refs.get(name).map_or(ZERO, String::as_str)
    }
}

/// The bearer token this repository's remote needs, or `None`.
///
/// **Delegated to [`crate::rest::credential`]**, which is this function
/// promoted rather than a second reader. The four spawns CLOUD-1338 removed all
/// justified themselves with *"this crate carries no HTTP client that resolves a
/// forge credential"*, and one of them was written in this file — so the reader
/// has one home now and the sentence has nowhere left to be true.
fn credential() -> Option<String> {
    crate::rest::credential()
}

/// The request headers for one exchange, with the credential attached when there
/// is one.
///
/// **An absent credential is not an error.** A public remote needs none, and a
/// private one answers `401`, which every caller here already reports as
/// could-not-look rather than as an unheld lease.
fn headers(accept: &str, content_type: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![(String::from("Accept"), accept.to_owned())];
    if let Some(content_type) = content_type {
        headers.push((String::from("Content-Type"), content_type.to_owned()));
    }
    if let Some(token) = credential() {
        headers.push((String::from("Authorization"), format!("Bearer {token}")));
    }
    headers
}

/// Ask the remote what it carries, over the service that will be used next.
///
/// **Discovery is service-specific and that is not a formality**: a server may
/// advertise different refs and different capabilities to a reader and a writer,
/// and the `old` side of a CAS must come from the receive-pack view or it is a
/// value from a different conversation.
///
/// # Errors
///
/// A non-200 answer, a body that is not a well-formed advertisement, or a
/// transport failure — all could-not-look (exit `3`), never a verdict about the
/// lease. A lease gate that could not read the lease has not judged it.
pub fn advertise(remote: &str, service: Service) -> Result<Advertisement> {
    let url = format!(
        "{}/info/refs?service={}",
        remote.trim_end_matches('/'),
        service.as_str()
    );
    let responses = fetch::spend(&[Call {
        url: &url,
        headers: &headers("*/*", None),
        body: None,
    }])?;
    let response = responses
        .first()
        .ok_or_else(|| anyhow::anyhow!("lease: the transport returned no answer for {url}"))?;
    if response.status != 200 {
        return Err(anyhow::anyhow!(
            "lease: ref discovery answered {} rather than 200",
            response.status
        ));
    }
    parse_advertisement(&response.body, service)
}

/// Parse a smart-HTTP advertisement body.
///
/// Split out from [`advertise`] because it is the half that can be tested without
/// a world — the transport's own suite proves the request, and this proves the
/// reading, which is where every shape error actually lives.
///
/// # Errors
///
/// A body whose first pkt-line does not name `service`, or whose lines are not
/// pkt-framed. Both are could-not-look.
pub fn parse_advertisement(body: &[u8], service: Service) -> Result<Advertisement> {
    let mut lines = pktlines(body)?;
    // THE FIRST LINE IS THE SERVICE BANNER, and checking it is what stops a
    // proxy's error page or a dumb-HTTP directory listing being read as an empty
    // ref set — which would answer "the lease is unheld" about a server that
    // never spoke git at all.
    let banner = lines
        .first()
        .ok_or_else(|| anyhow::anyhow!("lease: the advertisement is empty"))?;
    let expected = format!("# service={}", service.as_str());
    if banner.trim() != expected {
        return Err(anyhow::anyhow!(
            "lease: the advertisement does not announce {}",
            service.as_str()
        ));
    }
    lines.remove(0);

    let mut refs = BTreeMap::new();
    let mut capabilities = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let line = line.trim_end_matches('\n');
        if line.is_empty() {
            continue;
        }
        // CAPABILITIES RIDE THE FIRST REF, after a NUL. On a repository with no
        // refs at all the server sends the zero id under `capabilities^{}`, which
        // parses through this same path and contributes no ref — the empty-remote
        // case, and one the lease meets on a fresh fleet.
        let (payload, caps) = match line.split_once('\0') {
            Some((payload, caps)) if index == 0 => (payload, Some(caps)),
            _ => (line, None),
        };
        if let Some(caps) = caps {
            capabilities = caps
                .split(' ')
                .filter(|c| !c.is_empty())
                .map(str::to_owned)
                .collect();
        }
        let Some((id, name)) = payload.split_once(' ') else {
            continue;
        };
        if name == "capabilities^{}" {
            continue;
        }
        refs.insert(name.to_owned(), id.to_owned());
    }
    Ok(Advertisement { refs, capabilities })
}

/// One ref update, as receive-pack takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// What the ref must currently read for the swap to apply — [`ZERO`] to
    /// create it.
    pub old: String,
    /// What it becomes — [`ZERO`] to delete it.
    pub new: String,
    /// The full ref name. `refs/heads/…`, per the lease's own pressure-tested
    /// property.
    pub name: String,
}

impl Update {
    /// The command line receive-pack reads, without its pkt framing.
    ///
    /// `report-status` is requested on the first command's capability list,
    /// because without it the server may answer with nothing at all and a silent
    /// success is indistinguishable from a silent rejection — which for a CAS is
    /// the whole answer.
    #[must_use]
    pub fn command(&self) -> String {
        format!("{} {} {}\0report-status\n", self.old, self.new, self.name)
    }
}

/// What the server did with a command list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The swap applied: the ref read `old` and now reads `new`.
    Applied,
    /// The ref did not read `old`, so nothing was written. **This is the CAS
    /// losing, which is an ordinary outcome rather than an error** — the caller
    /// re-observes and decides again.
    Rejected {
        /// The server's own reason, carried verbatim as a pointer for a reader.
        reason: String,
    },
}

/// Parse receive-pack's report-status.
///
/// # Errors
///
/// A report that is not pkt-framed, or that carries neither `unpack` nor a
/// per-ref line — could-not-look, because a push whose result cannot be read has
/// not been shown to have applied.
pub fn parse_report(body: &[u8]) -> Result<Outcome> {
    let lines = pktlines(body)?;
    let mut unpacked = false;
    for line in &lines {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("unpack ") {
            if rest != "ok" {
                return Ok(Outcome::Rejected {
                    reason: format!("unpack {rest}"),
                });
            }
            unpacked = true;
        } else if let Some(rest) = line.strip_prefix("ng ") {
            return Ok(Outcome::Rejected {
                reason: rest.to_owned(),
            });
        }
    }
    if !unpacked {
        return Err(anyhow::anyhow!(
            "lease: the push reported no unpack status, so nothing is known about it"
        ));
    }
    // EVERY `ng` RETURNS ABOVE, so reaching here with a good unpack means every
    // command was accepted. Read that way round rather than by counting `ok`
    // lines: a server that reports the unpack and omits the per-ref line would
    // otherwise read as a rejection it never issued.
    Ok(Outcome::Applied)
}

/// Split a smart-HTTP body into its pkt-line payloads and whatever follows them.
///
/// **The framing is `gix-packetline`'s, not this module's**, for the reason
/// `.claude/rules/policy-modules.md` gives one domain over: a second parser is a
/// second AUTHORITY, and two readers of one wire can disagree about a truncation
/// or length case neither author had in mind. What this function adds is the
/// BOUNDARY — where the pkt-framed section stops and a raw packfile begins —
/// because upload-pack answers `NAK` and then the pack with nothing framed
/// between them.
///
/// A flush-pkt is a delimiter and never a payload, so a caller iterates lines
/// without having to know where the sections are. Sideband is not decoded:
/// neither exchange this module performs asks for it.
///
/// # Errors
///
/// A line whose length header promises more bytes than the body carries. That is
/// could-not-look rather than a short read — reading the remainder as a whole
/// line is how a proxy-truncated answer becomes a confident wrong verdict about
/// the lease.
fn pkt_split(body: &[u8]) -> Result<(Vec<String>, &[u8])> {
    let mut lines = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        match gix_packetline::decode::streaming(rest) {
            Ok(gix_packetline::decode::Stream::Complete {
                line,
                bytes_consumed,
            }) => {
                if let Some(payload) = line.as_slice() {
                    lines.push(String::from_utf8_lossy(payload).into_owned());
                }
                rest = &rest[bytes_consumed..];
            }
            // A HEADER THAT PROMISES MORE THAN IS THERE IS A TRUNCATION, and it
            // is the one decode outcome that must not be read as "the framed
            // section ended here": the bytes it wants are missing rather than
            // being something else.
            Ok(gix_packetline::decode::Stream::Incomplete { bytes_needed }) => {
                return Err(anyhow::anyhow!(
                    "lease: a pkt-line is short by {bytes_needed} byte(s)"
                ));
            }
            // ANYTHING ELSE IS THE BOUNDARY. `PACK` is not four hex digits, so
            // this is how the framed section ends when a packfile follows it —
            // and it is also how a proxy's HTML error page ends up as an empty
            // line set, which every caller here refuses on its own terms rather
            // than by trusting the framing.
            Err(_) => break,
        }
    }
    Ok((lines, rest))
}

/// The pkt-line payloads of a body that carries nothing else.
///
/// # Errors
///
/// As [`pkt_split`].
fn pktlines(body: &[u8]) -> Result<Vec<String>> {
    Ok(pkt_split(body)?.0)
}

/// Frame `payload` as one pkt-line.
///
/// # Errors
///
/// A payload that will not fit the 4-hex length header. The lease's own lines are
/// three object ids and a ref name, so this is unreachable for its own callers
/// and is checked anyway rather than truncating a command silently.
fn pktline(payload: &str) -> Result<Vec<u8>> {
    let mut framed = Vec::new();
    gix_packetline::blocking_io::encode::data_to_write(payload.as_bytes(), &mut framed)
        .map_err(|err| anyhow::anyhow!("lease: a pkt-line will not frame: {err}"))?;
    Ok(framed)
}

/// The flush-pkt, which ends a section.
const FLUSH: &[u8] = b"0000";

/// Compose a receive-pack request body: the command list, a flush, then the pack.
///
/// # Errors
///
/// As [`pktline`].
pub fn receive_pack_body(update: &Update, pack: &[u8]) -> Result<Vec<u8>> {
    let mut body = pktline(&update.command())?;
    body.extend_from_slice(FLUSH);
    body.extend_from_slice(pack);
    Ok(body)
}

/// Perform the compare-and-swap.
///
/// Returns [`Outcome::Rejected`] when the ref had moved — the CAS losing is an
/// answer, not a failure, and the caller decides what to do about it.
///
/// # Errors
///
/// A transport failure or an unreadable report: could-not-look, exit `3`. **Every
/// lease gate fails OPEN on that**, per the landing loop's own asymmetry — the
/// cost of failing open is one matrix and the cost of failing closed is the fleet.
pub fn swap(remote: &str, update: &Update, pack: &[u8]) -> Result<Outcome> {
    let url = format!(
        "{}/{}",
        remote.trim_end_matches('/'),
        Service::ReceivePack.as_str()
    );
    let body = receive_pack_body(update, pack)?;
    let content_type = format!("application/x-{}-request", Service::ReceivePack.as_str());
    let responses = fetch::spend(&[Call {
        url: &url,
        headers: &headers(
            &format!("application/x-{}-result", Service::ReceivePack.as_str()),
            Some(&content_type),
        ),
        body: Some(&body),
    }])?;
    let response = responses
        .first()
        .ok_or_else(|| anyhow::anyhow!("lease: the transport returned no answer for {url}"))?;
    if response.status != 200 {
        return Err(anyhow::anyhow!(
            "lease: receive-pack answered {} rather than 200",
            response.status
        ));
    }
    parse_report(&response.body)
}

/// A git object, as both halves of its identity: the id it hashes to and the
/// bytes that hash to it.
///
/// Carried together because a pack writer needs the bytes and a CAS command needs
/// the id, and computing the id twice from two places is how the two stop
/// agreeing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// The object id, as forty hex characters.
    pub id: String,
    /// What kind of object it is.
    ///
    /// **Carried rather than assumed, and a live run is what taught that.** A
    /// `want` for one commit returns its whole CLOSURE, so the pack a lease read
    /// receives carries the commit AND the empty tree it points at — and a reader
    /// that assumed every member was a commit refused the real answer while
    /// passing every synthetic case, because the fixture packs it was tested
    /// against carried one object each.
    pub kind: gix::object::Kind,
    /// The object's payload — no loose header, which is not part of what a pack
    /// carries.
    pub body: Vec<u8>,
}

/// The identity every lease object is authored and committed by.
///
/// **Supplied rather than read from configuration, and that is a portability fix
/// rather than a style choice**: `git commit-tree` refuses with "Author identity
/// unknown" on any machine with no configured `user.email`, which is every CI
/// runner and every fresh clone — measured on the bash predecessor, where every
/// acquiring test passed locally and failed in CI for exactly that reason.
/// Pinning it also makes the lease object independent of whoever runs it, which
/// is the right property for a commit nobody authored and nothing merges.
const LEASE_NAME: &str = "batten";
/// The email half of [`LEASE_NAME`].
const LEASE_EMAIL: &str = "batten@localhost";

/// Mint a lease object: a parentless commit over the empty tree carrying
/// `message`.
///
/// **Parentless and over the empty tree** so it shares history with nothing and
/// can never fast-forward over a live lease — the property that makes every swap
/// a genuine CAS rather than an occasional silent merge.
///
/// **The caller supplies `seconds`, and the message must carry a nonce.** Git
/// addresses objects by content, so two mints agreeing on every field produce the
/// SAME id, and pushing an id the ref already points at is an "up to date" no-op
/// that reports success — a rejected claim read as a win. Measured on the bash
/// predecessor: without a nonce a second acquire reported "acquired" rather than
/// recognising its own lease, and a renew left the ref unmoved. This function
/// does not invent one, because a mint that salted itself could not be tested for
/// the property it exists to have.
///
/// # Errors
///
/// A commit that will not serialise, or a hash that will not finalise. Both are
/// could-not-look.
pub fn lease_object(message: &str, seconds: i64) -> Result<Object> {
    use gix::objs::WriteTo as _;

    let who = gix::actor::Signature {
        name: LEASE_NAME.into(),
        email: LEASE_EMAIL.into(),
        time: gix::date::Time { seconds, offset: 0 },
    };
    let commit = gix::objs::Commit {
        tree: gix::hash::ObjectId::empty_tree(gix::hash::Kind::Sha1),
        parents: std::iter::empty().collect(),
        author: who.clone(),
        committer: who,
        encoding: None,
        message: message.into(),
        extra_headers: Vec::new(),
    };
    let mut body = Vec::new();
    commit
        .write_to(&mut body)
        .map_err(|err| anyhow::anyhow!("lease: the lease commit will not serialise: {err}"))?;
    let id = gix::objs::compute_hash(gix::hash::Kind::Sha1, gix::object::Kind::Commit, &body)
        .map_err(|err| anyhow::anyhow!("lease: the lease commit will not hash: {err}"))?;
    Ok(Object {
        id: id.to_string(),
        kind: gix::object::Kind::Commit,
        body,
    })
}

/// The pack type numbers, which are the wire's own and not gix's.
///
/// Only the four undeltified kinds are named. `6` and `7` are the delta forms,
/// refused by number where they are met rather than given a name here, since
/// naming them would suggest a reader that resolves them.
const fn pack_type(kind: gix::object::Kind) -> u8 {
    match kind {
        gix::object::Kind::Commit => 1,
        gix::object::Kind::Tree => 2,
        gix::object::Kind::Blob => 3,
        gix::object::Kind::Tag => 4,
    }
}

/// The inverse of [`pack_type`], or `None` for a delta or an unassigned number.
const fn pack_kind(number: u8) -> Option<gix::object::Kind> {
    match number {
        1 => Some(gix::object::Kind::Commit),
        2 => Some(gix::object::Kind::Tree),
        3 => Some(gix::object::Kind::Blob),
        4 => Some(gix::object::Kind::Tag),
        _ => None,
    }
}
/// The pack format this module writes and reads.
const PACK_VERSION: u32 = 2;

/// Write a packfile carrying `objects`, each undeltified.
///
/// **No deltas, deliberately.** A lease is one small parentless commit, so a
/// delta would save nothing and would put a second encoding on a path whose whole
/// job is to be unambiguous. The reader below refuses one for the same reason
/// rather than growing a resolver it can never exercise.
///
/// # Errors
///
/// A body that will not compress, or a trailer that will not hash.
pub fn pack_of(objects: &[Object]) -> Result<Vec<u8>> {
    use std::io::Write as _;

    let count = u32::try_from(objects.len())
        .map_err(|_| anyhow::anyhow!("lease: a pack cannot carry {} objects", objects.len()))?;
    let mut pack = Vec::from(*b"PACK");
    pack.extend_from_slice(&PACK_VERSION.to_be_bytes());
    pack.extend_from_slice(&count.to_be_bytes());
    for object in objects {
        // The type/size header: four size bits in the first byte beside the
        // type, then seven per continuation byte, little-endian, with the high
        // bit meaning "another byte follows".
        let mut size = object.body.len();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "masked to four bits before the cast"
        )]
        let mut byte = (pack_type(object.kind) << 4) | ((size & 0x0f) as u8);
        size >>= 4;
        while size > 0 {
            pack.push(byte | 0x80);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "masked to seven bits before the cast"
            )]
            {
                byte = (size & 0x7f) as u8;
            }
            size >>= 7;
        }
        pack.push(byte);
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(&object.body)
            .and_then(|()| encoder.finish())
            .map_err(|err| anyhow::anyhow!("lease: an object will not compress: {err}"))
            .map(|compressed| pack.extend_from_slice(&compressed))?;
    }
    // THE TRAILER IS OVER EVERYTHING BEFORE IT, which is what makes a truncated
    // pack detectable by the server rather than half-applied.
    let mut hasher = gix::hash::hasher(gix::hash::Kind::Sha1);
    hasher.update(&pack);
    let checksum = hasher
        .try_finalize()
        .map_err(|err| anyhow::anyhow!("lease: the pack trailer will not hash: {err}"))?;
    pack.extend_from_slice(checksum.as_slice());
    Ok(pack)
}

/// Read the undeltified objects out of a packfile.
///
/// # Errors
///
/// A body that is not a version-2 pack, an object that is a delta, a member that
/// will not inflate, or a pack carrying fewer objects than its header claims. All
/// could-not-look: a lease body that cannot be read has not been read, and the
/// caller fails open on that rather than deciding from a guess.
pub fn objects_in(pack: &[u8]) -> Result<Vec<Object>> {
    if pack.len() < 12 || &pack[..4] != b"PACK" {
        return Err(anyhow::anyhow!("lease: the answer is not a packfile"));
    }
    let version = u32::from_be_bytes([pack[4], pack[5], pack[6], pack[7]]);
    if version != PACK_VERSION {
        return Err(anyhow::anyhow!(
            "lease: the pack is version {version}, which this reader does not speak"
        ));
    }
    let count = u32::from_be_bytes([pack[8], pack[9], pack[10], pack[11]]);
    let mut cursor = 12_usize;
    let mut objects: Vec<Object> = Vec::new();
    // WHERE EACH MEMBER STARTED, because an offset delta names its base by the
    // distance back to it. The index is the pack's own coordinate system and
    // there is no other way to resolve one — an id would do, but an ofs-delta
    // deliberately does not carry one.
    let mut at_offset: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for _ in 0..count {
        let start = cursor;
        let rest = &pack[cursor..];
        let (number, size, header) = pack_header(rest)?;
        cursor += header;
        // A delta names a base, and the two forms name it differently: `6` by a
        // negative offset into this same pack, `7` by object id. Both are read
        // here rather than refused, because a real server delta-compresses any
        // multi-object pack and a fetch that refused them could not read one.
        let base = match number {
            OFS_DELTA => {
                let (distance, read) = offset_base(&pack[cursor..])?;
                cursor += read;
                let base_at = start.checked_sub(distance).ok_or_else(|| {
                    anyhow::anyhow!("lease: an offset delta points before the pack")
                })?;
                let index = *at_offset.get(&base_at).ok_or_else(|| {
                    anyhow::anyhow!("lease: an offset delta names no member of this pack")
                })?;
                Some(index)
            }
            REF_DELTA => {
                let raw = pack.get(cursor..cursor + 20).ok_or_else(|| {
                    anyhow::anyhow!("lease: a reference delta runs off the end of the pack")
                })?;
                cursor += 20;
                let id = hex_of(raw);
                let index = objects
                    .iter()
                    .position(|object| object.id == id)
                    .ok_or_else(|| {
                        // A THIN PACK NAMES A BASE THE PACK DOES NOT CARRY. Refused
                        // rather than resolved from the odb: nothing here asks for a
                        // thin pack, so accepting one would be a path no test reaches.
                        anyhow::anyhow!("lease: a reference delta names a base outside this pack")
                    })?;
                Some(index)
            }
            _ => None,
        };
        let kind = match base {
            Some(_) => gix::object::Kind::Blob,
            None => pack_kind(number).ok_or_else(|| {
                anyhow::anyhow!(
                    "lease: the pack carries object type {number}, which this reader does not \
                     resolve"
                )
            })?,
        };
        let rest = &pack[cursor..];
        let mut body = Vec::with_capacity(size);
        let mut inflate = flate2::Decompress::new(true);
        let status = inflate
            .decompress_vec(rest, &mut body, flate2::FlushDecompress::Finish)
            .map_err(|err| anyhow::anyhow!("lease: a pack member will not inflate: {err}"))?;
        // THE STREAM MUST HAVE ENDED, and the length check below does not imply
        // it: a zlib stream's last bytes are its adler-32, so a member truncated
        // by exactly that much still inflates to its full declared size and only
        // the end-of-stream marker is missing. Measured here — the truncation
        // case passed on the length check alone.
        if status != flate2::Status::StreamEnd {
            return Err(anyhow::anyhow!(
                "lease: a pack member's compressed stream does not end"
            ));
        }
        if body.len() != size {
            return Err(anyhow::anyhow!(
                "lease: a pack member inflated to {} bytes and its header claims {size}",
                body.len()
            ));
        }
        let consumed = usize::try_from(inflate.total_in())
            .map_err(|_| anyhow::anyhow!("lease: a pack member's length does not fit"))?;
        cursor += consumed;
        // A DELTA'S INFLATED BYTES ARE INSTRUCTIONS, NOT AN OBJECT. Applying them
        // to the base yields the object, and the KIND is the base's — a delta
        // carries no kind of its own, which is why the placeholder above is
        // replaced here rather than trusted.
        let (kind, body) = match base {
            Some(index) => {
                let base = objects
                    .get(index)
                    .ok_or_else(|| anyhow::anyhow!("lease: a delta's base has gone missing"))?;
                (base.kind, apply_delta(&base.body, &body)?)
            }
            None => (kind, body),
        };
        // HASHED AS ITS OWN KIND, because the loose header the id is taken over
        // names it: hashing a tree as a commit yields an id nothing on the remote
        // carries, and `fetch_object`'s "does this answer carry what was asked
        // for" check would then refuse every real answer.
        let id = gix::objs::compute_hash(gix::hash::Kind::Sha1, kind, &body)
            .map_err(|err| anyhow::anyhow!("lease: a pack member will not hash: {err}"))?;
        at_offset.insert(start, objects.len());
        objects.push(Object {
            id: id.to_string(),
            kind,
            body,
        });
    }
    Ok(objects)
}

/// The pack type number for a delta naming its base by offset.
const OFS_DELTA: u8 = 6;

/// The pack type number for a delta naming its base by object id.
const REF_DELTA: u8 = 7;

/// Forty hex characters for twenty bytes.
fn hex_of(raw: &[u8]) -> String {
    raw.iter().fold(String::with_capacity(40), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Read an offset delta's base distance — git's other variable-length integer.
///
/// **It is NOT the size encoding [`pack_header`] uses**, and that is the trap:
/// this one adds `1 << 7` at each continuation so the encoding is dense rather
/// than merely little-endian, which makes a decoder written from the size
/// encoding read a base that is subtly too close.
///
/// # Errors
///
/// An encoding that runs off the end of the pack.
fn offset_base(rest: &[u8]) -> Result<(usize, usize)> {
    let mut index = 0;
    let mut byte = *rest
        .first()
        .ok_or_else(|| anyhow::anyhow!("lease: an offset delta has no base"))?;
    let mut value = usize::from(byte & 0x7f);
    index += 1;
    while byte & 0x80 != 0 {
        byte = *rest.get(index).ok_or_else(|| {
            anyhow::anyhow!("lease: an offset delta runs off the end of the pack")
        })?;
        value = value
            .checked_add(1)
            .and_then(|value| value.checked_shl(7))
            .and_then(|value| value.checked_add(usize::from(byte & 0x7f)))
            .ok_or_else(|| anyhow::anyhow!("lease: an offset delta's base does not fit"))?;
        index += 1;
    }
    Ok((value, index))
}

/// Apply a delta stream to its base.
///
/// The format is two varint sizes then a run of instructions: a high bit set
/// means COPY a span out of the base, clear means INSERT the next `n` literal
/// bytes. Both sizes are checked against what actually happens, because a delta
/// that produces the wrong length silently produces the wrong OBJECT — and an
/// object hashed from wrong bytes gets an id nothing asked for, which surfaces
/// far from here.
///
/// # Errors
///
/// A stream that runs off its own end, names a span outside the base, or produces
/// a result of a length its own header did not declare.
fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = 0;
    let declared_base = delta_size(delta, &mut cursor)?;
    if declared_base != base.len() {
        return Err(anyhow::anyhow!(
            "lease: a delta expects a {declared_base}-byte base and its base is {}",
            base.len()
        ));
    }
    let declared = delta_size(delta, &mut cursor)?;
    let mut out = Vec::with_capacity(declared);
    while cursor < delta.len() {
        let instruction = delta[cursor];
        cursor += 1;
        if instruction & 0x80 == 0 {
            // INSERT. A zero-length insert is not a no-op, it is a malformed
            // stream — git never emits one and treating it as harmless would let
            // a corrupt delta loop.
            let length = usize::from(instruction & 0x7f);
            if length == 0 {
                return Err(anyhow::anyhow!(
                    "lease: a delta carries a zero-length insert"
                ));
            }
            let bytes = delta
                .get(cursor..cursor + length)
                .ok_or_else(|| anyhow::anyhow!("lease: a delta's insert runs off its end"))?;
            out.extend_from_slice(bytes);
            cursor += length;
            continue;
        }
        // COPY. Offset and length are each assembled from whichever of the four
        // and three following bytes the instruction's low bits say are present,
        // so an absent byte means that octet is zero rather than that the stream
        // is short.
        let mut offset = 0_usize;
        for shift in 0..4 {
            if instruction & (1 << shift) != 0 {
                let byte = *delta
                    .get(cursor)
                    .ok_or_else(|| anyhow::anyhow!("lease: a delta's copy runs off its end"))?;
                offset |= usize::from(byte) << (shift * 8);
                cursor += 1;
            }
        }
        let mut length = 0_usize;
        for shift in 0..3 {
            if instruction & (0x10 << shift) != 0 {
                let byte = *delta
                    .get(cursor)
                    .ok_or_else(|| anyhow::anyhow!("lease: a delta's copy runs off its end"))?;
                length |= usize::from(byte) << (shift * 8);
                cursor += 1;
            }
        }
        // The one magic number in the format: a length of zero means 0x10000.
        if length == 0 {
            length = 0x1_0000;
        }
        let span = base
            .get(offset..offset + length)
            .ok_or_else(|| anyhow::anyhow!("lease: a delta copies a span outside its base"))?;
        out.extend_from_slice(span);
    }
    if out.len() != declared {
        return Err(anyhow::anyhow!(
            "lease: a delta produced {} bytes and declared {declared}",
            out.len()
        ));
    }
    Ok(out)
}

/// One of a delta header's two little-endian varint sizes.
fn delta_size(delta: &[u8], cursor: &mut usize) -> Result<usize> {
    let mut value = 0_usize;
    let mut shift = 0_u32;
    loop {
        let byte = *delta
            .get(*cursor)
            .ok_or_else(|| anyhow::anyhow!("lease: a delta header runs off its end"))?;
        *cursor += 1;
        // **THE SHIFT IS BOUNDED, and it was not** (review of #848). `shift += 7`
        // with no bound over bytes the REMOTE supplied: ten continuation bytes
        // reach 70, which is `attempt to shift left with overflow` in a debug
        // build — a panic on a reachable path, which `.claude/rules/rust.md`
        // forbids — and a silently masked shift in release, so the decoded size is
        // wrong and surfaces as the generic length mismatch rather than as the
        // malformed input it is. A truncated or corrupted pack through a flaky
        // proxy is enough; no malice required.
        //
        // A varint wider than the machine's own word cannot describe a size this
        // process could allocate, so it is could-not-look rather than a value to
        // salvage — the same direction every other reader on this path takes.
        value |= usize::from(byte & 0x7f).checked_shl(shift).ok_or_else(|| {
            anyhow::anyhow!("lease: a delta header's size varint is out of range")
        })?;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
}

/// Read a pack object header: its type, its inflated size, and its own length.
///
/// # Errors
///
/// A header that runs off the end of the pack.
fn pack_header(rest: &[u8]) -> Result<(u8, usize, usize)> {
    let first = *rest
        .first()
        .ok_or_else(|| anyhow::anyhow!("lease: the pack ends where an object header should be"))?;
    let kind = (first >> 4) & 0x07;
    let mut size = usize::from(first & 0x0f);
    let mut shift = 4_u32;
    let mut index = 1;
    let mut byte = first;
    while byte & 0x80 != 0 {
        byte = *rest.get(index).ok_or_else(|| {
            anyhow::anyhow!("lease: an object header runs off the end of the pack")
        })?;
        // Bounded for `delta_size`'s reason, one function up: the same unbounded
        // shift over the same remote-supplied bytes.
        size |= usize::from(byte & 0x7f).checked_shl(shift).ok_or_else(|| {
            anyhow::anyhow!("lease: an object header's size varint is out of range")
        })?;
        shift += 7;
        index += 1;
    }
    Ok((kind, size, index))
}

/// Read one object back from the remote, by id.
///
/// **Plain `want`/`done` with no `deepen` and no sideband.** A lease is a
/// parentless commit over the empty tree, so its whole closure is itself — there
/// is no history to shorten, and asking for a shallow negotiation would add a
/// section to parse for no object saved. Without sideband the packfile follows
/// the `NAK` line raw, which is the boundary [`pkt_split`] returns.
///
/// # Errors
///
/// A transport failure, a non-200 answer, an unreadable pack, or a pack that does
/// not carry the id that was asked for. The last is the load-bearing one: a
/// server answering with some OTHER object is not an answer about this lease, and
/// accepting it would let a stale or unrelated body decide who holds the matrix.
pub fn fetch_object(remote: &str, id: &str) -> Result<Object> {
    let url = format!(
        "{}/{}",
        remote.trim_end_matches('/'),
        Service::UploadPack.as_str()
    );
    let mut body = pktline(&format!("want {id} no-progress\n"))?;
    body.extend_from_slice(FLUSH);
    body.extend_from_slice(&pktline("done\n")?);
    let responses = fetch::spend(&[Call {
        url: &url,
        headers: &headers(
            &format!("application/x-{}-result", Service::UploadPack.as_str()),
            Some(&format!(
                "application/x-{}-request",
                Service::UploadPack.as_str()
            )),
        ),
        body: Some(&body),
    }])?;
    let response = responses
        .first()
        .ok_or_else(|| anyhow::anyhow!("lease: the transport returned no answer for {url}"))?;
    if response.status != 200 {
        return Err(anyhow::anyhow!(
            "lease: upload-pack answered {} rather than 200",
            response.status
        ));
    }
    let (_, pack) = pkt_split(&response.body)?;
    objects_in(pack)?
        .into_iter()
        .find(|object| object.id == id)
        .ok_or_else(|| anyhow::anyhow!("lease: the answer does not carry the object asked for"))
}

/// The lease body's own fields, as `mint` writes them and `observe` reads them.
///
/// **Three of these are ADVISORY and three are not, and the separation is
/// load-bearing rather than documentary.** `holder` decides ownership and nothing
/// else does; `expires` decides liveness. `branch`, `head`, `next` and `progress`
/// are read by waiters and by CI and by NO predicate that decides who holds the
/// lease — because an identity another clone could DERIVE (from a branch, a head,
/// an issue key) is an identity another clone could accidentally claim, which is
/// the two-holders bug the whole design exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Body {
    /// The clone that holds it. The ONE field ownership is decided by.
    pub holder: String,
    /// The instant it lapses, or `0` for a tombstone.
    ///
    /// **`0` is a sentinel and not an instant.** A release is a DECLARATION and an
    /// expiry is an INFERENCE, and only the second needs a clock; epoch 0 is
    /// unmistakable under any clock and on any machine. Conflating the two made a
    /// release wait a full beat before anyone could take it, and made three
    /// separate renderers print a wall-clock epoch as an age.
    pub expires: i64,
    /// The branch this lease authorises to spend a matrix. Advisory.
    pub branch: String,
    /// The commit that is about to become trunk, for a waiter deciding what to
    /// rebase onto. Advisory.
    pub head: String,
    /// The one admitted successor, or empty. Advisory.
    pub next: String,
    /// The holder's own progress token. **Opaque by design**: a rival tests it for
    /// EQUALITY OVER TIME and never interprets it, so no clock crosses the wire.
    /// Advisory.
    pub progress: String,
    /// What makes every mint a distinct object. See [`lease_object`].
    pub nonce: String,
}

/// The banner every lease body opens with, so a commit that is not a lease is not
/// read as one.
const BANNER: &str = "land-lock";

impl Body {
    /// The body as [`lease_object`] takes it.
    #[must_use]
    pub fn render(&self) -> String {
        // `nonce:` STAYS LAST. Its uniqueness argument is what makes every mint a
        // distinct sha, and the check half treats it as the terminal line.
        format!(
            "{BANNER}\nholder: {}\nexpires: {}\nbranch: {}\nhead: {}\nnext: {}\nprogress: {}\nnonce: {}\n",
            self.holder, self.expires, self.branch, self.head, self.next, self.progress, self.nonce
        )
    }

    /// Explicitly handed over, as opposed to merely lapsed. No clock involved.
    #[must_use]
    pub const fn released(&self) -> bool {
        self.expires == 0
    }

    /// Lapsed as of `now`.
    ///
    /// `>=`, not `>`: a lease with zero seconds left has none, and the release
    /// tombstone sets the expiry to exactly now. Under `>` that read as still-held
    /// for one more second, so a release did not free the lease until the clock
    /// ticked — measured, as a release the releaser itself still saw as held.
    #[must_use]
    pub const fn expired(&self, now: i64) -> bool {
        now >= self.expires
    }
}

/// Read a lease body out of a commit object.
///
/// **A commit that does not open with the banner is not a lease**, and returning
/// `None` for it is the same refusal [`parse_advertisement`] makes about a body
/// that never announced a service: a foreign object parsed loosely yields empty
/// fields, which read as an unheld lease.
///
/// A body with no `expires:` line yields `None` for the same reason rather than
/// defaulting here — the default belongs to the caller that knows its own TTL, and
/// a parser inventing one would report a lease it could not read as one it could.
#[must_use]
pub fn parse_body(object: &[u8]) -> Option<Body> {
    let text = String::from_utf8_lossy(object);
    let mut body = Body::default();
    let mut banner = false;
    let mut expires = None;
    for line in text.lines() {
        if line == BANNER {
            banner = true;
            continue;
        }
        let Some((key, value)) = line.split_once(": ") else {
            // The commit's own headers and its blank separator land here, as does
            // a field written with an empty value — `branch: ` has no `": "` to
            // split on once the trailing space is gone, and an empty advisory
            // field is a READING rather than an absence.
            if let Some(key) = line.strip_suffix(':') {
                match key {
                    "branch" => body.branch.clear(),
                    "head" => body.head.clear(),
                    "next" => body.next.clear(),
                    "progress" => body.progress.clear(),
                    _ => {}
                }
            }
            continue;
        };
        match key {
            "holder" => value.clone_into(&mut body.holder),
            "expires" => expires = value.parse().ok(),
            "branch" => value.clone_into(&mut body.branch),
            "head" => value.clone_into(&mut body.head),
            "next" => value.clone_into(&mut body.next),
            "progress" => value.clone_into(&mut body.progress),
            "nonce" => value.clone_into(&mut body.nonce),
            _ => {}
        }
    }
    if !banner {
        return None;
    }
    body.expires = expires?;
    Some(body)
}

/// What a read of the remote lease found.
///
/// **Absent and unreadable are different states and must never collapse.** An
/// unreachable remote read as an unheld lease is precisely the misread that lets
/// two sessions land at once, so "could not look" is `Err` from the reader and
/// never a variant here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observed {
    /// No lease ref on the remote. The next acquire wins.
    Absent,
    /// A lease is there, at `sha`, saying `body`.
    Held {
        /// The lease object's id — the CAS's expected value.
        sha: String,
        /// What it says.
        body: Body,
    },
    /// The ref is there and carries no lease body.
    ///
    /// **A separate state rather than a default body, and that distinction is the
    /// whole of what the health gate reads.** Substituting a full-TTL body keeps
    /// the SAFE behaviour — a lease we do not understand is respected until it
    /// ages out, never treated as free — but it also makes the wrong ref
    /// indistinguishable from a healthy hold, so a stray push blocks landing for a
    /// TTL with nothing anywhere saying why. Every decision below still treats
    /// this as held; only the report can now tell them apart.
    Garbage {
        /// The object the ref points at, for the CAS's expected value.
        sha: String,
        /// Why it did not read as a lease. A pointer, never the ref body.
        why: String,
    },
}

/// May this branch spend a matrix right now?
///
/// **The one question a runner can ask.** Every other verb answers about a CLONE
/// — ownership is a holder id minted per clone, which a runner has nothing to
/// compare against. A branch name is the one identifier both ends see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority {
    /// Run, for the reason given.
    Run(String),
    /// Stop: the lease authorises somebody else, named in the reason.
    Stop(String),
}

/// Decide [`Authority`] over a lease reading.
///
/// **`None` IS COULD-NOT-LOOK AND IT ANSWERS `Run`.** Every other refusal in this
/// design fails closed and this one deliberately does not: a lease it cannot read
/// stops EVERY job in the fleet, where waving one matrix through costs one matrix.
/// The asymmetry is the whole justification, and it is why an unreachable remote
/// answers `Run` here while it is an error to a status reader.
///
/// A lease carrying no branch is the same reading one level in — during the
/// rollout of the field that row was not an edge case, it was every lease.
#[must_use]
pub fn authorises(observed: Option<&Observed>, want: &str, now: i64) -> Authority {
    let Some(observed) = observed else {
        return Authority::Run(String::from(
            "cannot read the lease; running rather than stopping the fleet",
        ));
    };
    // GARBAGE FAILS OPEN HERE like everything else this arm cannot read. It is the
    // health gate's finding, not this one's: stopping the fleet over a ref
    // somebody mis-pushed is the cost this arm exists never to pay.
    let observed = match observed {
        Observed::Held { body, .. } => body,
        Observed::Garbage { .. } => {
            return Authority::Run(String::from(
                "the lease does not parse; running rather than stopping the fleet",
            ));
        }
        Observed::Absent => {
            return Authority::Run(format!("no lease is held; {want} may run"));
        }
    };
    let body = observed;
    if body.released() || body.expired(now) {
        return Authority::Run(format!("no lease is held; {want} may run"));
    }
    if body.branch.is_empty() {
        return Authority::Run(String::from(
            "the lease names no branch; running rather than guessing",
        ));
    }
    if body.branch == want {
        return Authority::Run(format!("the lease authorises {want}"));
    }
    // THE ADMITTED SUCCESSOR, and the reason the bound is two rather than one. A
    // branch that reserved the slot behind this holder is buying the matrix that
    // OVERLAPS the holder's merge — so stopping it here would cancel the very run
    // the reservation exists to start, and the queue would be cold again with the
    // mechanism intact and useless. Exactly one, by construction: the slot is
    // filled by a CAS, so nothing here counts, compares ages or breaks ties.
    if !body.next.is_empty() && body.next == want {
        return Authority::Run(format!(
            "the lease authorises {want} as the successor behind {}",
            body.branch
        ));
    }
    // Pointer-only (non-negotiable rule 4): the holder's branch is a ref name the
    // caller could read for itself, and naming it is what makes a stopped run
    // diagnosable rather than mysterious. No lease body, no expiry arithmetic.
    Authority::Stop(format!("the lease authorises {}, not {want}", body.branch))
}

/// Where the lease lives, and the bounds the design was pressure-tested into.
///
/// **`refs/heads`, and it is an environment limitation rather than a preference.**
/// A custom namespace is the better home — invisible to a remote branch listing,
/// untouched by a push of every ref, absent from base pickers, and the CAS behaves
/// identically there — but this sandbox proxies git and its write policy refuses
/// any push outside `refs/heads`. GitHub also does not enforce the fast-forward
/// rule off `refs/heads`: a parentless orphan was ACCEPTED on a custom namespace,
/// which is the whole safety property gone. Moving is a one-line change the day
/// the proxy allows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terms {
    /// The remote the lease lives on, as a URL the transport can reach.
    pub remote: String,
    /// The lease's OWN ref. **Deliberately not the branch a lease authorises** —
    /// those are different things with confusingly similar names, and writing this
    /// one into the body would stamp the lease's own ref into every lease while
    /// looking correct.
    pub reference: String,
    /// How long a fresh lease lasts.
    pub ttl: i64,
    /// How often a holder re-mints it. **The TTL is three beats wide on purpose**:
    /// a dropped connection, a proxy hiccup or a rate limit must not hand the
    /// lease away, so two consecutive failures are survivable and a third is not.
    pub beat: i64,
}

/// How many beats fit inside a TTL — the RATIO the field docs call the property.
///
/// Written once because it is now read twice: [`Terms::default`] derives the
/// shipped beat from it, and [`terms`] restores it when an operator declares a
/// `LAND_LOCK_HEARTBEAT` that is not narrower than their `LAND_LOCK_TTL`. Two
/// spellings of one relation is exactly the drift this module records elsewhere,
/// and the pair went unchecked for its whole life because the relation lived in
/// prose (review of #848).
const BEATS_PER_TTL: i64 = 4;

/// The shipped TTL. The beat is derived, so the two cannot be edited apart.
const DEFAULT_TTL: i64 = 120;

impl Default for Terms {
    fn default() -> Self {
        Self {
            remote: String::from("origin"),
            reference: String::from("refs/heads/batten-land-lock"),
            // 120s over a 30s beat. See the field docs for why the ratio rather
            // than either number is the property, and `BEATS_PER_TTL` for where
            // that ratio is written down.
            ttl: DEFAULT_TTL,
            beat: DEFAULT_TTL / BEATS_PER_TTL,
        }
    }
}

/// Why a clone has no lease terms, and the two are not the same answer.
///
/// **A clone with no remote is a FACT about the clone, not a failure to look.**
/// The could-not-look guard exists so an unreadable lease is never reported as a
/// free one; a repository with no remote has no lease ref to misread, so folding
/// it into that guard made `lease status` an error in every clone that has not
/// been pushed anywhere — including the census fixture, where every other
/// data-channel verb answers cleanly.
///
/// The distinction is only ever RELAXED for the reporting arms. The write arms
/// refuse either way, because acquiring a lease that has nowhere to live is not
/// something a missing remote makes safe.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TermsMissing {
    /// No remote is configured, so this clone cannot participate in a lease.
    NoRemote,
    /// A remote exists and something about reading it failed. This is the
    /// could-not-look the guard is for.
    Unreadable(String),
}

impl TermsMissing {
    /// The diagnostic, for the arms that report one.
    #[must_use]
    pub fn say(&self, name: &str) -> String {
        match self {
            TermsMissing::NoRemote => format!("no remote named {name} is configured"),
            TermsMissing::Unreadable(reason) => reason.clone(),
        }
    }
}

/// The remote the lease lives on, by configured name.
///
/// Named here rather than at each reader because [`terms`] and every diagnostic
/// that reports a missing remote must agree on which name went missing.
#[must_use]
pub fn remote_name() -> String {
    std::env::var("LAND_LOCK_REMOTE").unwrap_or_else(|_| String::from("origin"))
}

/// A positive whole number of seconds from the environment, or `None`.
///
/// **Zero and negative are `None`**, not values: every bound the lease carries is
/// a duration, and a zero TTL or beat would turn a lease into a spin rather than
/// into a tighter test.
#[must_use]
pub fn env_secs(name: &str) -> Option<i64> {
    std::env::var(name)
        .ok()?
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|seconds| *seconds > 0)
}

/// Resolve the lease's terms from this checkout.
///
/// **The remote must resolve to a URL rather than a name.** The transport speaks
/// smart-HTTP over the vendored client, which has no notion of a git remote
/// alias, and a name reaching it would be an unresolvable host rather than a
/// clear refusal here.
///
/// **It lives in this module rather than beside the verb dispatch**, and that is
/// CLOUD-1148's move rather than tidying: a `[[recorder]]` column now asks the
/// lease for a grade ([`adjudicate`]), and a resolver reachable only from `lib`
/// would have had to be written a second time to serve it — which is the second
/// authority every other duplicated reading in this repository was.
///
/// # Errors
///
/// [`TermsMissing`], whose two variants are a fact about the clone and a
/// could-not-look respectively. The distinction is the whole point; see its docs.
pub fn terms(root: &Path) -> std::result::Result<Terms, TermsMissing> {
    let name = remote_name();
    let remotes = crate::git::remotes(root)
        .map_err(|err| TermsMissing::Unreadable(format!("cannot read this repository: {err}")))?;
    let url = remotes
        .iter()
        .find(|(configured, _)| *configured == name)
        .map(|(_, url)| url.clone())
        .ok_or(TermsMissing::NoRemote)?;
    let mut resolved = Terms {
        remote: url,
        ..Terms::default()
    };
    // Overridable so a suite can drive the bounds without waiting out a real TTL.
    // Each falls back to the shipped default rather than to zero: a TTL of zero
    // is a lease that has already lapsed, which would report as a fleet with no
    // lease at all rather than as a misconfiguration.
    if let Some(ttl) = env_secs("LAND_LOCK_TTL") {
        resolved.ttl = ttl;
    }
    if let Some(beat) = env_secs("LAND_LOCK_HEARTBEAT") {
        resolved.beat = beat;
    }
    // **THE RELATION IS THE SAFETY PROPERTY, AND IT WAS PROSE.** `Terms`' own
    // field docs say the TTL is three beats wide on purpose, and every consumer
    // of `beat`/`ttl` assumes it — but the two were read INDEPENDENTLY, each
    // filtered only for `> 0`, so `LAND_LOCK_HEARTBEAT=120 LAND_LOCK_TTL=30`
    // loaded clean and left the lease expired for 90s of every beat. A waiter's
    // `body.expired(now) && held_for >= terms.beat` then takes a lease whose
    // holder is alive and two landers run concurrently, which is the one thing
    // this module exists to prevent (review of #848).
    //
    // THE TTL IS KEPT AND THE BEAT IS DERIVED, which is not a coin toss between
    // two values. The TTL is the OUTER bound — how long a dead holder can wedge
    // the fleet — so an operator who raised it wants it raised, and it is the
    // half that stays. The beat is an implementation detail of staying alive
    // inside it, so it is the half that moves, back to the width the field docs
    // already declare. Restoring the relation cannot widen the window a waiter
    // sees; it can only shorten it.
    //
    // **AND THE GUARD IS THE RATIO, NOT THE LIMIT** (review of #848). This fired
    // only at `beat >= ttl`, so it enforced "a beat shorter than the TTL" while
    // the paragraph above calls the RELATION the safety property. `LAND_LOCK_TTL=31`
    // against the shipped 30s beat passed both filters and loaded with a
    // one-second margin between a renewal and expiry — and the renewal is a smart
    // HTTP round trip, so a second of latency leaves the lease expired while its
    // holder is alive. That is the same two-landers outcome the measurement above
    // describes, reached by an env var rather than by two.
    if resolved.beat.saturating_mul(BEATS_PER_TTL) > resolved.ttl {
        resolved.beat = (resolved.ttl / BEATS_PER_TTL).max(1);
    }
    if let Ok(reference) = std::env::var("LAND_LOCK_BRANCH") {
        resolved.reference = format!("refs/heads/{reference}");
    }
    Ok(resolved)
}

/// Whether an observed lease leaves the clone reading it free to spend.
///
/// **The decision, extracted from both of its callers, and that is `rust.md`'s
/// rule rather than tidying**: the failing condition is a lease held by a rival
/// on a real remote, which no fixture in this sandbox can produce, so the
/// predicate is tested directly instead of asserting a conclusion over a
/// precondition nothing created. `batten lease status`'s verdict and
/// [`adjudicate`]'s `lease-status` answer are the two callers, and a second copy
/// of this comparison is exactly the drift that made the shell and the engine
/// disagree about the same lease.
///
/// **Absent, released and expired are one answer here**: the next `acquire`
/// wins, so nothing is authorised away from this clone.
///
/// **`Garbage` IS NOT IN THAT SET, and the sentence putting it there was false
/// about the column it feeds** (review of #848). It read *"a lease nothing can
/// parse stays held to every DECISION, and the decision this feeds is the
/// `landing-loop` preset's, which reads a could-not-look column rather than this
/// one"* — but [`adjudicate`] turned the `true` into exit `0`, and `batten.toml`
/// maps `"0"` to `authorised`, so the column recorded AUTHORISED. The preset's
/// refusal could not hold and this clone landed beside a live holder.
///
/// It also contradicted [`Observed::Garbage`]'s own doc one screen up — *"Every
/// decision below still treats this as held"* — which is the reading that
/// survives: a ref that is there and will not parse has not shown this clone
/// owns anything, and the safe direction over a lease is the closed one.
#[must_use]
pub fn authorises_this_clone(observed: &Observed, holder: &str, now: i64) -> bool {
    let body = match observed {
        Observed::Absent => return true,
        Observed::Garbage { .. } => return false,
        Observed::Held { body, .. } => body,
    };
    if body.released() || body.expired(now) {
        return true;
    }
    body.holder == holder
}

/// What a `[[recorder]]` column may ask the landing lease for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// Does the lease authorise THIS CLONE right now?
    Status,
    /// Which branch, if any, the live holder admitted behind it.
    Successor,
}

/// One recorder answer, in the exit-status-and-stdout contract a spawned program
/// would have produced (CLOUD-1148 §2).
///
/// # It answers in the ENGINE'S table, and the consumer's `status` map reconciles
///
/// `mise-tasks/land-lock.sh status` answered `0` authorising / `1` held
/// elsewhere / `2` could-not-look, and `[program.land-lock-status]` mapped the
/// first two and deliberately left the third unmapped — which is where the
/// lease's fail-open asymmetry is enforced, because an unmapped status records
/// could-not-look and the `landing-loop` preset's refusal cannot hold over it.
///
/// This returns the engine's one table instead: `0` authorising, `2` held
/// elsewhere, `3` could-not-look. The consumer's map moves with it, once. Every
/// other spelling of the reconciliation — a per-verb exception here, a second
/// table in the recorder — would put the same decision in two places.
///
/// # `None` is could-not-look and reaches the column as `-`
///
/// A clone with no remote, an unreadable identity and an unreachable lease all
/// answer `3` rather than `None`, because each is a reading the recorder should
/// store as *could not look* rather than an evaluation that failed. `None` is
/// reserved for the shape [`crate::recorder::evaluate`] already uses it for.
#[must_use]
pub fn adjudicate(asked: Asked, root: &Path, now: i64) -> Option<(i32, String)> {
    let unknown = Some((crate::exit::ExitCode::Internal.code(), String::new()));
    let Ok(resolved) = terms(root) else {
        return unknown;
    };
    let Ok(observed) = observe(&resolved) else {
        return unknown;
    };
    match asked {
        // THE SUCCESSOR IS SILENT WHERE THERE IS NONE, and silent-and-`0` rather
        // than could-not-look: "no reservation stands" is a reading, and the
        // preset compares the empty token against a branch name and finds them
        // unequal, which is the refusal standing rather than being waved.
        Asked::Successor => {
            let next = match &observed {
                Observed::Held { body, .. } if !body.released() && !body.expired(now) => {
                    body.next.clone()
                }
                _ => String::new(),
            };
            Some((0, format!("{next}\n")))
        }
        Asked::Status => {
            let Ok(git_dir) = crate::git::git_dir(root) else {
                return unknown;
            };
            let Ok(holder) = Local::under(&git_dir).holder() else {
                return unknown;
            };
            // A REF THAT WILL NOT PARSE IS COULD-NOT-LOOK ON THIS COLUMN, never
            // a verdict. `authorises_this_clone` now fails closed on it, which is
            // right for a caller deciding whether to spend — but `2` here would
            // record `held-elsewhere`, asserting a holder nobody could read. `3`
            // is unmapped, so the column reads `-` and the preset sees that it
            // could not look.
            if matches!(observed, Observed::Garbage { .. }) {
                return unknown;
            }
            if authorises_this_clone(&observed, &holder, now) {
                Some((0, String::new()))
            } else {
                Some((crate::exit::ExitCode::Violation.code(), String::new()))
            }
        }
    }
}

/// Read the remote lease.
///
/// Two round trips, and the pairing is a correctness property rather than an
/// economy: the sha and the body BOTH come from this read, so they are guaranteed
/// to describe the same lease. The bash predecessor took the sha from one command
/// and the body from a shared per-clone file, and measured **16 of 40 concurrent
/// reads returning the WRONG body** — which pairs THIS lease's sha with ANOTHER
/// lease's holder, so a release would CAS against that sha while judging ownership
/// from that holder. That is precisely the theft the CAS exists to prevent.
///
/// # Errors
///
/// Anything that stops the lease being read — could-not-look, and never an unheld
/// lease. **An unreachable remote read as free is the misread that lets two
/// sessions land at once**, so it is an error here and every caller decides for
/// itself which way to fail.
pub fn observe(terms: &Terms) -> Result<Observed> {
    let advertisement = advertise(&terms.remote, Service::ReceivePack)?;
    let Some(sha) = advertisement.refs.get(&terms.reference) else {
        return Ok(Observed::Absent);
    };
    let object = fetch_object(&terms.remote, sha)?;
    // A LEASE WE CANNOT PARSE IS ONE WE DO NOT UNDERSTAND, and treating it as free
    // would be the same misread as an unreachable remote. It stays HELD to every
    // decision here — and is reported as what it is rather than as a hold, which
    // is the half a substituted default body silently threw away.
    let Some(body) = parse_body(&object.body) else {
        return Ok(Observed::Garbage {
            sha: sha.clone(),
            why: String::from("the ref carries no lease body"),
        });
    };
    Ok(Observed::Held {
        sha: sha.clone(),
        body,
    })
}

/// Compare-and-swap the lease to `body`, from whatever `observed` said.
///
/// The expected value is what makes this safe to call from a heartbeat: a lease
/// that changed hands underneath is rejected rather than overwritten. [`Absent`]
/// swaps from [`ZERO`], which is how the very first claim is made without a
/// separate create path — so two sessions racing the same free state CAS from the
/// same expected value and exactly one wins.
///
/// [`Absent`]: Observed::Absent
///
/// # Errors
///
/// A transport failure or an unreadable report. A LOST RACE IS NOT AN ERROR — it
/// is [`Outcome::Rejected`], because reporting a rival's win as a failure makes
/// every caller that fails open on could-not-look fail open on a lease it lost.
pub fn cas(terms: &Terms, observed: &Observed, body: &Body, now: i64) -> Result<Outcome> {
    let old = match observed {
        Observed::Absent => ZERO,
        Observed::Held { sha, .. } | Observed::Garbage { sha, .. } => sha.as_str(),
    };
    let object = lease_object(&body.render(), now)?;
    // A FAILED MINT MUST NEVER BECOME A DELETE. The bash predecessor interpolated
    // its mint straight into a refspec, so an empty result produced git's DELETE
    // refspec rather than a no-op — and on the renew path, whose expected value is
    // the caller's own live lease, that CAS would have SUCCEEDED and destroyed the
    // lease it held. Here the id is a value the mint either produced or did not,
    // and `?` is what makes an unproduced one a refused swap.
    let update = Update {
        old: old.to_owned(),
        new: object.id.clone(),
        name: terms.reference.clone(),
    };
    swap(&terms.remote, &update, &pack_of(&[object])?)
}

/// The body a fresh claim mints.
///
/// **`next` is deliberately NOT carried from the previous holder.** A fresh
/// acquire is a new turn, and the previous holder's successor has already had its
/// admission — carrying it forward would authorise a third branch, then a fourth,
/// and the bound the whole design rests on would drift upward one handover at a
/// time. Renewal carries it and acquisition does not, which is the one asymmetry
/// between those two paths.
#[must_use]
pub fn claim(terms: &Terms, holder: &str, branch: &str, head: &str, now: i64) -> Body {
    Body {
        holder: holder.to_owned(),
        expires: now + terms.ttl,
        branch: branch.to_owned(),
        head: head.to_owned(),
        next: String::new(),
        progress: String::new(),
        nonce: nonce(),
    }
}

/// Does this branch land WITHOUT ever taking the lease?
///
/// # The population is the LANDER's, and that is the whole predicate
///
/// Some branches are fast-forwarded by a workflow that fires on a `workflow_run`
/// completion, so no agent holds the lease on their behalf and the runner-side
/// precondition would refuse the very run it exists to let through. Which
/// branches those are is a fact about which workflow lands them, and the workflow
/// selects on the branch NAME — so this does too.
///
/// **Not `crate::bot::is_lane_bot`, and collapsing the two would be wrong in both
/// directions.** That keys on a forge LOGIN. A human who names a branch with one
/// of these prefixes still gets fast-forwarded by the lander and still holds no
/// lease, so it must be exempt; a lane bot pushing a branch these prefixes do not
/// name is landed the ordinary way and must be judged.
///
/// **A PREFIX ON THE BRANCH, never a substring anywhere in the ref**, which the
/// predecessor's suite pinned as its own case. Given a full ref, the branch is
/// its `refs/heads/` remainder — a caller handing one over must not have the
/// question answered about the wrong string.
///
/// An empty prefix is ignored rather than matching everything: a blank row in
/// consumer config is a typo, and reading it as *exempt every branch* would
/// silently switch the whole gate off.
///
/// **ONE PREFIX, NEVER EVERY LEADING ONE.** `trim_start_matches` strips the
/// pattern repeatedly, so a branch literally named `refs/heads/lane/x` — which
/// git permits under `refs/heads/` — reduced to `lane/x` and was exempted by a
/// `lane/` row it does not belong to. `strip_prefix` removes at most one and
/// falls back to the branch as given, which is the only reading that answers the
/// question about the string the caller actually named.
#[must_use]
pub fn lands_by_fast_forward(branch: &str, prefixes: &[String]) -> bool {
    let branch = branch.strip_prefix("refs/heads/").unwrap_or(branch);
    prefixes
        .iter()
        .filter(|prefix| !prefix.is_empty())
        .any(|prefix| branch.starts_with(prefix.as_str()))
}

/// The body a release leaves behind.
///
/// **A tombstone, not a delete**: the expiry CASes to `0`, which leaves the lease
/// instantly claimable by anyone. That is all a release has to mean, and it keeps
/// every write in this module the same single operation.
#[must_use]
pub fn tombstone(body: &Body) -> Body {
    Body {
        expires: 0,
        nonce: nonce(),
        ..body.clone()
    }
}

/// The body a heartbeat mints, carrying forward what it must not erase.
///
/// **`next` and `progress` are carried and that is not tidiness.** A renewal
/// re-mints the WHOLE body, so a `next` written by a waiter between two beats
/// would be erased within one beat — by the holder, silently — and the admitted
/// successor would then be cancelled by CI mid-run. `progress` carries for the
/// mirrored hazard: a caller that cannot compute one would erase it by the act of
/// renewing, and the lease would look unstealable-forever to every rival.
#[must_use]
pub fn renewal(terms: &Terms, body: &Body, progress: Option<&str>, now: i64) -> Body {
    Body {
        expires: now + terms.ttl,
        progress: progress.map_or_else(|| body.progress.clone(), str::to_owned),
        nonce: nonce(),
        ..body.clone()
    }
}

/// Fill the one successor slot, re-minting every other field verbatim.
///
/// **The WAITER writes this, not the holder**, and that is forced rather than
/// chosen: waiters are not registered anywhere, so the holder has no way to name
/// one. A waiter appending itself is also what makes the slot a race with exactly
/// one winner — the same CAS that makes the lease safe, used for a second, smaller
/// decision.
///
/// **It is not a claim on the lease.** The holder id and the expiry are re-minted
/// AS THEY WERE: the holder keeps holding, its heartbeat carries the new field
/// forward, and ownership still answers for the holder. A reservation that moved
/// the holder id would be a steal wearing a different name, and one that recomputed
/// the expiry would hand the holder a fresh TTL every time a waiter arrived.
#[must_use]
pub fn reservation(body: &Body, want: &str) -> Body {
    Body {
        next: want.to_owned(),
        nonce: nonce(),
        ..body.clone()
    }
}

/// Sixteen hex characters of entropy, which is what keeps every mint distinct.
///
/// See [`lease_object`] for why a mint that agreed with another mint on every
/// other field would push an id the ref already carries — an "up to date" no-op
/// that REPORTS SUCCESS, turning a rejected claim into an apparent win.
fn nonce() -> String {
    let mut bytes = [0_u8; 8];
    // The engine's own source, so a lease's uniqueness rests on the same primitive
    // every other unforgeable value here does rather than on a second one.
    getrandom::fill(&mut bytes).map_or_else(
        // COULD-NOT-LOOK IS NOT A CONSTANT. A fixed fallback would make two clones
        // that both failed to read entropy mint the same object, which is exactly
        // the collision the nonce exists to prevent — so the fallback is the one
        // value guaranteed to differ between two processes on one machine.
        |_| format!("{:016x}", std::process::id()),
        |()| {
            bytes
                .iter()
                .fold(String::with_capacity(16), |mut out, byte| {
                    use std::fmt::Write as _;
                    let _ = write!(out, "{byte:02x}");
                    out
                })
        },
    )
}

/// The clone's own bookkeeping, under `$GIT_DIR`.
///
/// **Per CLONE, not per process**, and that is forced: `hold`, `held` and
/// `release` run as separate processes from the `acquire` that won, so a
/// per-process holder id would leave the holder unable to recognise its own lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Local {
    /// `$GIT_DIR/batten-land-lock`.
    pub dir: std::path::PathBuf,
}

impl Local {
    /// The bookkeeping directory under a git dir.
    #[must_use]
    pub fn under(git_dir: &std::path::Path) -> Self {
        Self {
            dir: git_dir.join("batten-land-lock"),
        }
    }

    /// This clone's holder id, minted once and reused by every later verb.
    ///
    /// # Errors
    ///
    /// A directory or file this clone cannot write. **Never defaulted**: a
    /// holder id that fell back to a constant would let two clones that both
    /// failed to write one recognise each other's leases as their own, which is
    /// the two-holders bug arriving through the identity rather than the CAS.
    pub fn holder(&self) -> Result<String> {
        let path = self.dir.join("holder");
        if let Ok(existing) = std::fs::read_to_string(&path) {
            let existing = existing.trim();
            if !existing.is_empty() {
                return Ok(existing.to_owned());
            }
        }
        let minted = format!(
            "{}-{}-{}",
            std::env::var("HOSTNAME").unwrap_or_else(|_| String::from("host")),
            std::process::id(),
            nonce()
        );
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(&path, format!("{minted}\n"))?;
        Ok(minted)
    }

    /// How long `token` has been what this clone sees under `name`, on OUR clock.
    ///
    /// **Expiry alone is not safe to steal on**, which is the whole reason this
    /// exists. `expires` is an absolute instant minted on the HOLDER's clock and
    /// compared against ours, and skew in one direction makes a live lease look
    /// expired — stealing on that reading produces exactly the two holders the
    /// design exists to prevent.
    ///
    /// A heartbeat mints a new nonce every beat, so a live holder CHANGES THE SHA
    /// every beat. "This exact value has been sitting there longer than a beat" is
    /// therefore evidence of the same thing expiry claims, derived entirely from
    /// durations on ONE clock, and no skew can forge it. The cost is one extra
    /// beat before a dead lease can be taken, which a waiter spends waiting anyway.
    ///
    /// **It RECORDS what it sees**, so a reader that only wants to render a number
    /// must not call it: doing so would move the instant a rival's steal becomes
    /// due, and would report `0` on a first call anyway.
    ///
    /// A first sighting is `0`, and a value this clone cannot record is `0` too —
    /// a corroboration clock that cannot be kept has corroborated nothing.
    #[must_use]
    pub fn held_for(&self, name: &str, token: &str, now: i64) -> i64 {
        let path = self.dir.join(name);
        let seen = std::fs::read_to_string(&path).unwrap_or_default();
        let mut fields = seen.split_whitespace();
        let previous = fields.next().unwrap_or_default();
        let since: Option<i64> = fields.next().and_then(|at| at.parse().ok());
        match since {
            Some(since) if previous == token => now.saturating_sub(since),
            _ => {
                let _ = std::fs::create_dir_all(&self.dir);
                let _ = std::fs::write(&path, format!("{token} {now}\n"));
                0
            }
        }
    }
}

/// What a waiter may do about the lease it just read.
///
/// **Three ways in and one way out.** The ref does not exist yet, it was
/// tombstoned by a release, or its holder stopped beating — all three are one
/// compare-and-swap from the same expected value, which is why there is no
/// separate create path to race.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Turn {
    /// This clone already holds it, and it has not lapsed.
    Mine,
    /// Take it. The reason is a pointer for the report, never a lease body.
    Take(String),
    /// Somebody else holds it and the evidence to take it does not exist.
    Wait,
}

/// Decide a [`Turn`] over one observation.
///
/// **`held_for` and `progress_for` are DURATIONS ON THIS CLOCK**, measured by
/// [`Local::held_for`], and passing anything derived from the lease's own
/// `expires` here would reintroduce the skew this design removes.
///
/// The two stealing arms fail in OPPOSITE directions and both are deliberate:
///
/// * An absent or released lease is a STATEMENT rather than a deduction, so it
///   needs no corroboration and no clock at all.
/// * An expired one is a deduction, so it needs the sha to have sat unchanged for
///   a beat.
/// * A lease that is still BEATING but has not progressed fails CLOSED — no
///   token, no steal — which is every lease minted before the field existed and
///   every holder that cannot see its own progress. Releasing a lease wrongly
///   costs its holder one lap; stealing one wrongly puts two holders on the same
///   trunk.
#[must_use]
pub fn turn(
    terms: &Terms,
    observed: &Observed,
    holder: &str,
    held_for: i64,
    progress_for: i64,
    stall_beats: i64,
    now: i64,
) -> Turn {
    // GARBAGE IS WAIT, and it is the one place this differs from `authorises`:
    // taking a ref nobody can read means overwriting whatever a stray push put
    // there, and a well-meant fix that races a real holder is worse than waiting
    // out a TTL. The health gate reports it; nothing here repairs it.
    let body = match observed {
        Observed::Held { body, .. } => body,
        Observed::Garbage { .. } => return Turn::Wait,
        Observed::Absent => return Turn::Take(String::from("no lease is held")),
    };
    if body.holder == holder && !body.expired(now) {
        return Turn::Mine;
    }
    if body.released() {
        return Turn::Take(format!("took the lease {} released", body.holder));
    }
    if body.expired(now) && held_for >= terms.beat {
        return Turn::Take(format!(
            "took the lease {}s after {} stopped holding it",
            now.saturating_sub(body.expires),
            body.holder
        ));
    }
    let stall = stall_beats.saturating_mul(terms.beat);
    if !body.progress.is_empty() && progress_for >= stall {
        // A steal from a holder that never stopped beating reads as theft unless
        // it says which evidence it acted on. Pointer-only: two counts.
        return Turn::Take(format!(
            "took the lease from {}, which was still beating but had not progressed in \
             {progress_for}s (stall bound: {stall}s)",
            body.holder
        ));
    }
    Turn::Wait
}

/// What the holder's own bookkeeping says about whether it is MOVING.
///
/// **Liveness answers a different question, and answers it happily for a process
/// wedged forever.** A holder that is alive, whose trap would fire perfectly well,
/// and which has stopped landing, is exactly the case a TTL cannot see: it keeps
/// beating, so every rival waits on it indefinitely.
///
/// Two stamps rather than one maximum, and folding them is the mistake worth
/// stating: the hang bound may only be applied WHILE A LOOP IS ACTUALLY TICKING,
/// which is exactly `tick_at > advance`. Folded, a 90-second bound would be
/// applied to a verify step that legitimately runs for minutes, and the
/// mechanism's first act would be to kill healthy landings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// The later of "a lap step began" and "the world moved" — the last time
    /// anything actually advanced.
    pub advance: i64,
    /// The last time a loop went round, whether or not it learned anything.
    pub tick_at: i64,
}

impl Progress {
    /// The opaque token a lease carries.
    ///
    /// **A rival tests it for EQUALITY OVER TIME and never interprets it**, which
    /// is what keeps the holder's clock out of the rival's decision: the two
    /// fields mean something to the writer and nothing to anyone else.
    #[must_use]
    pub fn token(self) -> String {
        format!("{}.{}", self.advance, self.tick_at)
    }
}

/// Read a task's progress stamps out of the registry the task runner writes.
///
/// **A READ of a data file, not a re-derivation.** The registry's layout has one
/// owner and this does not become a second one: it answers "what did the writer
/// record", never "is this task healthy", which is [`bail`]'s question.
///
/// `None` is the honest answer wherever there is nothing to read — no entry, or
/// an entry with no usable stamp at all. **A land whose bookkeeping never
/// registered is not evidence of a stall**, and killing one on that reading would
/// be inventing the finding.
#[must_use]
pub fn progress_of(git_dir: &std::path::Path, pid: u32) -> Option<Progress> {
    let text = std::fs::read_to_string(git_dir.join("batten-tasks").join(pid.to_string())).ok()?;
    let field = |name: &str| -> i64 {
        text.lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0)
    };
    let advance = field("phase_since").max(field("sig_at"));
    if advance == 0 {
        return None;
    }
    Some(Progress {
        advance,
        tick_at: field("tick_at"),
    })
}

/// What the heartbeat should do about the land it serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bail {
    /// Keep holding.
    Hold,
    /// Release and stop it, for the reason given.
    Stop(String),
}

/// Decide whether the land holding this lease is still moving.
///
/// **`None` IS `Hold`**, and that is the fail-open half of a deliberately
/// asymmetric pair: this clone and every rival agree to say nothing rather than
/// guess about a land that never registered. The rival's own steal fails the other
/// way — no token, no steal — because releasing a lease wrongly costs its holder
/// one lap, while stealing one wrongly puts two holders on the same trunk.
#[must_use]
pub fn bail(
    progress: Option<Progress>,
    terms: &Terms,
    stall_beats: i64,
    hang_beats: i64,
    now: i64,
) -> Bail {
    let Some(progress) = progress else {
        return Bail::Hold;
    };
    if now.saturating_sub(progress.advance) >= stall_beats.saturating_mul(terms.beat) {
        return Bail::Stop(format!("has not advanced in {stall_beats} beats"));
    }
    // ONLY WHILE A LOOP IS TICKING. A phase with no loop is judged by the stall
    // bound alone, because a verify step legitimately runs longer than this one.
    if progress.tick_at > progress.advance
        && now.saturating_sub(progress.tick_at) >= hang_beats.saturating_mul(terms.beat)
    {
        return Bail::Stop(format!("stopped turning {hang_beats} beats ago"));
    }
    Bail::Hold
}

/// Is the process this heartbeat serves still the task it was started for?
///
/// **Existence is not enough, and that is measured rather than cautious**: pids
/// recycle, and this container was observed wrapping its pid space inside twenty
/// minutes — well under the stall bound. So the pid must still BE a process whose
/// command line carries `marker`.
///
/// **Anything that cannot be evaluated reads as GONE.** A wrongly released lease
/// costs one lap and the holder's own fence catches it before it acts; a wrongly
/// renewed one wedges the fleet for as long as nobody notices. Release is the
/// cheap direction.
///
/// # `/proc` is the whole mechanism, so this probe is Linux-only and says so
///
/// The command line comes from `/proc/<pid>/cmdline`, which exists on Linux and
/// nowhere else this crate builds for. That was left implicit and the Windows job
/// found it: the read simply failed, the unevaluable-reads-as-gone arm answered
/// `false`, and the ANTI-VACUITY case beside it — the one proving the predicate
/// does not answer `false` for everything — was the thing that went red. A probe
/// that is inert on a target is exactly what that case exists to catch, and it
/// caught it on the one platform `cross-check` cannot see, because `cross-check`
/// type-checks and does not run.
///
/// So the platform split is declared rather than inherited. On a target without
/// `/proc` the answer is `false` for every pid, which is the stated asymmetry
/// taken to its limit: the probe contributes nothing and the lease is decided by
/// the corroboration clocks alone. That is inert, not wrong — but it is a
/// property somebody should have to delete a `cfg` to change, rather than one
/// that follows silently from a missing file.
#[must_use]
#[cfg(target_os = "linux")]
pub fn holder_alive(pid: u32, marker: &str) -> bool {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let command = String::from_utf8_lossy(&raw).replace('\0', " ");
    command.contains(marker)
}

/// The same question where no `/proc` answers it — see the Linux arm's docs.
///
/// Inert by construction: every pid reads as gone, so this never renews a lease
/// on a holder's behalf and never contributes to stealing one either. A steal
/// still needs the corroboration clocks `turn` requires.
#[must_use]
#[cfg(not(target_os = "linux"))]
pub fn holder_alive(_pid: u32, _marker: &str) -> bool {
    false
}

/// The lease ref's health, as a gate rather than a report.
///
/// **This runs on a CLOCK, never on the landing path**, and the split is the one
/// the tree already draws between a property of the COMMIT and a property of the
/// WORLD. Neither refusal below is a correctness hazard for the trunk — the lease
/// decides who goes first, never what may land — so on the landing path it would
/// fail whichever PR happened to be in flight over a condition that PR did not
/// cause and cannot fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// Nobody has ever taken it, or a holder handed it back, or it lapsed. All
    /// three are healthy and all three mean the next claimant wins.
    Free(String),
    /// Somebody is landing right now, within one term.
    Held(String),
    /// **Nothing legitimate produces this.** A lease is only ever minted at one
    /// term from now, so a horizon further out means somebody wrote the ref by
    /// hand or under a different term — and it would block the fleet for however
    /// long it says.
    Wedged(String),
    /// The ref exists and is not a lease. Every decision above treats it as held,
    /// which is safe and silent — so without this it blocks landing for a term
    /// with nothing anywhere saying why.
    Garbage(String),
}

impl Health {
    /// Whether this is a state a fleet can land through.
    #[must_use]
    pub const fn healthy(&self) -> bool {
        matches!(self, Health::Free(_) | Health::Held(_))
    }
}

/// Judge the lease ref's health.
///
/// **Reported, never repaired.** Overwriting a lease this cannot understand is how
/// a well-meant fix races a real holder, and the two refusals below are both
/// "something that is not this protocol wrote the ref" — a human's decision, not
/// a gate's.
///
/// Pointer-only throughout: a state, a holder id and a count of seconds. Never the
/// ref body.
#[must_use]
pub fn health(observed: &Observed, terms: &Terms, now: i64) -> Health {
    let body = match observed {
        Observed::Absent => {
            return Health::Free(String::from("absent — nobody holds the landing lease"));
        }
        Observed::Garbage { why, .. } => {
            return Health::Garbage(format!(
                "{why}. It reads as held, so landing is blocked until it expires or is overwritten"
            ));
        }
        Observed::Held { body, .. } => body,
    };
    // A LEASE WITH NO HOLDER CANNOT BE RELEASED BY ANYONE, since release requires
    // recognising your own id. Checked before the arithmetic for the same reason
    // the parse is: a state nobody can leave is a wedge whatever its expiry says.
    if body.holder.is_empty() {
        return Health::Garbage(String::from(
            "a lease with no holder cannot be released by anyone",
        ));
    }
    // THE ADMITTED SUCCESSOR (CLOUD-369), rendered ONCE and appended by every arm
    // below. The lease bounds confirming runs at two — the holder plus one branch
    // `reserve` admitted — and this report is what a human reads on a wedged
    // lease. Naming only the holder shows half the occupancy, so the one view
    // meant to explain who is spending CI could not name the second spender.
    //
    // Rendered here rather than at each arm so the four cannot drift into
    // describing the same field differently, which is the predecessor's own
    // reason for hoisting it.
    let behind = successor_clause(body);
    // The release sentinel, reported as a declaration rather than as an expiry
    // fifty-odd years in the past.
    if body.released() {
        return Health::Free(format!("free — released by {}{behind}", body.holder));
    }
    // **CHECKED, because `expires` is parsed straight out of a ref body somebody
    // may have written by hand** — which is the very case the `Wedged` arm below
    // exists for (review of #848). `i64::MIN` parses fine, is not `released()`,
    // and then this subtraction overflows: a panic under overflow checks, and in
    // release a wrap to a large positive `left`, so a lease that lapsed decades
    // ago reports as wedged for another nine billion seconds and blocks the fleet
    // on a lease that is actually free. `expired()` and `released()` above are
    // total; only this was not.
    //
    // A body whose arithmetic will not close is garbage rather than a duration,
    // and garbage is the state this module already refuses to read as an
    // occupancy.
    let Some(left) = body.expires.checked_sub(now) else {
        return Health::Wedged(format!(
            "held by {}{behind} with an expiry that will not compare — the body is not a lease this can read",
            body.holder
        ));
    };
    if left <= 0 {
        return Health::Free(format!(
            "free — lapsed by {} {}s ago{behind}",
            body.holder,
            left.saturating_neg()
        ));
    }
    if left > terms.ttl {
        return Health::Wedged(format!(
            "held by {}{behind} for another {left}s, beyond the {}s any lease may claim",
            body.holder, terms.ttl
        ));
    }
    Health::Held(format!("held by {}{behind}, {left}s left", body.holder))
}

/// The admitted successor as a clause, or the empty string.
///
/// **Advisory exactly like `branch:` and `head:`** — read for the report, never
/// for a verdict. It is absent on every lease minted before CLOUD-369 and on
/// every lease nobody has reserved behind, so an empty reading is the ORDINARY
/// case and the output stays byte-identical whenever it is empty. That
/// byte-identity is asserted by a case of its own in the suite this conserves.
fn successor_clause(body: &Body) -> String {
    if body.next.is_empty() {
        return String::new();
    }
    format!(", {} admitted behind it", body.next)
}

/// Delete `reference` on `remote`, from whatever it currently reads.
///
/// **A delete is the same command with [`ZERO`] on the NEW side**, so it inherits
/// the CAS: a ref that moved between the read and the write is refused rather
/// than deleted. That is the property a plain force-delete does not have, and it
/// matters here for the reason it matters on the lease — the thing being removed
/// is shared state somebody else may have just written.
///
/// The pack carries no objects, because a delete adds none. An empty pack is a
/// header and a checksum, which is what receive-pack expects for this command.
///
/// # This sandbox's git proxy REFUSES a delete, measured 2026-09-01
///
/// A push of a new ref applies; a delete of that same ref answers **403**, by
/// this code and by the `git` binary alike (`send-pack: unexpected disconnect`).
/// So this function is correct and unexercisable here, and its opt-in driver is
/// deliberately not run in this environment.
///
/// **That costs the landing loop nothing**, which is why it is a note rather than
/// a blocker: `mem:workflow/landing-loop` already records that the closing
/// `could not delete origin/<branch>` is *"expected output, not a failure"* —
/// GitHub's auto-delete-on-merge wins the race, so the branch is normally gone
/// before anyone asks. A caller treats this as best-effort.
///
/// # Errors
///
/// A transport failure or an unreadable report. A ref that already reads
/// something else is [`Outcome::Rejected`], not an error.
pub fn delete_ref(remote: &str, reference: &str) -> Result<Outcome> {
    let advertisement = advertise(remote, Service::ReceivePack)?;
    let old = advertisement.head_of(reference);
    if old == ZERO {
        // Already gone. Idempotent in effect, so idempotent in what it reports —
        // the same reason a release that finds a tombstone says "already
        // released" rather than minting a second one.
        return Ok(Outcome::Applied);
    }
    let update = Update {
        old: old.to_owned(),
        new: ZERO.to_owned(),
        name: reference.to_owned(),
    };
    swap(remote, &update, &pack_of(&[])?)
}

/// Push `head` to `reference` on `remote`, from whatever the remote currently has.
///
/// # This is the same CAS the lease uses, and that is the point
///
/// `Update` carries `old` and `new`, and receive-pack applies the change **only
/// while the ref still reads `old`**, decided under the server's own lock. A
/// branch push therefore gets the identical guarantee the lease does, and gets it
/// from the protocol rather than from a flag: `--force-with-lease` compares
/// against what the CLIENT last observed and races anything that moved in
/// between, which on a ref the fleet is actively rewriting is exactly the stale
/// value nothing should trust.
///
/// # What is sent
///
/// [`crate::git::objects_to_send`] decides the object set — the commits in `base..head`
/// plus their tree closure, minus what `base` already carries. `base` is the ref's
/// CURRENT value on the remote, read from the advertisement, so the pack carries
/// only what this push actually adds.
///
/// An absent ref advertises [`ZERO`], which is both "must not exist" to the CAS
/// and, here, "the remote has nothing to subtract" — so a first push of a branch
/// sends its whole closure, which is correct and is the one case that is large.
///
/// # Errors
///
/// A transport failure, an unreadable report, or a repository whose objects will
/// not enumerate. **A lost race is not an error** — it is [`Outcome::Rejected`],
/// for the reason [`cas`] states.
pub fn push(remote: &str, repo: &std::path::Path, reference: &str, head: &str) -> Result<Outcome> {
    let advertisement = advertise(remote, Service::ReceivePack)?;
    let old = advertisement.head_of(reference);
    // The subtraction base is the remote's OWN current value, never a local
    // guess: a branch this clone rebased carries commits the remote never had,
    // and any base but the advertised one either sends too little (a broken
    // push) or re-sends history the remote has had for months.
    let base = (old != ZERO).then_some(old);
    let objects: Vec<Object> = crate::git::objects_to_send(repo, base, head)?
        .into_iter()
        .map(|raw| Object {
            id: raw.id,
            kind: raw.kind,
            body: raw.body,
        })
        .collect();
    let update = Update {
        old: old.to_owned(),
        new: head.to_owned(),
        name: reference.to_owned(),
    };
    swap(remote, &update, &pack_of(&objects)?)
}

/// Fetch `reference` from `remote`, returning the sha it now points at and every
/// object the local odb was missing.
///
/// # `have` lines are the whole economy of this, not an optimisation
///
/// [`fetch_object`] sends `want` and `done` with no `have` at all, which is right
/// for a lease — a parentless commit whose closure is two objects. Asking for a
/// branch tip that way would have the server send THE ENTIRE HISTORY on every
/// lap. The `have` lines are what let it compute a delta instead, and they are
/// taken from local commits reachable from the caller's own tips.
///
/// **Bounded, and the bound is a COUNT rather than a clock.** A full `have` list
/// is the whole local history; git's own client sends a window and stops. The
/// window here is [`HAVE_WINDOW`]: enough for the server to find a common
/// ancestor on any branch a lap could be on, and small enough that the request
/// stays one round trip. Too small costs a bigger pack, never a wrong answer.
///
/// # Errors
///
/// A transport failure, a ref the remote does not advertise, or a pack that will
/// not read. **A ref the remote does not have is an error, not an empty fetch** —
/// "there is nothing to fetch" and "the thing you named is not there" are
/// different answers and only one of them is safe to continue from.
pub fn fetch(remote: &str, repo: &std::path::Path, reference: &str) -> Result<Fetched> {
    let advertisement = advertise(remote, Service::UploadPack)?;
    // **QUALIFIED, BECAUSE THE ADVERTISEMENT IS KEYED BY FULL REF NAME.**
    // `Advertisement::refs` says so in its own field doc and `head_of` is an
    // exact map lookup, but every driver-level caller carries `reference` SHORT
    // — `main`, as the CLI positional and the tracking-ref construction both
    // spell it. So `head_of("main")` missed `refs/heads/main`, answered `ZERO`,
    // and this reported *"{remote} does not advertise main"* about a remote
    // whose advertisement carried it twice. Measured against this repository:
    // 79,973 bytes of advertisement, `refs/heads/main` present, the fetch
    // refusing anyway.
    //
    // The `refs/` test rather than a slash test, because a branch is legitimately
    // `feature/x` and prefixing by "has no slash" would leave exactly those
    // unresolvable — which is the same half-right rule that made
    // `gitwrite::FullName` accept a slashed short name verbatim.
    let qualified = if reference.starts_with("refs/") {
        reference.to_owned()
    } else {
        format!("refs/heads/{reference}")
    };
    let want = advertisement.head_of(&qualified);
    if want == ZERO {
        return Err(anyhow::anyhow!(
            "lease: {remote} does not advertise {qualified}"
        ));
    }
    // Already in hand: the local odb has it, so there is nothing on the wire to
    // ask for. Reported as a fetch that moved nothing rather than as a no-op,
    // because the caller's next question is "what does the ref read now".
    if crate::git::has_object(repo, want) {
        return Ok(Fetched {
            head: want.to_owned(),
            objects: Vec::new(),
            advertised: advertisement.refs.keys().cloned().collect(),
        });
    }
    let haves = crate::git::recent_commits(repo, HAVE_WINDOW);
    let body = upload_pack_request(want, &haves)?;
    let responses = fetch::spend(&[Call {
        url: &format!(
            "{}/{}",
            remote.trim_end_matches('/'),
            Service::UploadPack.as_str()
        ),
        headers: &headers(
            &format!("application/x-{}-result", Service::UploadPack.as_str()),
            Some(&format!(
                "application/x-{}-request",
                Service::UploadPack.as_str()
            )),
        ),
        body: Some(&body),
    }])?;
    let response = responses
        .first()
        .ok_or_else(|| anyhow::anyhow!("lease: upload-pack returned no answer"))?;
    if response.status != 200 {
        return Err(anyhow::anyhow!(
            "lease: upload-pack answered {} rather than 200",
            response.status
        ));
    }
    // The framed section carries the negotiation's ACK/NAK and the pack follows
    // it unframed — the same boundary `fetch_object` finds, and the reason
    // `pkt_split` hands back its tail rather than stopping at the first line it
    // cannot parse.
    let (_, tail) = pkt_split(&response.body)?;
    Ok(Fetched {
        head: want.to_owned(),
        objects: objects_in(tail)?,
        advertised: advertisement.refs.keys().cloned().collect(),
    })
}

/// What a [`fetch`] came back with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The sha the fetched reference points at.
    pub head: String,
    /// Every object the answer carried. **Empty means the odb already had it**,
    /// never that the fetch failed.
    pub objects: Vec<Object>,
    /// Every ref the remote advertised on THIS exchange, by full name.
    ///
    /// Carried out rather than dropped because the fetch already read it, and
    /// the one caller that needs it — the landing path's prune — would otherwise
    /// have to take a second advertisement to learn what the first one said.
    /// Two readings of "what does the remote carry" is two answers, and the
    /// prune is exactly the decision that must not act on the staler one.
    ///
    /// **Never empty on a successful fetch**, because a fetch that found nothing
    /// to want has already failed by then — so a caller may read emptiness as a
    /// remote carrying no refs rather than as could-not-look.
    pub advertised: Vec<String>,
}

/// How many local commits are offered as `have` lines.
///
/// A COUNT, never a clock, and deliberately generous: the cost of too few is a
/// larger pack and the cost of too many is a larger request, so this errs toward
/// the side whose failure is measured in bytes rather than in minutes.
const HAVE_WINDOW: usize = 256;

/// The `want`/`have`/`done` body.
///
/// The first `want` carries the capabilities, which is where they go on this
/// protocol — a second `want` carrying them again is a malformed request. No
/// sideband is asked for, so the pack arrives raw rather than multiplexed, which
/// is what lets the reader find it by scanning past the framed section.
fn upload_pack_request(want: &str, haves: &[String]) -> Result<Vec<u8>> {
    let mut body = pktline(&format!("want {want} no-progress ofs-delta\n"))?;
    body.extend_from_slice(FLUSH);
    for have in haves {
        body.extend_from_slice(&pktline(&format!("have {have}\n"))?);
    }
    body.extend_from_slice(&pktline("done\n")?);
    Ok(body)
}

/// Ask a stalled holder to stop.
///
/// `SIGTERM`, so the holder's own trap runs and its cleanup happens — a `SIGKILL`
/// here would leave behind exactly the orphaned state the liveness probe exists
/// to clean up after.
///
/// # Why it lives here rather than in the dispatch module
///
/// It was written in `lib.rs`, and `spawn-adapters` refused it: a spawn belongs
/// in a module the adapter table has PLACED, and the CLI dispatch is not one —
/// placing it would admit every future spawn in the crate's largest file. So the
/// call moved to the module that owns the fact, which is the same argument
/// `symbols`, `pinned` and `prune` already carry on that table: the holder's pid
/// comes off the lease record, and whether that process is still there is a
/// property of the machine rather than of the tree.
///
/// **Spawning `kill(1)` rather than calling `kill(2)`**, because the workspace
/// forbids `unsafe` outright and there is no safe in-process route to signal a
/// process this one did not start. `signal-hook` is the receiving half and has no
/// sending half to reach for.
#[expect(
    clippy::disallowed_types,
    reason = "stays: there is no in-process way to signal another process without `unsafe`, which the workspace forbids, and the alternative — leaving a wedged holder running — is the fleet-wide stall this path exists to end"
)]
pub fn stop(pid: u32) {
    let _ = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
}

// ---------------------------------------------------------------------------
// CLOUD-420 / CLOUD-1148: the composite step-0 guard.
// ---------------------------------------------------------------------------

/// What the runner's step-0 guard decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Guarded {
    /// Spend the matrix.
    Run {
        /// Why, as a pointer a human reads off a green step.
        why: String,
    },
    /// Do not. The caller cancels the run it is standing in.
    Stop {
        /// Why, and it carries the REMEDY: a stopped run is a cancelled run with
        /// no failed step of its own, so a reader who is not told sees a red
        /// check and no cause.
        why: String,
    },
}

/// The guard's decision over the two readings it composes.
///
/// # STALENESS FIRST, AND THE LEASE IS NOT CONSULTED WHEN IT STOPS
///
/// The predecessor's ordering, conserved: `ci-lease-precondition.sh` sets `stop`
/// from the staleness row and enters the lease table only `if [[ -z "$stop" ]]`.
/// So `authority` is `None` where the caller never asked — one fewer forge read
/// on a head that is doomed either way — and `None` is not a third verdict.
///
/// **AN UNREADABLE STALENESS ROW IS NOT A STOP, so it does not skip the lease**
/// (review of #848). This arm returned `Run` before the `authority` match at all,
/// which INVERTS the ordering the paragraph above claims to conserve: in the
/// shell an unreadable row left `stop` UNSET — it said *"cannot read this head's
/// landing mechanism; not judging its age"* and carried on — so the lease table
/// was still entered. Measured consequence: with the forge rate-limited or the
/// credential absent, `decide` yields `Unknown`, the lease was never observed,
/// and a rival's live lease was ignored while this job spent a matrix.
///
/// `Unknown` still never stops on its own — it contributes no refusal — it just
/// stops being a reason not to ask the other half.
///
/// # EVERY COULD-NOT-LOOK RUNS
///
/// This gate is the opposite of every other refusal in this repository. A
/// reading it could not take would stop every job in the fleet, where waving one
/// matrix through costs one matrix. So [`Carries::Unknown`] runs, an absent
/// authority runs, and the only two things that stop are a head that provably
/// does not carry trunk's landing mechanism and a lease that provably names
/// somebody else.
#[must_use]
pub fn guard(carries: &Carries, authority: Option<&Authority>) -> Guarded {
    match carries {
        Carries::Stale { wanted } => {
            return Guarded::Stop {
                why: format!(
                    "this head does not carry {wanted}, so it cannot be serialised against the \
                     fleet. Rebase onto current trunk and land with it."
                ),
            };
        }
        Carries::Unknown { .. } | Carries::Current => {}
    }
    let unjudged = match carries {
        Carries::Unknown { because } => format!("{because}; not judging this head's age. "),
        _ => String::new(),
    };
    match authority {
        Some(Authority::Stop(why)) => Guarded::Stop {
            why: format!("{unjudged}{why}"),
        },
        Some(Authority::Run(why)) => Guarded::Run {
            why: format!("{unjudged}{why}"),
        },
        // The caller could not read the lease at all. `authorises` fails open by
        // contract and so does this.
        None => Guarded::Run {
            why: format!("{unjudged}the lease could not be read, so nothing refuses this branch"),
        },
    }
}

/// Ask the forge to cancel `run`.
///
/// `false` when the cancellation was refused, which the caller reports and then
/// runs anyway: a guard that could not stop a run must not also fail the job it
/// is standing in.
#[must_use]
pub fn cancel_run(repo: &str, run: &str) -> bool {
    crate::rest::post(&format!("repos/{repo}/actions/runs/{run}/cancel"))
}

// ---------------------------------------------------------------------------
// CLOUD-1148 §2: does this head carry the landing mechanism trunk has?
// ---------------------------------------------------------------------------

/// What the staleness read decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Carries {
    /// The head's history contains trunk's newest landing-mechanism commit.
    Current,
    /// It does not, so the head cannot be serialised against the fleet.
    Stale {
        /// Trunk's commit the head is missing. A pointer, never a diff.
        wanted: String,
    },
    /// The reading could not be taken.
    ///
    /// **A distinct variant BECAUSE THE CALLER MUST FAIL OPEN ON IT.** Folding
    /// it into `Stale` would cancel every run in the fleet on one unreachable
    /// forge, and folding it into `Current` is how the predecessor's row went
    /// dead. It is neither, and the caller decides — which for this gate means
    /// run the matrix.
    Unknown {
        /// What could not be read. A pointer for a human, never a payload.
        because: String,
    },
}

/// One REST read, as the body text.
///
/// **IN PROCESS, over [`crate::rest`].** This was a `gh` spawn whose
/// `#[expect(clippy::disallowed_types)]` reason claimed the crate carries no
/// HTTP client that resolves a forge credential — eighty lines from
/// [`credential`]'s predecessor in this same file, which reads `GH_TOKEN` and
/// attaches a bearer header to a [`crate::fetch`] call. The claim was false where
/// it was easiest to check.
///
/// Empty on any failure, which is the same could-not-look posture
/// [`crate::main_watch::read`] takes: every failure to reach the forge is a
/// reading nobody took, never a verdict.
#[must_use]
fn forge_read(path: &str) -> String {
    crate::rest::get(path, None).map_or_else(String::new, |answer| answer.body)
}

/// The newest commit at `trunk` touching any of `paths`.
///
/// One request per path, and the newest sha across them wins. **`per_page=1`
/// rather than a window**, because the question is "what is the latest" and a
/// page of history would be bytes fetched to discard.
///
/// `None` when no path answered, which is could-not-look rather than "nothing
/// has ever touched the mechanism" — the two are indistinguishable from here and
/// the caller fails open on both.
/// Percent-encode one query VALUE.
///
/// **A local encoder rather than a crate**, and the trade is stated because it is
/// the kind of thing that gets waved through: the unreserved set is four lines of
/// RFC 3986 and vendoring a dependency here would go through `deny.toml`,
/// `macos-link-check`, `darwin-link`, the ambient-authority bound and the SBOM
/// inventory to buy them. Everything outside `A-Za-z0-9-._~` is escaped, which is
/// the conservative direction: over-escaping a segment the server would have
/// accepted costs nothing, and under-escaping is the defect.
fn query_value(raw: &str) -> String {
    let mut encoded = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            // The two hex digits by hand rather than through `format!`, which
            // allocates per byte — and `write!` here would need `std::fmt::Write`
            // in scope beside `std::io::Write`, which this module already uses.
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

/// The newest commit at `trunk` touching any of `paths`.
///
/// One request per path, and the newest sha across them wins. **`per_page=1`
/// rather than a window**, because the question is "what is the latest" and a
/// page of history would be bytes fetched to discard.
///
/// # ORDERED BY ANCESTRY, NEVER BY THE COMMITTER'S DATE
///
/// This compared `commit.committer.date` across paths, and that is a MUTABLE
/// field: a rebase, a cherry-pick or a hand-set `GIT_COMMITTER_DATE` reorders it
/// freely, and the endpoint's own ordering says nothing across two separate
/// queries. An older trunk commit could therefore win, and [`carries`] would
/// report `Current` for a head missing the later landing commit — the guard
/// answering clean about exactly the staleness it exists to catch.
///
/// Every candidate is on `trunk`, so they are totally ordered by ancestry, and
/// the newest is the one that CARRIES the others. That is one extra compare per
/// additional path — three, for a four-row declaration — against a guard that
/// already spends one request per path.
///
/// # An unorderable pair is could-not-look for the WHOLE reading
///
/// Where [`head_carries`] cannot answer, the two candidates cannot be ordered at
/// all, and there is no safe way to pick one: taking the older makes the guard
/// too lenient, which is this function's own defect, and taking the newer makes
/// it refuse a head it has no evidence against. So the reading is abandoned and
/// the caller fails open, exactly as it does for a path that never answered.
///
/// `None` when no path answered, which is could-not-look rather than "nothing
/// has ever touched the mechanism" — the two are indistinguishable from here and
/// the caller fails open on both.
#[must_use]
pub fn newest_landing_commit(
    repo: &str,
    trunk: &str,
    paths: &[String],
) -> Option<(String, String)> {
    let mut newest: Option<(String, String)> = None;
    for path in paths {
        // AN EMPTY ROW ASKS ABOUT THE WHOLE REPOSITORY. `path=` with no value is
        // not "no filter I meant to write" to this endpoint — it is every commit
        // on the trunk, so one blank entry in a consumer's `landing_paths` makes
        // the newest trunk commit the answer and every head that is not tip-of-
        // trunk read as stale. Skipped rather than refused, because this reading
        // fails open on everything it cannot use.
        if path.is_empty() {
            continue;
        }
        // ENCODED, because a configured path is consumer data. A `&` or a `#` in
        // one silently truncated or re-keyed the query, so the request asked
        // about a different path than the row declared.
        let raw = forge_read(&format!(
            "repos/{repo}/commits?sha={}&path={}&per_page=1",
            query_value(trunk),
            query_value(path)
        ));
        let Ok(document) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        let Some(entry) = document.as_array().and_then(|rows| rows.first()) else {
            continue;
        };
        let Some(sha) = entry.get("sha").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some((held, _)) = newest.as_ref() else {
            newest = Some((sha.to_owned(), path.clone()));
            continue;
        };
        if held == sha {
            continue;
        }
        // Does the candidate carry what we hold? Then it is the later commit.
        match head_carries(repo, held, sha) {
            Some(true) => newest = Some((sha.to_owned(), path.clone())),
            Some(false) => {}
            None => return None,
        }
    }
    newest
}

/// Does `head` carry `wanted`?
///
/// # Server-side ancestry, and the reason is the predecessor's own
///
/// `ci-lease-precondition.sh` already records why this is an API question rather
/// than a `merge-base --is-ancestor`: that needs a deep fetch and "answers
/// wrongly after a rebase or a cherry-pick, both of which are the normal shape
/// of work here". The compare endpoint answers it in one request against no
/// clone at all, which is what lets the guard stay the genuine FIRST step.
///
/// `identical` and `ahead` carry it; `behind` and `diverged` do not.
/// [`crate::gitwrite::carries`] is the LOCAL form of the same question, used
/// where a clone exists.
#[must_use]
pub fn head_carries(repo: &str, wanted: &str, head: &str) -> Option<bool> {
    let raw = forge_read(&format!("repos/{repo}/compare/{wanted}...{head}"));
    let document = serde_json::from_str::<serde_json::Value>(&raw).ok()?;
    let status = document.get("status")?.as_str()?;
    match status {
        "identical" | "ahead" => Some(true),
        "behind" | "diverged" => Some(false),
        // A status this does not know is not a guess. The forge has only ever
        // sent those four, so a fifth means the contract moved and a verdict
        // taken over it would be one nobody checked.
        _ => None,
    }
}

/// The staleness DECISION, over readings the caller already took.
///
/// **Split from the reads so the predicate is testable without a forge.** The
/// two forge calls are `Cost::Effect` and cannot run in a suite; this is a pure
/// function of what they returned, which is the same split
/// `crates/batten/src/speculation.rs` makes and for the same reason: "does this
/// do what the bash did" has to be answerable without a network.
#[must_use]
pub fn decide(
    paths: &[String],
    head: &str,
    wanted: Option<&str>,
    ancestral: Option<bool>,
) -> Carries {
    if paths.is_empty() {
        return Carries::Unknown {
            because: String::from("no landing paths declared"),
        };
    }
    if head.trim().is_empty() {
        return Carries::Unknown {
            because: String::from("no head sha in the environment"),
        };
    }
    let Some(wanted) = wanted else {
        return Carries::Unknown {
            because: String::from("no landing commit readable at trunk"),
        };
    };
    match ancestral {
        Some(true) => Carries::Current,
        Some(false) => Carries::Stale {
            wanted: wanted.to_owned(),
        },
        None => Carries::Unknown {
            because: format!("the forge did not compare {wanted} with {head}"),
        },
    }
}

/// The whole staleness read: is this head's landing mechanism current with
/// trunk's?
///
/// The two reads, then [`decide`]. Nothing branches here that is not in that
/// function, which is what keeps the suite's verdict and production's the same.
#[must_use]
pub fn carries(repo: &str, trunk: &str, head: &str, paths: &[String]) -> Carries {
    if paths.is_empty() || head.trim().is_empty() {
        return decide(paths, head, None, None);
    }
    let wanted = newest_landing_commit(repo, trunk, paths).map(|(sha, _)| sha);
    let ancestral = wanted
        .as_deref()
        .and_then(|wanted| head_carries(repo, wanted, head));
    decide(paths, head, wanted.as_deref(), ancestral)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn framed(lines: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        for line in lines {
            if line.is_empty() {
                body.extend_from_slice(FLUSH);
            } else {
                body.extend_from_slice(&pktline(line).expect("frame"));
            }
        }
        body
    }

    /// **A PREFIX ON THE BRANCH, NEVER A SUBSTRING ANYWHERE IN THE REF**, which
    /// is `ci-lease-precondition.bats`'s own case: an arm matching mid-ref would
    /// exempt a branch that merely mentions a lander's name, and the exemption is
    /// the one thing in this gate that switches it off.
    #[test]
    fn the_exemption_is_a_prefix_on_the_branch_and_not_a_substring() {
        let lanes = vec![String::from("lane/"), String::from("cut-")];

        assert!(lands_by_fast_forward("lane/bump-x", &lanes));
        assert!(lands_by_fast_forward("cut-v1.2.3", &lanes));
        // The full ref resolves to the same answer as the branch name.
        assert!(lands_by_fast_forward("refs/heads/lane/bump-x", &lanes));

        assert!(
            !lands_by_fast_forward("fix/not-lane/bump-x", &lanes),
            "a mention mid-ref is not the lander's branch"
        );
        assert!(!lands_by_fast_forward("main", &lanes));
    }

    /// **AN EMPTY SET JUDGES EVERY BRANCH, and an empty ROW exempts none.**
    ///
    /// The default has to be *judge it* or a consumer that declares nothing has
    /// no gate; and a blank row is a typo, which read as a prefix would match
    /// every branch and silently switch the whole gate off — the failure the
    /// exemption is most able to cause and least likely to be noticed for.
    #[test]
    fn nothing_declared_exempts_nothing_and_a_blank_row_exempts_nothing_either() {
        assert!(!lands_by_fast_forward("lane/bump-x", &[]));
        assert!(!lands_by_fast_forward(
            "lane/bump-x",
            &[String::new(), String::new()]
        ));
    }

    #[test]
    fn a_flush_is_a_delimiter_and_never_a_payload() {
        let body = framed(&["one\n", "", "two\n"]);
        assert_eq!(pktlines(&body).expect("parse"), vec!["one\n", "two\n"]);
    }

    #[test]
    fn a_truncated_line_is_could_not_look_rather_than_a_short_read() {
        // The header promises more than the body carries. Reading the remainder
        // as a whole line is how a proxy-truncated answer becomes a confident
        // wrong verdict about the lease.
        let body = b"0010ab";
        assert!(pktlines(body).is_err());
    }

    #[test]
    fn a_non_git_body_does_not_parse_as_an_empty_ref_set() {
        // AN HTML ERROR PAGE IS THE CASE THAT MATTERS: parsed loosely it yields
        // no refs, which reads as "the lease is unheld" and hands the matrix to
        // everyone at once.
        let err = parse_advertisement(b"<html>nope</html>", Service::ReceivePack);
        assert!(err.is_err());
    }

    #[test]
    fn the_advertisement_yields_refs_and_capabilities() {
        let body = framed(&[
            "# service=git-receive-pack\n",
            "",
            "1111111111111111111111111111111111111111 refs/heads/main\0report-status atomic\n",
            "2222222222222222222222222222222222222222 refs/heads/batten-land-lock\n",
            "",
        ]);
        let advertisement = parse_advertisement(&body, Service::ReceivePack).expect("parse");
        assert_eq!(
            advertisement
                .refs
                .get("refs/heads/batten-land-lock")
                .map(String::as_str),
            Some("2222222222222222222222222222222222222222")
        );
        assert!(
            advertisement
                .capabilities
                .iter()
                .any(|c| c == "report-status")
        );
    }

    #[test]
    fn an_absent_ref_reads_as_zero_for_the_swap_and_stays_absent_in_the_map() {
        let body = framed(&["# service=git-receive-pack\n", "", ""]);
        let advertisement = parse_advertisement(&body, Service::ReceivePack).expect("parse");
        assert_eq!(advertisement.head_of("refs/heads/batten-land-lock"), ZERO);
        assert!(
            !advertisement
                .refs
                .contains_key("refs/heads/batten-land-lock")
        );
    }

    #[test]
    fn the_command_carries_both_sides_and_asks_for_a_report() {
        let update = Update {
            old: String::from("1111111111111111111111111111111111111111"),
            new: String::from("2222222222222222222222222222222222222222"),
            name: String::from("refs/heads/batten-land-lock"),
        };
        assert_eq!(
            update.command(),
            "1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/batten-land-lock\0report-status\n"
        );
    }

    #[test]
    fn a_good_report_is_applied() {
        let body = framed(&["unpack ok\n", "ok refs/heads/batten-land-lock\n", ""]);
        assert_eq!(parse_report(&body).expect("parse"), Outcome::Applied);
    }

    #[test]
    fn a_lost_race_is_rejected_rather_than_an_error() {
        // THE CAS LOSING IS THE ORDINARY OUTCOME. Reporting it as an error would
        // make the caller treat a rival's win as a broken lease and fail open on
        // it — handing two branches the matrix at once, which is the one thing
        // the lease exists to prevent.
        let body = framed(&[
            "unpack ok\n",
            "ng refs/heads/batten-land-lock fetch first\n",
            "",
        ]);
        assert_eq!(
            parse_report(&body).expect("parse"),
            Outcome::Rejected {
                reason: String::from("refs/heads/batten-land-lock fetch first"),
            }
        );
    }

    #[test]
    fn a_report_with_no_unpack_status_is_could_not_look() {
        // A push whose result cannot be read has not been shown to have applied,
        // and saying otherwise is the direction that loses a lease silently.
        let body = framed(&["ok refs/heads/batten-land-lock\n", ""]);
        assert!(parse_report(&body).is_err());
    }

    /// A directory nothing else in this process writes.
    ///
    /// Keyed on the thread as well as the pid, because the runner is parallel and
    /// two cases sharing a sighting file would corroborate each other's tokens.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "batten-lease-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    fn body(holder: &str, expires: i64, progress: &str) -> Observed {
        Observed::Held {
            sha: String::from("1111111111111111111111111111111111111111"),
            body: Body {
                holder: holder.to_owned(),
                expires,
                progress: progress.to_owned(),
                ..Body::default()
            },
        }
    }

    fn with_successor(holder: &str, expires: i64, next: &str) -> Observed {
        Observed::Held {
            sha: String::from("1111111111111111111111111111111111111111"),
            body: Body {
                holder: holder.to_owned(),
                expires,
                next: next.to_owned(),
                ..Body::default()
            },
        }
    }

    /// **CLOUD-369 CLAUSE F: every state names the successor admitted behind
    /// the holder, and the first port of `health` named it in none of them.**
    ///
    /// The lease bounds confirming runs at two — the holder plus one branch
    /// `reserve` admitted — and this report is what a human reads on a wedged
    /// lease. Naming only the holder shows half the occupancy, so the one view
    /// meant to explain who is spending CI could not name the second spender.
    ///
    /// Five cases in `tests/land-lock-check.bats` assert it, one per state.
    #[test]
    fn every_health_state_names_the_admitted_successor() {
        let terms = Terms::default();
        let now = 1000;

        let held = health(&with_successor("mine", now + 60, "theirs"), &terms, now);
        assert!(
            format!("{held:?}").contains("theirs admitted behind it"),
            "a held lease names who is behind it: {held:?}"
        );

        let released = health(&with_successor("mine", 0, "theirs"), &terms, now);
        assert!(
            format!("{released:?}").contains("theirs admitted behind it"),
            "a RELEASED lease still names who was admitted: {released:?}"
        );

        let lapsed = health(&with_successor("mine", now - 5, "theirs"), &terms, now);
        assert!(
            format!("{lapsed:?}").contains("theirs admitted behind it"),
            "a LAPSED lease names the successor it left behind: {lapsed:?}"
        );

        let wedged = health(
            &with_successor("mine", now + terms.ttl + 60, "theirs"),
            &terms,
            now,
        );
        assert!(
            format!("{wedged:?}").contains("theirs admitted behind it"),
            "a WEDGED lease names the successor too, and still fails: {wedged:?}"
        );
        assert!(
            matches!(wedged, Health::Wedged(_)),
            "and naming it does not soften the verdict: {wedged:?}"
        );
    }

    /// **BYTE-IDENTICAL WHEN NO SUCCESSOR IS ADMITTED**, which is the ordinary
    /// case: the field is absent on every lease minted before CLOUD-369 and on
    /// every lease nobody has reserved behind.
    ///
    /// The anti-vacuity mirror for the case above — without it, a clause that
    /// rendered `, admitted behind it` over an empty name would satisfy every
    /// assertion there and corrupt every report that has no successor.
    #[test]
    fn a_lease_with_no_successor_renders_byte_identically() {
        let terms = Terms::default();
        let now = 1000;
        for (expires, what) in [
            (now + 60, "held"),
            (0, "released"),
            (now - 5, "lapsed"),
            (now + terms.ttl + 60, "wedged"),
        ] {
            let rendered = format!(
                "{:?}",
                health(&with_successor("mine", expires, ""), &terms, now)
            );
            assert!(
                !rendered.contains("admitted behind it"),
                "{what} with no successor must read exactly as it did before: {rendered}"
            );
        }
    }

    /// A lease at exactly one TTL is the longest legitimate hold, not wedged.
    ///
    /// `>` rather than `>=`, and the boundary is the whole of it: the protocol
    /// mints exactly `now + ttl`, so the maximum legitimate horizon IS one TTL
    /// and refusing it would refuse every freshly-acquired lease.
    #[test]
    fn a_lease_at_exactly_one_ttl_is_the_longest_legitimate_hold() {
        let terms = Terms::default();
        let now = 1000;
        assert!(matches!(
            health(&with_successor("mine", now + terms.ttl, ""), &terms, now),
            Health::Held(_)
        ));
        assert!(matches!(
            health(
                &with_successor("mine", now + terms.ttl + 1, ""),
                &terms,
                now
            ),
            Health::Wedged(_)
        ));
    }

    fn at(expires: i64, holder: &str) -> Observed {
        Observed::Held {
            sha: String::from("1111111111111111111111111111111111111111"),
            body: Body {
                holder: holder.to_owned(),
                expires,
                ..Body::default()
            },
        }
    }

    #[test]
    fn the_three_free_states_are_all_healthy_and_all_distinguishable() {
        let terms = Terms::default();
        assert!(matches!(
            health(&Observed::Absent, &terms, 1000),
            Health::Free(_)
        ));
        let Health::Free(released) = health(&at(0, "a"), &terms, 1000) else {
            panic!("a tombstone is free");
        };
        assert!(released.contains("released"), "got: {released}");
        let Health::Free(lapsed) = health(&at(900, "a"), &terms, 1000) else {
            panic!("a lapsed lease is free");
        };
        // A declaration and an inference are reported differently, or a release
        // renders as an expiry half a century in the past.
        assert!(lapsed.contains("lapsed by a 100s ago"), "got: {lapsed}");
    }

    #[test]
    fn a_horizon_beyond_one_term_is_wedged() {
        // NOTHING LEGITIMATE PRODUCES THIS: a lease is only ever minted at one
        // term from now, so a longer horizon means somebody wrote the ref by hand
        // or under a different term — and it blocks the fleet for as long as it
        // says.
        let terms = Terms::default();
        assert!(matches!(
            health(&at(1000 + terms.ttl, "a"), &terms, 1000),
            Health::Held(_)
        ));
        assert!(matches!(
            health(&at(1000 + terms.ttl + 1, "a"), &terms, 1000),
            Health::Wedged(_)
        ));
    }

    #[test]
    fn a_ref_that_is_not_a_lease_is_garbage_rather_than_a_hold() {
        // Every decision treats it as held, which is safe and SILENT — so without
        // this it blocks landing for a term with nothing anywhere saying why.
        let garbage = Observed::Garbage {
            sha: String::from("2222222222222222222222222222222222222222"),
            why: String::from("the ref carries no lease body"),
        };
        let verdict = health(&garbage, &Terms::default(), 1000);
        assert!(matches!(verdict, Health::Garbage(_)));
        assert!(!verdict.healthy());
    }

    #[test]
    fn a_lease_nobody_can_release_is_garbage_whatever_its_expiry_says() {
        // Release requires recognising your own id, so a lease with no holder is
        // a state nobody can leave — a wedge, however healthy its clock looks.
        assert!(matches!(
            health(&at(1_000_000, ""), &Terms::default(), 1000),
            Health::Garbage(_)
        ));
    }

    #[test]
    fn garbage_is_waited_out_rather_than_taken() {
        // TAKING IT MEANS OVERWRITING WHATEVER A STRAY PUSH PUT THERE, and a
        // well-meant fix that races a real holder is worse than waiting a term.
        let garbage = Observed::Garbage {
            sha: String::from("2222222222222222222222222222222222222222"),
            why: String::from("the ref carries no lease body"),
        };
        assert_eq!(
            turn(&Terms::default(), &garbage, "me", 10_000, 10_000, 60, 1000),
            Turn::Wait
        );
    }

    #[test]
    fn garbage_still_lets_the_fleet_run() {
        // The other direction, and the asymmetry is the same one everywhere else:
        // stopping the fleet over a ref somebody mis-pushed is the cost the
        // authorising arm exists never to pay. The health gate is what reports it.
        let garbage = Observed::Garbage {
            sha: String::from("2222222222222222222222222222222222222222"),
            why: String::from("the ref carries no lease body"),
        };
        assert!(matches!(
            authorises(Some(&garbage), "claude/x", 1000),
            Authority::Run(_)
        ));
    }

    #[test]
    fn a_land_that_never_registered_is_not_a_stall() {
        // NO ENTRY, NO VERDICT. An unregistered land is not evidence, and killing
        // one on that reading would be inventing the finding.
        assert_eq!(bail(None, &Terms::default(), 60, 3, 1_000_000), Bail::Hold);
    }

    #[test]
    fn a_land_that_stopped_advancing_is_stopped() {
        let terms = Terms::default();
        let progress = Progress {
            advance: 1000,
            tick_at: 1000,
        };
        assert_eq!(
            bail(Some(progress), &terms, 60, 3, 1000 + 60 * terms.beat),
            Bail::Stop(String::from("has not advanced in 60 beats"))
        );
        assert_eq!(
            bail(Some(progress), &terms, 60, 3, 1000 + 60 * terms.beat - 1),
            Bail::Hold
        );
    }

    #[test]
    fn the_hang_bound_applies_only_while_a_loop_is_ticking() {
        // FOLDING THE TWO STAMPS WOULD KILL HEALTHY LANDINGS. A phase with no
        // loop has `tick_at <= advance`, and a verify step legitimately runs for
        // minutes — far longer than the three-beat hang bound.
        let terms = Terms::default();
        let quiet = Progress {
            advance: 1000,
            tick_at: 0,
        };
        let now = 1000 + 10 * terms.beat;
        assert_eq!(bail(Some(quiet), &terms, 60, 3, now), Bail::Hold);
        let ticking = Progress {
            advance: 1000,
            tick_at: 1001,
        };
        assert_eq!(
            bail(Some(ticking), &terms, 60, 3, 1001 + 3 * terms.beat),
            Bail::Stop(String::from("stopped turning 3 beats ago"))
        );
    }

    /// **The verdict `lease status` and the `lease-status` column both carry.**
    ///
    /// Shown able to fail on the arm that matters: a live lease held by a rival
    /// authorises nobody, and the same lease held by this clone authorises it.
    /// Tested here rather than over the binary because the failing condition is
    /// a lease on a real remote, which no fixture in this sandbox produces —
    /// `.claude/rules/rust.md`'s rule for exactly that case.
    ///
    /// The regression it pins is measured rather than imagined: the first port
    /// of `land-lock.sh status` returned `Success` on every answering path, so
    /// `[program.land-lock-status]`'s `held-elsewhere` mapping became
    /// unreachable, the recorder wrote `authorised` over a rival's lease, and
    /// the `landing-loop` preset allowed the overlapping spend it exists to
    /// refuse — a dead gate with a green suite, because no case drove the
    /// producer.
    #[test]
    fn a_live_lease_authorises_its_holder_and_nobody_else() {
        let now = 1000;
        let live = body("mine", now + 60, "");
        assert!(
            authorises_this_clone(&live, "mine", now),
            "the holder may spend"
        );
        assert!(
            !authorises_this_clone(&live, "theirs", now),
            "AND A RIVAL MAY NOT — the arm the whole verdict exists for"
        );
    }

    /// Absent, released and expired are one answer, because the next `acquire`
    /// wins and nothing is authorised away from anybody.
    ///
    /// The anti-vacuity mirror for the pair above: without it a predicate that
    /// answered *not authorised* for every clone but the holder would pass,
    /// which would stop a fleet standing on a free lease.
    #[test]
    fn a_lease_that_holds_nothing_authorises_every_clone() {
        let now = 1000;
        assert!(authorises_this_clone(&Observed::Absent, "anyone", now));
        assert!(
            authorises_this_clone(&body("theirs", 0, ""), "anyone", now),
            "a tombstone is a DECLARATION, and `0` is its sentinel rather than an instant"
        );
        assert!(
            authorises_this_clone(&body("theirs", now, ""), "anyone", now),
            "zero seconds left is none left — the `>=` the expiry comparison uses"
        );
    }

    /// **A REF THAT WILL NOT PARSE HAS NOT SHOWN THIS CLONE OWNS ANYTHING**, and
    /// it lived in the case above asserting the opposite (review of #848).
    ///
    /// The premise there was that garbage "reaches the preset as could-not-look
    /// on the COLUMN, so answering it here as a refusal would fail closed twice".
    /// It did not: [`adjudicate`] turned the `true` into exit `0` and
    /// `batten.toml` maps `"0"` to `authorised`, so the column recorded
    /// AUTHORISED, the `landing-loop` refusal could not hold, and this clone
    /// landed beside a live holder. It also contradicted [`Observed::Garbage`]'s
    /// own doc — "Every decision below still treats this as held".
    ///
    /// Moved to its own case because it is not one of "absent, released and
    /// expired": those three are provably free, and this one is unread.
    /// `adjudicate` answers `3` for it now, which is the could-not-look column
    /// the old premise described but did not produce.
    #[test]
    fn a_lease_nobody_can_parse_authorises_nobody() {
        assert!(
            !authorises_this_clone(
                &Observed::Garbage {
                    sha: String::from("1111111111111111111111111111111111111111"),
                    why: String::from("the ref carries no lease body"),
                },
                "anyone",
                1000
            ),
            "an unparseable lease must not read as free"
        );
    }

    #[test]
    fn a_progress_token_is_the_pair_and_nothing_interpreted() {
        assert_eq!(
            Progress {
                advance: 100,
                tick_at: 200
            }
            .token(),
            "100.200"
        );
    }

    #[test]
    fn a_registry_entry_with_no_usable_stamp_is_no_evidence() {
        // Distinct from an absent entry only in where it comes from; both are
        // "cannot tell", and reading a zero as a stall at the epoch would make
        // every unstamped land instantly reapable.
        let dir = scratch("registry");
        std::fs::create_dir_all(dir.join("batten-tasks")).expect("registry");
        std::fs::write(
            dir.join("batten-tasks").join("4242"),
            "task: land\npid: 4242\nphase_since: 0\nsig_at: 0\ntick_at: 0\n",
        )
        .expect("entry");
        assert_eq!(progress_of(&dir, 4242), None);
    }

    #[test]
    fn the_advance_is_the_later_of_the_two_ways_to_move() {
        let dir = scratch("registry-advance");
        std::fs::create_dir_all(dir.join("batten-tasks")).expect("registry");
        std::fs::write(
            dir.join("batten-tasks").join("4243"),
            "phase_since: 100\nsig_at: 700\ntick_at: 900\n",
        )
        .expect("entry");
        assert_eq!(
            progress_of(&dir, 4243),
            Some(Progress {
                advance: 700,
                tick_at: 900
            })
        );
    }

    #[test]
    fn a_pid_that_cannot_be_read_is_gone_rather_than_alive() {
        // RELEASE IS THE CHEAP DIRECTION. A wrongly released lease costs one lap;
        // a wrongly renewed one wedges the fleet.
        assert!(!holder_alive(0, "batten land"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn this_process_is_alive_under_a_marker_it_carries() {
        // The anti-vacuity mirror: without it the case above is satisfied by a
        // predicate that answers `false` for everything.
        //
        // LINUX-ONLY, and the `cfg` is the finding rather than a convenience. The
        // case read `/proc` directly and panicked on Windows CI — which is this
        // assertion doing its job on a target where the predicate really IS
        // vacuous, not a fixture that needed relaxing. The platform arm below
        // pins what that target answers, so the vacuity is declared instead of
        // being reported as a failure nobody could act on.
        let mine = std::process::id();
        let raw =
            std::fs::read(format!("/proc/{mine}/cmdline")).expect("this process has a cmdline");
        let command = String::from_utf8_lossy(&raw).replace('\0', " ");
        let word = command.split_whitespace().next().expect("argv0").to_owned();
        assert!(holder_alive(mine, &word));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn without_proc_the_probe_is_inert_rather_than_wrong() {
        // The other half of the split: on a target with no `/proc` every pid
        // reads as gone, including this process under its own argv0. Pinned so
        // the inertness is a declared property rather than something a reader
        // has to infer from a `cfg` on the function.
        assert!(!holder_alive(std::process::id(), "batten"));
    }

    #[test]
    fn an_absent_lease_is_taken_without_corroboration() {
        // A statement rather than a deduction, so no clock and no beat.
        assert!(matches!(
            turn(&Terms::default(), &Observed::Absent, "me", 0, 0, 60, 100),
            Turn::Take(_)
        ));
    }

    #[test]
    fn a_released_lease_is_taken_without_corroboration() {
        assert!(matches!(
            turn(&Terms::default(), &body("them", 0, ""), "me", 0, 0, 60, 100),
            Turn::Take(_)
        ));
    }

    #[test]
    fn an_expired_lease_is_not_taken_until_its_sha_has_sat_a_beat() {
        // THE ONE EXTRA BEAT. Expiry is an instant on the HOLDER's clock; the
        // sighting is a duration on ours, and no skew can forge it. Taking on
        // expiry alone is what puts two holders on one trunk.
        let terms = Terms::default();
        assert_eq!(
            turn(
                &terms,
                &body("them", 100, ""),
                "me",
                terms.beat - 1,
                0,
                60,
                200
            ),
            Turn::Wait
        );
        assert!(matches!(
            turn(&terms, &body("them", 100, ""), "me", terms.beat, 0, 60, 200),
            Turn::Take(_)
        ));
    }

    #[test]
    fn a_beating_but_stalled_lease_is_stealable() {
        // The wedge this arm exists to end: every other arm waits for the holder
        // to stop beating, and a holder that beats forever without landing never
        // does.
        let terms = Terms::default();
        assert!(matches!(
            turn(
                &terms,
                &body("them", 100_000, "1.2"),
                "me",
                0,
                60 * terms.beat,
                60,
                200
            ),
            Turn::Take(_)
        ));
    }

    #[test]
    fn a_lease_carrying_no_progress_token_is_never_stall_stealable() {
        // IT FAILS CLOSED, unlike the holder's own bail, and that asymmetry is
        // the design: this is every lease minted before the field existed and
        // every holder that cannot see its own progress. Releasing a lease
        // wrongly costs one lap; stealing one wrongly puts two holders on the
        // same trunk.
        let terms = Terms::default();
        assert_eq!(
            turn(
                &terms,
                &body("them", 100_000, ""),
                "me",
                0,
                1_000_000,
                60,
                200
            ),
            Turn::Wait
        );
    }

    #[test]
    fn a_live_lease_of_this_clones_own_is_not_re_taken() {
        assert_eq!(
            turn(
                &Terms::default(),
                &body("me", 100_000, ""),
                "me",
                0,
                0,
                60,
                200
            ),
            Turn::Mine
        );
    }

    #[test]
    fn this_clones_own_expired_lease_is_taken_rather_than_assumed() {
        // `Mine` is a claim about a LIVE lease. A holder that was paused past its
        // TTL must re-take rather than carry on believing it holds one.
        let terms = Terms::default();
        assert!(matches!(
            turn(&terms, &body("me", 100, ""), "me", terms.beat, 0, 60, 200),
            Turn::Take(_)
        ));
    }

    #[test]
    fn a_first_sighting_is_zero_and_the_second_measures_from_it() {
        let local = Local::under(&scratch("sighting"));
        assert_eq!(local.held_for("seen", "abc", 100), 0);
        assert_eq!(local.held_for("seen", "abc", 130), 30);
        // A CHANGED VALUE RESTARTS THE CLOCK, which is what makes this evidence
        // about the lease sitting still rather than about how long we have been
        // watching.
        assert_eq!(local.held_for("seen", "def", 200), 0);
    }

    #[test]
    fn a_holder_id_is_minted_once_and_reused() {
        // `hold`, `held` and `release` are separate processes from the `acquire`
        // that won, so a per-process id would leave the holder unable to
        // recognise its own lease.
        let local = Local::under(&scratch("holder"));
        let first = local.holder().expect("mint");
        assert_eq!(local.holder().expect("read"), first);
        assert!(!first.is_empty());
    }

    #[test]
    fn a_claim_does_not_carry_the_previous_holders_successor() {
        // THE BOUND WOULD DRIFT UPWARD ONE HANDOVER AT A TIME. A fresh acquire is
        // a new turn and the previous successor has had its admission; carrying it
        // would authorise a third branch, then a fourth.
        let terms = Terms::default();
        let claimed = claim(&terms, "host-2-bb", "claude/b", "3333", 1_700_000_000);
        assert!(claimed.next.is_empty());
        assert_eq!(claimed.expires, 1_700_000_000 + terms.ttl);
    }

    #[test]
    fn a_renewal_carries_the_successor_a_waiter_wrote() {
        // Erasing it would cancel the admitted successor's run mid-flight, within
        // one beat of the reservation being made.
        let terms = Terms::default();
        let body = Body {
            holder: String::from("host-1-aa"),
            expires: 1_700_000_060,
            branch: String::from("claude/a"),
            next: String::from("claude/b"),
            progress: String::from("100.200"),
            ..Body::default()
        };
        let renewed = renewal(&terms, &body, None, 1_700_000_030);
        assert_eq!(renewed.next, "claude/b");
        assert_eq!(renewed.progress, "100.200");
        assert_eq!(renewed.holder, "host-1-aa");
        assert_eq!(renewed.expires, 1_700_000_030 + terms.ttl);
    }

    #[test]
    fn a_reservation_moves_one_field_and_leaves_the_holder_holding() {
        // A reservation that moved the holder id would be a steal wearing a
        // different name; one that recomputed the expiry would hand the holder a
        // fresh TTL every time a waiter arrived.
        let body = Body {
            holder: String::from("host-1-aa"),
            expires: 1_700_000_060,
            branch: String::from("claude/a"),
            head: String::from("2222"),
            progress: String::from("100.200"),
            nonce: String::from("aaaaaaaaaaaaaaaa"),
            next: String::new(),
        };
        let reserved = reservation(&body, "claude/b");
        assert_eq!(reserved.next, "claude/b");
        assert_eq!(reserved.holder, body.holder);
        assert_eq!(reserved.expires, body.expires);
        assert_eq!(reserved.branch, body.branch);
        assert_eq!(reserved.head, body.head);
        assert_eq!(reserved.progress, body.progress);
        // The nonce must move even when nothing else does, or the re-mint is the
        // object the ref already carries and the push is a success that changed
        // nothing.
        assert_ne!(reserved.nonce, body.nonce);
    }

    #[test]
    fn a_tombstone_is_a_declaration_rather_than_an_instant() {
        let body = Body {
            holder: String::from("host-1-aa"),
            expires: 1_700_000_060,
            branch: String::from("claude/a"),
            nonce: String::from("aaaaaaaaaaaaaaaa"),
            ..Body::default()
        };
        let dead = tombstone(&body);
        assert_eq!(dead.expires, 0);
        assert!(dead.released());
        // It still names who left it, so a lease nobody released stays the tell
        // for a session that died holding one.
        assert_eq!(dead.branch, "claude/a");
        assert_ne!(dead.nonce, body.nonce);
    }

    #[test]
    fn two_nonces_from_one_process_differ() {
        // The whole uniqueness argument rests on this, and the fallback path is
        // the one that could quietly break it: a constant there would make two
        // clones that both failed to read entropy mint the same object.
        assert_ne!(nonce(), nonce());
    }

    fn held(branch: &str, next: &str, expires: i64) -> Observed {
        Observed::Held {
            sha: String::from("1111111111111111111111111111111111111111"),
            body: Body {
                holder: String::from("host-1-aa"),
                expires,
                branch: branch.to_owned(),
                next: next.to_owned(),
                ..Body::default()
            },
        }
    }

    #[test]
    fn a_lease_that_cannot_be_read_lets_the_fleet_run() {
        // THE ASYMMETRY IS THE WHOLE JUSTIFICATION. Failing closed here stops
        // EVERY job in the fleet; failing open costs one matrix. Every other
        // refusal in this design goes the other way, so this case is asserted
        // rather than left to follow from the code reading naturally.
        assert!(matches!(
            authorises(None, "claude/x", 100),
            Authority::Run(_)
        ));
    }

    #[test]
    fn a_lease_naming_no_branch_lets_the_fleet_run() {
        // Every lease minted before the field existed is this row, so during a
        // rollout it is not an edge case, it is all of them.
        assert!(matches!(
            authorises(Some(&held("", "", 900)), "claude/x", 100),
            Authority::Run(_)
        ));
    }

    #[test]
    fn a_lease_held_by_another_branch_stops_this_one() {
        let Authority::Stop(why) = authorises(Some(&held("claude/a", "", 900)), "claude/b", 100)
        else {
            panic!("a held lease must stop a branch it does not name");
        };
        // Pointer-only: the holder's branch is a ref name, never a lease body.
        assert_eq!(why, "the lease authorises claude/a, not claude/b");
    }

    #[test]
    fn the_admitted_successor_runs_beside_the_holder() {
        // The bound is TWO, not one: stopping the reserved branch would cancel
        // the very run the reservation exists to start.
        assert!(matches!(
            authorises(Some(&held("claude/a", "claude/b", 900)), "claude/b", 100),
            Authority::Run(_)
        ));
    }

    #[test]
    fn a_released_lease_authorises_everyone_without_consulting_the_clock() {
        // A tombstone satisfies `expired` trivially, so a reader that checked the
        // clock first would render an epoch-scale age for it. It is a HANDOVER.
        let lease = held("claude/a", "", 0);
        assert!(matches!(
            authorises(Some(&lease), "claude/b", 0),
            Authority::Run(_)
        ));
    }

    #[test]
    fn an_expired_lease_stops_nobody() {
        assert!(matches!(
            authorises(Some(&held("claude/a", "", 100)), "claude/b", 100),
            Authority::Run(_)
        ));
    }

    #[test]
    fn a_body_round_trips_through_its_own_rendering() {
        let body = Body {
            holder: String::from("host-1-aa"),
            expires: 1_700_000_060,
            branch: String::from("claude/x"),
            head: String::from("2222222222222222222222222222222222222222"),
            next: String::from("claude/y"),
            progress: String::from("1700000000.1700000030"),
            nonce: String::from("deadbeefdeadbeef"),
        };
        let object = lease_object(&body.render(), 1_700_000_000).expect("mint");
        assert_eq!(parse_body(&object.body), Some(body));
    }

    #[test]
    fn a_commit_that_is_not_a_lease_does_not_parse_as_an_unheld_one() {
        // The same refusal the advertisement makes: a foreign object parsed
        // loosely yields empty fields, which read as a lease nobody holds.
        let object = lease_object("some other commit\n", 1_700_000_000).expect("mint");
        assert_eq!(parse_body(&object.body), None);
    }

    #[test]
    fn a_lease_with_no_expiry_does_not_parse() {
        // The default belongs to the caller that knows its own TTL. A parser
        // inventing one would report a lease it could not read as one it could.
        let object =
            lease_object("land-lock\nholder: a\nnonce: bb\n", 1_700_000_000).expect("mint");
        assert_eq!(parse_body(&object.body), None);
    }

    #[test]
    fn an_empty_advisory_field_is_a_reading_rather_than_an_absence() {
        let body = Body {
            holder: String::from("host-1-aa"),
            expires: 1_700_000_060,
            nonce: String::from("deadbeefdeadbeef"),
            ..Body::default()
        };
        let object = lease_object(&body.render(), 1_700_000_000).expect("mint");
        let read = parse_body(&object.body).expect("parse");
        assert_eq!(read, body);
        assert!(read.branch.is_empty());
    }

    #[test]
    fn a_lease_object_round_trips_through_a_pack() {
        let object =
            lease_object("holder: a\nexpires: 1\nnonce: aa\n", 1_700_000_000).expect("mint");
        let pack = pack_of(std::slice::from_ref(&object)).expect("pack");
        assert_eq!(objects_in(&pack).expect("unpack"), vec![object]);
    }

    #[test]
    fn two_mints_differing_only_in_their_nonce_are_different_objects() {
        // GIT ADDRESSES BY CONTENT, so two agreeing mints produce one id and the
        // second push is an "up to date" no-op that reports success — a rejected
        // claim read as a win. This is the property the nonce exists for, and it
        // is asserted rather than trusted because the failure is silent.
        let one = lease_object("holder: a\nexpires: 1\nnonce: aa\n", 1_700_000_000).expect("mint");
        let two = lease_object("holder: a\nexpires: 1\nnonce: bb\n", 1_700_000_000).expect("mint");
        assert_ne!(one.id, two.id);
    }

    #[test]
    fn a_lease_object_is_parentless_over_the_empty_tree() {
        // The two structural properties that make every swap a CAS: no parent to
        // fast-forward from, and no tree anyone could be tempted to merge.
        let object = lease_object("holder: a\n", 1_700_000_000).expect("mint");
        let text = String::from_utf8_lossy(&object.body);
        assert!(!text.contains("parent "), "got: {text}");
        assert!(
            text.starts_with("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"),
            "got: {text}"
        );
    }

    /// The live FETCH. Gated like the push, and the discriminating case for D2.
    ///
    /// **The pack a real server sends is delta-compressed**, which is exactly what
    /// the single-`want` lease path never produced: every lease pack carries two
    /// undeltified objects. So this is the only case that drives `apply_delta` and
    /// the offset-base decoder over bytes GitHub actually built.
    #[test]
    fn a_ref_fetches_and_its_objects_arrive() {
        let Ok(reference) = std::env::var("BATTEN_LIVE_FETCH_REF") else {
            return;
        };
        let remote = std::env::var("BATTEN_LIVE_PUSH_REMOTE").expect("remote url");
        let repo = std::path::Path::new(".");
        let fetched = fetch(&remote, repo, &reference).expect("fetch");
        assert_eq!(fetched.head.len(), 40, "the head must be a full sha");
        // Every object must hash to the id the reader computed for it — the pack
        // reader derives the id from the bytes, so a delta applied wrongly yields
        // an id nothing asked for rather than a visible corruption.
        for object in &fetched.objects {
            let id = gix::objs::compute_hash(gix::hash::Kind::Sha1, object.kind, &object.body)
                .expect("hash");
            assert_eq!(
                id.to_string(),
                object.id,
                "a member must hash to its own id"
            );
        }
        // And the thing asked for has to be in the answer, or the negotiation
        // agreed on a common ancestor that did not include it.
        assert!(
            fetched.objects.is_empty() || fetched.objects.iter().any(|o| o.id == fetched.head),
            "a non-empty answer must carry the wanted head"
        );
    }

    /// The full D2 round trip: fetch, write into the odb, move the ref.
    ///
    /// **The half a wire test cannot reach.** Reading objects off the network
    /// proves the reader; only writing them and finding them again proves the
    /// engine can USE what it fetched, which is the whole point of the capability.
    #[test]
    fn fetched_objects_land_in_the_odb_and_the_ref_moves() {
        let Ok(reference) = std::env::var("BATTEN_LIVE_ROUNDTRIP_REF") else {
            return;
        };
        let remote = std::env::var("BATTEN_LIVE_PUSH_REMOTE").expect("remote url");
        let repo = std::path::Path::new(".");
        let fetched = fetch(&remote, repo, &reference).expect("fetch");
        let written =
            crate::gitwrite::write_objects(repo, &fetched.objects).expect("write the objects");
        // Every object must be findable afterwards, by the id the reader derived.
        // A write that "succeeded" and left nothing readable is the failure this
        // case exists for.
        for object in &fetched.objects {
            assert!(
                crate::git::has_object(repo, &object.id),
                "{} was written and cannot be found",
                object.id
            );
        }
        // The ref goes somewhere this repository does not otherwise use, so the
        // case never moves a ref a lap depends on.
        let landed = "refs/batten-fetch-probe/head";
        crate::gitwrite::set_ref(repo, landed, &fetched.head).expect("move the ref");
        assert_eq!(
            crate::git::resolve_ref(repo, landed).expect("read it back"),
            Some(fetched.head.clone()),
            "the ref must read what the fetch landed"
        );
        assert!(
            written <= fetched.objects.len(),
            "writing cannot invent objects"
        );
    }

    /// The live DELETE, gated the same way and for the same reason.
    ///
    /// **Do not set this variable in the Batten sandbox**: its git proxy answers
    /// 403 to a ref deletion, so the case can only fail there. See
    /// [`delete_ref`]'s own note — the refusal is the environment's, not the
    /// code's, and the landing loop treats a failed delete as best-effort anyway.
    #[test]
    fn a_scratch_ref_deletes_when_asked() {
        let Ok(reference) = std::env::var("BATTEN_LIVE_DELETE_REF") else {
            return;
        };
        let remote = std::env::var("BATTEN_LIVE_PUSH_REMOTE").expect("remote url");
        let outcome = delete_ref(&remote, &reference).expect("delete");
        assert_eq!(outcome, Outcome::Applied, "the scratch delete must apply");
    }

    /// The live push, run only when the environment names a scratch ref.
    ///
    /// **Not a suite case, and it must not become one.** It writes to a real
    /// remote, so it is gated on an explicit opt-in rather than on a credential
    /// being present — a case that fires whenever a token happens to exist is a
    /// case that pushes from CI.
    #[test]
    fn a_branch_pushes_to_a_scratch_ref_when_asked() {
        let Ok(reference) = std::env::var("BATTEN_LIVE_PUSH_REF") else {
            return;
        };
        let repo = std::path::Path::new(".");
        let remote = std::env::var("BATTEN_LIVE_PUSH_REMOTE").expect("remote url");
        let head = crate::git::head_commit(repo).expect("head");
        let outcome = push(&remote, repo, &reference, &head).expect("push");
        assert_eq!(outcome, Outcome::Applied, "the scratch push must apply");
    }

    #[test]
    fn a_real_branch_enumerates_more_than_a_handful_of_objects() {
        // THE SHAPE EVERY LEASE FIXTURE LACKS. A lease pack carries one commit and
        // one empty tree; a branch push carries commits, trees and blobs in the
        // hundreds, and the pack writer had never been asked for one. This drives
        // the enumeration over THIS repository's own history — the only corpus to
        // hand that is genuinely branch-shaped.
        let repo = std::path::Path::new(".");
        let Ok(head) = crate::git::head_commit(repo) else {
            // A checkout this test cannot read is not a finding about the pack
            // writer. Could-not-look, never a pass asserted over nothing.
            return;
        };
        let Ok(parent) = crate::git::commits_in_range(repo, "HEAD~1", "HEAD") else {
            return;
        };
        if parent.is_empty() {
            return;
        }
        let Ok(objects) = crate::git::objects_to_send(repo, Some("HEAD~1"), &head) else {
            return;
        };
        // One commit's worth of change touches at least the commit, the root tree
        // and one blob. A set smaller than that is an enumeration that walked
        // nothing, which is the failure a green suite would otherwise hide.
        assert!(
            objects.len() >= 3,
            "one commit should enumerate at least commit + root tree + a blob, got {}",
            objects.len()
        );
        assert!(
            objects.iter().any(|o| o.kind == gix::object::Kind::Commit),
            "the commit itself must be in the set"
        );
        assert!(
            objects.iter().any(|o| o.kind == gix::object::Kind::Tree),
            "the root tree must be in the set"
        );
        // And it must round-trip through the pack writer, which is the half the
        // single-object fixtures never exercised.
        let packed: Vec<Object> = objects
            .into_iter()
            .map(|raw| Object {
                id: raw.id,
                kind: raw.kind,
                body: raw.body,
            })
            .collect();
        let pack = pack_of(&packed).expect("pack a real branch delta");
        let read = objects_in(&pack).expect("unpack a real branch delta");
        assert_eq!(read, packed, "every member must survive the round trip");
    }

    #[test]
    fn the_base_is_subtracted_rather_than_resent() {
        // The whole economy of the push. Without the subtraction a lap would
        // re-send the repository's entire history every time.
        let repo = std::path::Path::new(".");
        let Ok(head) = crate::git::head_commit(repo) else {
            return;
        };
        let Ok(narrow) = crate::git::objects_to_send(repo, Some("HEAD~1"), &head) else {
            return;
        };
        let Ok(wide) = crate::git::objects_to_send(repo, Some("HEAD~3"), &head) else {
            return;
        };
        assert!(
            wide.len() >= narrow.len(),
            "a wider range cannot enumerate fewer objects: {} vs {}",
            wide.len(),
            narrow.len()
        );
    }

    #[test]
    fn a_pack_carrying_the_commits_closure_still_yields_the_commit() {
        // MEASURED AGAINST THE REAL REMOTE, not imagined: a `want` for one commit
        // returns its whole closure, so the answer carries the commit AND the
        // empty tree it points at. A reader that assumed every member was a
        // commit refused that while passing every synthetic case, because the
        // fixture packs it was tested against carried one object each.
        let commit =
            lease_object("land-lock\nholder: a\nexpires: 1\n", 1_700_000_000).expect("mint");
        let tree = Object {
            id: String::from("4b825dc642cb6eb9a060e54bf8d69288fbee4904"),
            kind: gix::object::Kind::Tree,
            body: Vec::new(),
        };
        let pack = pack_of(&[commit.clone(), tree.clone()]).expect("pack");
        let read = objects_in(&pack).expect("unpack");
        assert_eq!(read, vec![commit.clone(), tree]);
        // And the id survives the round trip, which is what `fetch_object`'s
        // "does this answer carry what was asked for" check turns on.
        assert!(read.iter().any(|object| object.id == commit.id));
    }

    #[test]
    fn a_body_that_is_not_a_pack_is_could_not_look() {
        // The upload-pack answer's tail is whatever followed the framed section,
        // so a proxy that returned prose leaves prose here. Reading it as an
        // empty object set would say "the lease body is unreadable, carry on",
        // which is the direction that loses the fleet.
        assert!(objects_in(b"not a pack at all").is_err());
    }

    #[test]
    fn a_truncated_pack_member_is_could_not_look_rather_than_a_short_body() {
        let object = lease_object("holder: a\n", 1_700_000_000).expect("mint");
        let pack = pack_of(&[object]).expect("pack");
        assert!(objects_in(&pack[..pack.len() - 24]).is_err());
    }

    #[test]
    fn a_pack_section_is_found_after_the_framed_one() {
        // NOTHING IS FRAMED BETWEEN `NAK` AND THE PACK, which is why the split
        // has to return a boundary rather than a line list. A reader that stopped
        // at the first unparseable header without handing back the tail could
        // never reach the lease body at all.
        let mut body = framed(&["NAK\n"]);
        let object = lease_object("holder: a\n", 1_700_000_000).expect("mint");
        body.extend_from_slice(&pack_of(std::slice::from_ref(&object)).expect("pack"));
        let (lines, tail) = pkt_split(&body).expect("split");
        assert_eq!(lines, vec!["NAK\n"]);
        assert_eq!(objects_in(tail).expect("unpack"), vec![object]);
    }

    #[test]
    fn the_request_body_is_commands_then_a_flush_then_the_pack() {
        let update = Update {
            old: String::from(ZERO),
            new: String::from("3333333333333333333333333333333333333333"),
            name: String::from("refs/heads/batten-land-lock"),
        };
        let body = receive_pack_body(&update, b"PACKFAKE").expect("compose");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("refs/heads/batten-land-lock"));
        assert!(text.ends_with("0000PACKFAKE"), "got: {text}");
    }
}

#[cfg(test)]
// Panicking on a failed assertion is how a test fails loudly.
#[allow(clippy::expect_used)]
mod staleness_tests {
    use super::{Authority, Carries, Guarded, decide, guard};

    /// **THE FAIL-OPEN DIRECTION IS THIS GATE'S WHOLE CORRECTNESS, and it is the
    /// opposite of every other refusal in this repository.**
    ///
    /// A reading the guard could not take would cancel every job in the fleet,
    /// where waving one matrix through costs one matrix. So the set below runs,
    /// and only a PROVEN stop stops. Asserted as the whole set because a version
    /// that ran on everything and one that stopped on everything each satisfy
    /// any single case.
    #[test]
    fn every_reading_it_could_not_take_runs_and_only_a_proven_stop_stops() {
        let unknown = Carries::Unknown {
            because: String::from("no landing paths declared"),
        };
        for (carries, authority) in [
            (&unknown, None),
            (
                &unknown,
                Some(Authority::Run(String::from("nobody holds it"))),
            ),
            (&Carries::Current, None),
        ] {
            let verdict = guard(carries, authority.as_ref());
            assert!(
                matches!(verdict, Guarded::Run { .. }),
                "a could-not-look must spend the matrix: {verdict:?}"
            );
        }

        // And the two that DO stop, which is what keeps the above from being a
        // gate that never fires.
        assert!(matches!(
            guard(
                &Carries::Stale {
                    wanted: String::from("trunksha")
                },
                None
            ),
            Guarded::Stop { .. }
        ));
        assert!(matches!(
            guard(
                &Carries::Current,
                Some(&Authority::Stop(String::from("somebody else holds it")))
            ),
            Guarded::Stop { .. }
        ));
    }

    /// **AN UNKNOWN STALENESS READING DOES NOT OUTRANK A LEASE THAT SAYS STOP**,
    /// and this doc asserted the opposite over a predecessor that says so in the
    /// other direction (review of #848).
    ///
    /// Read at `origin/main:mise-tasks/ci-lease-precondition.sh:163`: the
    /// unreadable arm is `say "cannot read this head's mise-tasks/land.sh; not
    /// judging its age"` and sets NOTHING, so `if [[ -z "${stop:-}" ]]` holds and
    /// the lease table is entered. Only the STALE arm sets `stop=1`. So `Unknown`
    /// never skipped the lease; the port made it do so, and the case below pinned
    /// the port rather than the behaviour it claimed to conserve.
    ///
    /// What is true, and what this case actually shows, is the STALE half: a head
    /// that provably does not carry trunk's landing mechanism stops without the
    /// lease being read at all.
    #[test]
    fn a_stale_head_stops_without_the_lease_being_consulted() {
        // A stop from staleness names the commit the head is missing, so the
        // remedy is in the annotation rather than in a follow-up read.
        let verdict = guard(
            &Carries::Stale {
                wanted: String::from("abc123"),
            },
            Some(&Authority::Run(String::from("nobody holds it"))),
        );
        match verdict {
            Guarded::Stop { why } => {
                assert!(
                    why.contains("abc123"),
                    "the refusal names the commit: {why}"
                );
                assert!(
                    why.contains("Rebase"),
                    "and the remedy, because a cancelled run has no failed step to read: {why}"
                );
            }
            Guarded::Run { why } => panic!("a stale head must not spend a matrix: {why}"),
        }
    }

    /// **AND AN UNJUDGED HEAD STILL ANSWERS TO THE LEASE**, which is the arm the
    /// case above used to assert away.
    ///
    /// With the forge rate-limited or the credential absent, `decide` yields
    /// `Carries::Unknown`. Returning `Run` there without asking the lease meant a
    /// rival's live hold was ignored and this job spent a matrix beside it —
    /// two landers, which is the one thing this module exists to prevent.
    #[test]
    fn an_unjudged_head_still_stops_on_a_lease_somebody_else_holds() {
        let unknown = Carries::Unknown {
            because: String::from("the forge did not answer"),
        };
        let verdict = guard(
            &unknown,
            Some(&Authority::Stop(String::from("somebody else holds it"))),
        );
        match verdict {
            Guarded::Stop { why } => {
                assert!(
                    why.contains("somebody else holds it"),
                    "the lease's own reason reaches the reader: {why}"
                );
                assert!(
                    why.contains("not judging this head's age"),
                    "and so does the reading that could not be taken: {why}"
                );
            }
            Guarded::Run { why } => {
                panic!("an unjudged head must still answer to the lease: {why}")
            }
        }
    }

    fn paths() -> Vec<String> {
        vec![String::from("mise-tasks/land.sh")]
    }

    /// **The discriminating pair: a head carrying trunk's landing commit is
    /// current, one that does not is stale.**
    ///
    /// This is the predicate whose predecessor is about to go SILENTLY dead.
    /// `ci-lease-precondition.sh:157` greps the head's `mise-tasks/land.sh` for
    /// `land-lock acquire`; once that file is retired the read fails, the script
    /// takes its own fail-open path — "not judging this head's age" — and every
    /// stale head passes. A path SET survives the retirement that killed a grep
    /// string, because what changes when the mechanism moves is which paths, and
    /// that is config a retirement edits rather than a literal it invalidates.
    #[test]
    fn a_head_carrying_trunks_landing_commit_is_current_and_one_behind_is_stale() {
        assert_eq!(
            decide(&paths(), "headsha", Some("trunksha"), Some(true)),
            Carries::Current
        );
        assert_eq!(
            decide(&paths(), "headsha", Some("trunksha"), Some(false)),
            Carries::Stale {
                wanted: String::from("trunksha")
            },
            "the refusal names the commit the head is missing, and nothing else"
        );
    }

    /// **EVERY UNKNOWN IS ITS OWN VARIANT, AND NEVER `Stale`.**
    ///
    /// This gate is the opposite of every other refusal in the repository: it
    /// fails OPEN, because a reading it cannot take would cancel every job in
    /// the fleet where waving one matrix through costs one matrix. Reading a
    /// could-not-look as stale is the expensive direction; reading it as current
    /// is how the predecessor's row died. It is neither, and the caller decides.
    ///
    /// Asserted as the whole set, because a version that answered `Unknown` for
    /// everything and one that answered `Current` for everything each satisfy a
    /// single case.
    #[test]
    fn every_reading_that_could_not_be_taken_is_unknown_rather_than_a_verdict() {
        for (paths, head, wanted, ancestral) in [
            (Vec::new(), "headsha", Some("trunksha"), Some(false)),
            (paths(), "", Some("trunksha"), Some(false)),
            (paths(), "   ", Some("trunksha"), Some(false)),
            (paths(), "headsha", None, Some(false)),
            (paths(), "headsha", Some("trunksha"), None),
        ] {
            let verdict = decide(&paths, head, wanted, ancestral);
            assert!(
                matches!(verdict, Carries::Unknown { .. }),
                "an unreadable input must not become a verdict: {verdict:?}"
            );
        }
    }

    /// The unknown NAMES what could not be read.
    ///
    /// Pointer-only (non-negotiable rule 4): a reason a human can act on, never
    /// a byte of the response. A stopped run is a cancelled run with no failed
    /// step of its own, so without this the reader sees a red check and no clue.
    #[test]
    fn an_unknown_names_which_reading_was_missing() {
        let no_paths = decide(&[], "headsha", None, None);
        let no_head = decide(&paths(), "", None, None);
        assert_ne!(
            format!("{no_paths:?}"),
            format!("{no_head:?}"),
            "two different could-not-looks must not report the same reason"
        );
    }
}
