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
        headers: &[(String::from("Accept"), String::from("*/*"))],
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
        headers: &[
            (String::from("Content-Type"), content_type),
            (
                String::from("Accept"),
                format!("application/x-{}-result", Service::ReceivePack.as_str()),
            ),
        ],
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
        body,
    })
}

/// The pack object type receive-pack reads for a commit.
const PACK_COMMIT: u8 = 1;
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
        let mut byte = (PACK_COMMIT << 4) | ((size & 0x0f) as u8);
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
    let mut rest = &pack[12..];
    let mut objects = Vec::new();
    for _ in 0..count {
        let (kind, size, header) = pack_header(rest)?;
        // A DELTA IS REFUSED RATHER THAN RESOLVED. `pack_of` never writes one and
        // a single-object fetch never receives one, so a resolver here would be a
        // path no test could reach — which is the shape that rots.
        if kind == 6 || kind == 7 {
            return Err(anyhow::anyhow!(
                "lease: the pack carries a delta, which this reader does not resolve"
            ));
        }
        if kind != PACK_COMMIT {
            return Err(anyhow::anyhow!(
                "lease: the pack carries object type {kind}, and a lease is a commit"
            ));
        }
        rest = &rest[header..];
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
        rest = &rest[consumed..];
        let id = gix::objs::compute_hash(gix::hash::Kind::Sha1, gix::object::Kind::Commit, &body)
            .map_err(|err| anyhow::anyhow!("lease: a pack member will not hash: {err}"))?;
        objects.push(Object {
            id: id.to_string(),
            body,
        });
    }
    Ok(objects)
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
    let mut shift = 4;
    let mut index = 1;
    let mut byte = first;
    while byte & 0x80 != 0 {
        byte = *rest.get(index).ok_or_else(|| {
            anyhow::anyhow!("lease: an object header runs off the end of the pack")
        })?;
        size |= usize::from(byte & 0x7f) << shift;
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
        headers: &[
            (
                String::from("Content-Type"),
                format!("application/x-{}-request", Service::UploadPack.as_str()),
            ),
            (
                String::from("Accept"),
                format!("application/x-{}-result", Service::UploadPack.as_str()),
            ),
        ],
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
