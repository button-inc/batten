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

/// Split a smart-HTTP body into its pkt-line payloads, dropping the delimiters.
///
/// **A flush-pkt is a delimiter and never a payload**, which is what lets a caller
/// iterate lines without having to know where the sections are. Sideband is not
/// decoded here: receive-pack only multiplexes when the client asks for it, and
/// this module does not.
///
/// # Errors
///
/// A truncated line, or a length header that is not four hex digits. Both mean
/// the body is not an answer from a git server.
fn pktlines(body: &[u8]) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut rest = body;
    while rest.len() >= 4 {
        let header = std::str::from_utf8(&rest[..4])
            .map_err(|_| anyhow::anyhow!("lease: a pkt-line length is not text"))?;
        let length = usize::from_str_radix(header, 16)
            .map_err(|_| anyhow::anyhow!("lease: `{header}` is not a pkt-line length"))?;
        // 0000 flush, 0001 delim, 0002 response-end — all delimiters, none of
        // which carries a payload.
        if length < 4 {
            rest = &rest[4..];
            continue;
        }
        if length > rest.len() {
            return Err(anyhow::anyhow!(
                "lease: a pkt-line claims {length} bytes and only {} remain",
                rest.len()
            ));
        }
        let payload = &rest[4..length];
        lines.push(String::from_utf8_lossy(payload).into_owned());
        rest = &rest[length..];
    }
    Ok(lines)
}

/// Frame `payload` as one pkt-line.
///
/// # Errors
///
/// A payload that will not fit the 4-hex length header. The lease's own lines are
/// three object ids and a ref name, so this is unreachable for its own callers
/// and is checked anyway rather than truncating a command silently.
fn pktline(payload: &str) -> Result<Vec<u8>> {
    let length = payload.len() + 4;
    if length > 0xFFFF {
        return Err(anyhow::anyhow!(
            "lease: a pkt-line payload of {} bytes does not fit its header",
            payload.len()
        ));
    }
    let mut framed = format!("{length:04x}").into_bytes();
    framed.extend_from_slice(payload.as_bytes());
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

#[cfg(test)]
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
