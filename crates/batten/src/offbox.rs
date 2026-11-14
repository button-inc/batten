//! Off-box session state: whether this machine can reach the state repository
//! (CLOUD-2717, CLOUD-2718).
//!
//! # Why this module exists
//!
//! Everything a session knows lives on one disk, and a reclaimed container loses
//! all of it. The store therefore has to be somewhere else: one repository for
//! the whole fleet, named by [`crate::session::STATE_REPO_ENV`]. This module is
//! the root of that chain — it reads the variable, derives the remote, and says
//! whether the remote can be written. Nothing here pushes, snapshots or restores.
//!
//! # Unset is inert
//!
//! The variable is the feature's only switch (ruling 2). Unset — or set to
//! nothing — [`status`] answers [`Status::Off`] before it derives a URL, makes a
//! network call or touches the state directory, so a machine that never asked for
//! the feature pays nothing for it and has nothing written under its name.
//!
//! # No repository is named here
//!
//! The remote is the project origin's scheme and host with the path replaced by
//! the variable's value. So the core carries no host and no repository name
//! (non-negotiable rule 1): both arrive from the clone and from the environment.
//! Only an `http` or `https` origin qualifies, because the transport is
//! [`crate::lease`]'s smart-HTTP and an `ssh` or local-path origin gives it no
//! host to speak to.
//!
//! # `unattached` cannot tell two causes apart
//!
//! Measured through an agent proxy on 2026-11-14: discovery answered `200` once
//! the repository was attached to the session, `403` before, and `403` for a
//! name that does not exist. So a refusal means "not attached, or misspelled",
//! and [`attach_note`] says both, along with both remedies — Batten cannot tell
//! a cloud container from a local machine either.
//!
//! # No gate
//!
//! An unreachable repository denies nothing (ruling 12). [`Status::code`] maps a
//! refusal to [`ExitCode::Usage`], never [`ExitCode::Violation`], and
//! `policy/module-layering.rego` forbids the `hook -> offbox` edge so no
//! mediated call can come to depend on a network answer.

use crate::Result;
use crate::exit::ExitCode;
use crate::lease::{self, Service};

/// The directory under [`crate::state::state_root`] the off-box feature owns.
///
/// Named here so the one writer and every reader spell it once. [`status`] never
/// creates it: the feature being off must leave no trace.
pub const DIR: &str = "offbox";

/// What `batten offbox status` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The variable is unset or empty: the feature is off.
    Off,
    /// The variable is set and the project has no `http(s)` origin to derive a
    /// remote from.
    NoHttpOrigin,
    /// Discovery answered `401`, `403` or `404`: not attached, or misspelled.
    Unattached,
    /// Discovery answered `200`: the repository can be written.
    Attached,
}

impl Status {
    /// The one word printed on stdout — a token, never the remote's answer.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Status::Off => "off",
            Status::NoHttpOrigin => "no-http-origin",
            Status::Unattached => "unattached",
            Status::Attached => "attached",
        }
    }

    /// The exit this status leaves with.
    ///
    /// Never [`ExitCode::Violation`]: this is a diagnosis of the machine, not a
    /// policy verdict over the work, so no harness can read it as a deny.
    #[must_use]
    pub const fn code(self) -> ExitCode {
        match self {
            Status::Off | Status::Attached => ExitCode::Success,
            Status::NoHttpOrigin | Status::Unattached => ExitCode::Usage,
        }
    }
}

/// The state repository's URL: `origin`'s scheme and host, with the path
/// replaced by `value`.
///
/// `None` where `origin` is not `http(s)` or names no host. Any userinfo the
/// origin carries is dropped — the credential is [`crate::lease`]'s to attach,
/// and one copied out of a clone's config would travel into every error line
/// that names the remote.
#[must_use]
pub fn remote_for(origin: &str, value: &str) -> Option<String> {
    let (scheme, rest) = origin.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}/{}", value.trim_matches('/')))
}

/// Whether the state repository named by `value` can be written from here.
///
/// `value` is the variable as read, and `origin` the project origin's URL where
/// there is one. Both are passed in rather than read here so the decision is a
/// pure function of them plus one discovery call.
///
/// The probe is over receive-pack, because the question is whether this machine
/// can WRITE: a repository attached read-only answers upload-pack and would read
/// as attached to a feature that can never push to it.
///
/// # Errors
///
/// A transport failure, or a status that is none of `200`, `401`, `403` and
/// `404` — both could-not-look (exit `3`), never a refusal.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT unset-still-probes|s@^    if value.is_empty() {$@    if false {@|unset_is_off_and_makes_no_call
//MUTANT unattached-reads-attached|s@^        401 \x7c 403 \x7c 404 => Ok(Status::Unattached),$@        401 \x7c 403 \x7c 404 => Ok(Status::Attached),@|a_refused_discovery_is_unattached
//MUTANT transport-failure-reads-unattached|s@^    let answered = lease::probe(&remote, Service::ReceivePack)?;$@    let answered = lease::probe(\&remote, Service::ReceivePack).unwrap_or(403);@|a_transport_failure_is_an_error_and_never_a_refusal
//MUTANT attach-note-omits-the-repo|s@^    let repo = format!("the state repository {value}");$@    let repo = format!("the state repository{value:.0}");@|the_attach_note_names_the_repo_and_both_remedies
//MUTANT-SUITE crates/batten/tests/it/offbox_status.rs
//MUTANT unset-creates-the-state-dir|s@^    if value.is_empty() {$@    let _ = crate::state::state_root().map(\x7croot\x7c std::fs::create_dir_all(root.join(DIR))); if value.is_empty() {@|unset_is_off_and_leaves_no_directory
pub fn status(value: Option<&str>, origin: Option<&str>) -> Result<Status> {
    let value = value.map(str::trim).unwrap_or_default();
    if value.is_empty() {
        return Ok(Status::Off);
    }
    let Some(remote) = origin.and_then(|origin| remote_for(origin, value)) else {
        return Ok(Status::NoHttpOrigin);
    };
    let answered = lease::probe(&remote, Service::ReceivePack)?;
    match answered {
        200 => Ok(Status::Attached),
        401 | 403 | 404 => Ok(Status::Unattached),
        other => Err(anyhow::anyhow!(
            "offbox: state repository discovery answered {other}, which is neither attached nor a refusal"
        )),
    }
}

/// The one line that tells an agent how to get access to the repository `value`
/// names.
///
/// The same on every harness, and it says both remedies and the misspelling,
/// because a `403` is all three cases at once (see the module header).
#[must_use]
pub fn attach_note(value: &str) -> String {
    let repo = format!("the state repository {value}");
    format!(
        "offbox: {repo} cannot be written from here. \
         Attach it to this session with push access, or give this machine a git credential for it; \
         it may also be misspelled in `{}`.",
        crate::session::STATE_REPO_ENV
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::fetch::{self, Response};
    use std::cell::Cell;
    use std::rc::Rc;

    /// The origin every case derives its remote from.
    const ORIGIN: &str = "https://forge.invalid/acme/widgets.git";

    /// Stand a remote up that answers every discovery with `status`, and count
    /// the calls it was asked.
    fn answering(status: u16) -> Rc<Cell<usize>> {
        let calls = Rc::new(Cell::new(0));
        let seen = Rc::clone(&calls);
        fetch::stand_in(Box::new(move |asked: &[fetch::Call<'_>]| {
            seen.set(seen.get() + asked.len());
            Ok(asked
                .iter()
                .map(|_| Response {
                    status,
                    body: Vec::new(),
                    headers: Vec::new(),
                })
                .collect())
        }));
        calls
    }

    /// Fails by: an unset variable reaching the network.
    #[test]
    fn unset_is_off_and_makes_no_call() {
        let calls = answering(200);
        assert_eq!(status(None, Some(ORIGIN)).unwrap(), Status::Off);
        assert_eq!(status(Some("  "), Some(ORIGIN)).unwrap(), Status::Off);
        assert_eq!(calls.get(), 0, "off must not probe");
    }

    /// Fails by: a served discovery reading as anything but attached.
    #[test]
    fn a_served_discovery_is_attached() {
        let calls = answering(200);
        let found = status(Some("example/state"), Some(ORIGIN)).unwrap();
        assert_eq!(found, Status::Attached);
        assert_eq!(found.code(), ExitCode::Success);
        assert_eq!(calls.get(), 1);
    }

    /// Fails by: a refusal reading as attached.
    #[test]
    fn a_refused_discovery_is_unattached() {
        for refusal in [401, 403, 404] {
            answering(refusal);
            let found = status(Some("example/state"), Some(ORIGIN)).unwrap();
            assert_eq!(found, Status::Unattached, "{refusal}");
            assert_eq!(found.code(), ExitCode::Usage);
        }
    }

    /// Fails by: could-not-look being reported as a refusal the agent can fix.
    #[test]
    fn a_transport_failure_is_an_error_and_never_a_refusal() {
        fetch::stand_in(Box::new(|_: &[fetch::Call<'_>]| {
            Err(anyhow::anyhow!("the wire is down"))
        }));
        assert!(status(Some("example/state"), Some(ORIGIN)).is_err());
        answering(500);
        assert!(status(Some("example/state"), Some(ORIGIN)).is_err());
    }

    /// Fails by: probing a host the project never named.
    #[test]
    fn only_an_http_origin_gives_a_remote() {
        let calls = answering(200);
        for origin in [
            None,
            Some("/srv/git/widgets.git"),
            Some("git@forge.invalid:acme/widgets.git"),
            Some("ssh://git@forge.invalid/acme/widgets.git"),
            Some("https:///acme/widgets.git"),
        ] {
            assert_eq!(
                status(Some("example/state"), origin).unwrap(),
                Status::NoHttpOrigin,
                "{origin:?}"
            );
        }
        assert_eq!(calls.get(), 0);
    }

    /// Fails by: the origin's path, or its credential, surviving into the remote.
    #[test]
    fn the_remote_is_the_origins_host_with_the_path_replaced() {
        assert_eq!(
            remote_for(ORIGIN, "example/state").as_deref(),
            Some("https://forge.invalid/example/state")
        );
        assert_eq!(
            remote_for(
                "HTTP://user:secret@forge.invalid:8443/a/b",
                "/example/state/"
            )
            .as_deref(),
            Some("http://forge.invalid:8443/example/state")
        );
    }

    /// Fails by: a note an agent cannot act on.
    #[test]
    fn the_attach_note_names_the_repo_and_both_remedies() {
        let note = attach_note("example/state");
        assert!(note.contains("example/state"), "{note}");
        assert!(note.contains("push access"), "{note}");
        assert!(note.contains("git credential"), "{note}");
        assert!(note.contains("misspelled"), "{note}");
        assert!(!note.contains('\n'), "one line: {note}");
    }
}
