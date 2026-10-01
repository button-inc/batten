//! Whether a git signing configuration names a key anyone can verify
//! (CLOUD-669, CLOUD-1717).
//!
//! # This is not an argument against signing
//!
//! SIGNING IS GOOD, and a reading of this module that says otherwise is wrong:
//! signing in CI, with a key whose public half is published, is the desired end
//! state and CLOUD-591 owns getting there. What this names is the narrower
//! thing — a signature produced by a key that cannot be verified or reproduced,
//! which is WORSE than no signature because it looks like provenance and
//! carries none.
//!
//! # Two independent conditions, both measured rather than assumed (2026-08-18)
//!
//! * `gpg.ssh.program` resolves inside `/tmp`. The container reclaims it, so the
//!   signer and whatever key it holds are not reproducible across sessions. A
//!   signature nobody can re-verify later is provenance theatre.
//! * `user.signingkey` names a file that is empty or unreadable. The public half
//!   cannot be read, so no `allowed_signers` entry can be derived from it and
//!   nothing downstream can check the signature.
//!
//! A signer failing NEITHER test is left alone and signing stays on.
//!
//! # A literal key is not a path
//!
//! With `gpg.format ssh`, git accepts the public key inline (`ssh-ed25519
//! AAAA…`) or behind a `key::` prefix as well as a filename. A literal is the
//! MOST publishable form there is — it is already the public half — so testing
//! it as a file would report the healthiest possible configuration as broken.
//!
//! # Four file tests, not one, and that was a real defect rather than thoroughness
//!
//! A size test alone is true for anything non-empty that `stat` can size,
//! including an unreadable file and a DIRECTORY — both of which leave the public
//! half unreadable, which is the condition being named. Each test carries its
//! own reason, so the refusal says which one.
//!
//! # The two config values are read here, in process
//!
//! [`read`] resolves `user.signingkey` and `gpg.ssh.program` through
//! [`crate::git::config_value`] — gix, across every scope git consults, no spawn —
//! and hands them to [`posture`], which stays a pure function of the two strings
//! so a scratch path exercises every arm without a repository. The producer task
//! that used to run `git config` and pass the values in retired under CLOUD-843.
//!
//! # What is NOT here any more
//!
//! The record once also carried `config conflict` and one `signed <sha>` line per
//! signed commit in range, both gathered in a task body. Those are git facts the
//! engine now projects directly (`input.tree["git-config"]`,
//! `input.tree["commit-meta"]`), and deciding the conflict between scopes is the
//! `supply-chain` preset's (`signer-is-verifiable.rego`). What stays is the one
//! reading a module cannot make: whether a PATH names a readable, non-empty file.

use std::path::Path;

/// The spellings git accepts for a key given INLINE rather than as a path.
const LITERAL_PREFIXES: [&str; 4] = ["ssh-", "key::", "sk-ssh-", "sk-ecdsa-"];

/// The directory a container reclaims between sessions.
const RECLAIMED_PREFIX: &str = "/tmp/";

/// What a signing configuration amounts to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Posture {
    /// Nothing about this configuration stops anyone verifying a signature.
    Verifiable,
    /// A signature from this configuration cannot be verified, for this reason.
    Broken(&'static str),
}

impl Posture {
    /// The record line a module reads this under.
    #[must_use]
    pub fn token(&self) -> String {
        match self {
            Posture::Verifiable => "verifiable".to_owned(),
            Posture::Broken(why) => format!("broken {why}"),
        }
    }
}

/// Classify a signing configuration from the two git config values.
///
/// ORDER IS LOAD-BEARING. The `/tmp` test comes first because a reclaimed
/// signer makes the signature unverifiable whatever the key is — including a
/// perfectly healthy inline one — and the literal test comes before every file
/// test because a literal is not a path and stating it as one would report the
/// healthiest configuration as broken.
#[must_use]
pub fn posture(signingkey: &str, program: &str) -> Posture {
    if program.starts_with(RECLAIMED_PREFIX) {
        return Posture::Broken(
            "the signer resolves inside /tmp, which the container reclaims, so the key is not \
             reproducible",
        );
    }
    if signingkey.is_empty()
        || LITERAL_PREFIXES
            .iter()
            .any(|prefix| signingkey.starts_with(prefix))
    {
        return Posture::Verifiable;
    }

    let path = Path::new(signingkey);
    let Ok(found) = path.metadata() else {
        return Posture::Broken(
            "user.signingkey names a path that does not exist, so the public half cannot be read \
             or published",
        );
    };
    if !found.is_file() {
        return Posture::Broken(
            "user.signingkey names something that is not a regular file, so the public half \
             cannot be read or published",
        );
    }
    // OPENING IT IS THE READ TEST. A permission-bit comparison would be a second
    // authority over what this process may read — ACLs, capabilities and running
    // as root all make the bits and the outcome disagree, and the outcome is the
    // condition being named.
    if std::fs::File::open(path).is_err() {
        return Posture::Broken(
            "user.signingkey names a file this checkout cannot read, so the public half cannot be \
             read or published",
        );
    }
    if found.len() == 0 {
        return Posture::Broken(
            "user.signingkey names an empty file, so the public half cannot be read or published",
        );
    }
    Posture::Verifiable
}

/// Read the signing configuration git resolves for `dir`, and classify it.
///
/// Effective values, across every scope, exactly as `git config --get` read
/// them in the retired producer: the question is what WILL sign, and a key
/// inherited from a wider scope signs as surely as a local one. An unset key is
/// the empty string, which [`posture`] reads as nothing being signed with it.
///
/// # Errors
///
/// Raises when `dir` is not inside a repository this binary can open — the
/// could-not-look the retired producer spelled as exit 2 and wrote nothing on.
pub fn read(dir: &Path) -> anyhow::Result<Posture> {
    let signingkey = crate::git::config_value(dir, "user.signingkey")?.unwrap_or_default();
    let program = crate::git::config_value(dir, "gpg.ssh.program")?.unwrap_or_default();
    Ok(posture(&signingkey, &program))
}

/// What [`repair`] did to this checkout.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Repair {
    /// The signer is verifiable, so signing was left on.
    LeftOn,
    /// The signer is broken for this reason, and signing is now off locally.
    Disabled(&'static str),
}

impl Repair {
    /// The one-line report, pointer-only: the reason, never the key or signer.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Repair::LeftOn => "attribution: signer is verifiable, leaving signing on".to_owned(),
            Repair::Disabled(why) => {
                format!("attribution: signing disabled in this checkout — {why}")
            }
        }
    }
}

/// Switch signing off in THIS checkout when its signer cannot be verified or
/// reproduced (CLOUD-669), retiring `[tasks.signing-posture-repair]`.
///
/// It fires ONLY against the broken configuration: disabling signing
/// unconditionally would also switch off a correctly configured signer, which is
/// the outcome CLOUD-591 is working toward. Local-only, never global — the
/// narrowing is [`crate::git::set_config_local`]'s own — and local beats global,
/// which matters because a launcher may rewrite global every session.
///
/// # Errors
///
/// Raises when `dir` is not a repository, or when the local write fails; a
/// repair that did not happen is never reported as one.
pub fn repair(dir: &Path) -> anyhow::Result<Repair> {
    match read(dir)? {
        Posture::Verifiable => Ok(Repair::LeftOn),
        Posture::Broken(why) => {
            crate::git::set_config_local(dir, "commit.gpgsign", "false")?;
            Ok(Repair::Disabled(why))
        }
    }
}

/// The whole `signing-posture` record: one `signer <token>` line.
///
/// ONE LINE, and the narrowing is the CLOUD-843 split rather than a loss: the
/// conflict and the signed commits are facts the module reads straight off the
/// tree now, so the record carries only what no projection can — the file tests
/// behind the key. Pointer-only (rule 4): the token names WHY, never the key.
#[must_use]
pub fn record(posture: &Posture) -> String {
    format!("signer {}\n", posture.token())
}

#[cfg(test)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly —
// the house spelling, as `render.rs`, `contract.rs` and `mint.rs` carry it.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Posture, posture};

    const LITERAL: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample";
    const SIGNER: &str = "/usr/bin/ssh-keygen";

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("batten-signer-posture-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn an_inline_public_key_is_a_literal_not_a_path_and_is_verifiable() {
        for literal in [
            LITERAL,
            "key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample",
            "sk-ssh-ed25519@openssh.com AAAAGexample",
            "sk-ecdsa-sha2-nistp256@openssh.com AAAAInexample",
        ] {
            assert_eq!(
                posture(literal, SIGNER),
                Posture::Verifiable,
                "a literal is already the public half: {literal}"
            );
        }
    }

    #[test]
    fn a_signer_under_tmp_is_unverifiable_because_the_container_reclaims_it() {
        // ORDER: the key here is perfectly healthy, and the signer still decides.
        let broken = posture(LITERAL, "/tmp/code-sign");
        assert!(matches!(broken, Posture::Broken(_)), "{broken:?}");
        assert!(broken.token().contains("/tmp"), "{}", broken.token());
    }

    #[test]
    fn an_empty_signing_key_is_what_makes_it_unverifiable() {
        let dir = scratch("empty");
        let key = dir.join("key.pub");
        std::fs::write(&key, "").expect("write empty key");
        let broken = posture(key.to_str().expect("utf8 path"), SIGNER);
        assert!(matches!(broken, Posture::Broken(_)), "{broken:?}");
        assert!(broken.token().contains("empty file"), "{}", broken.token());
    }

    /// THE MEASURED DEFECT. A size test alone calls a directory healthy, because
    /// `stat` sizes one happily and the public half is still unreadable.
    #[test]
    fn a_signing_key_that_is_a_directory_is_unverifiable() {
        let dir = scratch("directory");
        let keydir = dir.join("keydir");
        std::fs::create_dir_all(&keydir).expect("scratch keydir");
        let broken = posture(keydir.to_str().expect("utf8 path"), SIGNER);
        assert!(matches!(broken, Posture::Broken(_)), "{broken:?}");
        assert!(
            broken.token().contains("regular file"),
            "{}",
            broken.token()
        );
    }

    #[test]
    fn a_signing_key_naming_a_path_that_does_not_exist_is_unverifiable() {
        let broken = posture("/nowhere/at/all/key.pub", SIGNER);
        assert!(matches!(broken, Posture::Broken(_)), "{broken:?}");
        assert!(
            broken.token().contains("does not exist"),
            "{}",
            broken.token()
        );
    }

    /// ANTI-VACUITY. Without this, every arm above could be passing because the
    /// function returns `Broken` for everything.
    #[test]
    fn a_signer_failing_neither_test_is_left_alone() {
        let dir = scratch("healthy");
        let key = dir.join("key.pub");
        std::fs::write(&key, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample\n")
            .expect("write real key");
        assert_eq!(
            posture(key.to_str().expect("utf8 path"), SIGNER),
            Posture::Verifiable
        );
    }

    /// An absent `user.signingkey` is not a broken one: nothing is being signed
    /// with it, so there is no unverifiable signature to name.
    #[test]
    fn an_unset_signing_key_is_not_a_finding() {
        assert_eq!(posture("", SIGNER), Posture::Verifiable);
    }

    /// A signer merely NAMED `/tmpfoo` is not under `/tmp/`. Without the
    /// trailing separator the prefix test would catch a sibling directory.
    #[test]
    fn a_signer_whose_name_merely_starts_with_tmp_is_not_under_tmp() {
        assert_eq!(posture(LITERAL, "/tmpfoo/code-sign"), Posture::Verifiable);
    }

    // --- the record's own shape -------------------------------------------

    #[test]
    fn a_healthy_signer_is_one_verifiable_line() {
        assert_eq!(
            super::record(&posture(LITERAL, SIGNER)),
            "signer verifiable\n"
        );
    }

    /// One line whatever the reason, and the reason never carries the key.
    #[test]
    fn a_broken_signer_is_one_line_naming_why_and_never_the_key() {
        let written = super::record(&posture("/nowhere/at/all/key.pub", SIGNER));
        assert!(written.starts_with("signer broken "), "{written}");
        assert_eq!(written.lines().count(), 1, "{written}");
        assert!(!written.contains("/nowhere/at/all"), "{written}");
    }

    /// Pointer-only (rule 4): the reason never carries the key or the signer.
    #[test]
    fn no_reason_echoes_the_key_or_the_signer_path() {
        let secret = "/tmp/SECRET-SIGNER-PATH";
        let broken = posture("SECRET-KEY-MATERIAL", secret);
        let said = broken.token();
        assert!(!said.contains("SECRET-SIGNER-PATH"), "{said}");
        assert!(!said.contains("SECRET-KEY-MATERIAL"), "{said}");
    }
}
