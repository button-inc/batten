//! CLOUD-1728: the hook surface is four sources, each with a declared vocabulary.
//!
//! Every case reads through `HookSource::ALL` and `HookSource::<s>.vocabulary()`,
//! never the tables behind them: a case reading `GIT_HOOKS` directly would
//! survive a mutation of the `vocabulary()` arm, which is the accessor every
//! consumer reaches.

use std::collections::BTreeSet;

use batten::hook::{Event, Harness, HookDisposition, HookSource};
use batten::surface::SURFACE;

fn is_kebab_id(reason: &str) -> bool {
    !reason.is_empty()
        && reason
            .split('-')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase()))
}

#[test]
fn every_hook_source_is_enumerated_with_a_nonempty_vocabulary() {
    let tokens: BTreeSet<&str> = HookSource::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        tokens,
        BTreeSet::from(["cli", "harness", "git", "ci"]),
        "the four sources are the owner's split; a missing one reports clean today"
    );
    assert_eq!(HookSource::ALL.len(), 4, "no source is listed twice");
    for source in HookSource::ALL {
        let vocabulary = source.vocabulary();
        assert!(
            !vocabulary.is_empty(),
            "{} declares no vocabulary",
            source.as_str()
        );
        let names: BTreeSet<&str> = vocabulary.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names.len(),
            vocabulary.len(),
            "{} names a hook twice",
            source.as_str()
        );
    }
}

/// githooks(5) as git 2.43 defines it. A SNAPSHOT: a hook a later git adds is
/// not caught automatically — this set is what was reproduced against the
/// installed binary when the table was written, nothing more.
const GITHOOKS_5: [&str; 28] = [
    "applypatch-msg",
    "commit-msg",
    "fsmonitor-watchman",
    "p4-changelist",
    "p4-post-changelist",
    "p4-pre-submit",
    "p4-prepare-changelist",
    "post-applypatch",
    "post-checkout",
    "post-commit",
    "post-index-change",
    "post-merge",
    "post-receive",
    "post-rewrite",
    "post-update",
    "pre-applypatch",
    "pre-auto-gc",
    "pre-commit",
    "pre-merge-commit",
    "pre-push",
    "pre-rebase",
    "pre-receive",
    "prepare-commit-msg",
    "proc-receive",
    "push-to-checkout",
    "reference-transaction",
    "sendemail-validate",
    "update",
];

#[test]
fn the_git_vocabulary_is_githooks5_with_one_disposition_each() {
    let vocabulary = HookSource::Git.vocabulary();
    let names: Vec<&str> = vocabulary.iter().map(|(n, _)| n.as_str()).collect();
    let unique: BTreeSet<&str> = names.iter().copied().collect();
    assert_eq!(unique.len(), names.len(), "a git hook named twice");
    assert_eq!(unique, BTreeSet::from(GITHOOKS_5));
    for (name, disposition) in &vocabulary {
        if let HookDisposition::Unsupported { reason } = disposition {
            assert!(
                is_kebab_id(reason),
                "{name}: reason {reason:?} is not a kebab id"
            );
        }
    }
}

#[test]
fn every_registered_disposition_names_a_declared_verb() {
    let verbs: BTreeSet<&str> = SURFACE.iter().map(|row| row.path).collect();
    let mut registered = 0;
    for source in HookSource::ALL {
        for (name, disposition) in source.vocabulary() {
            match disposition {
                HookDisposition::Registered { check } => {
                    registered += 1;
                    assert!(
                        verbs.contains(check),
                        "{}:{name} is checked by {check:?}, which no surface row declares",
                        source.as_str()
                    );
                }
                HookDisposition::Unsupported { reason } => {
                    assert!(is_kebab_id(reason), "{name}: {reason:?}");
                }
            }
        }
    }
    assert!(
        registered > 0,
        "a census with nothing registered checks nothing"
    );
}

#[test]
fn the_harness_vocabulary_agrees_with_wiring_registrations() {
    let vocabulary = HookSource::Harness.vocabulary();
    let moments = Event::ALL
        .iter()
        .filter(|event| **event != Event::Unrecognized)
        .count();
    assert_eq!(vocabulary.len(), Harness::ALL.len() * moments);
    for harness in Harness::ALL {
        let prefix = format!("{}:", harness.as_str());
        let own: Vec<(&str, HookDisposition)> = vocabulary
            .iter()
            .filter_map(|(name, d)| name.strip_prefix(&prefix).map(|event| (event, *d)))
            .collect();
        assert_eq!(own.len(), moments, "{prefix} is not one entry per moment");
        match harness.wiring() {
            None => assert!(
                own.iter().all(|(_, d)| *d
                    == HookDisposition::Unsupported {
                        reason: "no-wiring-surface"
                    }),
                "{prefix} has no wiring surface, so nothing on it is registered"
            ),
            Some(wiring) => {
                let want: BTreeSet<&str> = wiring
                    .registrations(*harness)
                    .into_iter()
                    .map(|(event, _)| event.as_str())
                    .collect();
                let got: BTreeSet<&str> = own
                    .iter()
                    .filter(|(_, d)| matches!(d, HookDisposition::Registered { .. }))
                    .map(|(event, _)| *event)
                    .collect();
                assert!(!want.is_empty(), "{prefix} registers nothing");
                assert_eq!(got, want, "{prefix} disagrees with its wiring");
            }
        }
    }
}
