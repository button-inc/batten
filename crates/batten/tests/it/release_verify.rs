//! G1, `batten release verify` (CLOUD-2033): a release is fully and correctly
//! published, or it is refused with a pointer per reason.
//!
//! The decision is [`batten::release_verify::judge`], pure over a read release,
//! the asset module's answer and an asset fetcher, so each refusal is driven
//! alone and its twin passes. The read is driven over the fixture forge.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use batten::release::{Asset, Published};
use batten::release_verify::{Refusal, Release, Verdict, judge};

use crate::common;

const COMMIT: &str = "1111111111111111111111111111111111111111";

/// Asset bytes by name, with a matching `SHA256SUMS` over every other one.
fn files(extra: &[(&str, &str)]) -> BTreeMap<String, Vec<u8>> {
    let mut files: BTreeMap<String, Vec<u8>> = extra
        .iter()
        .map(|(name, body)| ((*name).to_owned(), body.as_bytes().to_vec()))
        .collect();
    let sums = files.iter().fold(String::new(), |mut sums, (name, bytes)| {
        use std::fmt::Write as _;
        let _ = writeln!(sums, "{}  {name}", batten::release::digest(bytes));
        sums
    });
    files.insert(String::from("SHA256SUMS"), sums.into_bytes());
    files
}

fn release(files: &BTreeMap<String, Vec<u8>>) -> Release {
    Release {
        draft: false,
        immutable: Some(true),
        target: COMMIT.to_owned(),
        tag_commit: Some(COMMIT.to_owned()),
        published: Published {
            tag: String::from("v1.0.0"),
            assets: files
                .keys()
                .enumerate()
                .map(|(id, name)| Asset {
                    id: id as u64,
                    name: name.clone(),
                })
                .collect(),
        },
    }
}

fn judged(
    release: &Release,
    draft: bool,
    missing: &[&str],
    files: &BTreeMap<String, Vec<u8>>,
) -> Verdict {
    let mut fetch = |asset: &Asset| {
        files
            .get(&asset.name)
            .cloned()
            .ok_or_else(|| format!("{} is not in the fixture", asset.name))
    };
    judge(
        release,
        draft,
        Ok(missing.iter().map(|name| (*name).to_owned()).collect()),
        &mut fetch,
    )
}

fn refusals(verdict: Verdict) -> Vec<Refusal> {
    match verdict {
        Verdict::Refused(refused) => refused,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_complete_immutable_matching_release_passes() {
    let files = files(&[
        ("batten-x86_64.tar.xz", "archive"),
        ("install.sh", "script"),
    ]);
    assert_eq!(
        judged(&release(&files), false, &[], &files),
        Verdict::Verified
    );
}

#[test]
fn a_release_missing_a_target_is_refused() {
    let files = files(&[("install.sh", "script")]);
    let refused = refusals(judged(
        &release(&files),
        false,
        &["batten-x86_64.tar.xz"],
        &files,
    ));
    assert!(refused.contains(&Refusal::MissingAsset(String::from("batten-x86_64.tar.xz"))));
}

#[test]
fn a_published_mutable_release_is_refused() {
    let files = files(&[("install.sh", "script")]);
    let mut mutable = release(&files);
    mutable.immutable = Some(false);
    assert_eq!(
        refusals(judged(&mutable, false, &[], &files)),
        vec![Refusal::Mutable]
    );
}

#[test]
fn a_missing_immutable_field_is_could_not_look_never_a_pass() {
    let files = files(&[("install.sh", "script")]);
    let mut unread = release(&files);
    unread.immutable = None;
    assert!(matches!(
        judged(&unread, false, &[], &files),
        Verdict::CouldNotLook(_)
    ));
}

#[test]
fn a_mismatched_public_asset_is_refused() {
    let mut files = files(&[("install.sh", "script")]);
    files.insert(String::from("install.sh"), b"tampered".to_vec());
    let refused = refusals(judged(&release(&files), false, &[], &files));
    assert_eq!(
        refused,
        vec![Refusal::Mismatched(String::from("install.sh"))]
    );
}

#[test]
fn an_asset_without_a_sums_line_is_refused() {
    let mut files = files(&[("install.sh", "script")]);
    files.insert(String::from("batten.spdx.json"), b"{}".to_vec());
    let refused = refusals(judged(&release(&files), false, &[], &files));
    assert_eq!(
        refused,
        vec![Refusal::Unsummed(String::from("batten.spdx.json"))]
    );
}

#[test]
fn a_tag_off_its_target_commit_is_refused() {
    let files = files(&[("install.sh", "script")]);
    let mut moved = release(&files);
    moved.tag_commit = Some(String::from("2222222222222222222222222222222222222222"));
    assert!(matches!(
        refusals(judged(&moved, false, &[], &files)).as_slice(),
        [Refusal::TagOffTarget { .. }]
    ));
}

#[test]
fn a_draft_is_verified_only_when_a_draft_is_asked_for() {
    let files = files(&[("install.sh", "script")]);
    let mut draft = release(&files);
    draft.draft = true;
    draft.immutable = None;
    draft.tag_commit = None;
    assert_eq!(judged(&draft, true, &[], &files), Verdict::Verified);
    assert!(matches!(
        refusals(judged(&draft, false, &[], &files)).as_slice(),
        [Refusal::State(_)]
    ));
}

// ---- G2, `batten release path` ------------------------------------------------

use batten::release_path::{self, Published as G1, Side};

fn side(pin: &str, version: &str) -> Side {
    Side {
        pin: Some(pin.to_owned()),
        version: Some(version.to_owned()),
    }
}

fn paths(changed: &[&str]) -> std::collections::BTreeSet<String> {
    changed.iter().map(|path| (*path).to_owned()).collect()
}

/// G2 with G1 and the ancestry read answering as given, counting the asks.
fn graded(
    base: &Side,
    head: &Side,
    changed: &[&str],
    g1: &G1,
    ancestor: Option<bool>,
) -> (release_path::Verdict, usize) {
    let mut asked = 0;
    let mut verify = |_: &str| {
        asked += 1;
        Ok(g1.clone())
    };
    let mut is_ancestor = |_: &str| Ok(ancestor);
    let verdict = release_path::judge(
        base,
        head,
        &paths(changed),
        false,
        &mut verify,
        &mut is_ancestor,
    );
    (verdict, asked)
}

#[test]
fn an_untouched_pin_and_version_is_success_with_no_request_made() {
    let pinned = side("v0.0.5", "0.0.5");
    let (verdict, asked) = graded(
        &pinned,
        &pinned,
        &["crates/batten/src/lib.rs"],
        &G1::Refused(vec![]),
        Some(false),
    );
    assert!(matches!(verdict, release_path::Verdict::Success(_)));
    assert_eq!(asked, 0, "an inherited pin asks the forge nothing");
}

#[test]
fn a_pin_change_is_failure_until_its_release_verifies() {
    let base = side("v0.0.5", "0.0.5");
    let head = side("v0.0.6", "0.0.6");
    let release_paths = ["Cargo.toml", "Cargo.lock", "batten.toml"];
    let (refused, _) = graded(
        &base,
        &head,
        &release_paths,
        &G1::Refused(vec![String::from("release verify: it is still a draft")]),
        Some(true),
    );
    assert!(matches!(refused, release_path::Verdict::Failure(_)));
    let (verified, asked) = graded(
        &base,
        &head,
        &release_paths,
        &G1::Verified(COMMIT.to_owned()),
        Some(true),
    );
    assert!(matches!(verified, release_path::Verdict::Success(_)));
    assert_eq!(asked, 1);
}

#[test]
fn a_release_head_touching_another_path_is_failure() {
    let (verdict, _) = graded(
        &side("v0.0.5", "0.0.5"),
        &side("v0.0.6", "0.0.6"),
        &["Cargo.toml", "crates/batten/src/lib.rs"],
        &G1::Verified(COMMIT.to_owned()),
        Some(true),
    );
    let release_path::Verdict::Failure(why) = verdict else {
        panic!("a release head touching src is failure, got {verdict:?}");
    };
    assert!(
        why.iter()
            .any(|line| line.contains("crates/batten/src/lib.rs"))
    );
}

#[test]
fn a_burned_release_is_failure() {
    let (verdict, _) = graded(
        &side("v0.0.5", "0.0.5"),
        &side("v0.0.6", "0.0.6"),
        &["Cargo.toml"],
        &G1::Verified(COMMIT.to_owned()),
        Some(false),
    );
    assert!(
        matches!(verdict, release_path::Verdict::Failure(_)),
        "a tag commit off this head's history is burned, got {verdict:?}"
    );
}

#[test]
fn a_pin_that_is_not_its_version_is_failure() {
    let (verdict, asked) = graded(
        &side("v0.0.5", "0.0.5"),
        &side("v0.0.7", "0.0.6"),
        &["Cargo.toml", "batten.toml"],
        &G1::Verified(COMMIT.to_owned()),
        Some(true),
    );
    assert!(matches!(verdict, release_path::Verdict::Failure(_)));
    assert_eq!(asked, 0);
}

#[test]
fn a_config_change_beyond_the_engine_line_is_failure() {
    let base = side("v0.0.5", "0.0.5");
    let head = side("v0.0.6", "0.0.6");
    let mut verify = |_: &str| Ok(G1::Verified(COMMIT.to_owned()));
    let mut is_ancestor = |_: &str| Ok(Some(true));
    let verdict = release_path::judge(
        &base,
        &head,
        &paths(&["batten.toml"]),
        true,
        &mut verify,
        &mut is_ancestor,
    );
    assert!(matches!(verdict, release_path::Verdict::Failure(_)));
    assert_eq!(
        release_path::without_engine_line("a = 1\nengine = { release = \"v1\" }\nb = 2"),
        release_path::without_engine_line("a = 1\nengine = { release = \"v2\" }\nb = 2"),
    );
}

/// The verb end to end over a fixture repository: an inherited pin is success,
/// read from git alone, and `--post` posts it on the graded head.
#[test]
fn release_path_posts_success_for_an_inherited_pin_on_the_graded_head() {
    // THE RUNNING VERSION, because every load checks the pin against the
    // binary's own version first, and a pin naming another release is an
    // engine install this case is not about.
    let version = env!("CARGO_PKG_VERSION");
    let repo = common::Fixture::new("release-path-inherited")
        .config(&format!(
            "version = 1\nengine = {{ release = \"v{version}\" }}\n"
        ))
        .file(
            "Cargo.toml",
            &format!("[workspace.package]\nversion = \"{version}\"\n"),
        )
        .base_commit()
        .file("src.txt", "work\n")
        .work_commit()
        .build();
    common::git_in(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widgets.git",
        ],
    );
    let head = common::git_in(&repo, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    let forge = common::scratch("release-path-forge");
    common::write(
        &forge,
        "status",
        "HTTP/2 201\ncontent-type: application/json\n\n{\"state\":\"success\"}\n",
    );
    common::write(&forge, "routes", "/statuses/\tstatus\n");
    let output = common::batten()
        .current_dir(&repo)
        .env("BATTEN_REST_FIXTURE", &forge)
        .args(["release", "path", &head, "--post"])
        .output()
        .expect("run release path");
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
    assert!(common::stdout(&output).contains("release path: success"));
    let asked = std::fs::read_to_string(forge.join("status.request")).expect("a status post");
    let asked: serde_json::Value = serde_json::from_str(&asked).expect("a JSON body");
    assert_eq!(asked["state"], "success");
    assert_eq!(asked["context"], "release-path");
    let args = std::fs::read_to_string(forge.join("args")).unwrap_or_default();
    assert!(
        args.contains(&format!("statuses/{head}")),
        "the status is posted on the graded head, never HEAD of a merge ref: {args}"
    );
}

/// A post the forge refuses is could-not-post, never "posted": the verdict
/// printed is not the status the forge holds.
#[test]
fn release_path_reports_a_refused_post_rather_than_posting_it() {
    let version = env!("CARGO_PKG_VERSION");
    let repo = common::Fixture::new("release-path-refused-post")
        .config(&format!(
            "version = 1\nengine = {{ release = \"v{version}\" }}\n"
        ))
        .file(
            "Cargo.toml",
            &format!("[workspace.package]\nversion = \"{version}\"\n"),
        )
        .base_commit()
        .file("src.txt", "work\n")
        .work_commit()
        .build();
    common::git_in(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widgets.git",
        ],
    );
    let head = common::git_in(&repo, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    let forge = common::scratch("release-path-refused-forge");
    common::write(
        &forge,
        "status",
        "HTTP/2 500\ncontent-type: application/json\n\n{\"message\":\"no\"}\n",
    );
    common::write(&forge, "routes", "/statuses/\tstatus\n");
    let output = common::batten()
        .current_dir(&repo)
        .env("BATTEN_REST_FIXTURE", &forge)
        .args(["release", "path", &head, "--post"])
        .output()
        .expect("run release path");
    assert_eq!(output.status.code(), Some(3), "{}", common::stderr(&output));
    assert!(
        common::stderr(&output).contains("could not post: the forge answered 500"),
        "{}",
        common::stderr(&output)
    );
    assert!(!common::stdout(&output).contains("posted"));
}

/// The read, over the fixture forge: the release object's `draft`,
/// `immutable` and `target_commitish`, and the tag's commit peeled.
#[test]
fn the_read_takes_state_from_the_release_object_and_the_tag_ref() {
    let forge = common::scratch("release-verify-forge");
    common::write(
        &forge,
        "release",
        &format!(
            "HTTP/2 200\ncontent-type: application/json\n\n{{\"tag_name\":\"v1.0.0\",\"draft\":false,\"immutable\":true,\"target_commitish\":\"{COMMIT}\",\"assets\":[{{\"id\":7,\"name\":\"SHA256SUMS\"}}]}}\n"
        ),
    );
    common::write(
        &forge,
        "ref",
        "HTTP/2 200\ncontent-type: application/json\n\n{\"object\":{\"type\":\"tag\",\"sha\":\"aaaa\"}}\n",
    );
    common::write(
        &forge,
        "peeled",
        &format!(
            "HTTP/2 200\ncontent-type: application/json\n\n{{\"object\":{{\"type\":\"commit\",\"sha\":\"{COMMIT}\"}}}}\n"
        ),
    );
    common::write(
        &forge,
        "routes",
        "/releases/tags/\trelease\n/git/ref/tags/\tref\n/git/tags/\tpeeled\n",
    );
    let get = |path: &str| batten::rest::fixture_get(&forge, path);
    let read = batten::release_verify::read("acme/widgets", "v1.0.0", &get).expect("a release");
    assert!(!read.draft);
    assert_eq!(read.immutable, Some(true));
    assert_eq!(read.target, COMMIT);
    assert_eq!(
        read.tag_commit.as_deref(),
        Some(COMMIT),
        "an annotated tag is peeled"
    );
}

// ---- The release path's verbs (P3, P4) --------------------------------------

use batten::release_state::{
    self, Files, Flight, Found, LandFacts, LandState, Pending, Read, Relation, Step, Unusable,
};

#[test]
fn discard_refuses_a_published_release() {
    assert!(release_state::discard(&Found::Published).is_err());
}

#[test]
fn discard_deletes_a_draft_then_its_tag() {
    assert_eq!(
        release_state::discard(&Found::Draft(9)),
        Ok(vec![Step::DeleteRelease(9), Step::DeleteTag])
    );
}

#[test]
fn discard_leaves_an_orphan_tag_alone() {
    assert_eq!(release_state::discard(&Found::Absent), Ok(vec![]));
}

fn quiet() -> Flight {
    Flight {
        active_run: None,
        drafts: vec![],
        pending: vec![],
        land_hold: release_state::LAND_HOLD_SECS,
    }
}

fn owed(land_failed_ago: Option<u64>) -> Pending {
    Pending {
        tag: String::from("v1.0.1"),
        relation: Relation::MainBehind,
        land_failed_ago,
    }
}

#[test]
fn nothing_in_flight_is_none() {
    assert_eq!(release_state::in_flight(&quiet()), None);
}

#[test]
fn a_running_build_is_in_flight() {
    let flight = Flight {
        active_run: Some(String::from("release-artifacts v1.0.1")),
        ..quiet()
    };
    assert!(release_state::in_flight(&flight).is_some());
}

#[test]
fn a_young_draft_is_in_flight_and_an_orphan_is_not() {
    let young = Flight {
        drafts: vec![(String::from("v1.0.1"), 60)],
        ..quiet()
    };
    assert!(release_state::in_flight(&young).is_some());
    let orphan = Flight {
        drafts: vec![(String::from("v1.0.1"), release_state::DRAFT_WINDOW_SECS)],
        ..quiet()
    };
    assert_eq!(release_state::in_flight(&orphan), None);
}

#[test]
fn a_pending_land_is_in_flight_until_its_hold_expires() {
    let running = Flight {
        pending: vec![owed(None)],
        ..quiet()
    };
    assert!(release_state::in_flight(&running).is_some());
    let failed_recently = Flight {
        pending: vec![owed(Some(60))],
        ..quiet()
    };
    assert!(release_state::in_flight(&failed_recently).is_some());
    let expired = Flight {
        pending: vec![owed(Some(release_state::LAND_HOLD_SECS))],
        ..quiet()
    };
    assert_eq!(release_state::in_flight(&expired), None);
    let landed = Flight {
        pending: vec![Pending {
            relation: Relation::MainAhead,
            ..owed(None)
        }],
        ..quiet()
    };
    assert_eq!(release_state::in_flight(&landed), None);
}

/// The forge's compare and local ancestry answer one `Relation` for one
/// commit, and no commit is never read as diverged (CLOUD-2245).
#[test]
fn both_producers_agree_on_every_relation() {
    for (status, pair, relation) in [
        ("identical", (true, true), Relation::Identical),
        ("behind", (true, false), Relation::MainAhead),
        ("ahead", (false, true), Relation::MainBehind),
        ("diverged", (false, false), Relation::Diverged),
    ] {
        assert_eq!(Relation::of_compare(status), Some(relation), "{status}");
        assert_eq!(Relation::of_ancestry(Some(pair)), relation, "{pair:?}");
    }
    assert_eq!(Relation::of_compare("unknown"), None);
    assert_eq!(Relation::of_ancestry(None), Relation::Absent);
}

/// `main` at the commit itself holds a pending release landed, a published one
/// skipped to (f), and a draft's target reached, whichever source said so.
#[test]
fn an_identical_main_is_landed_on_every_reader() {
    let landed = Flight {
        pending: vec![Pending {
            relation: Relation::Identical,
            ..owed(None)
        }],
        ..quiet()
    };
    assert_eq!(release_state::in_flight(&landed), None);
    let published = LandFacts {
        relation: Relation::Identical,
        ..facts(published_at(COMMIT))
    };
    assert_eq!(release_state::land_state(&published), LandState::SkipToF);
    let draft = LandFacts {
        relation: Relation::Identical,
        ..facts(Read::Draft {
            target: COMMIT.to_owned(),
        })
    };
    assert_eq!(release_state::land_state(&draft), LandState::DraftOk);
}

fn facts(read: Read) -> LandFacts {
    LandFacts {
        read,
        tag: String::from("v1.0.1"),
        sha: COMMIT.to_owned(),
        relation: Relation::MainBehind,
        tag_ref: None,
        pin_at_target: Some(String::from("v1.0.1")),
        version_at_target: Some(String::from("1.0.1")),
        head: None,
        draft_sums: None,
    }
}

fn published_at(commit: &str) -> Read {
    Read::Published {
        tag_commit: Some(commit.to_owned()),
    }
}

#[test]
fn land_state_skips_to_f_when_main_holds_the_release() {
    let landed = LandFacts {
        relation: Relation::MainAhead,
        ..facts(published_at(COMMIT))
    };
    assert_eq!(release_state::land_state(&landed), LandState::SkipToF);
}

#[test]
fn land_state_resumes_a_published_release_main_is_behind() {
    assert_eq!(
        release_state::land_state(&facts(published_at(COMMIT))),
        LandState::ResumeAtD
    );
}

#[test]
fn land_state_calls_a_release_off_its_sha_burned() {
    let other = "2222222222222222222222222222222222222222";
    assert_eq!(
        release_state::land_state(&facts(published_at(other))),
        LandState::Burned
    );
}

#[test]
fn land_state_admits_a_draft_every_assertion_holds_for() {
    let draft = facts(Read::Draft {
        target: COMMIT.to_owned(),
    });
    assert_eq!(release_state::land_state(&draft), LandState::DraftOk);
    assert_eq!(LandState::DraftOk.line(), "draft-ok");
}

#[test]
fn land_state_refuses_a_draft_an_assertion_fails_for() {
    let target = Read::Draft {
        target: COMMIT.to_owned(),
    };
    let elsewhere = LandFacts {
        sha: String::from("2222222222222222222222222222222222222222"),
        ..facts(target.clone())
    };
    let moved_tag = LandFacts {
        tag_ref: Some(String::from("3333333333333333333333333333333333333333")),
        ..facts(target.clone())
    };
    let wrong_pin = LandFacts {
        pin_at_target: Some(String::from("v1.0.0")),
        ..facts(target.clone())
    };
    let main_ahead = LandFacts {
        relation: Relation::MainAhead,
        ..facts(target)
    };
    for bad in [elsewhere, moved_tag, wrong_pin, main_ahead] {
        let state = release_state::land_state(&bad);
        assert!(
            state.line().starts_with("draft-bad "),
            "{bad:?} gave {state:?}"
        );
    }
}

// ---- The bake (CLOUD-2287) ---------------------------------------------------

/// The baked commit B, a child of the draft target [`COMMIT`].
const BAKED: &str = "4444444444444444444444444444444444444444";

/// The draft's `SHA256SUMS` for v1.0.1: every bootstrap archive, one digest.
fn draft_sums() -> String {
    use std::fmt::Write as _;
    batten::install::TARGETS
        .iter()
        .fold(String::new(), |mut sums, target| {
            let _ = writeln!(sums, "{}  batten-v1.0.1-{target}.tar.gz", "a".repeat(64));
            sums
        })
}

/// B as the bake writes it: a child of [`COMMIT`] changing only the two files,
/// its lock baked from [`draft_sums`].
fn baked_head() -> release_state::Head {
    let lock = batten::install::Lock::from_sums("batten", "v1.0.1", &draft_sums())
        .expect("every target has a line");
    release_state::Head {
        parent: Some(COMMIT.to_owned()),
        changed: ["install.lock", "install.sh"]
            .into_iter()
            .map(String::from)
            .collect(),
        lock: Some(lock.render()),
    }
}

/// THE BAKED HEAD LANDS (CLOUD-2287): a draft targeting A, dispatched with B,
/// is `draft-ok` when B is A's bake, so the tag lands on B and `main`
/// fast-forwards to the commit carrying its own lock.
#[test]
fn a_baked_head_of_the_drafts_target_is_draft_ok() {
    let baked = LandFacts {
        sha: BAKED.to_owned(),
        head: Some(baked_head()),
        draft_sums: Some(draft_sums()),
        ..facts(Read::Draft {
            target: COMMIT.to_owned(),
        })
    };
    assert_eq!(release_state::land_state(&baked), LandState::DraftOk);
}

/// Any other child of A stays `draft-bad`: one changing another path, one whose
/// lock disagrees with the draft's sums, and one that is not A's child at all.
#[test]
fn a_child_of_the_target_that_is_not_its_bake_stays_draft_bad() {
    let mut wider = baked_head();
    wider.changed.insert(String::from("Cargo.toml"));
    let mut wrong_lock = baked_head();
    wrong_lock.lock = Some(wrong_lock.lock.unwrap_or_default().replacen(
        &"a".repeat(64),
        &"b".repeat(64),
        1,
    ));
    let mut orphan = baked_head();
    orphan.parent = Some(String::from("5555555555555555555555555555555555555555"));
    for head in [wider, wrong_lock, orphan] {
        let bad = LandFacts {
            sha: BAKED.to_owned(),
            head: Some(head.clone()),
            draft_sums: Some(draft_sums()),
            ..facts(Read::Draft {
                target: COMMIT.to_owned(),
            })
        };
        let state = release_state::land_state(&bad);
        assert!(
            state.line().starts_with("draft-bad "),
            "{head:?} gave {state:?}"
        );
    }
}

/// THE CUT NEVER LOOPS ON ITS OWN BAKE (CLOUD-2287): B is landed; any other
/// head, or no open draft, is cut as before.
#[test]
fn cut_or_land_lands_a_baked_head_and_cuts_any_other() {
    use release_state::CutOrLand;
    let sums = draft_sums();
    assert_eq!(
        release_state::cut_or_land(Some(COMMIT), &baked_head(), "v1.0.1", &sums),
        CutOrLand::Land
    );
    let mut moved = baked_head();
    moved
        .changed
        .insert(String::from("crates/batten/src/lib.rs"));
    assert_eq!(
        release_state::cut_or_land(Some(COMMIT), &moved, "v1.0.1", &sums),
        CutOrLand::Cut
    );
    assert_eq!(
        release_state::cut_or_land(None, &baked_head(), "v1.0.1", &sums),
        CutOrLand::Cut
    );
}

/// A present `install.lock` naming a sha256 `SHA256SUMS` does not carry is
/// refused; an absent one — every release before the bake — passes.
#[test]
fn a_lock_disagreeing_with_sha256sums_is_refused() {
    let sums = draft_sums();
    let lock = baked_head().lock.unwrap_or_default();
    assert!(batten::release_verify::judge_lock(Some(&lock), "v1.0.1", &sums).is_empty());
    assert!(batten::release_verify::judge_lock(None, "v1.0.1", &sums).is_empty());
    let wrong = lock.replacen(&"a".repeat(64), &"c".repeat(64), 1);
    assert_eq!(
        batten::release_verify::judge_lock(Some(&wrong), "v1.0.1", &sums).len(),
        1
    );
    assert!(
        !batten::release_verify::judge_lock(Some(&lock), "v1.0.2", &sums).is_empty(),
        "a lock naming another release is refused"
    );
}

#[test]
fn land_state_reports_no_release_as_absent() {
    assert_eq!(
        release_state::land_state(&facts(Read::Absent)).line(),
        "absent"
    );
}

#[test]
fn a_stray_tag_is_unusable() {
    assert_eq!(
        release_state::unusable(&Found::Absent, true, true),
        Some(Unusable::StrayTag)
    );
    assert_eq!(release_state::unusable(&Found::Absent, true, false), None);
}

#[test]
fn a_burned_version_is_unusable_and_a_reachable_one_is_not() {
    assert_eq!(
        release_state::unusable(&Found::Published, false, true),
        Some(Unusable::Burned)
    );
    assert_eq!(release_state::unusable(&Found::Published, true, true), None);
    assert_eq!(release_state::unusable(&Found::Draft(1), true, true), None);
}

#[test]
fn an_unusable_version_bumps_all_four_paths() {
    let files = Files {
        manifest: String::from("[workspace.package]\nversion = \"0.0.7\"\n"),
        lock: String::from(
            "[[package]]\nname = \"batten\"\nversion = \"0.0.7\"\n\n[[package]]\nname = \"other\"\nversion = \"0.0.7\"\nsource = \"registry+https://example.invalid\"\n",
        ),
        config: String::from("engine = { release = \"v0.0.7\" }\n"),
        changelog: String::from(
            "# Changelog\n\n## [Unreleased]\n\n## [0.0.7](https://example.invalid/compare/v0.0.6...v0.0.7) - 2026-10-11\n",
        ),
    };
    let (to, bumped) =
        release_state::bump(&files, "0.0.7", &[String::from("batten")]).expect("a bump");
    assert_eq!(to, "0.0.8");
    assert!(bumped.manifest.contains("version = \"0.0.8\""));
    assert!(
        bumped
            .lock
            .contains("name = \"batten\"\nversion = \"0.0.8\""),
        "the workspace package moves"
    );
    assert!(
        bumped
            .lock
            .contains("name = \"other\"\nversion = \"0.0.7\""),
        "a registry package at the same number does not"
    );
    assert!(bumped.config.contains("release = \"v0.0.8\""));
    assert!(
        bumped
            .changelog
            .contains("## [0.0.8](https://example.invalid/compare/v0.0.6...v0.0.8)"),
        "the heading and its compare link move: {}",
        bumped.changelog
    );
}

/// `discard` end to end over the fixture forge: a draft is found in the list,
/// then the draft and its tag are deleted, in that order.
#[test]
fn release_discard_deletes_a_draft_and_its_tag_over_the_forge() {
    let repo = common::Fixture::new("release-discard-draft")
        .config("")
        .base_commit()
        .build();
    common::git_in(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widgets.git",
        ],
    );
    let forge = common::scratch("release-discard-forge");
    common::write(&forge, "missing", "HTTP/2 404\n\n{}\n");
    common::write(
        &forge,
        "list",
        "HTTP/2 200\ncontent-type: application/json\n\n[{\"id\":41,\"tag_name\":\"v1.0.1\",\"draft\":true}]\n",
    );
    common::write(&forge, "gone", "HTTP/2 204\n\n");
    common::write(
        &forge,
        "routes",
        "DELETE \tgone\n/releases/tags/\tmissing\n/releases?\tlist\n",
    );
    let output = common::batten()
        .current_dir(&repo)
        .env("BATTEN_REST_FIXTURE", &forge)
        .args(["release", "discard", "v1.0.1"])
        .output()
        .expect("run release discard");
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
    let asked = std::fs::read_to_string(forge.join("args")).unwrap_or_default();
    let deletes: Vec<&str> = asked
        .lines()
        .filter(|line| line.starts_with("DELETE "))
        .collect();
    assert_eq!(deletes.len(), 2, "{asked}");
    assert!(deletes[0].ends_with("/releases/41"), "{asked}");
    assert!(deletes[1].ends_with("/git/refs/tags/v1.0.1"), "{asked}");
}

#[test]
fn guard_refuses_a_published_release_and_a_foreign_draft() {
    let ours = Read::Draft {
        target: COMMIT.to_owned(),
    };
    assert_eq!(release_state::guard(&ours, COMMIT), Ok(()));
    let foreign = Read::Draft {
        target: String::from("2222222222222222222222222222222222222222"),
    };
    assert!(release_state::guard(&foreign, COMMIT).is_err());
    assert!(release_state::guard(&published_at(COMMIT), COMMIT).is_err());
    assert!(release_state::guard(&Read::Absent, COMMIT).is_err());
}

#[test]
fn the_seal_holds_an_unverified_pin_until_the_settings_are_green() {
    let failed = release_path::Verdict::Failure(vec![String::from("unverified")]);
    let passed = release_path::Verdict::Success(String::from("inherited"));
    assert!(
        release_path::seals(&failed, false, true),
        "not release-shaped"
    );
    assert!(
        release_path::seals(&failed, true, false),
        "settings not green"
    );
    assert!(
        !release_path::seals(&failed, true, true),
        "after B2 a release-shaped head is excused: release-path itself gates it"
    );
    assert!(!release_path::seals(&passed, false, false));
    assert!(release_path::release_shaped(
        &paths(&["Cargo.toml", "batten.toml"]),
        false
    ));
    assert!(!release_path::release_shaped(&paths(&["Cargo.toml"]), true));
    assert!(!release_path::release_shaped(&paths(&["src.rs"]), false));
}

#[test]
fn a_changelog_anywhere_is_a_release_path_and_source_is_not() {
    assert!(release_path::is_release_path("crates/batten/CHANGELOG.md"));
    assert!(release_path::is_release_path("CHANGELOG.md"));
    assert!(release_path::is_release_path("Cargo.lock"));
    assert!(!release_path::is_release_path("crates/batten/src/lib.rs"));
    assert!(!release_path::is_release_path("NOT-CHANGELOG.md.bak"));
}

#[test]
fn the_notes_are_the_versions_own_section() {
    let changelog = "# Changelog\n\n## [Unreleased]\n\n## [0.0.8](https://example.invalid) - 2026-10-12\n\n### Fixed\n\n- one\n\n## [0.0.7](https://example.invalid) - 2026-10-11\n\n- older\n";
    assert_eq!(
        release_state::section(changelog, "0.0.8").as_deref(),
        Some("### Fixed\n\n- one")
    );
    assert_eq!(release_state::section(changelog, "0.0.9"), None);
}

// ---- G4, `batten release settings` ------------------------------------------

use batten::release_guard::{self, Facts};

fn holding() -> Facts {
    Facts {
        trunk_non_fast_forward: true,
        tags_restrict_updates: true,
        bypassed: vec![],
        immutable_releases: true,
    }
}

#[test]
fn settings_name_every_owed_item() {
    assert!(release_guard::owed(&holding()).is_empty());
    let mut bypassed = holding();
    bypassed.bypassed = vec![String::from("protect-main")];
    assert!(
        release_guard::owed(&bypassed)
            .iter()
            .any(|item| item.contains("protect-main"))
    );
    let empty = Facts::default();
    assert_eq!(
        release_guard::owed(&empty).len(),
        3,
        "non-fast-forward, the v* tag ruleset and immutable releases"
    );
}
