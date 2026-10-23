//! G1: whether a release is fully and correctly published (CLOUD-2033).
//!
//! `batten release verify <tag> [--draft]` exits 0 only if every one of these
//! holds, and each is a refusal of its own:
//!
//! * **state** — the release is a draft (`--draft`), or it is published,
//!   immutable, and its tag commit is its `target_commitish`. Immutability is
//!   the release object's `immutable` field; a missing field is could-not-look,
//!   never a pass.
//! * **assets** — the release carries every name `policy/release-assets.rego`
//!   demands. The set is that module's, evaluated over the release's own
//!   record, never restated here.
//! * **sums** — `SHA256SUMS` has exactly one line per other asset, and every
//!   asset hashes to its line.
//! * **lock** — where the release's commit carries an `install.lock`
//!   (CLOUD-2287), it names this release and every line of it is the line
//!   `SHA256SUMS` publishes. An absent lock — every release before the bake,
//!   and every consumer's — is nothing to check.
//!
//! Everything a run needs is an argument, so the decision is testable with no
//! network: [`judge`] is pure over a read [`Release`], and [`read`] is the one
//! place the forge is asked.
//!
//! # Pointer-only
//!
//! A refusal names a tag, an asset name, a field or a SHA, never a byte of an
//! asset or a forge body (rule 4).

use std::collections::BTreeSet;

use crate::release::{Asset, Download, Get, Published};

/// The manifest every release carries its checksums in.
pub const SUMS: &str = "SHA256SUMS";

/// One release as G1 reads it: the fields the state check needs, and the assets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Whether it is still a draft.
    pub draft: bool,
    /// The `immutable` field, or `None` where the forge sent none.
    pub immutable: Option<bool>,
    /// The commit the release says it was built from.
    pub target: String,
    /// The commit its tag points at, or `None` where the tag does not exist.
    pub tag_commit: Option<String>,
    /// Its tag and assets.
    pub published: Published,
}

/// Why a release fails G1, each a pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `--draft` was asked and the release is published, or the reverse.
    State(String),
    /// Published but not immutable.
    Mutable,
    /// Published, and its tag commit is not its target.
    TagOffTarget {
        /// What the tag points at.
        tag: String,
        /// What the release says it was built from.
        target: String,
    },
    /// A name the asset module demands that the release does not carry.
    MissingAsset(String),
    /// An asset `SHA256SUMS` has no line for.
    Unsummed(String),
    /// An asset whose bytes do not hash to its line, or a line naming nothing.
    Mismatched(String),
    /// A committed `install.lock` line `SHA256SUMS` does not publish, or a lock
    /// naming another release or none (CLOUD-2287).
    LockDisagrees(String),
    /// No release is tagged this, as both reads answered (CLOUD-2518): the
    /// release PR's pin names a release the cut has not created yet.
    Absent(String),
}

impl Refusal {
    /// The pointer line.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Self::State(why) => format!("release verify: {why}"),
            Self::Mutable => String::from("release verify: published but not immutable"),
            Self::TagOffTarget { tag, target } => {
                format!("release verify: its tag points at {tag}, not its target {target}")
            }
            Self::MissingAsset(name) => format!("release verify: missing {name}"),
            Self::Unsummed(name) => format!("release verify: {SUMS} has no line for {name}"),
            Self::Mismatched(name) => {
                format!("release verify: {name} does not hash to its {SUMS} line")
            }
            Self::LockDisagrees(what) => format!(
                "release verify: {} disagrees with {SUMS}: {what}",
                crate::install::LOCK_FILE
            ),
            Self::Absent(tag) => format!("release verify: {tag} is not cut yet"),
        }
    }
}

/// What G1 found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every check holds.
    Verified,
    /// At least one refusal, in check order.
    Refused(Vec<Refusal>),
    /// A read that could not be made, as a pointer.
    CouldNotLook(String),
}

/// The state check: a draft when `draft` is asked, otherwise published,
/// immutable, and tagged at its target.
//MUTANT-SUITE crates/batten/tests/it/release_verify.rs
//MUTANT mutable-release-admitted|s@^        Some(false) => refused.push(Refusal::Mutable),$@        Some(false) => {}@|a_published_mutable_release_is_refused
//MUTANT tag-commit-unchecked|s@^    if release.tag_commit.as_deref() != Some(release.target.as_str()) {$@    if false {@|a_tag_off_its_target_commit_is_refused
fn judge_state(release: &Release, draft: bool, refused: &mut Vec<Refusal>) -> Result<(), String> {
    if draft {
        if !release.draft {
            refused.push(Refusal::State(String::from(
                "asked for a draft, and it is published",
            )));
        }
        return Ok(());
    }
    if release.draft {
        refused.push(Refusal::State(String::from("it is still a draft")));
        return Ok(());
    }
    match release.immutable {
        None => {
            return Err(format!(
                "the forge sent no `immutable` field for {}",
                release.published.tag
            ));
        }
        Some(false) => refused.push(Refusal::Mutable),
        Some(true) => {}
    }
    if release.tag_commit.as_deref() != Some(release.target.as_str()) {
        refused.push(Refusal::TagOffTarget {
            tag: release
                .tag_commit
                .clone()
                .unwrap_or_else(|| String::from("nothing")),
            target: release.target.clone(),
        });
    }
    Ok(())
}

/// The sums check: one `SHA256SUMS` line per other asset, each matching.
///
/// `fetch` hands back an asset's bytes, or the pointer saying why it could not.
//MUTANT sums-line-missing-admitted|s@^            refused.push(Refusal::Unsummed(asset.name.clone()));$@@|an_asset_without_a_sums_line_is_refused
//MUTANT public-bytes-unchecked|s@^        if crate::release::digest(\&bytes) != \*expected {$@        if false {@|a_mismatched_public_asset_is_refused
fn judge_sums(
    published: &Published,
    fetch: &mut dyn FnMut(&Asset) -> Result<Vec<u8>, String>,
    refused: &mut Vec<Refusal>,
) -> Result<(), String> {
    let Some(manifest) = published.assets.iter().find(|asset| asset.name == SUMS) else {
        refused.push(Refusal::MissingAsset(String::from(SUMS)));
        return Ok(());
    };
    let listed = crate::release::entries(&String::from_utf8_lossy(&fetch(manifest)?));
    let named: BTreeSet<&str> = listed.iter().map(|(_, name)| name.as_str()).collect();
    for asset in published.assets.iter().filter(|asset| asset.name != SUMS) {
        if !named.contains(asset.name.as_str()) {
            refused.push(Refusal::Unsummed(asset.name.clone()));
        }
    }
    for (expected, name) in &listed {
        let Some(asset) = published.assets.iter().find(|asset| asset.name == *name) else {
            refused.push(Refusal::Mismatched(name.clone()));
            continue;
        };
        let bytes = fetch(asset)?;
        if crate::release::digest(&bytes) != *expected {
            refused.push(Refusal::Mismatched(name.clone()));
        }
    }
    Ok(())
}

/// G1 over a release already read.
///
/// `missing` is the asset module's answer: the names it demands that the
/// release does not carry, or the pointer saying it could not evaluate.
//MUTANT missing-target-admitted|s@^    refused.extend(missing.into_iter().map(Refusal::MissingAsset));$@    drop(missing);@|a_release_missing_a_target_is_refused
pub fn judge(
    release: &Release,
    draft: bool,
    missing: Result<Vec<String>, String>,
    fetch: &mut dyn FnMut(&Asset) -> Result<Vec<u8>, String>,
) -> Verdict {
    let mut refused = Vec::new();
    if let Err(why) = judge_state(release, draft, &mut refused) {
        return Verdict::CouldNotLook(why);
    }
    let missing = match missing {
        Ok(missing) => missing,
        Err(why) => return Verdict::CouldNotLook(why),
    };
    refused.extend(missing.into_iter().map(Refusal::MissingAsset));
    if let Err(why) = judge_sums(&release.published, fetch, &mut refused) {
        return Verdict::CouldNotLook(why);
    }
    if refused.is_empty() {
        Verdict::Verified
    } else {
        Verdict::Refused(refused)
    }
}

/// The lock check (CLOUD-2287): a present `install.lock` must name release
/// `tag` and carry, for each archive it lists, exactly the line `sums`
/// publishes. An absent lock has nothing to check, so nothing is refused.
//MUTANT baked-lock-unchecked|s@^    refused.extend(disagreeing.into_iter().map(Refusal::LockDisagrees));$@@|a_lock_disagreeing_with_sha256sums_is_refused
#[must_use]
pub fn judge_lock(lock: Option<&str>, tag: &str, sums: &str) -> Vec<Refusal> {
    let Some(text) = lock else {
        return Vec::new();
    };
    let lock = match crate::install::Lock::parse(text) {
        Ok(lock) => lock,
        Err(why) => return vec![Refusal::LockDisagrees(why.to_string())],
    };
    let mut refused = Vec::new();
    if lock.tag != tag {
        refused.push(Refusal::LockDisagrees(format!(
            "it names {}, not {tag}",
            lock.tag
        )));
    }
    if lock.sums.is_empty() {
        refused.push(Refusal::LockDisagrees(String::from("it lists no archive")));
    }
    let disagreeing = lock.disagreements(sums);
    refused.extend(disagreeing.into_iter().map(Refusal::LockDisagrees));
    refused
}

/// `verdict` with the lock check's `refused` folded in: a pass with a lock
/// refusal is refused, and could-not-look stays could-not-look.
#[must_use]
pub fn with_lock(verdict: Verdict, refused: Vec<Refusal>) -> Verdict {
    match verdict {
        Verdict::Verified if refused.is_empty() => Verdict::Verified,
        Verdict::Verified => Verdict::Refused(refused),
        Verdict::Refused(mut before) => {
            before.extend(refused);
            Verdict::Refused(before)
        }
        Verdict::CouldNotLook(why) => Verdict::CouldNotLook(why),
    }
}

/// The `install.lock` committed at `reference`, through the forge contents API,
/// `Ok(None)` where the commit carries none.
///
/// # Errors
///
/// The could-not-look pointer: an answer but `200` or `404`, or a body that is
/// not a file's.
pub fn committed_lock(slug: &str, reference: &str, get: Get<'_>) -> Result<Option<String>, String> {
    let path = format!(
        "repos/{slug}/contents/{}?ref={reference}",
        crate::install::LOCK_FILE
    );
    let answer = get(&path).ok_or_else(|| format!("{path} did not answer"))?;
    if answer.status == 404 {
        return Ok(None);
    }
    if !answer.is_reading() {
        return Err(format!("{path} answered {}", answer.status));
    }
    let value: serde_json::Value =
        serde_json::from_str(&answer.body).map_err(|_| format!("{path} is not JSON"))?;
    let content = value
        .get("content")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{path} carries no content"))?;
    let bytes = base64_decode(content).ok_or_else(|| format!("{path}'s content is not base64"))?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| format!("{path} is not UTF-8"))
}

/// Standard base64, ignoring the line breaks the contents API wraps it in.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |byte: u8| -> Option<u32> {
        Some(u32::from(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let clean: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && *byte != b'=')
        .collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut word = 0u32;
        for (at, byte) in chunk.iter().enumerate() {
            word |= value(*byte)? << (18 - 6 * at);
        }
        let bytes = word.to_be_bytes();
        let take = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => return None,
        };
        out.extend_from_slice(&bytes[1..=take]);
    }
    Some(out)
}

/// Read release `tag` and its tag's commit from the forge.
///
/// # Errors
///
/// The could-not-look pointer: the release or its object would not read.
pub fn read(slug: &str, tag: &str, get: Get<'_>) -> Result<Release, String> {
    let published = crate::release::read_release(slug, Some(tag), get)?;
    let object = object(slug, tag, get)?;
    let draft = object
        .get("draft")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| format!("the release {tag} carries no `draft` field"))?;
    let immutable = object.get("immutable").and_then(serde_json::Value::as_bool);
    let target = object
        .get("target_commitish")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(Release {
        draft,
        immutable,
        target,
        tag_commit: tag_commit(slug, tag, get),
        published,
    })
}

/// The release object for `tag`: the tag read, or the list's entry for a draft.
fn object(slug: &str, tag: &str, get: Get<'_>) -> Result<serde_json::Value, String> {
    let at = format!("repos/{slug}/releases/tags/{tag}");
    if let Some(answer) = get(&at).filter(crate::rest::Answer::is_reading)
        && let Ok(value) = serde_json::from_str(&answer.body)
    {
        return Ok(value);
    }
    let list = format!("repos/{slug}/releases?per_page=100");
    let answer = get(&list)
        .filter(crate::rest::Answer::is_reading)
        .ok_or_else(|| format!("neither {at} nor {list} answered"))?;
    let listed: Vec<serde_json::Value> =
        serde_json::from_str(&answer.body).map_err(|_| format!("{list} is not a release list"))?;
    listed
        .into_iter()
        .find(|entry| entry.get("tag_name").and_then(serde_json::Value::as_str) == Some(tag))
        .ok_or_else(|| format!("no release is tagged {tag}"))
}

/// The commit `refs/tags/<tag>` points at, peeling an annotated tag, or `None`
/// where the tag does not exist (a draft's may not).
#[must_use]
pub fn tag_commit(slug: &str, tag: &str, get: Get<'_>) -> Option<String> {
    let answer =
        get(&format!("repos/{slug}/git/ref/tags/{tag}")).filter(crate::rest::Answer::is_reading)?;
    let value: serde_json::Value = serde_json::from_str(&answer.body).ok()?;
    let object = value.get("object")?;
    let sha = object.get("sha")?.as_str()?.to_owned();
    if object.get("type").and_then(serde_json::Value::as_str) != Some("tag") {
        return Some(sha);
    }
    let peeled =
        get(&format!("repos/{slug}/git/tags/{sha}")).filter(crate::rest::Answer::is_reading)?;
    let value: serde_json::Value = serde_json::from_str(&peeled.body).ok()?;
    Some(value.get("object")?.get("sha")?.as_str()?.to_owned())
}

/// An asset's bytes: through the assets API for a draft, which only an
/// authenticated read can see, or its public URL for a published release, which
/// is what an installer downloads.
///
/// # Errors
///
/// The pointer naming the asset and the answer it got.
pub fn fetch(
    slug: &str,
    tag: &str,
    draft: bool,
    asset: &Asset,
    download: Download<'_>,
) -> Result<Vec<u8>, String> {
    let path = if draft {
        format!("repos/{slug}/releases/assets/{}", asset.id)
    } else {
        format!(
            "https://github.com/{slug}/releases/download/{tag}/{}",
            asset.name
        )
    };
    match download(&path) {
        Some((200, bytes)) => Ok(bytes),
        Some((status, _)) => Err(format!("{} answered {status}", asset.name)),
        None => Err(format!("{} could not be downloaded", asset.name)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_every_padding_and_ignores_line_breaks() {
        assert_eq!(base64_decode("Zm9v\nYmFy").unwrap(), b"foobar");
        assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(base64_decode("Zm9vYmE=").unwrap(), b"fooba");
        assert!(base64_decode("Z").is_none());
    }

    #[test]
    fn base64_decodes_the_two_symbol_digits() {
        assert_eq!(base64_decode("+/+/").unwrap(), b"\xfb\xff\xbf");
    }

    fn answer(status: u16, body: &str) -> crate::rest::Answer {
        crate::rest::Answer {
            status,
            etag: None,
            poll_floor: None,
            backoff: None,
            body: body.to_owned(),
            headers: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn a_committed_lock_is_its_content_none_or_could_not_look() {
        let lock = |status: u16, body: &'static str| {
            move |path: &str| {
                assert_eq!(
                    path,
                    format!("repos/o/r/contents/{}?ref=abc", crate::install::LOCK_FILE)
                );
                Some(answer(status, body))
            }
        };
        assert_eq!(
            committed_lock("o/r", "abc", &lock(200, r#"{"content": "Zm9v\n"}"#)),
            Ok(Some(String::from("foo")))
        );
        assert_eq!(committed_lock("o/r", "abc", &lock(404, "{}")), Ok(None));
        assert!(committed_lock("o/r", "abc", &lock(500, "{}")).is_err());
        assert!(committed_lock("o/r", "abc", &lock(200, "{}")).is_err());
        assert!(committed_lock("o/r", "abc", &|_: &str| None).is_err());
    }

    #[test]
    fn a_refusal_is_one_pointer_line() {
        assert_eq!(
            Refusal::Mutable.line(),
            "release verify: published but not immutable"
        );
        assert_eq!(
            Refusal::MissingAsset(String::from("x.tar.gz")).line(),
            "release verify: missing x.tar.gz"
        );
    }

    #[test]
    fn a_lock_refusal_turns_a_pass_into_a_refusal_and_nothing_else() {
        assert_eq!(with_lock(Verdict::Verified, Vec::new()), Verdict::Verified);
        assert_eq!(
            with_lock(Verdict::Verified, vec![Refusal::Mutable]),
            Verdict::Refused(vec![Refusal::Mutable])
        );
        assert_eq!(
            with_lock(
                Verdict::CouldNotLook(String::from("x")),
                vec![Refusal::Mutable]
            ),
            Verdict::CouldNotLook(String::from("x"))
        );
    }

    /// A draft is not at its tag, so the list's entry for the tag is the object.
    #[test]
    fn a_draft_s_object_is_the_list_entry_carrying_its_tag() {
        let get = |path: &str| {
            if path.contains("/releases/tags/") {
                Some(answer(404, "{}"))
            } else {
                Some(answer(
                    200,
                    r#"[{"tag_name": "v2", "draft": false}, {"tag_name": "v1", "draft": true}]"#,
                ))
            }
        };
        assert_eq!(object("o/r", "v1", &get).unwrap()["draft"], true);
        assert!(object("o/r", "v3", &get).is_err());
    }

    #[test]
    fn an_asset_is_fetched_from_where_its_release_state_serves_it() {
        let asset = Asset {
            id: 7,
            name: String::from("x.tar.gz"),
        };
        let download = |path: &str| -> Option<(u16, Vec<u8>)> {
            match path {
                "repos/o/r/releases/assets/7" => Some((200, b"draft".to_vec())),
                "https://github.com/o/r/releases/download/v1/x.tar.gz" => {
                    Some((200, b"public".to_vec()))
                }
                _ => Some((404, Vec::new())),
            }
        };
        assert_eq!(
            fetch("o/r", "v1", true, &asset, &download).unwrap(),
            b"draft"
        );
        assert_eq!(
            fetch("o/r", "v1", false, &asset, &download).unwrap(),
            b"public"
        );
        assert!(fetch("o/r", "v2", false, &asset, &download).is_err());
    }
}
