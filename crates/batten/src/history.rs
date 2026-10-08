//! A rule's history, and the gate that makes reading it the price of changing it
//! (CLOUD-2144).
//!
//! # The failure this closes
//!
//! A rule's reasons live in the comment block above its row, the class paragraph
//! beside it and the commits that shaped it — and nothing linked them to the rule
//! or checked that anyone read them. So a row could be rewritten by a context
//! that never saw why it existed, which is how a gate's prose decays.
//!
//! # The shape
//!
//! * **The owner map.** A row of the config authority owns its own lines, the
//!   comment block directly above its header, and the sub-tables that follow it
//!   (`[[rule.*]]` under a rule, `[[verdict.route]]` under a class). An id-less
//!   row — `[[mint]]`, `[pattern]`, a plain section — owns nothing gated.
//! * **The digest is of the owned text at HEAD.** A commit that changes the row
//!   changes it; the agent's own uncommitted edits do not, so a context that read
//!   the history can make several edits. The gate never walks history: that
//!   costs about a second per row, far over the hook budget.
//! * **The receipt is per context.** One file per (row, context), so one
//!   session's read never admits another's edit, and a compaction drops this
//!   context's reads because what was read left the window with it.
//MUTANT-SUITE crates/batten/tests/it/history_gate.rs

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The most bytes `--history` prints for one row: about 2,000 tokens at bytes/4.
pub const HISTORY_BYTES: usize = 8_000;

/// How many commits that changed a row a history read walks back to.
const CHANGES_MAX: usize = 12;

/// How many of the newest changes print their whole message, not just a subject.
const FULL_MESSAGES: usize = 3;

/// One region of the config authority and the id it is gated under, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The `id` of the `[[rule]]` or `[[verdict]]` row, or `None` where the
    /// region is not a gated row.
    pub id: Option<String>,
    /// The first byte the row owns: the start of its leading comment block.
    pub start: usize,
    /// One past the last byte it owns.
    pub end: usize,
}

/// What a header line opens.
enum Opens {
    /// A gated row of this kind.
    Gated(&'static str),
    /// A sub-table of the gated row of this kind that precedes it.
    Child(&'static str),
    /// Anything else, which owns nothing gated.
    Other,
}

fn opens(header: &str) -> Opens {
    match header {
        "[[rule]]" => Opens::Gated("rule"),
        "[[verdict]]" => Opens::Gated("verdict"),
        _ if header.starts_with("[[rule.") || header.starts_with("[rule.") => Opens::Child("rule"),
        _ if header.starts_with("[[verdict.") || header.starts_with("[verdict.") => {
            Opens::Child("verdict")
        }
        _ => Opens::Other,
    }
}

/// Every row of `text`, in order, covering it end to end.
#[must_use]
pub fn rows(text: &str) -> Vec<Row> {
    // (byte offset, line) pairs, so every boundary below is a byte offset.
    let mut lines: Vec<(usize, &str)> = Vec::new();
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        lines.push((at, line));
        at += line.len();
    }
    let mut rows: Vec<Row> = Vec::new();
    let mut kinds: Vec<Option<&'static str>> = Vec::new();
    let mut last_content_end = 0;
    for (index, &(offset, line)) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let header = trimmed.split('#').next().unwrap_or(trimmed).trim();
            match opens(header) {
                Opens::Child(kind) if kinds.last().copied().flatten() == Some(kind) => {}
                opened => {
                    // THE COMMENT BLOCK ABOVE A HEADER IS THE ROW'S OWN: it starts
                    // after the last content line before the header.
                    let start = comment_start(&lines, index, last_content_end);
                    if let Some(previous) = rows.last_mut() {
                        previous.end = start;
                    }
                    let id = match opened {
                        Opens::Gated(_) => row_id(&lines[index + 1..]),
                        _ => None,
                    };
                    kinds.push(match opened {
                        Opens::Gated(kind) => Some(kind),
                        _ => None,
                    });
                    rows.push(Row {
                        id,
                        start,
                        end: text.len(),
                    });
                }
            }
        }
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            last_content_end = offset + line.len();
        }
    }
    if rows.first().is_none_or(|first| first.start > 0) {
        let end = rows.first().map_or(text.len(), |first| first.start);
        rows.insert(
            0,
            Row {
                id: None,
                start: 0,
                end,
            },
        );
    }
    rows
}

/// The first byte of the comment block directly above line `index`.
fn comment_start(lines: &[(usize, &str)], index: usize, floor: usize) -> usize {
    let mut start = lines[index].0;
    for &(offset, line) in lines[..index].iter().rev() {
        if offset < floor || !line.trim().starts_with('#') {
            break;
        }
        start = offset;
    }
    start
}

/// The `id = "…"` a row declares before its next header.
fn row_id(after_header: &[(usize, &str)]) -> Option<String> {
    for &(_, line) in after_header {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            return None;
        }
        if let Some(value) = trimmed.strip_prefix("id") {
            let value = value.trim_start().strip_prefix('=')?.trim();
            let parsed: toml::Value = toml::from_str(&format!("v = {value}")).ok()?;
            return parsed.get("v")?.as_str().map(str::to_owned);
        }
    }
    None
}

/// The gated ids whose rows a change over `ranges` touches.
///
/// A range is `[start, end)` in `text`. An empty range is an insertion: it is
/// owned only when it falls strictly inside a row, because an insertion at a
/// row's boundary is new text between rows — a new row, which owes no history.
#[must_use]
pub fn owner_of(text: &str, ranges: &[(usize, usize)]) -> BTreeSet<String> {
    let mut owners = BTreeSet::new();
    for row in rows(text) {
        let Some(id) = row.id else { continue };
        let touched = ranges.iter().any(|&(start, end)| {
            if start == end {
                row.start < start && start < row.end
            } else {
                row.start < end && start < row.end
            }
        });
        if touched {
            owners.insert(id);
        }
    }
    owners
}

/// The text every row gated under `id` owns, concatenated, or `None` where no
/// row declares it — a new row.
#[must_use]
pub fn owned_text(text: &str, id: &str) -> Option<String> {
    let owned: String = rows(text)
        .into_iter()
        .filter(|row| row.id.as_deref() == Some(id))
        .map(|row| &text[row.start..row.end])
        .collect();
    (!owned.is_empty()).then_some(owned)
}

/// The digest a history receipt is checked against.
#[must_use]
pub fn digest(owned: &str) -> String {
    crate::receipt::hex_sha256(owned.as_bytes())
}

/// The byte ranges in `current` that a write replaces.
///
/// `content` is a whole-file write; `spans` an edit's old/new pairs. `None` is
/// could-not-look — an old span not found in the file — which the gate allows,
/// because a gate that cannot locate the change must not refuse every change.
#[must_use]
pub fn changed_ranges(
    current: &str,
    content: Option<&str>,
    spans: &[(String, String, bool)],
) -> Option<Vec<(usize, usize)>> {
    if let Some(new) = content {
        let prefix = current
            .bytes()
            .zip(new.bytes())
            .take_while(|(left, right)| left == right)
            .count();
        let suffix = current[prefix..]
            .bytes()
            .rev()
            .zip(new[prefix.min(new.len())..].bytes().rev())
            .take_while(|(left, right)| left == right)
            .count();
        if prefix == current.len() && prefix == new.len() {
            return Some(Vec::new());
        }
        return Some(vec![(prefix, current.len() - suffix)]);
    }
    let mut ranges = Vec::new();
    for (old, _, replace_all) in spans {
        if old.is_empty() {
            return None;
        }
        let found: Vec<usize> = current
            .match_indices(old.as_str())
            .map(|(at, _)| at)
            .collect();
        let first = *found.first()?;
        let starts = if *replace_all { found } else { vec![first] };
        ranges.extend(starts.into_iter().map(|at| (at, at + old.len())));
    }
    Some(ranges)
}

/// The receipt file for one (row, context) pair.
fn receipt_path(git_dir: &Path, id: &str, context: &str) -> PathBuf {
    let short = |text: &str| crate::receipt::hex_sha256(text.as_bytes())[..16].to_owned();
    git_dir
        .join("batten-receipts")
        .join(format!("history-read.{}.{}", short(id), short(context)))
}

/// Record that `context` read `id`'s history while its owned text digested to
/// `digest`.
///
/// # Errors
///
/// When the receipt directory cannot be written.
pub fn record_read(
    git_dir: &Path,
    context: &str,
    id: &str,
    digest: &str,
    now: u64,
) -> std::io::Result<()> {
    let path = receipt_path(git_dir, id, context);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, format!("{id}\x1f{digest}\x1f{now}\n"))
}

/// Whether `context` holds a read of `id`'s history at `digest`.
//MUTANT history-receipt-ignores-digest|s@^        .is_some_and(|held| held == digest)$@        .is_some()@|a_new_commit_to_the_rule_invalidates_the_history_receipt
#[must_use]
pub fn admits(git_dir: &Path, context: &str, id: &str, digest: &str) -> bool {
    std::fs::read_to_string(receipt_path(git_dir, id, context))
        .ok()
        .and_then(|body| body.split('\x1f').nth(1).map(str::to_owned))
        .is_some_and(|held| held == digest)
}

/// Drop every history read `context` holds, for a compaction, clear or startup.
///
/// # Errors
///
/// When the receipt directory exists and cannot be listed.
pub fn forget_context(git_dir: &Path, context: &str) -> std::io::Result<()> {
    let dir = git_dir.join("batten-receipts");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(());
    };
    let suffix = format!(".{}", &crate::receipt::hex_sha256(context.as_bytes())[..16]);
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("history-read.") && name.ends_with(&suffix) {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// The gated ids a write to the config authority touches that `context` has not
/// read the current history of.
///
/// `head` is the authority's text at `HEAD`; `current` the working text the
/// ranges index. An id absent at `HEAD` is a new row and owes nothing.
//MUTANT history-receipt-ignores-context|s@^        .filter(|id| !admits(git_dir, context, id, \&digest(\&owned_at_head(id))))$@        .filter(|id| !admits(git_dir, "", id, \&digest(\&owned_at_head(id))))@|another_contexts_receipt_does_not_admit
#[must_use]
pub fn unread(
    git_dir: &Path,
    context: &str,
    head: &str,
    current: &str,
    ranges: &[(usize, usize)],
) -> Vec<String> {
    let owned_at_head = |id: &str| owned_text(head, id).unwrap_or_default();
    owner_of(current, ranges)
        .into_iter()
        .filter(|id| owned_text(head, id).is_some())
        .filter(|id| !admits(git_dir, context, id, &digest(&owned_at_head(id))))
        .collect()
}

/// The histories one `batten policy explain <id>… --history` call prints.
///
/// ONE WALK PER CALL, NOT PER ROW. A sweep reads many rows' histories at once,
/// and one squash commit commonly changed all of them: re-reading every version
/// of the authority per row cost seconds each, and re-printing that commit's
/// whole message under every row it touched cost about 2,000 tokens a row for
/// nothing new. So the versions are walked once, each version's text is read
/// once, and a commit's message prints in full the first time only.
#[derive(Debug)]
pub struct Assembler<'a> {
    root: &'a Path,
    config: &'a str,
    head: String,
    versions: Vec<(String, String)>,
    texts: std::collections::HashMap<String, Option<String>>,
    shown: BTreeSet<String>,
}

impl<'a> Assembler<'a> {
    /// Reads the authority at `HEAD` and lists the commits that changed it.
    ///
    /// # Errors
    ///
    /// When the authority cannot be read at `HEAD`, or its history cannot be
    /// walked (a shallow clone).
    pub fn new(root: &'a Path, config: &'a str) -> anyhow::Result<Self> {
        Ok(Self {
            root,
            config,
            head: crate::git::show(root, "HEAD", config)?,
            versions: crate::git::path_changes(root, config)?,
            texts: std::collections::HashMap::new(),
            shown: BTreeSet::new(),
        })
    }

    /// One row's owned text at the `index`th version, read at most once a call.
    fn owned_at(&mut self, index: usize, id: &str) -> Option<String> {
        let sha = self.versions.get(index)?.0.clone();
        let (root, config) = (self.root, self.config);
        self.texts
            .entry(sha)
            .or_insert_with_key(|sha| crate::git::show(root, sha, config).ok())
            .as_deref()
            .and_then(|text| owned_text(text, id))
    }

    /// The history printed for one row, or `None` when `HEAD` declares no such id.
    ///
    /// The row as it stands at `HEAD` (its comment block, keys and class
    /// paragraph), then the commits that changed it, newest first: the newest
    /// few in full unless this call already printed them, the rest as
    /// `sha subject`, capped at [`HISTORY_BYTES`].
    pub fn assemble(&mut self, id: &str) -> Option<String> {
        let now = owned_text(&self.head, id)?;
        let mut out = format!("{}\n", now.trim_end());
        let mut changes: Vec<(String, String)> = Vec::new();
        for index in 0..self.versions.len() {
            let here = self.owned_at(index, id);
            let before = self.owned_at(index + 1, id);
            if here != before {
                changes.push(self.versions[index].clone());
            }
            if before.is_none() || changes.len() >= CHANGES_MAX {
                break;
            }
        }
        if !changes.is_empty() {
            out.push_str("\nchanged by, newest first:\n");
        }
        for (index, (sha, subject)) in changes.iter().enumerate() {
            let short = &sha[..sha.len().min(10)];
            // A FULL MESSAGE THAT WOULD NOT FIT FALLS BACK TO ITS SUBJECT rather than
            // ending the list: a row whose newest change is one long squash would
            // otherwise print no change at all.
            let fits = |entry_len: usize| out.len() + entry_len <= HISTORY_BYTES;
            let message = (!self.shown.contains(sha) && index < FULL_MESSAGES).then(|| {
                crate::git::message_of(self.root, sha).unwrap_or_else(|_| subject.clone())
            });
            //MUTANT history-marks-unprinted|s@^            let full = message$@            let full = message.is_some() \&\& self.shown.insert(sha.clone()) \&\& message@|a_message_the_cap_cut_is_not_pointed_at
            //MUTANT history-full-unfitted|s@^                .is_some_and(|message| fits(short.len() + message.trim_end().len() + 3));$@                .is_some();@|a_message_the_cap_cut_is_not_pointed_at
            let full = message
                .as_ref()
                .is_some_and(|message| fits(short.len() + message.trim_end().len() + 3));
            let entry = if self.shown.contains(sha) {
                format!("{short} {subject} (printed above)\n")
            } else if let Some(message) = message.as_ref().filter(|_| full) {
                format!("\n{short}\n{}\n", message.trim_end())
            } else {
                format!("{short} {subject}\n")
            };
            if out.len() + entry.len() > HISTORY_BYTES {
                out.push_str(&format!(
                    "… {} older change(s) not shown\n",
                    changes.len() - index
                ));
                break;
            }
            // MARKED ONLY ONCE IT IS IN THE OUTPUT: a message the cap cut was
            // never printed, so a later row must not point at it as if it were.
            if full {
                self.shown.insert(sha.clone());
            }
            out.push_str(&entry);
        }
        Some(out)
    }
}

/// The history `batten policy explain <id> --history` prints for one row.
///
/// # Errors
///
/// As [`Assembler::new`].
pub fn assemble(root: &Path, config: &str, id: &str) -> anyhow::Result<Option<String>> {
    Ok(Assembler::new(root, config)?.assemble(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "\
version = 1

# Why the first rule exists.
[[rule]]
id = \"first rule\"
kind = \"x\"

[[rule.conserves]]
case = \"a\"

[[mint]]
name = \"m\"

# The class.
[[verdict]]
id = \"some class\"
gloss = \"g\"

[[verdict.route]]
id = \"r\"
";

    fn at(text: &str) -> usize {
        CONFIG.find(text).expect("the fixture carries it")
    }

    #[test]
    fn owner_of_maps_a_toml_hunk_to_its_rule_id() {
        let in_rule = at("kind = \"x\"");
        assert_eq!(
            owner_of(CONFIG, &[(in_rule, in_rule + 3)]),
            BTreeSet::from(["first rule".to_owned()])
        );
        let comment = at("# Why the first");
        assert!(
            owner_of(CONFIG, &[(comment, comment + 5)]).contains("first rule"),
            "a row owns the comment block above it"
        );
        let child = at("case = \"a\"");
        assert!(owner_of(CONFIG, &[(child, child + 4)]).contains("first rule"));
        let route = at("id = \"r\"");
        assert!(owner_of(CONFIG, &[(route, route + 4)]).contains("some class"));
        let mint = at("name = \"m\"");
        assert!(
            owner_of(CONFIG, &[(mint, mint + 4)]).is_empty(),
            "an id-less row"
        );
        let version = at("version");
        assert!(owner_of(CONFIG, &[(version, version + 3)]).is_empty());
    }

    #[test]
    fn owned_text_is_a_rows_comment_and_its_children() {
        let owned = owned_text(CONFIG, "first rule").expect("declared");
        assert!(owned.starts_with("# Why the first rule exists."), "{owned}");
        assert!(owned.contains("case = \"a\""), "{owned}");
        assert!(!owned.contains("[[mint]]"), "{owned}");
        assert_eq!(owned_text(CONFIG, "no such row"), None);
    }

    #[test]
    fn an_edit_span_is_located_and_an_unfound_one_is_could_not_look() {
        let spans = vec![("kind = \"x\"".to_owned(), "kind = \"y\"".to_owned(), false)];
        let ranges = changed_ranges(CONFIG, None, &spans).expect("found");
        assert_eq!(ranges, vec![(at("kind = \"x\""), at("kind = \"x\"") + 10)]);
        let missing = vec![("absent".to_owned(), "x".to_owned(), false)];
        assert_eq!(changed_ranges(CONFIG, None, &missing), None);
    }

    #[test]
    fn a_whole_file_write_is_the_span_between_its_common_ends() {
        let new = CONFIG.replace("kind = \"x\"", "kind = \"yy\"");
        let ranges = changed_ranges(CONFIG, Some(&new), &[]).expect("a write");
        assert_eq!(
            owner_of(CONFIG, &ranges),
            BTreeSet::from(["first rule".to_owned()])
        );
    }
}
