//! Candidate resolutions for a conflicted replay, never applied (CLOUD-1956).
//!
//! `land.rs` is emphatic that the loop **will not resolve a conflict**, and this
//! module keeps that true: it WRITES a candidate and names the shape that made it,
//! and `batten land replay --resolve <path>=<file>` remains the only act that puts
//! one into a tree. What changes is what the human is handed: instead of a bare
//! path, a merge they can read in one look.
//!
//! # Why this exists
//!
//! Every race with trunk on #928 and #1035 was resolved by a script written in the
//! moment — 25 resolutions, all of four shapes: a JSON allow-list both sides grew,
//! a comma-separated gate list both sides grew, a comment both sides reworded, and
//! a file the branch never meant to change. The last of those scripts SORTED a list
//! trunk had never sorted, and a corrective commit followed. A mechanism does the
//! same union the same way every time, in trunk's order.
//!
//! # Built in, not declared
//!
//! The shapes are a closed set here rather than a `[[land.resolution]]` table in
//! config. A proposal is only ever read, so a wrong candidate costs a reviewer one
//! look; a new config table widens configuration, which non-negotiable rule 6
//! refuses. A consumer who wants a shape off does not pass `--propose`.
//!
//! # All or nothing, per path
//!
//! A candidate exists only when EVERY conflict region of the path matches a
//! shape. One unmatched region and the path gets nothing: a candidate that merged
//! three regions and left the fourth to the reader would be the partial
//! resolution `gitwrite`'s header refuses, arrived at by omission.
//!
//! `net-zero` (a branch that did not change the file) is not a shape: the three-way
//! merge never conflicts on a file one side left alone.

use std::fmt;
use std::num::NonZeroU8;

use regex::Regex;

/// The regularity a conflict region matched, reported beside its candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Shape {
    /// Every line on every side is blank or a comment: trunk's text is taken.
    CommentOnly,
    /// One `KEY = "a,b,c"` line per side: trunk's items, minus the branch's
    /// removals, plus the branch's additions in the branch's order.
    ListUnion,
    /// Every line is a `"string",` array element: merged as [`Shape::ListUnion`].
    JsonArrayUnion,
}

impl Shape {
    /// The stable token printed beside a candidate (house-style §6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Shape::CommentOnly => "comment-only",
            Shape::ListUnion => "list-union",
            Shape::JsonArrayUnion => "json-array-union",
        }
    }
}

impl fmt::Display for Shape {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(self.as_str())
    }
}

/// A candidate: the merged bytes, and every shape that produced a region of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The whole file, every conflict region replaced by its shape's merge.
    pub bytes: Vec<u8>,
    /// The shapes used, deduplicated and ordered, for the report line.
    pub shapes: Vec<Shape>,
}

/// Propose a merge of `ours` (trunk) and `theirs` (the branch's commit) over
/// `ancestor`, or `None` when any conflict region matches no shape.
///
/// `None` too for bytes that are not UTF-8 and for a merge with no conflict — the
/// replay only asks about a path it could not merge, and a clean merge here would
/// mean the two merges disagree, which is not something to guess past.
#[must_use]
pub fn propose(ancestor: &[u8], ours: &[u8], theirs: &[u8]) -> Option<Proposal> {
    let marked = diff3(ancestor, ours, theirs)?;
    resolve_marked(&marked)
}

/// The three-way text merge with every conflict kept as diff3 markers.
fn diff3(ancestor: &[u8], ours: &[u8], theirs: &[u8]) -> Option<String> {
    let mut out = Vec::new();
    let mut input = Default::default();
    let options = gix::merge::blob::builtin_driver::text::Options {
        conflict: gix::merge::blob::builtin_driver::text::Conflict::Keep {
            style: gix::merge::blob::builtin_driver::text::ConflictStyle::Diff3,
            marker_size: NonZeroU8::new(MARKER).expect("seven is not zero"),
        },
        ..Default::default()
    };
    let resolution = gix::merge::blob::builtin_driver::text(
        &mut out,
        &mut input,
        gix::merge::blob::builtin_driver::text::Labels::default(),
        ours,
        ancestor,
        theirs,
        options,
    );
    if resolution != gix::merge::blob::Resolution::Conflict {
        return None;
    }
    String::from_utf8(out).ok()
}

const MARKER: u8 = 7;

/// Replace every diff3 region of `marked` by its shape's merge.
fn resolve_marked(marked: &str) -> Option<Proposal> {
    let ours_open = "<".repeat(usize::from(MARKER));
    let base_open = "|".repeat(usize::from(MARKER));
    let divider = "=".repeat(usize::from(MARKER));
    let close = ">".repeat(usize::from(MARKER));

    let mut out = String::with_capacity(marked.len());
    let mut shapes = Vec::new();
    let mut lines = marked.split_inclusive('\n');
    while let Some(line) = lines.next() {
        if !line.starts_with(&ours_open) {
            out.push_str(line);
            continue;
        }
        let mut sides: [Vec<&str>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        let mut side = 0;
        let mut closed = false;
        for inner in lines.by_ref() {
            if inner.starts_with(&base_open) {
                side = 1;
            } else if inner.trim_end_matches(['\r', '\n']) == divider {
                side = 2;
            } else if inner.starts_with(&close) {
                closed = true;
                break;
            } else {
                sides[side].push(inner);
            }
        }
        if !closed {
            return None;
        }
        let [ours, base, theirs] = sides;
        let (merged, shape) = resolve_region(&ours, &base, &theirs)?;
        out.push_str(&merged);
        shapes.push(shape);
    }
    if shapes.is_empty() {
        return None;
    }
    shapes.sort_unstable();
    shapes.dedup();
    Some(Proposal {
        bytes: out.into_bytes(),
        shapes,
    })
}

/// The one region's merge and the shape it matched, or `None`.
///
/// Tried from narrowest to widest, so a region both a comment and a list would
/// be read as the comment it is.
///
/// THE MUTANT NEUTERS `comment_only`'s GUARD rather than appending a catch-all
/// arm here: a row is split on `|`, so a closure's `||` in the sed would make it
/// a five-field row that never runs (`mem:toolchain-and-hooks`).
//MUTANT-SUITE crates/batten/tests/it/land_propose.rs
//MUTANT undeclared-hunk-proposed|s@^    (ours.iter().all(comment) && base.iter().all(comment) && theirs.iter().all(comment))$@    (true)@|an_unshaped_region_gets_no_candidate
fn resolve_region(ours: &[&str], base: &[&str], theirs: &[&str]) -> Option<(String, Shape)> {
    comment_only(ours, base, theirs)
        .or_else(|| list_union(ours, base, theirs))
        .or_else(|| json_array_union(ours, base, theirs))
}

fn comment_only(ours: &[&str], base: &[&str], theirs: &[&str]) -> Option<(String, Shape)> {
    let comment = |line: &&str| {
        let text = line.trim();
        text.is_empty() || text.starts_with('#') || text.starts_with("//")
    };
    (ours.iter().all(comment) && base.iter().all(comment) && theirs.iter().all(comment))
        .then(|| (ours.concat(), Shape::CommentOnly))
}

/// `KEY = "a,b,c"`, one line per side, same key and same quoting on every side.
fn list_union(ours: &[&str], base: &[&str], theirs: &[&str]) -> Option<(String, Shape)> {
    let assignment = Regex::new(r#"^(\s*[A-Za-z0-9_.:-]+\s*=\s*")([^"]*)("[ \t]*\r?\n?)$"#)
        .expect("the assignment pattern compiles");
    let split = |lines: &[&str]| -> Option<(String, Vec<String>, String)> {
        let [line] = lines else { return None };
        let caps = assignment.captures(line)?;
        let items = caps[2]
            .split(',')
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect();
        Some((caps[1].to_owned(), items, caps[3].to_owned()))
    };
    let (prefix, ours_items, suffix) = split(ours)?;
    let (base_prefix, base_items, _) = split(base)?;
    let (theirs_prefix, theirs_items, _) = split(theirs)?;
    if prefix != base_prefix || prefix != theirs_prefix {
        return None;
    }
    let merged = union(&ours_items, &base_items, &theirs_items);
    Some((
        format!("{prefix}{}{suffix}", merged.join(",")),
        Shape::ListUnion,
    ))
}

/// Every line on trunk's and the branch's side a `"string",` element. The base
/// side may be empty: both sides adding at the same position is the commonest
/// allow-list race.
fn json_array_union(ours: &[&str], base: &[&str], theirs: &[&str]) -> Option<(String, Shape)> {
    let element =
        Regex::new(r#"^(\s*)"([^"\\]*)",(\r?\n?)$"#).expect("the element pattern compiles");
    let parse = |lines: &[&str]| -> Option<Vec<(String, String, String)>> {
        lines
            .iter()
            .map(|line| {
                let caps = element.captures(line)?;
                Some((caps[1].to_owned(), caps[2].to_owned(), caps[3].to_owned()))
            })
            .collect()
    };
    let ours_parsed = parse(ours)?;
    let base_parsed = parse(base)?;
    let theirs_parsed = parse(theirs)?;
    let (indent, newline) = ours_parsed
        .first()
        .or_else(|| theirs_parsed.first())
        .map(|(indent, _, newline)| (indent.clone(), newline.clone()))?;
    let values = |parsed: &[(String, String, String)]| -> Vec<String> {
        parsed.iter().map(|(_, value, _)| value.clone()).collect()
    };
    let merged = union(
        &values(&ours_parsed),
        &values(&base_parsed),
        &values(&theirs_parsed),
    );
    let text = merged
        .iter()
        .map(|value| format!("{indent}\"{value}\",{newline}"))
        .collect();
    Some((text, Shape::JsonArrayUnion))
}

/// Trunk's items in trunk's order, minus what the branch removed from the base,
/// plus what the branch added, in the branch's order.
///
/// TRUNK'S ORDER IS THE POINT: the resolution this replaces sorted a list trunk
/// never sorted, and the diff it produced was every line of the list.
fn union(ours: &[String], base: &[String], theirs: &[String]) -> Vec<String> {
    let removed_by_branch = |item: &String| base.contains(item) && !theirs.contains(item);
    let mut merged: Vec<String> = ours
        .iter()
        .filter(|item| !removed_by_branch(item))
        .cloned()
        .collect();
    for item in theirs {
        if !base.contains(item) && !merged.contains(item) {
            merged.push(item.clone());
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(proposal: &Proposal) -> &str {
        std::str::from_utf8(&proposal.bytes).expect("utf-8")
    }

    #[test]
    fn a_list_both_sides_grew_keeps_trunks_order_and_appends_the_branchs_addition() {
        let base = b"GATES = \"b,a,c\"\n";
        let ours = b"GATES = \"b,a,c,trunk\"\n";
        let theirs = b"GATES = \"b,a,branch,c\"\n";
        let proposal = propose(base, ours, theirs).expect("a list-union region");
        assert_eq!(text(&proposal), "GATES = \"b,a,c,trunk,branch\"\n");
        assert_eq!(proposal.shapes, vec![Shape::ListUnion]);
    }

    #[test]
    fn a_branch_removal_from_the_list_is_kept() {
        let base = b"GATES = \"a,old,c\"\n";
        let ours = b"GATES = \"a,old,c,trunk\"\n";
        let theirs = b"GATES = \"a,c\"\n";
        let proposal = propose(base, ours, theirs).expect("a list-union region");
        assert_eq!(text(&proposal), "GATES = \"a,c,trunk\"\n");
    }

    #[test]
    fn a_json_allow_list_both_sides_grew_is_unioned() {
        let base = b"[\n  \"a\",\n  \"z\"\n]\n";
        let ours = b"[\n  \"a\",\n  \"trunk\",\n  \"z\"\n]\n";
        let theirs = b"[\n  \"a\",\n  \"branch\",\n  \"z\"\n]\n";
        let proposal = propose(base, ours, theirs).expect("a json-array-union region");
        assert_eq!(
            text(&proposal),
            "[\n  \"a\",\n  \"trunk\",\n  \"branch\",\n  \"z\"\n]\n"
        );
        assert_eq!(proposal.shapes, vec![Shape::JsonArrayUnion]);
    }

    #[test]
    fn a_comment_both_sides_reworded_takes_trunks_text() {
        let base = b"# old\nx = 1\n";
        let ours = b"# trunk wording\nx = 1\n";
        let theirs = b"# branch wording\nx = 1\n";
        let proposal = propose(base, ours, theirs).expect("a comment-only region");
        assert_eq!(text(&proposal), "# trunk wording\nx = 1\n");
        assert_eq!(proposal.shapes, vec![Shape::CommentOnly]);
    }

    /// ALL OR NOTHING: a code change both sides made matches no shape, so the
    /// path gets no candidate at all — even though another region would.
    #[test]
    fn one_unshaped_region_withholds_the_whole_candidate() {
        let base = b"# old\nx = 1\n\n\n\ny = 1\n";
        let ours = b"# trunk\nx = 1\n\n\n\ny = 2\n";
        let theirs = b"# branch\nx = 1\n\n\n\ny = 3\n";
        assert_eq!(propose(base, ours, theirs), None);
    }

    #[test]
    fn a_clean_merge_is_not_a_proposal() {
        assert_eq!(propose(b"a\n", b"a\nb\n", b"a\n"), None);
    }
}
