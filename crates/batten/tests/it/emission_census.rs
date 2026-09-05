//! The data channel has one emission path, and nothing bypasses it (CLOUD-371).
//!
//! `output.rs` funnelled *stderr* through `message`/`error`/`verdict` from the
//! start; stdout had no funnel at all. The crate spells a renderer three ways —
//! `line`, `line_text`, `summary` — and `lib.rs` wrote whichever one a type
//! happened to name straight to `out`, so nothing made a type reaching the data
//! channel declare that it does. `rules::Finding`, the most-emitted type in the
//! engine, had no renderer whatsoever and was composed by an inline `match` on
//! `Option<usize>` at two separate call sites. `output::Line` plus
//! `output::line`/`output::lines` is the funnel; this file keeps it one.
//!
//! ## What the compiler decides, and what it cannot
//!
//! The row asked for a census "checked by construction rather than by
//! inspection", and half of that is genuinely the compiler's: `output::line` and
//! `output::lines` accept `&dyn Line` and `T: Line`, so a type routed through the
//! funnel without an impl **fails to build**. That half needs no test and gets
//! none — asserting it would be asserting that Rust type-checks.
//!
//! **The other half is not a compile error and this file exists because of it.**
//! A thirty-first `writeln!(out, "{}", thing.renderer())?` compiles perfectly
//! well; it simply does not go through the funnel. The row's §2 says such a site
//! "fails to build instead of being found by grep", and that is the one claim in
//! it a type system cannot make good on — no signature can forbid a macro from
//! writing to a `&mut dyn Write` that is right there in scope. So this is a
//! source scan, and saying so is the point: `.claude/rules/policy-modules.md`
//! records that a paragraph disclaiming the ambitious guarantee while quietly
//! failing to hold the modest one is the shape to avoid. The modest one is held
//! here.
//!
//! ## What it does not decide
//!
//! **Content**, which is `pointer_only.rs`'s at the process boundary, for the
//! reason that file states: no trait can stop a `String` carrying a payload. This
//! owns the pointer *shape* and the census of what emits; that owns the bytes.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use common::at_root;

/// The renderer spellings that reached `out` before the funnel existed.
///
/// Three names for one contract is what made "which types render on the data
/// channel" a question answerable only by grepping method names and hoping a
/// fourth was not invented. They still exist as inherent methods — `Line` impls
/// forward to them rather than restating them — so what is refused is *writing
/// one straight to `out`*, never the method.
const RENDERERS: &[&str] = &["line", "line_text", "summary"];

/// The lines of `lib.rs` that write a renderer's output to the data channel
/// without going through the funnel.
///
/// Deliberately narrow: it matches the exact shape the funnel replaced —
/// `writeln!(out, "{}", <expr>.<renderer>())`. A broader scan over every
/// `writeln!(out` would condemn the many sites that legitimately compose a line
/// from several sources, which is not what this row unified.
fn bypasses(source: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let text = line.trim();
        if !text.starts_with("writeln!(out, \"{}\", ") {
            continue;
        }
        if RENDERERS
            .iter()
            .any(|renderer| text.contains(&format!(".{renderer}())")))
        {
            found.push((index + 1, text.to_owned()));
        }
    }
    found
}

/// The inline `rules::Finding` renderings the funnel replaced.
///
/// Its own shape rather than `bypasses`', because this one never went through a
/// renderer at all: it was a `match` on `Option<usize>` composing the pointer at
/// the call site, in two verbs, which is the asymmetry that proved the funnel was
/// missing. `Finding` has a renderer now, so a site reaching for the fields again
/// is re-opening exactly that.
fn inline_finding_renderings(source: &str) -> Vec<(usize, String)> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("writeln!(out,") && line.contains("finding.rule"))
        .map(|(index, line)| (index + 1, line.trim().to_owned()))
        .collect()
}

fn lib_source() -> String {
    fs::read_to_string(at_root("crates/batten/src/lib.rs")).expect("read lib.rs")
}

#[test]
fn no_renderer_reaches_the_data_channel_outside_the_funnel() {
    let source = lib_source();
    // The corpus is not empty — a scan over a file that failed to load reports
    // clean and is indistinguishable from a tree with nothing to find, which is
    // the could-not-look-as-clean failure this repository keeps re-meeting.
    assert!(
        source.len() > 100_000,
        "lib.rs read back as {} bytes, too small to be the file this scans",
        source.len()
    );
    let found = bypasses(&source);
    assert!(
        found.is_empty(),
        "these sites write a renderer straight to the data channel instead of \
         through `output::line`/`output::lines` (CLOUD-371):\n{}",
        found
            .iter()
            .map(|(line, text)| format!("  lib.rs:{line}  {text}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn finding_renders_through_its_own_renderer() {
    let source = lib_source();
    let found = inline_finding_renderings(&source);
    assert!(
        found.is_empty(),
        "`rules::Finding` has a renderer now; these sites compose its pointer \
         inline instead, which is the asymmetry CLOUD-371 closed:\n{}",
        found
            .iter()
            .map(|(line, text)| format!("  lib.rs:{line}  {text}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn the_scan_discriminates() {
    // CLOUD-418: a gate that cannot fail is not a gate. Both scans are shown
    // able to fail here rather than by trusting that they would — the same
    // reason `primitives.rs` extracts a decision and tests it directly instead
    // of asserting a conclusion over a precondition nothing created.
    //
    // These are the exact strings that stood in `lib.rs` before this row, so the
    // fixtures are the defect rather than an imitation of it.
    let renderer_bypass = "        writeln!(out, \"{}\", outcome.line())?;";
    assert_eq!(
        bypasses(renderer_bypass).len(),
        1,
        "the renderer scan did not catch the shape it exists to catch"
    );
    let inline_finding = "                Some(line) => writeln!(out, \"{}:{} {}\", finding.path, line, \
         finding.rule)?,";
    assert_eq!(
        inline_finding_renderings(inline_finding).len(),
        1,
        "the finding scan did not catch the shape it exists to catch"
    );

    // And that neither fires on the funnel itself, or the gate would forbid the
    // very call it exists to require.
    assert!(bypasses("        output::lines(out, &outcomes)?;").is_empty());
    assert!(inline_finding_renderings("        output::lines(out, &findings)?;").is_empty());

    // Nor on a `message` to stderr, which is a different channel and keeps its
    // renderer call by design (`lib.rs`'s `suppressed.line_text()` sites).
    assert!(
        bypasses("            output::message(mode, Verbosity::Normal, err, &s.line_text())?;")
            .is_empty()
    );
}
