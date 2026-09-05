//! CLOUD-760 §7: the first `Cost::Effect` fact, and what its first occupant owes.
//!
//! Resolving the fact SPAWNS THE ANALYSER over this crate, which takes real time
//! and must not be paid by every unit-test binary that happens to link `batten`.
//!
//! **This module is NOT its own integration binary, and said it was for its whole
//! life** (CLOUD-1439). CLOUD-1210 grouped 144 targets into 2, so these cases are
//! a module inside `it` — which is why `-E 'binary(symbols)'` matches nothing and
//! the filter is `binary(it) & test(/^symbols::/)`. Same defect class as
//! CLOUD-1417: a header asserting a shape the tree contradicts.
//!
//! What the grouping costs here, measured rather than assumed: the three
//! analyser-spawning cases share one target directory, so under parallelism one
//! runs `cargo clippy` and the other two block on cargo's lock. All three are
//! then billed the build by nextest, which is what made them read as 21.8% of the
//! suite in `bench/rust-suites/RESULTS.md`. The marginal wall is one build. Do
//! not "fix" it by serialising them or by sharing a resolution — both were
//! measured and both recover zero, because the build already overlaps the other
//! 4,532 cases.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use batten::facts::Look;
use batten::symbols;

/// The analyser the ENGINE would reach, not whichever build is first on the test
/// runner's `PATH` (CLOUD-1324). A suite resolving it differently would assert
/// this census against a tool `batten check` never runs — and measured here, the
/// two are not the same: this container carries an older build ahead of the
/// pinned one, and it refuses the crate's own `rust-version`.
fn launcher(root: &Path) -> symbols::Launcher {
    batten::rules::symbols_launcher(root)
}

/// THE ARGV A PINNED LAUNCHER PRODUCES, composed rather than assumed
/// (CLOUD-1324).
///
/// Extracted and tested directly for `rules/rust.md`'s reason: the
/// failing condition is which build of the analyser a spawn reaches, and a test
/// cannot rearrange this process's `PATH` without `unsafe`. What CAN be created
/// is the composition, and it is where the defect would live — a dropped prefix
/// makes the mediated shape byte-identical to the bare one, which is exactly the
/// bug being fixed.
#[test]
fn a_launchers_prefix_precedes_the_analysers_own_flags() {
    let bare = symbols::Launcher::new("cargo", &[]);
    assert_eq!(bare.argv(&["clippy", "--version"]), ["clippy", "--version"]);

    let prefix = ["exec", "--", "cargo"].map(str::to_owned);
    let mediated = symbols::Launcher::new("runner", &prefix);
    assert_eq!(
        mediated.argv(&["clippy", "--version"]),
        ["exec", "--", "cargo", "clippy", "--version"],
        "the runner's own arguments come first, or it is handed the analyser's"
    );
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the repository root resolves")
}

/// §7(a). THE CASE THE FACT EXISTS FOR — asserted over SETS, not counts.
///
/// CLOUD-760 specifies this discriminator as three numbers: 14 from a byte scan,
/// 11 from a syntax matcher, 9 from name resolution. **Measured on this tree the
/// numbers collide and the sets do not**, which makes a count comparison the
/// wrong assertion: the byte tier and the resolved tier both report 16 here, and
/// a test comparing totals would have passed while the tiers disagreed about
/// every interesting file.
///
/// They disagree in both directions, which is the point:
///
/// * `surface.rs` is in the BYTE set and absent from the RESOLVED one — it calls
///   `clap::Command::new` twice, and that is the whole `clap`-versus-`std`
///   collision the fact exists to separate;
/// * `exec.rs` carries more resolved usages than it has `::new` occurrences,
///   because a type is used by an import and an annotation as well as by a call,
///   and the byte tier cannot see those at all.
///
/// So the assertion is membership. A count that happens to match proves nothing;
/// a set that excludes `surface.rs` could only have come from name resolution.
#[test]
fn the_resolved_set_excludes_what_only_name_resolution_can_exclude() {
    let root = repo();
    let Look::Is(resolved) = symbols::resolve(&root, &launcher(&root)) else {
        panic!("the analyser did not resolve; this suite needs a working `cargo clippy`");
    };

    let resolved_files: std::collections::BTreeSet<&str> = resolved
        .sites
        .iter()
        .filter(|site| site.lint == "clippy::disallowed_types")
        .map(|site| site.path.as_str())
        .collect();
    let byte_files = byte_scan(&root);

    // THE DISCRIMINATING PAIR, in both directions.
    assert!(
        byte_files.contains("crates/batten/src/surface.rs"),
        "the byte tier must still name surface.rs, or this tree no longer \
         carries the `clap::Command` case and the discriminator is gone"
    );
    assert!(
        !resolved_files
            .iter()
            .any(|path| path.ends_with("surface.rs")),
        "surface.rs uses `clap::Command`, not `std::process::Command` — a fact \
         naming it has not resolved anything. resolved={resolved_files:?}"
    );

    // And the sets differ, which a coinciding total would hide.
    let byte_only: Vec<&str> = byte_files
        .iter()
        .copied()
        .filter(|path| !resolved_files.contains(path))
        .collect();
    assert!(
        !byte_only.is_empty(),
        "the two tiers must disagree somewhere, or the resolved tier is buying \
         nothing over the byte one"
    );
}

/// The byte tier, run here rather than quoted, so the comparison above is a
/// MEASUREMENT and not a remembered number.
fn byte_scan(root: &Path) -> std::collections::BTreeSet<&'static str> {
    let dir = root.join("crates").join("batten").join("src");
    let needle = ["Command", "::new"].concat();
    let mut found = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("read the source directory") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read a source file");
        if source.contains(needle.as_str()) {
            let name = path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .expect("a source file name");
            // Leaked deliberately and boundedly: the set is compared against
            // repo-relative paths and this suite runs once.
            found.insert(&*Box::leak(
                format!("crates/batten/src/{name}").into_boxed_str(),
            ));
        }
    }
    found
}

/// §7(b) and (c). Two runs over identical bytes agree, AND the provenance that
/// makes that claim meaningful is present.
///
/// The determinism half alone is not enough, which is (c)'s point: two runs of a
/// DIFFERENT analyser version would also agree with each other, and a fact that
/// did not record which version produced it could not tell the reader that the
/// meaning had moved. So the version is asserted present and non-empty rather
/// than merely assumed to exist.
#[test]
fn two_runs_agree_and_the_analyser_that_produced_them_is_named() {
    let root = repo();
    let (Look::Is(first), Look::Is(second)) = (
        symbols::resolve(&root, &launcher(&root)),
        symbols::resolve(&root, &launcher(&root)),
    ) else {
        panic!("the analyser did not resolve twice");
    };

    assert_eq!(
        first.sites, second.sites,
        "two runs over identical bytes must produce identical sites"
    );
    assert_eq!(
        first.provenance, second.provenance,
        "and identical provenance"
    );

    assert_eq!(first.provenance.tool, symbols::ANALYSER);
    assert!(
        !first.provenance.version.is_empty(),
        "a fact whose meaning depends on an unrecorded tool version is not \
         canonical — the version is part of the fact, not beside it"
    );
    assert_eq!(
        first.provenance.invocation,
        symbols::ANALYSER_FLAGS
            .iter()
            .map(|flag| (*flag).to_owned())
            .collect::<Vec<_>>(),
        "the invocation records WHICH question was asked, so a reader can tell \
         an inventory run from an enforcement one"
    );
}

/// §5. Pointer-only: a site carries a path, a line and a lint name, and nothing
/// the analyser said about the source.
#[test]
fn no_site_carries_a_byte_of_what_the_analyser_read() {
    let root = repo();
    let Look::Is(resolved) = symbols::resolve(&root, &launcher(&root)) else {
        panic!("the analyser did not resolve");
    };
    for site in &resolved.sites {
        assert!(
            !site.path.starts_with('/'),
            "a site path is repo-relative, or the fact varies by checkout \
             location: {}",
            site.path
        );
        assert!(site.line > 0, "a site line is 1-indexed");
        assert!(
            site.lint.starts_with("clippy::") || site.lint.starts_with("rustc::"),
            "a site names its lint and nothing else: {}",
            site.lint
        );
    }
}

/// §7(d). FAIL-CLOSED, carried verbatim from `secrets.rs`: **clean is never
/// inferred from a stream that failed to parse.**
///
/// Over the PARSER rather than over a real analyser, for `rules/rust.md`'s
/// reason and `secrets.rs`'s: the failing condition is a stream shape, and making
/// a real clippy emit a malformed diagnostic on demand is not something a fixture
/// can do. Extracting the decision is what makes it testable at all.
#[test]
fn an_unreadable_stream_is_could_not_look_and_never_an_empty_census() {
    let root = Path::new("/repo");

    // A clean run that genuinely found nothing: an empty site list, which is a
    // STATEMENT and not a failure.
    let Look::Is(none) = symbols::sites_in("", root) else {
        panic!("an empty stream is an answer");
    };
    assert!(none.is_empty(), "nothing emitted means nothing found");

    // Cargo's own non-JSON chatter is skipped, not refused — refusing it would
    // make the fact unresolvable for a reason unrelated to the analyser.
    let Look::Is(chatter) = symbols::sites_in("   Compiling batten v0.0.1\n", root) else {
        panic!("cargo's progress is not a diagnostic");
    };
    assert!(chatter.is_empty());

    // But a line that IS a compiler message and cannot be read as one is
    // CouldNotLook. Skipping it would undercount SILENTLY, which is the direction
    // that reports a clean tree from a stream that failed to parse.
    for malformed in [
        // a compiler-message with no `message` object at all
        r#"{"reason":"compiler-message"}"#,
        // a lint code with no spans array
        r#"{"reason":"compiler-message","message":{"code":{"code":"clippy::disallowed_types"}}}"#,
        // a primary span missing its line
        r#"{"reason":"compiler-message","message":{"code":{"code":"clippy::disallowed_types"},"spans":[{"is_primary":true,"file_name":"a.rs"}]}}"#,
    ] {
        assert!(
            matches!(symbols::sites_in(malformed, root), Look::CouldNotLook),
            "a diagnostic this build cannot read is could-not-look, never an \
             empty census: {malformed}"
        );
    }
}

/// This module's own header, and the bench record that reads it (CLOUD-1439).
///
/// **A prose claim about cost is exactly the kind that rots**, and this one did:
/// the header asserted its own integration binary for its whole life after
/// CLOUD-1210 removed it, and `RESULTS.md` priced these cases at 21.8% of the
/// suite from a summed duration under lock contention. Both were read by a later
/// author and acted on. `rules/scanning.md`'s own gate
/// (`scanner_taxonomy.rs`) is the shape borrowed here: assert the prose still
/// says the thing, so deleting or reverting the correction reddens rather than
/// going quiet.
///
/// It catches **deletion and drift in the prose** and nothing else. Whether the
/// measurement is right is not a property of the tree, and a case claiming to
/// decide that would be the model verdict non-negotiable rule 3 forbids.
/// **The region is the HEADER, not the file, and the first spelling of this case
/// proved why.** Asserted over the whole source, the deny arm failed on its own
/// needle and the allow arm passed on its own — a case that reddens because of
/// its own text and greens because of its own text decides nothing about the
/// prose it names. So the header is cut out first, and the needles are split the
/// way `byte_scan` above already splits `Command::new`.
fn module_header() -> String {
    include_str!("symbols.rs")
        .lines()
        .take_while(|line| line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_header_does_not_reclaim_a_binary_the_grouping_removed() {
    let header = module_header();
    assert!(
        !header.is_empty(),
        "the header region resolved empty, so both arms below would pass over \
         nothing — the same silent-empty answer this suite exists to refuse"
    );

    // The retired claim, in the spelling it actually had.
    let retired = ["Its own integration", " binary"].concat();
    assert!(
        !header.contains(retired.as_str()),
        "the header claims a target CLOUD-1210 removed; these cases are a module \
         inside `it`"
    );

    // And the replacement has to name the filter that DOES select them, or the
    // next reader re-derives the same wrong `-E 'binary(symbols)'`.
    let filter = ["binary(it) & ", "test(/^symbols::/)"].concat();
    assert!(
        header.contains(filter.as_str()),
        "the header must name the filter that selects this module, since the \
         obvious one matches nothing"
    );
}

/// The bench record's correction, asserted from the suite it is about.
#[test]
fn the_bench_record_prices_the_analyser_group_as_one_build() {
    let record = include_str!("../../../../bench/rust-suites/RESULTS.md");

    assert!(
        record.contains("sum of per-case durations"),
        "RESULTS.md must still distinguish a summed duration from a cost, or its \
         module table reads as a cost table again"
    );
    assert!(
        record.contains("21.8%") && record.contains("artifact"),
        "the 21.8% must stay named as an artifact beside the figure itself — a \
         correction elsewhere in the file is one a reader of the table misses"
    );
}

/// §5 again, at the parse boundary: an absolute path from the analyser is made
/// repo-relative, or the fact would vary by checkout location and §6
/// byte-stability could not hold.
#[test]
fn an_analyser_path_is_made_relative_to_the_repository() {
    let stream = r#"{"reason":"compiler-message","message":{"code":{"code":"clippy::disallowed_types"},"spans":[{"is_primary":true,"file_name":"/repo/crates/batten/src/exec.rs","line_start":12}]}}"#;
    let Look::Is(sites) = symbols::sites_in(stream, Path::new("/repo")) else {
        panic!("the stream parses");
    };
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].path, "crates/batten/src/exec.rs");
    assert_eq!(sites[0].line, 12);
}
