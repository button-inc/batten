//! The Rust tier is cargo-mutants' alone (CLOUD-2253), refused at BUILD time.
//!
//! Two things kept coming back into Rust after each removal: hand-written
//! mutation markers (868 rows and 518 markers that no runner ever read, in line
//! comments, in `/* */` blocks, beside the code they named), and a hand-rolled
//! harness that built its own cargo-mutants argv. A test can be filtered out and
//! clippy cannot read a comment, so `build.rs` includes this file and refuses to
//! build a crate carrying either: no `check`, `clippy`, test or lap runs on it.
//!
//! The library compiles the same file, so its cases below judge the one
//! predicate `build.rs` applies.

/// The argument that makes a cargo invocation cargo-mutants'. Built in exactly
/// one place, `mutate::cargo_mutants_argv`, which both the listing and the run
/// of cargo-mutants itself take their argv from.
pub(crate) const CARGO_MUTANTS_ARGV: &str = "String::from(\"mutants\")";

/// The one source allowed to carry [`CARGO_MUTANTS_ARGV`], relative to the crate.
pub(crate) const CARGO_MUTANTS_SITE: &str = "src/mutate.rs";

/// The 1-indexed lines of `text` that carry a hand-written mutation marker: a
/// `//MUTANT…` line anywhere, or a `#MUTANT…` or `MUTANT…` line inside a `/* */`
/// block, the two shapes rows were carried in. A `#MUTANT` row in a string
/// literal is another language's fixture text and is not one.
#[must_use]
pub(crate) fn marker_lines(text: &str) -> Vec<usize> {
    let mut in_block = false;
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        match trimmed {
            "/*" => in_block = true,
            "*/" => in_block = false,
            _ if trimmed.starts_with("//MUTANT")
                || (in_block
                    && (trimmed.starts_with("#MUTANT") || trimmed.starts_with("MUTANT"))) =>
            {
                found.push(index + 1);
            }
            _ => {}
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE ANTI-VACUITY HALF: every marker shape is found at any indent, and
    /// another language's row in a string literal is not. Fails by: a shape
    /// dropped, which is how 518 markers outlived the first ban.
    #[test]
    fn every_marker_shape_is_found_at_any_indent() {
        let source = [
            "//MUTANT-SUITE tests/a.rs",
            "//MUTANT top|s/a/b/|case",
            "fn f() {",
            "    //MUTANT nested|s/a/b/|case",
            "    let fixture = \"",
            "    #MUTANT rego|s/a/b/|case",
            "\";",
            "}",
            "/*",
            "#MUTANT-SUITE tests/a.rs",
            "MUTANT bare|s/a/b/|case",
            "*/",
            "",
        ]
        .join("\n");
        assert_eq!(marker_lines(&source), [1, 2, 4, 10, 11]);
    }

    /// Fails by: the named site gone or renamed, so the build's one-site rule
    /// would refuse the crate's own runner, or the argv spelled there some other
    /// way, so the rule counts nothing and passes a second harness.
    #[test]
    fn the_one_site_builds_the_argv_once() {
        let site = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(CARGO_MUTANTS_SITE);
        // `std`, not `crate::fsio`: `build.rs` includes this file as its own
        // module, so it reaches nothing in the crate (CLOUD-2692).
        let text = std::fs::read_to_string(&site).unwrap_or_default();
        assert_eq!(
            text.matches(CARGO_MUTANTS_ARGV).count(),
            1,
            "{}",
            site.display()
        );
    }

    /// Fails by: an ordinary comment or block read as a marker.
    #[test]
    fn ordinary_comments_carry_no_marker() {
        let source = "// a note about MUTANT handling\n/*\nprose\n*/\nfn f() {}\n";
        assert!(marker_lines(source).is_empty());
    }
}
