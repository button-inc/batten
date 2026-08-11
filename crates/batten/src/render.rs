//! Human-facing renderings of the command surface (CLOUD-69).
//!
//! House-style §11 says completions, man pages, and markdown are *derivations*
//! of the one spec, "so the shipped binary and the generated docs can never
//! drift." [`crate::spec`] emits the machine reading of that surface and
//! `clap_complete` emits the shell reading; this module emits the two human
//! readings. All four walk the same [`crate::surface::SURFACE`]-built
//! [`clap::Command`] tree, so none of them can describe a verb the binary does
//! not have.
//!
//! **Both renderers return a `String` and write nothing.** That is what keeps
//! `generate` an [`Effect::Read`](crate::effect::Effect::Read) verb (§5,
//! CLOUD-244): the redirect that refreshes a committed artifact belongs to the
//! caller (`mise run man`), never to the binary. A renderer that took a path
//! would make `read` a promise about behaviour instead of a structural fact.
//!
//! Output is byte-stable (§6). The markdown walks [`crate::spec::CommandSpec`],
//! whose flags and subcommands are already sorted for exactly this reason, and
//! neither renderer stamps a date — `clap_mangen`'s `.TH` date field is left
//! unset rather than defaulted to today, which would make every regeneration a
//! diff and the drift gate unable to hold.

use std::fmt::Write as _;

use anyhow::{Result, anyhow};
use clap::Command;

use crate::spec::CommandSpec;

/// The roff man page for one command, selected by its root-relative path.
///
/// `path` is the same key the spec and the §5 effect table use — `config show`,
/// never `batten config show` — and `None` (or the empty string) selects the
/// root page. The rendered `.TH` title is the conventional hyphen-joined form,
/// so `config show` becomes `batten-config-show(1)` and `man
/// batten-config-show` resolves once the page is installed.
///
/// # Errors
///
/// Returns an error if `path` names no command in the tree, and if the roff
/// itself is not valid UTF-8 — neither is reachable for a declared surface, but
/// a path arrives from the command line and so is caller-supplied.
pub fn man(root: &Command, path: Option<&str>) -> Result<String> {
    let path = path.unwrap_or_default().trim();
    let node = find(root, path)?;

    // A subcommand's own name is its leaf (`show`), so an unqualified page would
    // be `show(1)` and collide with every other tool's. Three fields carry the
    // qualified form, because `clap_mangen` reads a different one for each and
    // leaving any unset publishes the leaf: `display_name` titles the page and
    // heads its NAME section, `bin_name` is what SYNOPSIS spells, and `source`
    // (set on the builder below) is the `.TH` attribution.
    let title = page_name(root.get_name(), path);
    // The version lives on the root only, so a subcommand page would otherwise
    // carry no footer. Read from the same `CARGO_PKG_VERSION` the root sets
    // rather than from `root.get_version()`, whose borrow is not `'static` and
    // so cannot reach clap's builder — one constant, still one source.
    let page = node
        .clone()
        .display_name(title.clone())
        .bin_name(qualified(root.get_name(), path))
        .version(env!("CARGO_PKG_VERSION"));

    let mut buffer: Vec<u8> = Vec::new();
    // `date` is left at its empty default rather than stamped with today:
    // a dated page would differ on every regeneration, which no byte-for-byte
    // drift gate can hold (§6).
    clap_mangen::Man::new(page)
        .source(format!("{} {}", root.get_name(), env!("CARGO_PKG_VERSION")))
        .render(&mut buffer)?;
    String::from_utf8(buffer).map_err(|_| anyhow!("clap_mangen emitted invalid UTF-8"))
}

/// The conventional page name for a root-relative path: `config show` under
/// `batten` becomes `batten-config-show`.
///
/// Public because the caller that *writes* the pages needs the same spelling —
/// `mise run man` derives its filenames from the emitted spec, and a second
/// place that joined the path with hyphens would be a second authority for the
/// artifact's name.
#[must_use]
pub fn page_name(program: &str, path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        return program.to_owned();
    }
    format!("{program}-{}", path.replace(' ', "-"))
}

/// The invocation a reader types: `batten config show`.
///
/// Distinct from [`page_name`] in one character, and deliberately a separate
/// function: the hyphenated form is a *filename*, the spaced form is a
/// *command line*, and a man page that spelled its SYNOPSIS with hyphens would
/// document an invocation that does not parse.
fn qualified(program: &str, path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        return program.to_owned();
    }
    format!("{program} {path}")
}

/// Resolve a root-relative path to its node in the tree.
fn find<'a>(root: &'a Command, path: &str) -> Result<&'a Command> {
    let mut node = root;
    if path.is_empty() {
        return Ok(node);
    }
    for segment in path.split_whitespace() {
        node = node
            .get_subcommands()
            .find(|sub| sub.get_name() == segment)
            .ok_or_else(|| anyhow!("no such command: {path}"))?;
    }
    Ok(node)
}

/// The whole surface as one markdown document — the CLI reference (CLOUD-171).
///
/// Rendered from [`CommandSpec`] rather than from the `clap` tree directly, and
/// rather than through a third-party markdown crate, for one reason: the spec
/// carries the §5 `effect` column, which is the fact an agent reading this
/// reference most needs and which nothing outside this repository knows about.
/// Reusing the spec also means the coverage gate ("every flag in the spec
/// appears in the reference and vice versa") holds by construction rather than
/// by review.
#[must_use]
pub fn markdown(spec: &CommandSpec) -> String {
    let mut out = String::new();
    // `writeln!` into a String is infallible; the results are discarded rather
    // than unwrapped because the workspace lints forbid `unwrap`/`expect` on
    // reachable paths and there is no error to propagate.
    let _ = writeln!(out, "# {}", spec.path);
    if let Some(about) = &spec.about {
        let _ = writeln!(out, "\n{about}");
    }
    let _ = writeln!(
        out,
        "\nDerived from the command surface by `batten generate markdown`. \
         Do not edit: the surface is the source of truth."
    );
    section(&mut out, spec, spec.path.as_str());
    out
}

/// Render one node and then its subcommands, depth-first in the spec's own
/// (sorted) order.
fn section(out: &mut String, node: &CommandSpec, program: &str) {
    // The root is rendered by `markdown` itself as the document title; only its
    // global flags belong under a heading of their own, so that a reader can
    // tell a global from a verb's own flag.
    if node.path == program {
        if !node.flags.is_empty() {
            let _ = writeln!(out, "\n## Global flags\n");
            flag_table(out, node);
        }
    } else {
        let _ = writeln!(out, "\n## `{program} {}`\n", node.path);
        if let Some(about) = &node.about {
            let _ = writeln!(out, "{about}\n");
        }
        let _ = writeln!(out, "Effect: `{}`\n", node.effect.as_str());
        if node.flags.is_empty() {
            let _ = writeln!(out, "No arguments of its own.");
        } else {
            flag_table(out, node);
        }
    }
    for sub in &node.subcommands {
        section(out, sub, program);
    }
}

/// One node's arguments as a table, in the spec's already-sorted order.
fn flag_table(out: &mut String, node: &CommandSpec) {
    let _ = writeln!(out, "| Name | Long | Short | Takes a value | Description |");
    let _ = writeln!(out, "| ---- | ---- | ----- | ------------- | ----------- |");
    for flag in &node.flags {
        let long = flag
            .long
            .as_ref()
            .map_or_else(|| "—".to_owned(), |long| format!("`--{long}`"));
        let short = flag
            .short
            .map_or_else(|| "—".to_owned(), |short| format!("`-{short}`"));
        let takes = if flag.takes_value { "yes" } else { "no" };
        // A help string is prose an author wrote; a `|` in it would split the
        // row. Escaped rather than stripped, so the reference says what the
        // `--help` output says.
        let help = flag
            .help
            .as_ref()
            .map_or_else(String::new, |help| help.replace('|', "\\|"));
        let _ = writeln!(
            out,
            "| `{}` | {long} | {short} | {takes} | {help} |",
            flag.name
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::spec;
    use crate::surface::{self, SURFACE};

    #[test]
    fn every_declared_path_renders_a_non_empty_page() {
        // The §7 smoke clause, over the whole surface rather than a sample: a
        // row that renders nothing is a page shipped empty, and the drift gate
        // would happily hold two empty files equal.
        let root = surface::command();
        for decl in SURFACE {
            let page = man(&root, Some(decl.path)).expect("a declared path renders");
            assert!(!page.trim().is_empty(), "{} rendered an empty page", decl.path);
        }
    }

    #[test]
    fn the_root_page_is_reachable_by_both_spellings() {
        let root = surface::command();
        assert_eq!(man(&root, None).unwrap(), man(&root, Some("")).unwrap());
    }

    #[test]
    fn an_undeclared_path_is_an_error_not_an_empty_page() {
        let root = surface::command();
        assert!(man(&root, Some("no-such-verb")).is_err());
    }

    #[test]
    fn a_page_name_is_the_hyphen_joined_path() {
        assert_eq!(page_name("batten", ""), "batten");
        assert_eq!(page_name("batten", "check"), "batten-check");
        assert_eq!(page_name("batten", "config show"), "batten-config-show");
    }

    #[test]
    fn both_renderings_are_byte_stable() {
        // §6, and the precondition for the drift gate: the same surface must
        // render identical bytes, or every regeneration would report drift.
        let root = surface::command();
        assert_eq!(man(&root, Some("check")).unwrap(), man(&root, Some("check")).unwrap());
        let described = spec::describe(&surface::command());
        assert_eq!(markdown(&described), markdown(&described));
    }

    #[test]
    fn the_markdown_names_every_command_and_every_flag() {
        // The coverage property CLOUD-171's gate asserts from outside, held
        // here from inside: a renderer that silently skipped a node would pass
        // a non-emptiness check and fail this one.
        let described = spec::describe(&surface::command());
        let rendered = markdown(&described);
        for decl in SURFACE {
            if decl.path.is_empty() {
                continue;
            }
            assert!(
                rendered.contains(&format!("`batten {}`", decl.path)),
                "{} is missing from the reference",
                decl.path
            );
            for flag in decl.flags {
                assert!(
                    rendered.contains(&format!("`{}`", flag.id)),
                    "{}'s {} flag is missing from the reference",
                    decl.path,
                    flag.id
                );
            }
        }
    }
}
