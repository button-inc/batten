//! The `[[register]]` table: a declared key set a `reference` rule resolves
//! cited tokens against (CLOUD-2005).
//!
//! # Why the set is DECLARED rather than written in a module
//!
//! *Every cited token resolves to a key of a declared set* is one predicate, and
//! a consumer was hand-writing it in five places — the GFM cell grammar in RE2,
//! a second copy in a script, a test keeping the two agreeing, and a join that
//! re-scanned every register row per row. Measured on the consumer that filed
//! it: 94.6 s for one policy row whose twelve register ids were that join. The
//! grammar and the join belong to the engine; the vocabulary (which files, which
//! column, which frontmatter node) is the consumer's, so it lives in
//! `batten.toml` exactly as `[[pattern]]` and `[[traversal]]` rows do
//! (non-negotiable rule 1).
//!
//! # Layering
//!
//! Pure. This module opens no files: the caller acquires each declared path once
//! and hands over its lines or its parsed frontmatter, so the register cannot
//! become a second acquirer — [`crate::graph`]'s posture, one surface over.
//!
//! # Could-not-look is not an empty set
//!
//! A declared path matching nothing, or a document that will not parse, makes
//! the WHOLE register [`Built::CouldNotLook`]. A reference rule reading an empty
//! set would refuse every citation in the tree for a reason that is about the
//! config, and one reading it as "nothing to check" would pass a tree it never
//! looked at — CLOUD-1793's class, from both sides.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::facts::Node;

/// Where a register's keys come from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Source {
    /// GFM table rows: the key is one column of every data row.
    Table {
        /// The 1-based column holding the key.
        key: usize,
        /// How many cells every data row carries. DECLARED, never read from the
        /// header: a header is content, and a register whose width is whatever
        /// its first line says cannot refuse its first line.
        width: usize,
        /// Only rows whose key cell starts with this prefix are rows of the
        /// register. A file mixing a register table with prose tables declares
        /// it; absent, every data row of every table in the file counts.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        row_prefix: Option<String>,
        /// A `[[pattern]]` id every key must match in full.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_pattern: Option<String>,
        /// Whether a key may appear on two rows, across every declared path.
        #[serde(default)]
        unique: bool,
    },
    /// Documents whose frontmatter `key_node` names the key (a scalar or a list).
    Documents {
        /// The dotted node holding the key.
        key_node: String,
        /// A document carrying one of these values at the named node is not a
        /// witness — it contributes no key.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        refused_values: BTreeMap<String, Vec<String>>,
    },
    /// Tracked paths: the key is a `[[pattern]]`'s one capture group over the path.
    Tree {
        /// The `[[pattern]]` id; it must carry exactly one capture group.
        pattern: String,
    },
}

/// One declared key set, keyed by an id a `reference` rule names.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclaredRegister {
    /// The name a `reference` rule resolves against.
    pub id: String,
    /// Globs over tracked paths, unioned.
    pub paths: Vec<String>,
    /// Where the keys come from.
    #[serde(flatten)]
    pub source: Source,
}

/// Where a key was witnessed: a path and, for a table row, its line.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Witness {
    /// The tracked path.
    pub path: String,
    /// The 1-based line, where the witness is a row.
    pub line: Option<usize>,
}

/// A defect in the register itself, found while building it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Defect {
    /// A key on a second row of a `unique` register.
    Duplicated(Witness),
    /// A data row whose cell count is not the declared width.
    Width(Witness),
    /// A key cell that does not match `key_pattern`.
    Malformed(Witness),
}

/// A register, built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Built {
    /// Every key and where it was seen, plus any defect in the register itself.
    Keys {
        /// Key to its witnesses, in path-then-line order.
        keys: BTreeMap<String, Vec<Witness>>,
        /// Defects found while building.
        defects: Vec<Defect>,
    },
    /// A declared path matched nothing, or a witness could not be read.
    CouldNotLook {
        /// The path that could not be read, or the glob that matched nothing.
        at: String,
    },
}

impl Built {
    /// Whether `key` is in the set. `None` is could-not-look.
    #[must_use]
    pub fn contains(&self, key: &str) -> Option<bool> {
        match self {
            Built::Keys { keys, .. } => Some(keys.contains_key(key)),
            Built::CouldNotLook { .. } => None,
        }
    }

    /// The witnesses of `key` — empty where absent or could-not-look.
    #[must_use]
    pub fn witnesses(&self, key: &str) -> &[Witness] {
        match self {
            Built::Keys { keys, .. } => keys.get(key).map_or(&[], Vec::as_slice),
            Built::CouldNotLook { .. } => &[],
        }
    }
}

/// The cells of one GFM table row, or `None` where the line is not a data row.
///
/// THE ONE ROW GRAMMAR. A cell runs to the next UNESCAPED `|`; `\|` stays in its
/// cell and is unescaped to `|`. Splitting on every `|` was the consumer's bug:
/// a name containing `\|` shifted every later column, and "the row stopped being
/// SEEN rather than starting to fail". Header and separator rows are not data:
/// the separator is recognised by shape, and the header is the row immediately
/// above it.
#[must_use]
pub fn cells(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    let body = trimmed.strip_prefix('|')?;
    let mut out = Vec::new();
    let mut cell = String::new();
    let mut chars = body.chars().peekable();
    let mut closed = false;
    while let Some(ch) = chars.next() {
        match ch {
            '\\' if chars.peek() == Some(&'|') => {
                cell.push('|');
                chars.next();
            }
            '|' => {
                out.push(cell.trim().to_owned());
                cell.clear();
                closed = chars.peek().is_none();
            }
            other => {
                cell.push(other);
                closed = false;
            }
        }
    }
    // A row without a trailing pipe still ends its last cell at end of line.
    if !closed && !cell.trim().is_empty() {
        out.push(cell.trim().to_owned());
    }
    Some(out)
}

/// Whether `cells` is a GFM separator row (`---`, `:--`, `--:`, `:-:`).
fn is_separator(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells.iter().all(|cell| {
            let inner = cell.trim_start_matches(':').trim_end_matches(':');
            !inner.is_empty() && inner.chars().all(|ch| ch == '-')
        })
}

/// Every data row of every table in `lines`, as `(1-based line, cells)`.
///
/// A line is a header when the next line is a separator; the separator itself is
/// skipped. Everything else that starts with `|` is a data row.
#[must_use]
pub fn data_rows(lines: &[String]) -> Vec<(usize, Vec<String>)> {
    let parsed: Vec<Option<Vec<String>>> = lines.iter().map(|line| cells(line)).collect();
    let mut rows = Vec::new();
    for (index, row) in parsed.iter().enumerate() {
        let Some(row) = row else { continue };
        if is_separator(row) {
            continue;
        }
        let next_is_separator = parsed
            .get(index + 1)
            .and_then(Option::as_ref)
            .is_some_and(|next| is_separator(next));
        if next_is_separator {
            continue;
        }
        rows.push((index + 1, row.clone()));
    }
    rows
}

/// One acquired witness file, handed in by the caller.
#[derive(Debug)]
pub enum Input<'a> {
    /// A file's lines, for a table register.
    Lines {
        /// The tracked path.
        path: &'a str,
        /// Its lines, endings removed.
        lines: &'a [String],
    },
    /// A document's frontmatter, for a document register.
    Document {
        /// The tracked path.
        path: &'a str,
        /// The parsed frontmatter, or `None` where it could not be parsed.
        node: Option<&'a Node>,
    },
    /// A tracked path, for a tree register.
    Path(&'a str),
}

/// Build `register` from its acquired inputs.
///
/// `key_pattern` is the compiled `[[pattern]]` the row names (table) or its
/// capture pattern (tree); the caller resolves the id so this stays pure.
/// `inputs` empty is could-not-look (`at` is the first declared glob).
#[must_use]
pub fn build(
    register: &DeclaredRegister,
    key_pattern: Option<&regex::Regex>,
    inputs: &[Input<'_>],
) -> Built {
    if inputs.is_empty() {
        return Built::CouldNotLook {
            at: register.paths.first().cloned().unwrap_or_default(),
        };
    }
    let mut keys: BTreeMap<String, Vec<Witness>> = BTreeMap::new();
    let mut defects = Vec::new();
    for input in inputs {
        match (input, &register.source) {
            (
                Input::Lines { path, lines },
                Source::Table {
                    key,
                    width,
                    row_prefix,
                    unique,
                    ..
                },
            ) => {
                for (line, row) in data_rows(lines) {
                    let Some(cell) = row.get(key.saturating_sub(1)) else {
                        continue;
                    };
                    if row_prefix.as_deref().is_some_and(|prefix| !cell.starts_with(prefix)) {
                        continue;
                    }
                    let witness = Witness {
                        path: (*path).to_owned(),
                        line: Some(line),
                    };
                    if row.len() != *width {
                        defects.push(Defect::Width(witness.clone()));
                    }
                    if key_pattern.is_some_and(|re| !full_match(re, cell)) {
                        defects.push(Defect::Malformed(witness.clone()));
                    }
                    let seen = keys.entry(cell.clone()).or_default();
                    if *unique && !seen.is_empty() {
                        defects.push(Defect::Duplicated(witness.clone()));
                    }
                    seen.push(witness);
                }
            }
            (
                Input::Document { path, node },
                Source::Documents {
                    key_node,
                    refused_values,
                },
            ) => {
                let Some(node) = node else {
                    return Built::CouldNotLook {
                        at: (*path).to_owned(),
                    };
                };
                if refused(node, refused_values) {
                    continue;
                }
                for value in scalars(node, key_node) {
                    keys.entry(value).or_default().push(Witness {
                        path: (*path).to_owned(),
                        line: None,
                    });
                }
            }
            (Input::Path(path), Source::Tree { .. }) => {
                if let Some(captured) = key_pattern
                    .and_then(|re| re.captures(path))
                    .and_then(|caps| caps.get(1))
                {
                    keys.entry(captured.as_str().to_owned())
                        .or_default()
                        .push(Witness {
                            path: (*path).to_owned(),
                            line: None,
                        });
                }
            }
            // A mismatched input is the caller's bug, not the tree's; it
            // contributes nothing rather than inventing a key.
            _ => {}
        }
    }
    for witnesses in keys.values_mut() {
        witnesses.sort();
    }
    defects.sort();
    Built::Keys { keys, defects }
}

/// Whether `re` matches the whole of `text`.
fn full_match(re: &regex::Regex, text: &str) -> bool {
    re.find(text)
        .is_some_and(|found| found.start() == 0 && found.end() == text.len())
}

/// Whether `node` carries a refused value at any declared node.
fn refused(node: &Node, refused_values: &BTreeMap<String, Vec<String>>) -> bool {
    refused_values.iter().any(|(path, values)| {
        scalars(node, path)
            .iter()
            .any(|value| values.iter().any(|refused| refused == value))
    })
}

/// The scalar values at a dotted node: one for a scalar, each item for a list.
///
/// POLYMORPHIC ON PURPOSE: a field written as a string in one document and a
/// list in the next is the same field, measured 45/15 in the consumer that
/// filed CLOUD-1868. A `name[].sub` segment reads `sub` from each list item.
#[must_use]
pub fn scalars(node: &Node, path: &str) -> Vec<String> {
    let (head, tail) = match path.split_once("[].") {
        Some((head, tail)) => (head, Some(tail)),
        None => (path, None),
    };
    let crate::facts::Look::Is(at) = node.at(head) else {
        return Vec::new();
    };
    match (at, tail) {
        (Node::List(items), Some(tail)) => items
            .iter()
            .flat_map(|item| scalars(item, tail))
            .collect(),
        (Node::List(items), None) => items.iter().filter_map(Node::scalar).collect(),
        (other, None) => other.scalar().into_iter().collect(),
        (_, Some(_)) => Vec::new(),
    }
}

/// Refuse a malformed table at load (house style §8).
///
/// # Errors
///
/// A [`UsageError`] for a blank or repeated id, no `paths`, a zero `key` or
/// `width`, a `key` past `width`, or a blank `key_node`.
pub fn validate(registers: &[DeclaredRegister]) -> anyhow::Result<()> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for row in registers {
        if row.id.trim().is_empty() {
            return Err(UsageError::raise(String::from(
                "register: `id` cannot be blank — it is the name a reference rule \
                 resolves against, and an empty one names nothing",
            )));
        }
        if !seen.insert(row.id.as_str()) {
            return Err(UsageError::raise(format!(
                "register `{}` is declared twice; a reference cannot resolve \
                 against two sets under one name",
                row.id
            )));
        }
        if row.paths.is_empty() || row.paths.iter().any(|glob| glob.trim().is_empty()) {
            return Err(UsageError::raise(format!(
                "register `{}`: `paths` must name at least one non-blank glob",
                row.id
            )));
        }
        match &row.source {
            Source::Table { key, width, .. } => {
                if *key == 0 || *width == 0 || key > width {
                    return Err(UsageError::raise(format!(
                        "register `{}`: `key` and `width` are 1-based and `key` \
                         must be a column within `width`",
                        row.id
                    )));
                }
            }
            Source::Documents { key_node, .. } => {
                if key_node.trim().is_empty() {
                    return Err(UsageError::raise(format!(
                        "register `{}`: `key_node` cannot be blank",
                        row.id
                    )));
                }
            }
            Source::Tree { pattern } => {
                if pattern.trim().is_empty() {
                    return Err(UsageError::raise(format!(
                        "register `{}`: `pattern` cannot be blank",
                        row.id
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(ToOwned::to_owned).collect()
    }

    fn table(width: usize, unique: bool) -> DeclaredRegister {
        DeclaredRegister {
            id: String::from("caps"),
            paths: vec![String::from("a.md"), String::from("b.md")],
            source: Source::Table {
                key: 1,
                width,
                row_prefix: None,
                key_pattern: None,
                unique,
            },
        }
    }

    #[test]
    fn an_escaped_pipe_stays_in_its_cell() {
        assert_eq!(
            cells(r"| a\|b | c |"),
            Some(vec![String::from("a|b"), String::from("c")])
        );
    }

    #[test]
    fn an_unescaped_pipe_widens_the_row() {
        assert_eq!(cells("| a|b | c |").map(|row| row.len()), Some(3));
    }

    #[test]
    fn header_and_separator_are_not_data() {
        let rows = data_rows(&lines("| id | x |\n| --- | :-: |\n| k1 | 1 |"));
        assert_eq!(rows, vec![(3, vec![String::from("k1"), String::from("1")])]);
    }

    #[test]
    fn a_wide_row_is_a_width_defect_and_the_escaped_one_is_quiet() {
        let reg = table(2, false);
        let text = lines("| k | v |\n| - | - |\n| a|b | 1 |\n| a\\|b | 1 |");
        let Built::Keys { defects, keys } =
            build(&reg, None, &[Input::Lines { path: "a.md", lines: &text }])
        else {
            panic!("built");
        };
        assert_eq!(
            defects,
            vec![Defect::Width(Witness {
                path: String::from("a.md"),
                line: Some(3)
            })]
        );
        assert!(keys.contains_key("a|b"));
    }

    #[test]
    fn a_key_in_two_paths_is_duplicated_across_the_union() {
        let reg = table(2, true);
        let a = lines("| k1 | 1 |");
        let b = lines("| k1 | 2 |");
        let built = build(
            &reg,
            None,
            &[
                Input::Lines { path: "a.md", lines: &a },
                Input::Lines { path: "b.md", lines: &b },
            ],
        );
        let Built::Keys { defects, .. } = built else {
            panic!("built");
        };
        assert_eq!(
            defects,
            vec![Defect::Duplicated(Witness {
                path: String::from("b.md"),
                line: Some(1)
            })]
        );
    }

    #[test]
    fn no_inputs_is_could_not_look_never_empty() {
        assert!(matches!(
            build(&table(2, false), None, &[]),
            Built::CouldNotLook { .. }
        ));
    }

    fn doc(pairs: &[(&str, Node)]) -> Node {
        Node::Map(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        )
    }

    #[test]
    fn a_refused_witness_contributes_no_key() {
        let reg = DeclaredRegister {
            id: String::from("attested"),
            paths: vec![String::from("att/*.md")],
            source: Source::Documents {
                key_node: String::from("attests"),
                refused_values: BTreeMap::from([(
                    String::from("stability"),
                    vec![String::from("unstable")],
                )]),
            },
        };
        let good = doc(&[
            ("attests", Node::Text(String::from("cap-a"))),
            ("stability", Node::Text(String::from("stable"))),
        ]);
        let bad = doc(&[
            ("attests", Node::Text(String::from("cap-b"))),
            ("stability", Node::Text(String::from("unstable"))),
        ]);
        let built = build(
            &reg,
            None,
            &[
                Input::Document { path: "att/1.md", node: Some(&good) },
                Input::Document { path: "att/2.md", node: Some(&bad) },
            ],
        );
        assert_eq!(built.contains("cap-a"), Some(true));
        assert_eq!(built.contains("cap-b"), Some(false));
    }

    #[test]
    fn an_unparseable_witness_is_could_not_look() {
        let reg = DeclaredRegister {
            id: String::from("d"),
            paths: vec![String::from("*.md")],
            source: Source::Documents {
                key_node: String::from("k"),
                refused_values: BTreeMap::new(),
            },
        };
        assert_eq!(
            build(&reg, None, &[Input::Document { path: "x.md", node: None }]).contains("k"),
            None
        );
    }

    #[test]
    fn scalars_read_a_string_a_list_and_a_list_of_maps() {
        let node = doc(&[
            ("one", Node::Text(String::from("a"))),
            (
                "many",
                Node::List(vec![Node::Text(String::from("b")), Node::Text(String::from("c"))]),
            ),
            (
                "consumes",
                Node::List(vec![doc(&[("id", Node::Text(String::from("d")))])]),
            ),
        ]);
        assert_eq!(scalars(&node, "one"), vec!["a"]);
        assert_eq!(scalars(&node, "many"), vec!["b", "c"]);
        assert_eq!(scalars(&node, "consumes[].id"), vec!["d"]);
    }
}
