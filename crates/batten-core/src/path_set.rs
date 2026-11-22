//! One glob evaluator over repo-relative, `/`-separated paths: an ordered
//! include/exclude list where an exclude beats an include. Moved below `rules`
//! (CLOUD-2789) because it is data over [`crate::selector::Selector`] and names
//! no verdict, so a layer `rules` may not reach (`mutate`) can still build one.

use batten_facts::error::UsageError;

use crate::selector::Selector;

/// The marker that turns a glob into an exclude inside an ordered
/// include/exclude list: gitignore's `!` prefix, so a reader who knows one knows
/// the other.
const EXCLUDE_PREFIX: char = '!';

/// One glob evaluator over repo-relative, `/`-separated paths.
///
/// A set answers exactly one question — *is this path a member?* — from its own
/// list and nothing else. Two sets built from two lists share no state, so
/// membership in each is computed independently (CLOUD-37). That independence is
/// the whole point: `scope`, `protected` and `unlanded` overlap in practice but
/// are not the same set, and collapsing them changes policy silently.
///
/// **An exclude beats an include.** Membership is `any include matches AND no
/// exclude matches`, so the outcome does not depend on the order the patterns
/// were written in — the strongest reading of "excludes win", and the one that
/// makes evaluation deterministic and order-stable for identical config (§6).
///
/// An empty include list makes the set empty. Absent config is *not* read as
/// "everything": a set that silently defaults to universal membership is a
/// widening, and widening is the one direction a policy engine may never drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSet {
    includes: Vec<Selector>,
    excludes: Vec<Selector>,
}

impl PathSet {
    /// The include patterns as written, so a caller can ENUMERATE what the set
    /// covers rather than only ask about one path (step 14: the protected-path
    /// snapshot walks them).
    #[must_use]
    pub fn include_patterns(&self) -> Vec<&str> {
        self.includes.iter().map(Selector::pattern).collect()
    }

    /// The set that contains nothing.
    ///
    /// Spelled out rather than derived as `Default`, because the safe empty value
    /// and the *obvious* one point in opposite directions here: an absent list
    /// must mean "no paths", never "all paths", and a `Default` impl is exactly
    /// the thing a future caller reaches for without reading which way it went
    /// (see the type's own doc comment). [`PathSet::contains`] needs at least one
    /// matching include, so this matches nothing by construction.
    #[must_use]
    pub const fn empty() -> Self {
        PathSet {
            includes: Vec::new(),
            excludes: Vec::new(),
        }
    }

    /// Whether this set can match anything.
    ///
    /// A set with no includes contains nothing, so a caller can skip the work of
    /// even asking. Excludes alone cannot make a set non-empty — they only
    /// subtract.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.includes.is_empty()
    }
}

impl PathSet {
    /// Build the ordered include/exclude set the `scope` key declares: a plain
    /// glob includes, a `!`-prefixed glob excludes.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a `!` with no glob after it —
    /// an exclude that excludes nothing is a typo, not an empty instruction —
    /// and for a glob that does not compile, which is refused here rather than
    /// silently narrowing the set to nothing.
    pub fn scope(patterns: &[String]) -> anyhow::Result<Self> {
        let mut set = PathSet {
            includes: Vec::new(),
            excludes: Vec::new(),
        };
        for pattern in patterns {
            match pattern.strip_prefix(EXCLUDE_PREFIX) {
                Some("") => {
                    return Err(UsageError::raise(
                        "scope: `!` must be followed by a glob".to_owned(),
                    ));
                }
                Some(rest) => set.excludes.push(Selector::new(rest)?),
                None => set.includes.push(Selector::new(pattern)?),
            }
        }
        Ok(set)
    }

    /// The set one tree-scoped rule selects: its `glob` as the sole include, its
    /// `exclude_paths` as excludes (CLOUD-883).
    ///
    /// Built here rather than as a bare [`Selector`] so a rule's selection gets
    /// this type's stated semantics for free — an exclude beats an include, and
    /// the answer does not depend on the order the author wrote the patterns in.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a glob that does not compile, and
    /// for a `!`-prefixed exclusion. The second is the load-bearing refusal: this
    /// column is ALREADY the negative half, so a `!` here is a double negative
    /// that reads as re-inclusion — the one direction that would widen the
    /// selection past what `glob` names, which is what this type's own doc says a
    /// policy engine may never drift towards.
    pub fn selecting(rule: &str, glob: &str, exclude_paths: &[String]) -> anyhow::Result<Self> {
        let mut set = PathSet {
            includes: vec![Selector::new(glob)?],
            excludes: Vec::with_capacity(exclude_paths.len()),
        };
        for pattern in exclude_paths {
            if pattern.starts_with(EXCLUDE_PREFIX) {
                return Err(UsageError::raise(format!(
                    "rule {rule}: `exclude_paths` entry `{pattern}` starts with `!`, and this \
                     column is already the exclusion — a `!` here reads as re-including what \
                     `glob` selected, which widens the rule past what its author wrote"
                )));
            }
            if pattern.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {rule}: `exclude_paths` carries an empty entry, which excludes nothing \
                     while reading as a narrowing"
                )));
            }
            set.excludes.push(
                Selector::new(pattern)
                    .map_err(|err| UsageError::raise(format!("rule {rule}: {err}")))?,
            );
        }
        Ok(set)
    }

    /// Build a plain include set from `key`'s list.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a `!`-prefixed entry. Only
    /// `scope` carries exclude semantics, so a `!` here would either be read as
    /// a literal glob or silently dropped — and a pattern the author believes
    /// excludes a path while the engine treats it as an include is precisely the
    /// silent policy change this issue exists to prevent. Refuse instead. A glob
    /// that does not compile is refused here too, for the same reason.
    pub fn includes(key: &str, patterns: &[String]) -> anyhow::Result<Self> {
        let mut includes = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            if pattern.starts_with(EXCLUDE_PREFIX) {
                return Err(UsageError::raise(format!(
                    "{key}: `{pattern}` — only `scope` takes `!` excludes; {key} is a plain \
                     include set"
                )));
            }
            includes.push(
                Selector::new(pattern).map_err(|err| UsageError::raise(format!("{key}: {err}")))?,
            );
        }
        Ok(PathSet {
            includes,
            excludes: Vec::new(),
        })
    }

    /// Whether `path` is a member of this set, computed from this set's lists
    /// alone.
    #[must_use]
    pub fn contains(&self, path: &str) -> bool {
        self.includes.iter().any(|selector| selector.matches(path))
            && !self.excludes.iter().any(|selector| selector.matches(path))
    }

    /// Whether `directory` is a member, **or encloses one** (CLOUD-609).
    ///
    /// # A second question over the same lists, and it gets its own name
    ///
    /// `dir/**` requires at least one component after the separator, so `dir` is
    /// not a member of it. Every mutating verb aimed at a guarded DIRECTORY was
    /// therefore allowed while the same verb naming a file inside it denied:
    /// `cp /tmp/draft.md .serena/memories/` passed, which is the exact shape the
    /// retiring `memory-guard-check` existed for — it matched by substring, so
    /// the CLOUD-312 port lost the coverage rather than the gate being designed
    /// without it.
    ///
    /// **[`PathSet::contains`] is deliberately untouched.** `scope` and
    /// `unlanded` are answers about FILES, and a rule selecting a directory
    /// would select nothing to inspect, so widening membership would change two
    /// callers that never asked this question — and it would look like nothing
    /// in the diff. That is why this is a named method rather than a quiet
    /// broadening, and why the only caller is `hook::protects`.
    ///
    /// # Decided over the declared PATTERNS, never over a probe path
    ///
    /// A synthetic path under `directory` matched against the set would answer
    /// for `dir/**` and get `dir/*.md` wrong, and any sentinel component can
    /// collide with an exclude. The exact question is a string one: does a
    /// protected pattern's literal head sit inside this directory? `dir/**`,
    /// `dir/*.md` and `dir/sub/x` all begin `dir/`; `dirty/**` does not, which is
    /// what the separator in the comparison buys.
    ///
    /// Excludes subtract from membership, as always, and cannot manufacture
    /// enclosure: a set whose only include is excluded still encloses whatever
    /// its include names, because the exclude speaks about a path rather than
    /// about the directory above it. That is the under-denying direction and the
    /// sanctioned one.
    #[must_use]
    pub fn encloses(&self, directory: &str) -> bool {
        if self.contains(directory) {
            return true;
        }
        let prefix = format!("{}/", directory.trim_end_matches('/'));
        self.includes
            .iter()
            .any(|selector| selector.pattern().starts_with(&prefix))
    }
}
