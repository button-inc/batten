//! One compiled glob over repo-relative paths: the selector every rule, the
//! tree walk and the move-aware gates match through, kept in a leaf
//! (CLOUD-2789).

use crate::error::UsageError;

/// One compiled glob, matched against repo-relative `/`-separated paths
/// (CLOUD-214).
///
/// [`globset`] rather than a hand-rolled matcher: the replaced one backtracked
/// over every `**` split point — exponential on a pattern with several — and
/// knew only `*`, `?` and `**`, so a consumer had no character classes, no
/// braces and no way to say "not this". Adopting the matcher ripgrep already
/// ships is the wrap-don't-rebuild directive applied to the one thing every rule
/// runs through.
///
/// **Compiled once, matched many.** A pattern is parsed when the rule loads, not
/// once per candidate path, which is what keeps the selection linear in the size
/// of the tree rather than in tree × pattern-length.
///
/// # Semantics, pinned rather than inherited
///
/// `literal_separator(true)` is the one non-default setting and it is
/// load-bearing: without it `*` crosses `/`, so `*.rs` would select every Rust
/// file at every depth and a rule scoped to one directory would silently widen.
/// Widening is the single direction a policy engine may never drift, and
/// `rules::tests::glob_semantics_are_pinned_at_the_shipped_patterns` is what
/// holds it.
///
/// **Parsed at load, compiled at first match** (CLOUD-2315). A malformed glob is
/// still refused when the rule loads, because parsing is what refuses it; the
/// regex a match runs is built the first time something asks. The hook loads
/// ~108 selectors per call and matches a handful, and compiling every one was
/// 14% of the instructions a warm call ran.
#[derive(Debug, Clone)]
pub struct Selector {
    /// Carries the pattern as written too (`Glob::glob`), so there is no
    /// second copy of it here.
    glob: globset::Glob,
    matcher: std::sync::OnceLock<globset::GlobMatcher>,
}

impl Selector {
    /// Compile `pattern`.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a pattern `globset` cannot
    /// parse — an unclosed character class, a stray `**` inside a component.
    /// A malformed glob is bad config, and refusing it at load is what stops it
    /// reaching a run as a rule that quietly selects nothing.
    pub fn new(pattern: &str) -> anyhow::Result<Self> {
        let glob = globset::GlobBuilder::new(pattern)
            // See the type's doc comment: without this, `*` crosses `/` and
            // every rule's scope widens.
            .literal_separator(true)
            .build()
            .map_err(|err| UsageError::raise(format!("glob `{pattern}` is not valid: {err}")))?;
        Ok(Selector {
            glob,
            matcher: std::sync::OnceLock::new(),
        })
    }

    /// Whether `path` — repo-relative, `/`-separated — is selected.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        self.matcher
            .get_or_init(|| self.glob.compile_matcher())
            .is_match(path)
    }

    /// The pattern this was compiled from, as the consumer wrote it.
    #[must_use]
    pub fn pattern(&self) -> &str {
        self.glob.glob()
    }
}

/// Hand-written because a compiled matcher has no equality of its own, and
/// stated over the pattern rather than derived so the compiled form stays an
/// implementation detail: a `rules::PathSet` comparison is a comparison of the
/// config that built it.
impl PartialEq for Selector {
    fn eq(&self, other: &Self) -> bool {
        self.pattern() == other.pattern()
    }
}

impl Eq for Selector {}
