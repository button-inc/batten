//! Test support the vocabularies below the cycle share with `batten` (CLOUD-2789).
//!
//! `#[doc(hidden)]` test-support, as in `batten`'s own `testing`, which
//! re-exports these under their old paths.

/// What [`declared_variants`] counted: variants enumerated by a list, and
/// variants enumerated by delegating to another vocabulary.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclaredVariants {
    /// Unit variants, each owing a row in the enum's own list.
    pub unit: usize,
    /// Tuple variants, each owing a `chain` into the vocabulary it wraps.
    pub delegated: usize,
}

/// How many variants `source` declares for the enum `name`, split by whether
/// each carries a payload, counted off the declaration rather than off a list
/// somebody re-typed (CLOUD-2379).
///
/// **IT ASKS THE PARSER, because a text scan kept being wrong in a way that
/// read as right.** Three line-shape heuristics stood here in turn and review
/// found a hole in each: a `starts_with("///")` clause its neighbour already
/// subsumed, a `contains('(')` split that read a struct variant as a unit, and
/// — the one that settles it — a per-LINE scan, under which a declaration
/// `rustfmt` wraps counts as neither. Every one of those failures is silent:
/// the totals still match, so a caller's assertions stay green while the
/// vocabulary goes unchained. The grammar has no such holes, and
/// [`crate::source::rust`] is the crate's one parse (CLOUD-1008).
///
/// **The predicate had three copies before this one, and they had already
/// diverged by a clause.** `WeakeningKind`, `DriftId` and `SmellId` each hold
/// their `ALL`/`UNITS` whole by counting the enum body, and a fourth such enum
/// would have copied whichever copy it found first. One authority decides what
/// a variant line is.
///
/// **BOTH COUNTS ARE RETURNED, and dropping the second was a hole in exactly
/// the mechanism this helper serves.** A unit variant is enumerated by a
/// hand-written list; a TUPLE variant delegates to another vocabulary and is
/// enumerated by a `chain` into that vocabulary's own `ALL`. An exhaustive
/// `definition()` forces an arm for either, but nothing forces the `chain` — so
/// a delegated variant added without one compiles, leaves the unit count
/// matching, and yields ids `all()` never reports. That is the
/// emitted-but-unexplainable id the type exists to make impossible, returning
/// through the type's own extension point. A caller asserts the tuple count it
/// has wired, so adding a variant is what fails.
///
/// The caller passes the source, because `include_str!` resolves against the
/// file it is written in and the point is to read the CALLER's declaration.
#[doc(hidden)]
#[must_use]
pub fn declared_variants(source: &str, name: &str) -> Option<DeclaredVariants> {
    let file = crate::source::rust(source).ok()?;
    let declared = file.items.iter().find_map(|item| match item {
        syn::Item::Enum(declared) if declared.ident == name => Some(declared),
        _ => None,
    })?;
    let unit = declared
        .variants
        .iter()
        .filter(|variant| matches!(variant.fields, syn::Fields::Unit))
        .count();
    Some(DeclaredVariants {
        unit,
        delegated: declared.variants.len() - unit,
    })
}

/// Panics unless every one of `items` is non-empty and no two are equal, naming
/// `what` they are (CLOUD-2379).
///
/// The check each id vocabulary holds over its tokens and its definitions:
/// non-empty kills a `""` arm, and distinct kills a constant one, which a mere
/// non-empty check passes. Each vocabulary still calls it from its own file,
/// since `mutate` judges a source by the cases beside it.
///
/// # Panics
///
/// On an empty entry or a repeated one, which is the assertion.
#[doc(hidden)]
#[track_caller]
pub fn assert_distinct_nonempty(what: &str, items: &[&str]) {
    if let Some(index) = items.iter().position(|item| item.is_empty()) {
        panic!("{what}: entry {index} is empty");
    }
    let mut sorted = items.to_vec();
    sorted.sort_unstable();
    if let Some([repeated, ..]) = sorted.windows(2).find(|pair| pair[0] == pair[1]) {
        panic!("{what}: two entries are {repeated:?}");
    }
}
