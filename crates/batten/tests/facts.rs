//! CLOUD-757's §7 obligations: the fact model's two axes, stated per fact,
//! exhaustively matched, and composing by the meet on both.
//!
//! Each case names the mutation that turns it red, because a totality gate that
//! nothing can fail is a comment with a test harness attached.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use batten::facts::{BYPASS, Class, Cost, Fact, KEYS, Look, RECEIPTS, STOP, Surface, WAIVED};

#[test]
fn all_covers_every_cost() {
    // `ALL` is what every census below iterates, so a rung missing from it is a
    // rung nothing tests — which is how an unclassified fact would reach the
    // mediated path. The compiler makes the match total; this asserts `ALL`
    // agrees with it. Fails by: dropping a variant from `Cost::ALL`.
    let mut seen = Vec::new();
    for cost in Cost::ALL {
        match cost {
            Cost::Free | Cost::Read | Cost::Effect | Cost::Stateful => seen.push(cost.as_str()),
        }
    }
    assert_eq!(seen, ["free", "read", "effect", "stateful"]);
}

#[test]
fn all_covers_every_surface() {
    // The same census on the second axis. Fails by: dropping a variant from
    // `Surface::ALL`.
    let mut seen = Vec::new();
    for surface in Surface::ALL {
        match surface {
            Surface::Hook | Surface::Check | Surface::VerifyOnly => seen.push(surface.as_str()),
        }
    }
    assert_eq!(seen, ["hook", "check", "verify-only"]);
}

#[test]
fn every_fact_names_a_cost_and_a_surface() {
    // The acceptance's first clause: a new fact cannot land unclassified, the
    // way a new `RuleKind` cannot. `class()` is a total function into the
    // product, so the assertion is that the census is non-empty and that every
    // row resolves — a fact added to `ALL` without an arm fails to compile.
    assert!(!Fact::ALL.is_empty());
    for fact in Fact::ALL {
        let class = fact.class();
        assert!(
            Cost::ALL.contains(&class.cost),
            "{}: cost is outside the enumerated axis",
            fact.as_str()
        );
        assert!(
            Surface::ALL.contains(&class.surface),
            "{}: surface is outside the enumerated axis",
            fact.as_str()
        );
    }
}

#[test]
fn every_fact_returns_its_stated_const() {
    // The classification is written beside the fact and `class()` returns it;
    // this is the only pairing that could drift. Fails by: pointing any arm of
    // `Fact::class` at a different `const`.
    assert_eq!(Fact::Bypass.class(), BYPASS);
    assert_eq!(Fact::Receipts.class(), RECEIPTS);
    assert_eq!(Fact::Keys.class(), KEYS);
    assert_eq!(Fact::Stop.class(), STOP);
    assert_eq!(Fact::Waived.class(), WAIVED);
}

#[test]
fn composition_takes_the_meet_on_both_axes() {
    // CLOUD-773's requirement, and the defect it prevents: a `read`-class rule
    // that inherits an `effect`-class dependency and still reports itself cheap.
    // Fails by: widening either half of `Class::meet` — returning the cheaper
    // cost, or the wider surface.
    let cheap_and_near = Class::new(Cost::Read, Surface::Hook);
    let costly_and_far = Class::new(Cost::Effect, Surface::VerifyOnly);
    let met = cheap_and_near.meet(costly_and_far);
    assert_eq!(met.cost, Cost::Effect, "the meet takes the more expensive");
    assert_eq!(
        met.surface,
        Surface::VerifyOnly,
        "the meet takes the narrower"
    );

    // Asserted BOTH WAYS, over the whole product rather than one worked pair: a
    // meet that depended on argument order would be a composition whose answer
    // changed with the order inputs happened to be listed in.
    for a_cost in Cost::ALL {
        for b_cost in Cost::ALL {
            for a_surface in Surface::ALL {
                for b_surface in Surface::ALL {
                    let a = Class::new(*a_cost, *a_surface);
                    let b = Class::new(*b_cost, *b_surface);
                    assert_eq!(
                        a.meet(b),
                        b.meet(a),
                        "meet is order-dependent for {}x{} and {}x{}",
                        a_cost.as_str(),
                        a_surface.as_str(),
                        b_cost.as_str(),
                        b_surface.as_str()
                    );
                    // And it never returns something cheaper or wider than an
                    // input: the direction is the safety property.
                    let met = a.meet(b);
                    assert_eq!(met.cost, met.cost.meet(a.cost).meet(b.cost));
                    assert_eq!(met.surface, met.surface.meet(a.surface).meet(b.surface));
                }
            }
        }
    }
}

#[test]
fn the_two_axes_are_independent() {
    // The whole reason there are two. Forge state is `read` by price and still
    // barred from the mediated path, because the bound is the no-runtime
    // assertion rather than the cost. A one-axis model cannot hold both of these
    // at once. Fails by: collapsing `Surface` into `Cost`, or classifying the
    // forge pair as anything a ladder could express.
    let forge = Class::new(Cost::Read, Surface::VerifyOnly);
    assert_eq!(forge.cost, RECEIPTS.cost, "forge state is priced as a read");
    assert_ne!(
        forge.surface, RECEIPTS.surface,
        "and is still barred from the surface a read-class fact reaches"
    );
    assert!(!forge.resolvable_on(Surface::Hook));
    assert!(forge.resolvable_on(Surface::VerifyOnly));
    assert!(RECEIPTS.resolvable_on(Surface::Hook));
}

#[test]
fn a_narrower_surface_is_never_admitted_by_a_wider_run() {
    // `admits` is the axis's whole consequence, so it is asserted over the full
    // 3x3 rather than at the two corners the other cases happen to touch.
    let expected = [
        (Surface::Hook, Surface::Hook, true),
        (Surface::Hook, Surface::Check, true),
        (Surface::Hook, Surface::VerifyOnly, true),
        (Surface::Check, Surface::Hook, false),
        (Surface::Check, Surface::Check, true),
        (Surface::Check, Surface::VerifyOnly, true),
        (Surface::VerifyOnly, Surface::Hook, false),
        (Surface::VerifyOnly, Surface::Check, false),
        (Surface::VerifyOnly, Surface::VerifyOnly, true),
    ];
    for (fact_surface, running_on, admitted) in expected {
        assert_eq!(
            fact_surface.admits(running_on),
            admitted,
            "{} on {}",
            fact_surface.as_str(),
            running_on.as_str()
        );
    }
}

#[test]
fn the_three_valued_answer_keeps_could_not_look_apart_from_is_not() {
    // `receipts` has carried this since it shipped and `Look` is where it is
    // stated once. The failure it guards is the one that reads `None` as "looked
    // and found nothing", which turns a gate that cannot look into a gate that
    // blocks everything.
    let looked: Look<u8> = Look::Is(1);
    let absent: Look<u8> = Look::IsNot;
    let blind: Look<u8> = Look::CouldNotLook;
    assert_eq!(
        [looked.as_str(), absent.as_str(), blind.as_str()],
        ["is", "is-not", "could-not-look"]
    );
    assert!(blind.could_not_look());
    assert!(!absent.could_not_look());
    assert!(!looked.could_not_look());
    assert_ne!(absent, blind);
}

#[test]
fn no_axis_match_carries_a_wildcard_arm() {
    // The one case the compiler cannot give us. Exhaustiveness is only a totality
    // guarantee while no arm is a wildcard: `_ => Cost::Free` compiles happily and
    // silently classifies every future fact as cheap and hook-safe, which is the
    // one direction this mistake is expensive in. So the module is scanned for the
    // wildcard shapes, the way `primitives.rs` scans for a basic-string path.
    //
    // Fails by: replacing any arm in `facts.rs` with `_ =>` or `_ if`.
    let source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/facts.rs");
    let source = fs::read_to_string(&source_path).expect("read src/facts.rs");
    // Collected rather than panicked on at the first hit: a wildcard introduced
    // in one axis is usually introduced in both, and one offender per run turns
    // one fix into one CI round trip each.
    let mut offenders = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let code = line.trim_start();
        // Doc comments are prose about the rule, not the rule.
        if code.starts_with("//") {
            continue;
        }
        if code.starts_with("_ =>") || code.starts_with("_ if") || code.contains(", _)") {
            // Pointer-only (rule 4): the line NUMBER, never the line.
            offenders.push(format!("src/facts.rs:{}", index + 1));
        }
    }
    assert!(
        offenders.is_empty(),
        "an axis match carries a wildcard arm, so a fact added later classifies itself instead of \
         failing to compile (CLOUD-757):\n  {}",
        offenders.join("\n  ")
    );
}
