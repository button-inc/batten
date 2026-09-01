//! CLOUD-757's §7 obligations: the fact model's two axes, stated per fact,
//! exhaustively matched, and composing by the meet on both.
//!
//! Each case names the mutation that turns it red, because a totality gate that
//! nothing can fail is a comment with a test harness attached.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

#[test]
fn a_content_block_envelope_unwraps_to_the_payload_a_bare_one_carries() {
    // CLOUD-1024, measured against the live host: the connector wraps every
    // response, so a reader of the payload's FIELDS sees an array where the
    // fields should be. The two spellings must decode to one value.
    let bare = serde_json::json!({"id": "CLOUD-1", "updatedAt": "2026-08-25T00:00:00.000Z"});
    let wrapped = serde_json::json!([
        {"type": "text", "text": bare.to_string()}
    ]);
    let nested = serde_json::json!({"content": [{"type": "text", "text": bare.to_string()}]});

    assert_eq!(batten::facts::payload_in(&bare), Some(bare.clone()));
    assert_eq!(batten::facts::payload_in(&wrapped), Some(bare.clone()));
    assert_eq!(batten::facts::payload_in(&nested), Some(bare));
    // And a buffer that says nothing stays nothing, rather than becoming an
    // empty object a caller could read fields off.
    assert_eq!(
        batten::facts::payload_in(&serde_json::Value::Null),
        None,
        "an absent buffer is not a payload"
    );
}

use batten::facts::{
    AGENT_SOURCED, BASE_DELTA, BYPASS, CAPTURED, COMMIT_META, Class, Cost, DOCUMENT, EXTERNAL,
    EXTRACTED, FORGE, Fact, GIT_HEAD, GIT_HISTORY, GIT_RANGE, GIT_REF, GIT_REMOTE, GIT_STATUS,
    INVOCATIONS, KEYS, LANDING, LINES, Look, PINNED, PRODUCED, PROSPECTIVE, RECEIPTS, RECORDS,
    STAGED, STATE, STOP, SYMBOLS, Surface, TASKS, TOOL_VERDICT, TRACKED, USES, WAIVED,
};

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
    //
    // IT ASSERTED FIVE OF SEVEN (CLOUD-849). `Document` and `AgentSourced` were
    // absent, so two arms could be repointed with nothing going red — in the
    // gate that guards the model. And the missing pair was the consequential
    // one: repointing `DOCUMENT` from `Surface::Check` to `Surface::Hook` is
    // exactly the wrong fix for the eleven hook bodies that need to read files,
    // and nothing would have caught it.
    //
    // Rewritten as a CENSUS OVER `Fact::ALL` rather than a longer list, because
    // a list is what was already wrong here: an eighth variant would join the
    // enum and go unasserted in silence. The expected class comes from an
    // exhaustive, wildcard-free match, so a new fact fails to COMPILE until
    // somebody states its pairing.
    let expected = |fact: Fact| -> Class {
        match fact {
            Fact::Bypass => BYPASS,
            Fact::Receipts => RECEIPTS,
            Fact::Keys => KEYS,
            Fact::Stop => STOP,
            Fact::Waived => WAIVED,
            Fact::Document => DOCUMENT,
            Fact::Tracked => TRACKED,
            Fact::Lines => LINES,
            Fact::External => EXTERNAL,
            Fact::AgentSourced => AGENT_SOURCED,
            Fact::Prospective => PROSPECTIVE,
            Fact::Produced => PRODUCED,
            Fact::GitHead => GIT_HEAD,
            Fact::GitStatus => GIT_STATUS,
            Fact::GitRemote => GIT_REMOTE,
            Fact::GitRef => GIT_REF,
            Fact::GitRange => GIT_RANGE,
            Fact::CommitMeta => COMMIT_META,
            Fact::Landing => LANDING,
            Fact::GitHistory => GIT_HISTORY,
            Fact::Staged => STAGED,
            Fact::State => STATE,
            Fact::Forge => FORGE,
            Fact::ToolVerdict => TOOL_VERDICT,
            Fact::Captured => CAPTURED,
            Fact::Tasks => TASKS,
            Fact::Extracted => EXTRACTED,
            Fact::Invocations => INVOCATIONS,
            Fact::Uses => USES,
            Fact::Symbols => SYMBOLS,
            Fact::BaseDelta => BASE_DELTA,
            Fact::Records => RECORDS,
            Fact::Pinned => PINNED,
        }
    };

    // ANTI-VACUITY, in the same function: a census over an empty `ALL` asserts
    // nothing, and the count is pinned so a DROPPED variant fails here too
    // rather than quietly shrinking the census.
    assert_eq!(
        Fact::ALL.len(),
        33,
        "the census covers every fact; update this count deliberately when the \
         model gains or loses one"
    );

    for fact in Fact::ALL {
        assert_eq!(
            fact.class(),
            expected(*fact),
            "{}: `Fact::class` disagrees with the `const` stated beside the fact",
            fact.as_str()
        );
    }
}

#[test]
fn no_effect_fact_is_hook_resolvable() {
    // CLOUD-760's §7(e). `Cost::Effect` means resolving the fact RUNS something —
    // here an analyser over the whole crate — and the mediated path is budgeted
    // in milliseconds per call. `run_static` already refuses a spawning kind on
    // that surface, and a fact classified `Surface::Hook` while costing `Effect`
    // would reintroduce exactly what that refusal removes, one layer down and
    // without passing through it.
    //
    // A CENSUS OVER `Fact::ALL`, not an assertion about `Symbols`. The first
    // `Effect` fact is the occasion for this rule, never its subject: naming it
    // would leave the second one unguarded, which is the shape CLOUD-849
    // measured in this very file.
    //
    // Fails by: flipping any `Cost::Effect` fact's `const` to `Surface::Hook`.
    let mut effect_facts = 0_usize;
    for fact in Fact::ALL {
        let class = fact.class();
        if class.cost != Cost::Effect {
            continue;
        }
        effect_facts += 1;
        assert!(
            !class.resolvable_on(Surface::Hook),
            "{}: a Cost::Effect fact must not be resolvable on the mediated path",
            fact.as_str()
        );
    }
    // ANTI-VACUITY. An all-`Free` model satisfies the loop above without the
    // rule ever being exercised, and that green is CLOUD-251's shape.
    assert!(
        effect_facts > 0,
        "the model carries no Cost::Effect fact, so this census asserted nothing"
    );
}

#[test]
fn every_class_arm_names_its_own_const() {
    // THE HALF A VALUE COMPARISON CANNOT MAKE, and it was measured rather than
    // reasoned. `every_fact_returns_its_stated_const` compares `Class` VALUES,
    // and `Class` is a pair — so repointing an arm at a different `const` that
    // happens to carry the same pair is invisible to it. Measured 2026-08-21:
    // `Fact::Stop => WAIVED` (both `Read` x `Hook`) left the whole cargo suite
    // GREEN, including CLOUD-834's projection census, which sees only the
    // surface.
    //
    // That is not a hypothetical shape. `Read` x `Hook` holds FIVE of the nine
    // facts today — `Receipts`, `Keys`, `Stop`, `Waived`, `AgentSourced` — so
    // twenty of the possible repointings among them are value-identical, and
    // every one would ship silently. The defect it hides is a fact whose
    // classification is read off the wrong neighbour: correct today by
    // coincidence, and wrong the moment that neighbour is reclassified.
    //
    // So this asserts the arm by the NAME it writes, which is the thing that
    // actually has to stay paired. Fails by: pointing any arm of `Fact::class`
    // at any other `const`, value-identical or not.
    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("facts.rs"),
    )
    .expect("facts.rs is readable");

    // The `class` match only — `as_str`'s arms have the same `Fact::X =>` shape
    // and must not be read as classifications.
    let body = source
        .split_once("pub const fn class(self) -> Class {")
        .expect("`Fact::class` is where the pairing lives")
        .1;
    let body = body.split_once("\n    }").expect("the match closes").0;

    let mut seen = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        let Some(arm) = line.strip_prefix("Fact::") else {
            continue;
        };
        let Some((variant, named)) = arm.split_once(" => ") else {
            continue;
        };
        let named = named.trim_end_matches(',');

        // `AgentSourced` -> `AGENT_SOURCED`: the convention the module already
        // follows, asserted rather than trusted.
        let mut want = String::new();
        for (index, character) in variant.char_indices() {
            if character.is_uppercase() && index > 0 {
                want.push('_');
            }
            want.push(character.to_ascii_uppercase());
        }

        assert_eq!(
            named, want,
            "`Fact::{variant}` is classified by `{named}`, but the `const` \
             written beside it is `{want}`. A fact must not read its class off \
             a neighbour — correct today only while that neighbour's class \
             happens to agree."
        );
        seen.push(variant.to_owned());
    }

    // ANTI-VACUITY, in the same function: this test is a source scan, so a
    // refactor that moves or renames the match would leave it reading an empty
    // body and passing forever — the exact failure mode of a scanner gate.
    assert_eq!(
        seen.len(),
        Fact::ALL.len(),
        "the scan found {} arm(s) for {} facts; `Fact::class`'s shape moved and \
         this gate stopped reading it",
        seen.len(),
        Fact::ALL.len()
    );
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
