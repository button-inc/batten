// The properties both fuzz targets assert — written **once**, driven twice.
//
// `include!`d by `fuzz_targets/*.rs` (driven by libFuzzer, under nightly) and
// by `crates/batten/tests/fuzz_corpus.rs` (driven by the checked-in corpus,
// under the stable toolchain, on the landing path). One body of assertions and
// two drivers, because the alternative — a target that checks one thing and a
// replay that checks another — makes a saved reproducer stop meaning what it
// meant when it was found.
//
// A crate would be the obvious home and cannot be one: the fuzz tree is a
// detached workspace that depends on `batten`, so a shared crate the library's
// own test target could also use would close a dependency cycle. `include!` is
// how the file stays single-definition without one.
//
// **These are properties, not just "does not panic".** A crash-only target
// would pass on a decoder that returned a different answer for the same bytes
// on alternate calls, or that promoted an undecodable payload into a deny —
// and both of those are the failures that matter for a mediation surface that
// is supposed to fail open.

/// Every property `hook::decode` owes a caller, over one input.
///
/// Runs against **every** harness rather than a chosen one: the dialects differ
/// materially (Cursor's specialized events carry the operand at top level,
/// Copilot's `toolArgs` may arrive stringified, any host may prefix a BOM), so
/// one input is five decisions and a fixed harness would fuzz a fifth of the
/// surface.
///
/// # Panics
///
/// On any violated property — which is the reporting channel, not an
/// accident: libFuzzer records a crash, and the replay gate fails the build.
pub fn exercise_hook_decode(data: &[u8]) {
    // Not `from_utf8_lossy`: a harness writes bytes, and the decoder is
    // responsible for refusing the ones that are not text. Sanitizing here
    // would fuzz the sanitizer.
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    for &harness in batten::hook::Harness::ALL {
        let first = batten::hook::decode(harness, raw);

        // DETERMINISM. Mediation happens once per tool call and its verdict is
        // recorded; a decoder whose answer depends on anything but its input
        // makes that record unfalsifiable.
        let second = batten::hook::decode(harness, raw);
        assert_eq!(
            first, second,
            "decode is not a function of its input for {harness:?}"
        );

        // FAIL OPEN. `decode` returns `None` for anything it cannot read, and
        // the contract is that this is an allow — never a deny, and never a
        // panic that a host would read as a crashed guard. The assertion below
        // is the part a crash-only target cannot make: a decoded envelope must
        // still be self-consistent, because `adjudicate` reads these fields
        // without re-validating them.
        if let Some(envelope) = first {
            // A shell-shaped call carries its command; a non-shell one carries
            // the empty string. Either way `command` is text, never a partial
            // read of `input`, and a write target that exists is a real path.
            if let Some(writes) = &envelope.writes {
                assert!(
                    !writes.is_empty(),
                    "a write target that exists must be a path, not an empty string ({harness:?})"
                );
            }
            // The host's own spelling is echoed verbatim into a decision
            // document, so it must survive decoding unmangled — and where the
            // payload named no event at all, the documented assumed default
            // stands in. Both halves matter, and the FIRST version of this
            // property asserted only the first: the fuzzer refuted it in about
            // a thousand execs with a payload whose key was mutated to
            // `hookaevent_name`, which names no event and therefore takes the
            // default. The property was wrong, not the decoder — which is the
            // search earning its keep on the day it landed. Its input is kept
            // as a seed (`corpus/hook_decode/no-event-key-takes-the-default`).
            let named = serde_json::from_str::<serde_json::Value>(raw)
                .ok()
                .and_then(|payload| {
                    payload
                        .get("hook_event_name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                });
            match named {
                Some(named) => assert_eq!(
                    envelope.raw_event, named,
                    "the host's own spelling was mangled in transit ({harness:?})"
                ),
                None => assert!(
                    !envelope.raw_event.is_empty(),
                    "a payload naming no event must take the assumed default, never an empty \
                     event a decision document would echo back blank ({harness:?})"
                ),
            }
        }
    }
}

/// Every property the config surface owes a caller, over one input.
///
/// Covers the authority parser, the override parser, and — on the `Ok` path —
/// the raise-only clamp, because `--config-from <ref>` (CLOUD-31) means a
/// `Config` can arrive from a ref rather than the working tree, and
/// `trust::weakenings` is what decides whether it weakened policy. Fuzzing the
/// parser alone would leave the function that consumes its output untested
/// against everything the parser is willing to produce.
///
/// # Panics
///
/// On any violated property, for the reason given above.
pub fn exercise_config_parse(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // DETERMINISM, same reason as above: `config show` is byte-stable by
    // contract (house-style §6), which is a claim about the parse as much as
    // about the printing.
    let parsed = batten::config::parse(text, "fuzz");
    assert_eq!(
        parsed.is_ok(),
        batten::config::parse(text, "fuzz").is_ok(),
        "parse is not a function of its input"
    );

    // The override surface is a SECOND type, not a second reading of `Config`
    // (CLOUD-239), so it is a second decision and gets its own exercise.
    let overridden = batten::config::parse_override(text, "fuzz");
    assert_eq!(
        overridden.is_ok(),
        batten::config::parse_override(text, "fuzz").is_ok(),
        "parse_override is not a function of its input"
    );

    if let Ok(config) = parsed {
        // ROUND TRIP (CLOUD-341). "Never a silently-wrong value" is the half of
        // the loader's contract that is easy to write and hard to check, and
        // this is what makes it decidable: an accepted `Config` re-emitted and
        // re-read must reach the same value. Without this clause the whole
        // property degenerates to a panic hunt — a parser that quietly coerced
        // a value, dropped a table or last-wins-merged a duplicate would satisfy
        // every other assertion here, which is exactly the class a `toml` bump
        // is most likely to shift.
        //
        // A serialization failure is NOT skipped. `Config` is `Serialize` and
        // every value in it came out of the parser a moment ago, so a shape the
        // emitter cannot write is a disagreement between the two halves of the
        // config surface, which is a finding rather than a case to tolerate.
        let emitted =
            batten::config::emit(&config).expect("an accepted Config must be re-emittable");
        let reread = batten::config::parse(&emitted, "fuzz")
            .expect("an accepted Config must survive its own emitted form");
        assert_eq!(
            config, reread,
            "the loader accepted a value it does not read back: a silently-wrong parse"
        );

        // TOTALITY of the clamp. `weakenings` is `#[must_use]` and infallible by
        // signature, which is a promise it can only keep if it terminates on
        // every `Config` the parser accepts — including the degenerate ones a
        // human would never write.
        let base = batten::config::Config::declaring_nothing();
        let against_empty = batten::trust::weakenings(&base, &config);
        let against_self = batten::trust::weakenings(&config, &config);

        // A config never weakens ITSELF. This is the property that makes the
        // report meaningful: a clamp reporting drift between a file and its own
        // bytes would fire on every unchanged branch.
        assert!(
            against_self.is_empty(),
            "a config weakened itself: {against_self:?}"
        );

        // SORTEDNESS, which §6 requires for a byte-stable report.
        let mut sorted = against_empty.clone();
        sorted.sort();
        assert_eq!(
            against_empty, sorted,
            "weakenings must be sorted, or two runs differ by ordering noise"
        );
    }
}
