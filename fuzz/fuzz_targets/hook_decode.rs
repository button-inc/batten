//! Fuzz the hook envelope decoder (CLOUD-112).
//!
//! `hook::decode` reads a payload an arbitrary agent harness wrote to stdin —
//! the one surface where Batten consumes bytes it did not produce and cannot
//! constrain. The properties live in `../properties.rs`, shared verbatim with
//! the corpus-replay gate in `crates/batten/tests/fuzz_corpus.rs`.
#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../properties.rs");

fuzz_target!(|data: &[u8]| {
    exercise_hook_decode(data);
});
