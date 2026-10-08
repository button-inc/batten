//! Fuzz the host-transcript reader (CLOUD-2136).
//!
//! `transcript::parse` reads a file the agent harness wrote, and `enforce`
//! decides turn findings over it. The properties live in `../properties.rs`,
//! shared verbatim with the corpus-replay gate in
//! `crates/batten/tests/it/fuzz_corpus.rs`.
#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../properties.rs");

fuzz_target!(|data: &[u8]| {
    exercise_transcript_parse(data);
});
