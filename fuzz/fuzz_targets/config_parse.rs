//! Fuzz the config parsers and the raise-only clamp (CLOUD-112).
//!
//! `--config-from <ref>` (CLOUD-31) makes the config a trust boundary: the
//! bytes can come from a ref rather than the working tree, so the parser and
//! the clamp that reads its output both consume partly-untrusted input. The
//! properties live in `../properties.rs`, shared verbatim with the
//! corpus-replay gate in `crates/batten/tests/fuzz_corpus.rs`.
#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../properties.rs");

fuzz_target!(|data: &[u8]| {
    exercise_config_parse(data);
});
