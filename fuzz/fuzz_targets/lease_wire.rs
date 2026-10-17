//! Fuzz the git smart-HTTP decoders the landing lease reads (CLOUD-2135).
//!
//! `lease::parse_advertisement`, `parse_report` and `parse_body` take bytes a
//! remote — or a proxy standing in for one — wrote. The properties live in
//! `../properties.rs`, shared verbatim with the corpus-replay gate in
//! `crates/batten/tests/it/fuzz_corpus.rs`.
#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../properties.rs");

fuzz_target!(|data: &[u8]| {
    exercise_lease_wire(data);
});
