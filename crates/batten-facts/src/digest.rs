//! Lowercase hex, and the SHA-256 of a byte string in it (CLOUD-2789).
//!
//! Five modules each carried their own copy of these two loops; a receipt's
//! key, a provisioned artifact's checksum, a cache stamp and a git object id
//! are all the same spelling, so they share one.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// `bytes` as lowercase hex, two characters a byte.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The SHA-256 of `bytes`, as 64 lowercase hex characters.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_spells_every_byte_as_two_lowercase_digits() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn sha256_hex_matches_the_published_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
