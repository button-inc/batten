//! One declaration per tokened enum (CLOUD-2442).
//!
//! An enum whose variants each carry a stable string token used to be typed
//! three or four times: the enum, a hand-kept `ALL`, a hand-kept `match` to the
//! token, and a test restating the variant list to prove `ALL` complete. Adding
//! a variant meant editing all of them, and the test edit read to `test-replay`
//! as a changed expectation. [`token_enum!`] takes one `Variant => "token",` line
//! per variant and generates the enum, `ALL` (declaration order) and a `const fn`
//! returning the token, so completeness holds by construction.
//!
//! A leading `serde` makes each token the variant's serde spelling too
//! (`#[serde(rename = …)]`), for an enum that derives serde — so the config
//! spelling and the token cannot diverge either.

/// Panic — at compile time, from a `const` — when two tokens are equal.
pub(crate) const fn assert_unique(tokens: &[&str]) {
    // Each token against every EARLIER one, so the outer bound indexes
    // `tokens[i]` directly: an off-by-one there reads past the end rather than
    // running an empty inner loop no test could tell apart.
    let mut i = 1;
    while i < tokens.len() {
        let mut j = 0;
        while j < i {
            assert!(
                !same(tokens[i], tokens[j]),
                "token_enum!: a token is declared twice"
            );
            j += 1;
        }
        i += 1;
    }
}

/// Byte equality, which `const` code cannot reach through `==` on `str`.
const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut at = 0;
    while at < a.len() {
        if a[at] != b[at] {
            return false;
        }
        at += 1;
    }
    true
}

/// Declare a tokened enum once. See the module docs.
///
/// ```ignore
/// token_enum! {
///     serde
///     #[derive(Debug, Clone, Copy, Deserialize, Serialize)]
///     pub enum Gate by as_str {
///         /// A doc comment rides on its variant.
///         Singleton => "singleton",
///     }
/// }
/// ```
macro_rules! token_enum {
    // The `serde` arm is the plain one with a rename on each variant, so the
    // enum is generated in one place.
    (
        serde
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident by $method:ident {
            $( $(#[$meta:meta])* $variant:ident => $token:literal ),* $(,)?
        }
    ) => {
        token_enum! {
            $(#[$enum_meta])*
            $vis enum $name by $method {
                $( $(#[$meta])* #[serde(rename = $token)] $variant => $token, )*
            }
        }
    };
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident by $method:ident {
            $( $(#[$meta:meta])* $variant:ident => $token:literal ),* $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        $vis enum $name {
            $( $(#[$meta])* $variant, )*
        }

        // TOKEN UNIQUENESS, AT COMPILE TIME: two variants sharing a token make
        // a refusal unattributable and, under the `serde` arm, a spelling that
        // silently deserializes to the first. A duplicate fails the build.
        const _: () = $crate::token_enum::assert_unique(&[ $( $token, )* ]);

        impl $name {
            /// Every variant, in declaration order — generated from the one
            /// declaration, so none can exist unlisted.
            pub const ALL: &'static [$name] = &[ $( $name::$variant, )* ];

            /// The token this variant is declared and rendered under.
            #[must_use]
            pub const fn $method(self) -> &'static str {
                match self {
                    $( $name::$variant => $token, )*
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::{assert_unique, same};

    /// The guard can fail: equal bytes are the same token, and a length or a
    /// single byte apart are not — the three ways `same` could be wrong.
    #[test]
    fn same_is_byte_equality() {
        assert!(same("tool run loose", "tool run loose"));
        assert!(!same("tool run loose", "tool run loos"));
        assert!(!same("tool run loose", "tool run lose!"));
        assert!(same("", ""));
    }

    #[test]
    #[should_panic(expected = "declared twice")]
    fn a_duplicate_token_is_refused() {
        assert_unique(&["a b c", "d e f", "a b c"]);
    }

    #[test]
    fn distinct_tokens_pass() {
        assert_unique(&["a b c", "d e f", "a b d"]);
        assert_unique(&["a b c"]);
        assert_unique(&[]);
    }

    #[test]
    #[should_panic(expected = "declared twice")]
    fn a_duplicate_of_the_first_token_is_refused() {
        assert_unique(&["a b c", "a b c"]);
    }
}
