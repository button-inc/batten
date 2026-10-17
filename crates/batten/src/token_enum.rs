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
    let mut i = 0;
    while i < tokens.len() {
        let mut j = i + 1;
        while j < tokens.len() {
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
    (@impl $name:ident $method:ident [$( $variant:ident => $token:literal ),*]) => {
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
    (
        serde
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident by $method:ident {
            $( $(#[$meta:meta])* $variant:ident => $token:literal, )*
        }
    ) => {
        $(#[$enum_meta])*
        $vis enum $name {
            $( $(#[$meta])* #[serde(rename = $token)] $variant, )*
        }
        token_enum!(@impl $name $method [$( $variant => $token ),*]);
    };
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident by $method:ident {
            $( $(#[$meta:meta])* $variant:ident => $token:literal, )*
        }
    ) => {
        $(#[$enum_meta])*
        $vis enum $name {
            $( $(#[$meta])* $variant, )*
        }
        token_enum!(@impl $name $method [$( $variant => $token ),*]);
    };
}
