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
