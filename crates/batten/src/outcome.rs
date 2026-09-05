//! The post-tool outcome, normalized (CLOUD-945).
//!
//! A bare pinned tool can fail loudly after the agent starts it — an OS
//! command-not-found, a permission failure. The pre-admission rule catches the
//! silent and more dangerous case, where an ambient tool succeeds at the wrong
//! version; it can say nothing about an outcome. This is the loud counterpart,
//! and it **advises rather than decides**: nothing here can deny a call, retry
//! one, mutate one, probe a binary or touch the filesystem.
//!
//! # What was measured, and what it settles
//!
//! CLOUD-945 makes the empirical question a precondition rather than a design
//! choice: *does the host's Bash post-tool payload carry a structured exit
//! status, and where does the outcome appear?* Measured over **364 real
//! payloads** from one Claude Code session, the answer is that it does **not**.
//! The union of keys observed is `stdout`, `stderr`, `interrupted`, `isImage`,
//! `noOutputExpected`, `backgroundTaskId`, `persistedOutputPath`,
//! `persistedOutputSize`, `returnCodeInterpretation`, `staleReadFileStateHint`
//! and `timedOutAfterMs`. There is no exit-code field;
//! `returnCodeInterpretation` occurred once and carried a human sentence
//! (`"Files differ"`), not a code. A command-not-found failure arrives as
//! diagnostic TEXT in `stdout` or `stderr`, with `interrupted: false` and
//! nothing structured beside it.
//!
//! `crates/batten/tests/fixtures/hooks/claude-code-posttool-failure.json` is
//! that shape, sanitized. It is a fixture rather than documentation, for the
//! reason that directory's README already gives: a fixture pins what was
//! measured, so a later edit argues with an observation instead of a
//! recollection.
//!
//! # So the exit-code arms are DECLARED AND UNREACHED, which is the honest state
//!
//! The row's signatures are exit 127 with command-not-found and exit 126 with a
//! permission failure — both requiring the code. On the measured host the code
//! is absent, so [`classify`] returns [`Class::Unknown`] and no advice is
//! emitted. That is the row's own rule working (*"absent exit status … fails
//! open with no advice"*), not a gap in it.
//!
//! **The alternative is what the row forbids by name.** Matching the diagnostic
//! text alone would recognise `sh: 1: x: not found` and also every echo, log
//! line and commit message that contains the phrase — the unanchored matcher
//! that "is what makes an advisory channel noise". A signature that fires on
//! prose is worse than one that never fires, because the first teaches a reader
//! to ignore the channel.
//!
//! So the classifier is built to the measured contract and the arms are declared
//! in the consumer's config, ready for a host that supplies a code. A host that
//! does is recognised the day it arrives, with no change here.
//!
//! # Pointer-only, and here it is the whole point (rule 4)
//!
//! An [`Outcome`] carries a closed class, an optional code, an OS family and a
//! literal program token. It carries no stdout, no stderr, no host payload byte
//! and no path. A command's output is the likeliest field in the whole envelope
//! to hold a secret, and an advisory that quoted it would put one in a channel
//! that is written to a log by construction.

use serde::{Deserialize, Serialize};

/// A normalized failure class.
///
/// Closed, and deliberately small: the row's whole posture is that only exact,
/// anchored signatures are recognised, and an open class set is how a matcher
/// widens without anybody deciding to widen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Class {
    /// The shell could not find the program.
    CommandNotFound,
    /// The program was found and could not be executed.
    PermissionDenied,
    /// A declared program rejected a flag.
    UnsupportedOption,
    /// **Could not look**, and the arm that is reached today. Not "succeeded":
    /// an outcome this build cannot classify is one nothing may advise on.
    Unknown,
}

impl Class {
    /// The stable token this class is reported under (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Class::CommandNotFound => "command-not-found",
            Class::PermissionDenied => "permission-denied",
            Class::UnsupportedOption => "unsupported-option",
            Class::Unknown => "unknown",
        }
    }

    /// Whether this class may carry advice at all.
    ///
    /// [`Class::Unknown`] never does, which is the fail-open half stated as a
    /// property rather than left to each caller to remember.
    #[must_use]
    pub const fn advisable(self) -> bool {
        !matches!(self, Class::Unknown)
    }
}

/// Which operating-system family the outcome came from.
///
/// An unsupported family is could-not-look, for [`Class::Unknown`]'s reason: a
/// remedy that names the wrong platform's spelling is worse than none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Family {
    /// A POSIX shell host.
    Unix,
    /// Anything this build has not surveyed.
    Unsupported,
}

/// One normalized outcome: everything a static remedy needs and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Outcome {
    /// The closed class.
    pub class: Class,
    /// The structured exit code, where the host supplies one.
    ///
    /// `None` on every host measured so far, and a signature requiring a code is
    /// simply unreached there. Carrying the field anyway is what lets a host
    /// that supplies one be recognised with no change to this type.
    pub code: Option<i64>,
    /// The OS family.
    pub family: Family,
    /// The literal program token a remedy names — the first word of the command
    /// as WRITTEN, never a path this build resolved.
    pub token: Option<String>,
}

/// A declared signature: what makes a class exact.
///
/// **Consumer config, and none of its content may be a literal in this crate**
/// (non-negotiable rule 1). The engine holds the matcher; which codes and which
/// program-specific patterns are recognised is the repository's own answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Signature {
    /// The class this signature establishes.
    pub class: String,
    /// The structured exit code it requires.
    ///
    /// REQUIRED, and that is the anchoring. A signature with no code would match
    /// on text alone, which is the unanchored matcher the row forbids by name.
    pub code: i64,
    /// The OS family it applies to.
    pub family: String,
}

/// Classify one post-tool result against the declared signatures.
///
/// # The order is the predicate
///
/// The structured code is read FIRST. A host that supplies none reaches
/// [`Class::Unknown`] before any text is examined, so no amount of diagnostic
/// prose can promote an outcome to a class — which is what keeps this from
/// recognising the phrase inside an echo, a log line or a commit message.
///
/// `result` is the envelope's raw value and is read, never retained: nothing it
/// carries reaches the returned [`Outcome`] except the exit code, if the host
/// gave one.
#[must_use]
pub fn classify(result: &serde_json::Value, command: &str, signatures: &[Signature]) -> Outcome {
    let family = family_of();
    let token = command
        .split_whitespace()
        .next()
        .filter(|word| !word.is_empty())
        .map(str::to_owned);
    let code = structured_code(result);
    let Some(code) = code else {
        // THE ARM REACHED ON EVERY HOST MEASURED SO FAR. Absent exit status is
        // could-not-look, and could-not-look never advises.
        return Outcome {
            class: Class::Unknown,
            code: None,
            family,
            token,
        };
    };
    let class = signatures
        .iter()
        .find(|signature| signature.code == code && signature.family == family_token(family))
        .and_then(|signature| class_of(&signature.class))
        .unwrap_or(Class::Unknown);
    Outcome {
        class,
        code: Some(code),
        family,
        token,
    }
}

/// The structured exit code, where the host supplies one.
///
/// Three spellings are read because three are plausible across hosts, and none
/// of them is present on the one this repository has measured. A value that is
/// not an integer is `None`: `returnCodeInterpretation` was observed carrying a
/// human sentence, and reading a sentence as a code is exactly the kind of
/// coercion that would make a signature fire on nothing it meant.
#[must_use]
pub fn structured_code(result: &serde_json::Value) -> Option<i64> {
    for key in ["exitCode", "exit_code", "returnCode"] {
        if let Some(code) = result.get(key).and_then(serde_json::Value::as_i64) {
            return Some(code);
        }
    }
    None
}

/// The class a declared token names, or `None` for one this build does not know.
///
/// An unknown token is could-not-look rather than a load error: the config's own
/// validator decides whether a row may declare it, and a classifier that refused
/// here would turn a config question into a runtime one.
#[must_use]
fn class_of(token: &str) -> Option<Class> {
    match token {
        "command-not-found" => Some(Class::CommandNotFound),
        "permission-denied" => Some(Class::PermissionDenied),
        "unsupported-option" => Some(Class::UnsupportedOption),
        _ => None,
    }
}

/// This build's OS family.
#[must_use]
const fn family_of() -> Family {
    if cfg!(unix) {
        Family::Unix
    } else {
        Family::Unsupported
    }
}

/// The token a signature's `family` column is compared against.
#[must_use]
const fn family_token(family: Family) -> &'static str {
    match family {
        Family::Unix => "unix",
        Family::Unsupported => "unsupported",
    }
}

/// Refuse a signature table that could not mean anything.
///
/// **At LOAD, for the reason the pattern table gives** (CLOUD-885): a row naming
/// a class this build cannot resolve is an arm that fires on nothing, and a
/// declared-but-dead arm is worse than an absent one — it reads as coverage
/// while its route has never been walked. Refusing here means `config lint` and
/// `doctor` catch it, rather than a mediated call discovering it at
/// adjudication, which is the worst time and the wrong exit class.
///
/// # Errors
///
/// [`crate::UsageError`] naming the row and the key: an unresolvable class, an
/// unknown OS family, or two rows claiming one (code, family) pair — the last
/// because a duplicate makes which arm answers depend on table order, and a
/// signature whose meaning depends on its position is not a declaration.
pub fn validate(signatures: &[Signature]) -> anyhow::Result<()> {
    let mut seen: Vec<(i64, &str)> = Vec::new();
    for (index, signature) in signatures.iter().enumerate() {
        let row = index + 1;
        if class_of(&signature.class).is_none() {
            return Err(crate::UsageError::raise(format!(
                "[[outcome]] row {row}: `class` is `{}`, which is not a class this build resolves",
                signature.class
            )));
        }
        if !matches!(signature.family.as_str(), "unix" | "unsupported") {
            return Err(crate::UsageError::raise(format!(
                "[[outcome]] row {row}: `family` is `{}`, which names no surveyed OS family",
                signature.family
            )));
        }
        let key = (signature.code, signature.family.as_str());
        if seen.contains(&key) {
            return Err(crate::UsageError::raise(format!(
                "[[outcome]] row {row}: a second row claims code {} on `{}`, so which arm answers \
                 would depend on table order",
                signature.code, signature.family
            )));
        }
        seen.push(key);
    }
    Ok(())
}

/// The key an advisory is rate-limited by: session, tool and class.
///
/// One key rather than three comparisons, so "the same normalized outcome twice"
/// is one lookup and cannot be half-remembered by a caller. The session is
/// hashed for the reason the observation receipt hashes it: a host's token may
/// itself be sensitive, and nothing here needs the raw one.
#[must_use]
pub fn advice_key(session: &str, tool: &str, class: Class) -> String {
    format!(
        "{}.{tool}.{}",
        crate::tools::digest(session.as_bytes()),
        class.as_str()
    )
}

#[cfg(test)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#[allow(clippy::expect_used, reason = "a test asserts by panicking")]
mod tests {
    use super::*;

    fn signatures() -> Vec<Signature> {
        vec![
            Signature {
                class: "command-not-found".to_owned(),
                code: 127,
                family: "unix".to_owned(),
            },
            Signature {
                class: "permission-denied".to_owned(),
                code: 126,
                family: "unix".to_owned(),
            },
        ]
    }

    /// The measured host shape: no code, so no class, so no advice.
    #[test]
    fn the_measured_payload_carries_no_code_and_reaches_no_class() {
        let measured = serde_json::json!({
            "stdout": "",
            "stderr": "sh: 1: example-program: not found",
            "interrupted": false,
            "isImage": false,
            "noOutputExpected": false,
        });
        let outcome = classify(&measured, "example-program --version", &signatures());
        assert_eq!(outcome.code, None);
        assert_eq!(outcome.class, Class::Unknown);
        assert!(!outcome.class.advisable());
    }

    /// **The discriminating case.** Arbitrary output carrying the phrase is not a
    /// class.
    ///
    /// An unanchored matcher passes every other negative here and fails only
    /// this one — which is why the code is read before any text is.
    #[test]
    fn arbitrary_output_containing_the_phrase_is_not_a_class() {
        let echo = serde_json::json!({
            "stdout": "sh: 1: example-program: not found\n",
            "stderr": "",
            "exitCode": 0,
        });
        let outcome = classify(
            &echo,
            "echo 'sh: 1: example-program: not found'",
            &signatures(),
        );
        assert_eq!(
            outcome.class,
            Class::Unknown,
            "a successful command that PRINTS the phrase is not a failure"
        );
    }

    /// A host that supplies a code is recognised, which is what keeps the arm
    /// above from being unconditional.
    #[test]
    fn a_host_that_supplies_a_code_is_recognised() {
        let with_code = serde_json::json!({"stdout": "", "stderr": "", "exitCode": 127});
        let outcome = classify(&with_code, "example-program --version", &signatures());
        assert_eq!(outcome.class, Class::CommandNotFound);
        assert_eq!(outcome.code, Some(127));
        assert_eq!(outcome.token.as_deref(), Some("example-program"));
        assert!(outcome.class.advisable());

        let denied = serde_json::json!({"exit_code": 126});
        assert_eq!(
            classify(&denied, "example-program", &signatures()).class,
            Class::PermissionDenied,
            "the alternative spelling is read too"
        );
    }

    /// A code no signature declares is could-not-look, not a class.
    #[test]
    fn an_undeclared_code_reaches_no_class() {
        let other = serde_json::json!({"exitCode": 2});
        assert_eq!(
            classify(&other, "example-program", &signatures()).class,
            Class::Unknown
        );
        // And with NO signatures declared, nothing is recognised at all — the
        // consumer's config is the authority, so an empty one advises nothing.
        assert_eq!(
            classify(
                &serde_json::json!({"exitCode": 127}),
                "example-program",
                &[]
            )
            .class,
            Class::Unknown
        );
    }

    /// A human sentence where a code might be is not coerced into one.
    #[test]
    fn a_sentence_is_never_read_as_a_code() {
        let observed = serde_json::json!({"returnCodeInterpretation": "Files differ"});
        assert_eq!(structured_code(&observed), None);
        assert_eq!(
            classify(&observed, "diff a b", &signatures()).class,
            Class::Unknown
        );
    }

    /// The outcome carries no byte of the payload (rule 4).
    #[test]
    fn an_outcome_carries_no_payload() {
        let secretish = serde_json::json!({
            "stdout": "token=SUPERSECRET",
            "stderr": "sh: 1: example-program: not found",
            "exitCode": 127,
        });
        let outcome = classify(&secretish, "example-program --flag", &signatures());
        let rendered = serde_json::to_string(&outcome).expect("the outcome serialises");
        assert!(!rendered.contains("SUPERSECRET"));
        assert!(!rendered.contains("not found"));
        assert_eq!(outcome.token.as_deref(), Some("example-program"));
    }

    /// The rate-limit key is one key over the three things the row names, and it
    /// carries no raw session token.
    #[test]
    fn the_rate_limit_key_covers_session_tool_and_class() {
        let one = advice_key("sess-a", "Bash", Class::CommandNotFound);
        assert!(!one.contains("sess-a"), "the session is hashed");
        assert_ne!(one, advice_key("sess-b", "Bash", Class::CommandNotFound));
        assert_ne!(one, advice_key("sess-a", "Shell", Class::CommandNotFound));
        assert_ne!(one, advice_key("sess-a", "Bash", Class::PermissionDenied));
        assert_eq!(one, advice_key("sess-a", "Bash", Class::CommandNotFound));
    }

    #[test]
    fn a_row_naming_an_unresolvable_class_is_refused_at_load() {
        let bogus = vec![Signature {
            class: "invented".to_owned(),
            code: 1,
            family: "unix".to_owned(),
        }];
        assert!(validate(&bogus).is_err());
        assert!(validate(&signatures()).is_ok());
    }

    #[test]
    fn an_unsurveyed_family_and_a_duplicate_code_are_each_refused() {
        let elsewhere = vec![Signature {
            class: "command-not-found".to_owned(),
            code: 127,
            family: "plan9".to_owned(),
        }];
        assert!(validate(&elsewhere).is_err());

        let mut twice = signatures();
        twice.push(Signature {
            class: "permission-denied".to_owned(),
            code: 127,
            family: "unix".to_owned(),
        });
        assert!(
            validate(&twice).is_err(),
            "two rows on one (code, family) would make the answer depend on table order"
        );
    }

    /// Every class has its own token, and only the could-not-look one is silent.
    #[test]
    fn every_class_is_distinct_and_only_unknown_is_silent() {
        let classes = [
            Class::CommandNotFound,
            Class::PermissionDenied,
            Class::UnsupportedOption,
            Class::Unknown,
        ];
        let tokens: std::collections::BTreeSet<&str> =
            classes.iter().map(|class| class.as_str()).collect();
        assert_eq!(tokens.len(), classes.len());
        for class in classes {
            assert_eq!(class.advisable(), class != Class::Unknown);
        }
    }
}
