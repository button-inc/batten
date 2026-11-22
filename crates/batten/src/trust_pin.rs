//! The base-ref authority and its last-known-good pin (house-style §8 and §4,
//! CLOUD-31, CLOUD-720): read the committed `batten.toml` at a git ref, and
//! answer an unreachable ref from the last validated config only where the call
//! and the pinned config both permit it.
//!
//! # Why this is its own module, below `resolve`
//!
//! It was the first half of `trust`, and `resolve` called it to load layer 1
//! from a ref. CLOUD-359's table forbids `resolve -> trust`, and the `uses`
//! fact never saw the edge: every reach was a qualified path
//! (`crate::trust::load(..)` as it then was), and the fact read `use` items alone until its
//! `qualified` field. Once the gate could see the edge, the honest fix was the
//! layer, not an exemption: loading a config at a ref reads `git`, `config`
//! and `state` and judges nothing, while `trust` proper (naming what a working
//! tree WEAKENED) is a judgement over two loaded configs. So the read sits
//! below `resolve` and the judgement stays above it.

use std::path::Path;

use anyhow::Result;

use crate::UsageError;
use crate::config_model::Config;
use crate::git;

/// The config parser a ref read hands its bytes to: `config::parse_base` at
/// every production call site, named by the CALLER.
///
/// A parameter rather than a call because the parser lives in `config`, which
/// sits inside the crate's largest cycle (`modules.lock`), and a direct call
/// put this module in that cycle with it: measured, cycle 61 -> 62 on the
/// commit that split this module out. Taking the parser as an argument keeps
/// the read below every module that reaches it, and it costs each caller one
/// word that says which grammar a ref's bytes are judged by.
pub type ParseBase = fn(&str, &str) -> Result<Config>;

/// Load the committed authority from a git ref instead of the working tree.
///
/// The strict reading, and the one every caller that must not degrade keeps:
/// both unreadable states collapse into one refusal. [`load`] is the same read
/// with the states returned as values, for the two callers that implement §4's
/// lifecycle.
///
/// # Errors
///
/// Returns a [`crate::UsageError`] (→ exit `1`) when the ref is unknown, the
/// config is absent at that ref, or it fails to parse — every one a statement
/// about the *invocation*, never a policy verdict.
pub fn load_base(dir: &Path, reference: &str, parse: ParseBase) -> Result<Config> {
    match load(dir, reference, OfflineFallback::Refuse, parse)? {
        Load::Loaded(loaded) => Ok(loaded.config),
        Load::RefUnreachable { reference } => Err(UsageError::raise(format!(
            "cannot resolve {reference} in this repository"
        ))),
        Load::AbsentAtRef { reference } => Err(UsageError::raise(format!(
            "{} is absent at {reference}",
            crate::config_model::CONFIG_FILE
        ))),
    }
}

/// Where the config a run was judged by actually came from.
///
/// Modelled on [`crate::git::Evidence`]: every variant that means "this config
/// governed the run" names what proves it, and [`Provenance::Pin`] cannot be
/// spelled without a [`PinEvidence`] — so "degraded, holding no pin" is not a
/// state this type can represent. [`Pin::verify`] is the only constructor of
/// that evidence, and it is private to this module.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Provenance {
    /// Read from the ref the caller named, at `commit`.
    Ref { reference: String, commit: String },
    /// Served from the last validated config, because the ref was unreachable
    /// and `[trust] offline_fallback` said it may be.
    Pin(PinEvidence),
}

/// What a served pin is, and what proves it is the config it claims to be.
///
/// The digest is [`crate::identity::surface_fingerprint`] over the one pinned
/// file — `epoch`'s own hashing, so the pin is checked with the construction
/// this crate already uses for config bytes rather than a second one. It is
/// **self-verification**: it catches truncation and corruption between the run
/// that minted the pin and the run that serves it.
///
/// It is deliberately **not** a defence against an attacker who can write
/// `state_home`, who could recompute the digest over bytes of their choosing.
/// Closing that is §8's signed content-addressed reference, filed separately;
/// stating the residual here is what keeps a later reader from mistaking this
/// for the stronger property.
///
/// **The fields are private, and that is the guarantee rather than tidiness.**
/// Public fields would make this constructible from a literal by anyone, so
/// [`Provenance::Pin`] would be spellable out of thin air and the promise above
/// would be prose. [`Pin::verify`] is the only place one is built, exactly as
/// `git::verdict` is the only place a [`crate::git::Verdict`] is;
/// `the_pin_evidence_cannot_be_forged` is the source-level gate on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinEvidence {
    /// The ref this pin was minted for. A pin is served only for the same one.
    reference: String,
    /// The commit the pinned bytes were read from.
    commit: String,
    /// The digest that verified them, as an opaque token.
    digest: String,
}

impl PinEvidence {
    /// The ref this pin answers for.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// The commit the pinned bytes came from.
    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }

    /// The digest that verified the pinned bytes.
    ///
    /// An opaque token, never the bytes it covers (non-negotiable rule 4).
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// A config that governed a run, and the proof of where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub config: Config,
    pub provenance: Provenance,
}

/// The outcome of loading the base-ref authority.
///
/// The shape CLOUD-720 exists to reach: `git::show` already told the two
/// unreadable states apart, but `Result<Config>` destroyed the distinction at
/// this boundary, and last-known-good is built entirely on it.
///
/// **Only [`Load::RefUnreachable`] may degrade.** A ref that resolves and
/// declares no `batten.toml` is [`Load::AbsentAtRef`] and refuses in every
/// configuration — otherwise a branch pointing `--config-from` at a config-less
/// ref picks its own policy, the exact substitution the flag exists to defeat.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Load {
    /// A config governs the run; its [`Provenance`] says which source it is.
    ///
    /// Boxed because a whole [`Config`] dwarfs the two refusal arms, and every
    /// caller of [`load`] pays the enum's size on the path where the ref was
    /// unreachable too.
    Loaded(Box<Loaded>),
    /// The revspec does not resolve here, and no pin was served — either
    /// because the key is off, or because there is no valid pin for this ref.
    RefUnreachable { reference: String },
    /// The ref resolves and carries no `batten.toml`. Never degrades.
    AbsentAtRef { reference: String },
}

/// Whether this call is permitted to answer an unreachable ref from a pin.
///
/// A parameter rather than a config read inside [`load`], because the answer is
/// a property of the *call site*: `config epoch --config-from` reads bytes for
/// every `[epoch] tracked` path and a pin carrying one file cannot answer for
/// it, so that caller passes [`OfflineFallback::Refuse`] regardless of what any
/// config says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineFallback {
    /// An unreachable ref refuses. The default everywhere.
    Refuse,
    /// An unreachable ref may be answered from a valid pin, if
    /// `[trust] offline_fallback` is on in the pinned config.
    Permitted,
}

/// Load the base-ref authority, with the two unreadable states as values.
///
/// On a readable ref this also **mints nothing**: writing the pin is the job of
/// the run that reaches a verdict ([`record_pin`]), not of the load, because a
/// config that loaded and then failed the run proved less than "validated".
///
/// # Errors
///
/// Returns a [`crate::UsageError`] (→ exit `1`) when the ref resolves to
/// something unreadable, when the config at it fails to parse, or when a pin
/// exists for this ref and cannot be honoured — see [`Pin::verify`] for why an
/// unreadable *pin* is loud where an unreadable cache is silent.
pub fn load(
    dir: &Path,
    reference: &str,
    fallback: OfflineFallback,
    parse: ParseBase,
) -> Result<Load> {
    match git::read_at(dir, reference, crate::config_model::CONFIG_FILE)? {
        git::BaseBlob::Found { text, commit } => {
            // `parse_base`, never `parse`: a ref carries the config the engine
            // of its day accepted, and a key THIS build has retired must not
            // make the whole comparison unreadable (`crate::config::RETIRED_KEYS`).
            let config = parse(
                &text,
                &format!("{reference}:{}", crate::config_model::CONFIG_FILE),
            )?;
            Ok(Load::Loaded(Box::new(Loaded {
                config,
                provenance: Provenance::Ref {
                    reference: reference.to_owned(),
                    commit,
                },
            })))
        }
        // The one state §4 lets degrade. Everything below still has to hold:
        // the call site must permit it, a pin must exist for THIS ref, it must
        // verify, and the pinned config must itself declare the key.
        git::BaseBlob::RefUnreachable { reference } => {
            if fallback == OfflineFallback::Refuse {
                return Ok(Load::RefUnreachable { reference });
            }
            let Some(pin) = Pin::read(dir, &reference)? else {
                return Ok(Load::RefUnreachable { reference });
            };
            let (config, evidence) = pin.verify(&reference, parse)?;
            // THE PINNED CONFIG'S OWN KEY DECIDES, not the working tree's. The
            // working tree is the change under review; letting it authorise the
            // fallback would be the branch choosing to be judged offline, which
            // is the substitution `--config-from` exists to defeat.
            if !offline_fallback(&config) {
                return Ok(Load::RefUnreachable { reference });
            }
            Ok(Load::Loaded(Box::new(Loaded {
                config,
                provenance: Provenance::Pin(evidence),
            })))
        }
        // Never degrades, in any configuration. There is no branch here to add
        // one to, which is the point of splitting the states rather than adding
        // a flag to one.
        git::BaseBlob::AbsentAtRef { reference, .. } => Ok(Load::AbsentAtRef { reference }),
    }
}

/// Is `[trust] offline_fallback` on in this config?
///
/// An absent `[trust]` table is the strict answer, so the default and the
/// missing table agree by construction rather than by two matching literals.
#[must_use]
pub fn offline_fallback(config: &Config) -> bool {
    config
        .trust
        .as_ref()
        .is_some_and(|trust| trust.offline_fallback)
}

/// The pin's file name inside the per-repository state directory.
///
/// Beside `epoch.json` and `store.json`, and deliberately **not** part of
/// CLOUD-232's cache contract: same directory, different file, different
/// failure semantics. The epoch cache may fail silently because an optimization
/// that can refuse the answer is a defect; a pinned *policy* is the inverse.
const PIN_FILE: &str = "trust-pin.json";

/// The pin format's version. An unrecognised value is refused, not ignored.
const PIN_SCHEMA: u32 = 1;

/// The last validated base-ref config, as it sits on disk.
///
/// One ref per pin, named inside the record rather than encoded in the file
/// name: a ref is `/`-separated and turning one into a filename would invent a
/// sanitisation scheme, and a pin minted for `origin/main` must not answer for
/// `origin/release`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Pin {
    schema: u32,
    reference: String,
    commit: String,
    digest: String,
    config: String,
}

impl Pin {
    /// This repository's pin file, or `None` when no state directory resolves.
    ///
    /// Canonicalized first for `epoch::cache_path`'s reason: callers reach here
    /// with `Path::new(".")`, whose final component is `None`, so
    /// [`crate::state::derive_repo_name`] would refuse it.
    fn path(dir: &Path) -> Option<std::path::PathBuf> {
        let absolute = std::fs::canonicalize(dir).ok()?;
        crate::state::repo_state_dir(&absolute)
            .ok()
            .map(|state| state.join(PIN_FILE))
    }

    /// The pin recorded for `reference`, if there is one.
    ///
    /// **Absent is `None`; unreadable is an error.** The asymmetry is the whole
    /// difference from the epoch cache one file over: a missing pin means this
    /// clone has never validated that ref, which is an ordinary state that
    /// resolves to a refusal. A pin that exists and cannot be read is a
    /// *policy* artifact this run cannot account for, and skipping it would
    /// turn a corrupt file into a silent strict-mode run — safe here, but the
    /// same code path is what a later reader would copy.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::UsageError`] (→ exit `1`) when the file exists and
    /// cannot be read or parsed.
    fn read(dir: &Path, reference: &str) -> Result<Option<Self>> {
        let Some(path) = Self::path(dir) else {
            return Ok(None);
        };
        let text = match crate::fsio::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(UsageError::raise(format!(
                    "the offline config pin at {} cannot be read",
                    path.display()
                )));
            }
        };
        let pin: Pin = serde_json::from_str(&text).map_err(|_| {
            UsageError::raise(format!(
                "the offline config pin at {} is not a pin this build can read",
                path.display()
            ))
        })?;
        // A pin minted for another ref is not this ref's answer, and a pin from
        // a schema this build does not know is not readable. Both are ABSENT
        // rather than corrupt: nothing was tampered with, there is simply no
        // pin here for this question.
        if pin.schema != PIN_SCHEMA || pin.reference != reference {
            return Ok(None);
        }
        Ok(Some(pin))
    }

    /// Check the pinned bytes against their digest and parse them.
    ///
    /// The only constructor of [`PinEvidence`], which is what makes
    /// [`Provenance::Pin`] unspellable without a pin that verified — the same
    /// construction `git::verdict` uses to keep a landed verdict from existing
    /// without its evidence.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::UsageError`] (→ exit `1`) when the digest does not
    /// match the bytes, or when the bytes do not parse as a config. Both refuse
    /// rather than falling through to the strict path: a pin that fails its own
    /// check is a fact about this clone's state that the operator has to see.
    fn verify(self, reference: &str, parse: ParseBase) -> Result<(Config, PinEvidence)> {
        let computed = pin_digest(&self.config);
        if computed != self.digest {
            return Err(UsageError::raise(format!(
                "the offline config pin for {reference} does not match its digest"
            )));
        }
        let config = parse(&self.config, &format!("pin:{reference}"))?;
        Ok((
            config,
            PinEvidence {
                reference: self.reference,
                commit: self.commit,
                digest: self.digest,
            },
        ))
    }
}

/// The digest a pin is verified against: `epoch`'s hashing over the one file.
///
/// [`crate::identity::surface_fingerprint`] rather than a bare `sha256`, so the
/// pin is checked with the domain-tagged construction this crate already uses
/// for config bytes. It coincides with `config_epoch` only for the default
/// `[epoch] tracked` list; it is used here as a self-integrity check, never as
/// an epoch.
fn pin_digest(config: &str) -> String {
    crate::identity::surface_fingerprint(&[(
        crate::config_model::CONFIG_FILE.to_owned(),
        config.as_bytes().to_vec(),
    )])
    .to_hex()
}

/// Record the config a run was judged by, so a later run with an unreachable
/// ref has a last-known-good to serve.
///
/// Called by the run that **reached a verdict**, never by the load: "validated"
/// is scoped to what a single run already proved, and a config that parsed and
/// then failed the run proved less than that.
///
/// Two things it deliberately does not do. It does not mint from a run that was
/// itself served from a pin — that would let one validation refresh itself
/// forever — and it does not fail the run it is called from. The second is the
/// only place this shares the epoch cache's posture, and for a different
/// reason: the verdict is already computed and correct, so refusing to publish
/// it over a full disk would discard an answer to protect a future one.
pub fn record_pin(dir: &Path, loaded: &Loaded) {
    let Provenance::Ref { reference, commit } = &loaded.provenance else {
        return;
    };
    let Ok(text) = toml::to_string(&loaded.config) else {
        return;
    };
    let Some(path) = Pin::path(dir) else { return };
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let pin = Pin {
        schema: PIN_SCHEMA,
        reference: reference.clone(),
        commit: commit.clone(),
        digest: pin_digest(&text),
        config: text,
    };
    let Ok(json) = serde_json::to_string_pretty(&pin) else {
        return;
    };
    // Temp file plus rename inside the state directory, the construction
    // `store::write_record` uses: a concurrent reader sees the old pin or the
    // new one, never a torn one — which `Pin::read` would refuse loudly.
    let temp = parent.join(format!("{PIN_FILE}.{}.tmp", std::process::id()));
    if crate::durable::replace(&temp, format!("{json}\n")).is_err() {
        return;
    }
    if std::fs::rename(&temp, &path).is_err() {
        let _ = std::fs::remove_file(&temp);
    }
}

/// The one line a run served from a pin writes, on the messaging channel.
///
/// Shaped like [`crate::config::DEFAULTS_NOTE`]: it names the consequence and the fix,
/// it is exactly one line, and it goes only to stderr. stdout stays the findings
/// channel and must be byte-identical to the run that read the ref, which is
/// also why no `-J` field pairs with this. A silent degrade is what this exists
/// to make impossible.
#[must_use]
pub fn pinned_note(evidence: &PinEvidence) -> String {
    let commit = evidence.commit();
    format!(
        "{} is unreachable; judging by the last validated config, pinned at {} — fetch the ref to \
         judge by it again",
        evidence.reference(),
        &commit[..commit.len().min(12)]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn config(extra: &str) -> Config {
        config::parse(&format!("version = 1\n{extra}"), "test").unwrap()
    }

    /// A pin is recorded for the ref a run read, read back only for that ref,
    /// verified against its digest, and noted by its ref and short commit.
    #[test]
    fn a_recorded_pin_answers_its_own_ref_and_refuses_tampering() {
        crate::testing::contain_state(&crate::scratch::scratch("trust-data"));
        let dir = crate::scratch::scratch("trust-pin-roundtrip");
        let path = Pin::path(&dir).expect("a state directory resolves");
        assert!(path.ends_with(PIN_FILE), "{}", path.display());
        let _ = std::fs::remove_file(&path);
        assert!(
            Pin::read(&dir, "origin/main").unwrap().is_none(),
            "no pin yet"
        );

        let loaded = Loaded {
            config: config("[trust]\noffline_fallback = true\n"),
            provenance: Provenance::Ref {
                reference: "origin/main".to_owned(),
                commit: "0123456789abcdef0123".to_owned(),
            },
        };
        record_pin(&dir, &loaded);
        assert!(Pin::read(&dir, "origin/other").unwrap().is_none());
        let pin = Pin::read(&dir, "origin/main").unwrap().expect("the pin");
        let (pinned, evidence) = pin
            .clone()
            .verify("origin/main", config::parse_base)
            .unwrap();
        assert!(offline_fallback(&pinned));
        assert_eq!(evidence.reference(), "origin/main");
        assert_eq!(evidence.commit(), "0123456789abcdef0123");
        assert_eq!(evidence.digest(), pin.digest);
        assert_eq!(evidence.digest(), pin_digest(&pin.config));
        assert_eq!(
            pinned_note(&evidence),
            "origin/main is unreachable; judging by the last validated config, pinned at \
             0123456789ab — fetch the ref to judge by it again"
        );

        let mut tampered = pin;
        tampered.config.push_str("\n# edited\n");
        assert!(tampered.verify("origin/main", config::parse_base).is_err());

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir_all(&path).unwrap();
        assert!(
            Pin::read(&dir, "origin/main").is_err(),
            "an unreadable pin is loud"
        );
        std::fs::remove_dir_all(&path).unwrap();
    }

    /// An unreachable ref is answered from its pin only where the call permits
    /// it and the pinned config declares the fallback.
    #[test]
    fn an_unreachable_ref_is_served_from_its_pin_only_where_both_permit() {
        crate::testing::contain_state(&crate::scratch::scratch("trust-data"));
        let dir = crate::scratch::scratch("trust-pin-load");
        crate::gitwrite::init_on_main(&dir).unwrap();
        let reference = "origin/nowhere";
        let pin = |extra: &str| {
            record_pin(
                &dir,
                &Loaded {
                    config: config(extra),
                    provenance: Provenance::Ref {
                        reference: reference.to_owned(),
                        commit: "c0ffee".to_owned(),
                    },
                },
            );
        };
        pin("[trust]\noffline_fallback = true\n");
        assert!(matches!(
            load(&dir, reference, OfflineFallback::Refuse, config::parse_base).unwrap(),
            Load::RefUnreachable { .. }
        ));
        let Load::Loaded(served) = load(
            &dir,
            reference,
            OfflineFallback::Permitted,
            config::parse_base,
        )
        .unwrap() else {
            panic!("a permitted call with a valid pin is served from it");
        };
        assert!(matches!(served.provenance, Provenance::Pin(_)));
        pin("");
        assert!(matches!(
            load(
                &dir,
                reference,
                OfflineFallback::Permitted,
                config::parse_base
            )
            .unwrap(),
            Load::RefUnreachable { .. }
        ));
    }

    #[test]
    fn the_pin_evidence_cannot_be_forged() {
        // THE GATE THAT SHIPS WITH THE CLAIM (non-negotiable rule 2, CLOUD-720).
        // `Provenance`'s doc says a degraded load "is not a state this type can
        // represent" — and that is only true while `PinEvidence` is
        // unconstructible from a literal. It shipped with three `pub` fields, so
        // the promise was prose: any caller could have written
        // `Provenance::Pin(PinEvidence { .. })` out of nothing and produced a
        // run claiming a validation no pin ever backed.
        //
        // Private fields move the guarantee to the crate boundary, which is
        // where the forgery risk is: inside this module the one construction
        // site is `Pin::verify`, and it is reviewable beside the check it
        // performs. `git.rs`'s `no_ancestry_decides_merged_ness` is the shape —
        // scan this file's own source, because the decision lives here and
        // exempting it would gut the gate.
        //
        // The search token is assembled so this test's own source is not a
        // match, and the slice starts AFTER the opening brace: the declaration
        // line is itself `pub`, and reading it as a field is the exact defect
        // this gate had on its first run.
        let source = include_str!("trust_pin.rs");
        let needle = ["pub struct ", "PinEvidence {"].concat();
        let open = source
            .find(&needle)
            .expect("the evidence type is declared here")
            + needle.len();
        let body = &source[open..];
        let fields = &body[..body.find("\n}").expect("the declaration is closed")];
        for line in fields.lines() {
            assert!(
                !line.trim_start().starts_with("pub "),
                "PinEvidence must keep its fields private, or `Provenance::Pin` becomes \
                 spellable from a literal outside this module and the type-level guarantee is \
                 prose. Offending field: {line}"
            );
        }
    }
}
