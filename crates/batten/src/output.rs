//! The verbosity ladder and the attended/unattended layer (house-style §3, §4).
//!
//! Two settings, resolved once, at the binary boundary:
//!
//! * **How much to say** — [`Verbosity`], a total order from `silent` to
//!   `trace`, selected by the §3 flag ladder or by `BATTEN_LOG_LEVEL`.
//! * **Who is reading** — whether stderr is a terminal, and therefore whether
//!   colour and prompting are appropriate at all (§4).
//!
//! ## The one property that makes `-J` safe
//!
//! Verbosity shapes **stderr only**. The data channel — the `-J` document, a
//! findings pointer line, an epoch value — is the answer to the question that
//! was asked, and an answer is not chatter: it is emitted whole or the command
//! did not run. That is not a rule anyone has to remember, because the types
//! make it unreachable. [`Mode`] is consumed here and in the binary; the
//! data-emitting functions in [`crate::run`] take `out: &mut dyn Write` and
//! **have no `Mode` to consult**, so no rung can gate stdout and colour can
//! never leak onto a parsed stream.
//!
//! ## Ungated by design
//!
//! [`verdict`] and [`error`] ignore the ladder. A verdict is the answer a
//! mediating harness reads back as the refusal reason, and exit `1` is defined
//! by [`crate::exit`] as *fail loud, do not block* — a statement about the
//! invocation, not chatter about it. `--silent` silencing either would turn the
//! one message several gates depend on into an empty stderr with a bare code.
//! [`tests::a_usage_error_is_loud_even_under_silent`] pins it.
//!
//! ## Last flag wins, and why the position is read from `argv`
//!
//! §3's tie-break is *position*: the rightmost ladder flag selects the rung, and
//! its own repetitions step further from `normal` (`-vv` is `debug`). That is
//! deliberately **not** derived from `clap`'s recorded argument indices, which
//! are not comparable across the subcommand boundary — a fresh parser starts its
//! counter at zero for an ordinary subcommand, so `batten --verbose check
//! --quiet` records both at the same index and the winner would fall out of
//! declaration order. The ladder is therefore read from the raw argument list,
//! whose order is the only total one available, with the value-consuming
//! spellings skipped as *derived* from [`crate::surface`] rather than listed
//! again here.
//!
//! The scan stops at `--`. Everything after it belongs to a wrapped command
//! (`batten exec`), never to Batten, and `surface`'s trailing-variadic declaration
//! makes that separator mandatory so the boundary is unambiguous for both parsers.

use std::ffi::OsStr;
use std::io::Write;

use anyhow::Result;
use clap::ValueEnum;

use crate::UsageError;
use crate::surface;

/// How much Batten says on stderr, quietest first.
///
/// The derived [`Ord`] is the ladder: `Silent < Quiet < Normal < Verbose < Debug
/// < Trace`, which is what makes [`Verbosity::admits`] a comparison rather than
/// a table anyone maintains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[non_exhaustive]
pub enum Verbosity {
    /// Say nothing but a verdict or a usage error.
    Silent,
    /// Suppress ordinary progress; keep warnings.
    Quiet,
    /// The default.
    Normal,
    /// Explain what is being checked.
    Verbose,
    /// Add resolution detail.
    Debug,
    /// Add everything.
    Trace,
}

impl Verbosity {
    /// Every rung, so anything ranging over the ladder is derived rather than
    /// re-typed — the token parse, the surface's rung census, and the
    /// total-order test all read this one list.
    pub const ALL: &'static [Verbosity] = &[
        Verbosity::Silent,
        Verbosity::Quiet,
        Verbosity::Normal,
        Verbosity::Verbose,
        Verbosity::Debug,
        Verbosity::Trace,
    ];

    /// The default rung, and the origin the ladder is measured from.
    pub const DEFAULT: Verbosity = Verbosity::Normal;

    /// The rung's token, as `--log-level` and `BATTEN_LOG_LEVEL` spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Verbosity::Silent => "silent",
            Verbosity::Quiet => "quiet",
            Verbosity::Normal => "normal",
            Verbosity::Verbose => "verbose",
            Verbosity::Debug => "debug",
            Verbosity::Trace => "trace",
        }
    }

    /// The rung named by `token`, or `None` if it names none.
    ///
    /// Derived from [`Verbosity::ALL`] and [`Verbosity::as_str`], so the
    /// accepted spellings are exactly the emitted ones by construction.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Verbosity> {
        Verbosity::ALL
            .iter()
            .copied()
            .find(|rung| rung.as_str() == token)
    }

    /// Step `extra` further rungs in the direction this rung lies from
    /// [`Verbosity::DEFAULT`], clamped at the end of the ladder.
    ///
    /// The one rule behind repetition: `-v` selects `Verbose`, and the second
    /// `-v` asks for one rung *further from normal* rather than for a second
    /// independent setting — so `-vv` is `debug` and `-vvvv` is `trace` rather
    /// than an error. `Normal.further(n)` is `Normal`: there is no direction to
    /// step in, which is why no flag selects it.
    #[must_use]
    pub fn further(self, extra: u8) -> Verbosity {
        if extra == 0 || self == Verbosity::DEFAULT {
            return self;
        }
        let steps = usize::from(extra);
        // `ALL` is the ladder in order, so "further from normal" is an index
        // walk in the sign of the offset, saturating at either end.
        let here = Verbosity::ALL
            .iter()
            .position(|rung| *rung == self)
            .unwrap_or(2);
        let origin = Verbosity::ALL
            .iter()
            .position(|rung| *rung == Verbosity::DEFAULT)
            .unwrap_or(2);
        let index = if here < origin {
            here.saturating_sub(steps)
        } else {
            (here + steps).min(Verbosity::ALL.len() - 1)
        };
        Verbosity::ALL.get(index).copied().unwrap_or(self)
    }

    /// Whether a message declared at `rung` is said at this verbosity.
    #[must_use]
    pub fn admits(self, rung: Verbosity) -> bool {
        self >= rung
    }
}

/// The environment variables §4 reads to decide whether a human is watching.
///
/// Declared as one list so [`tests::every_declared_signal_is_actually_read`] can
/// prove each is actually consulted: a signal documented and never read is the
/// same defect class as an env var declared on a flag and applied by nobody
/// (CLOUD-31).
pub const SIGNALS: &[&str] = &["NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "TERM", "CI"];

/// The presentation flags as they appeared on the command line.
///
/// Flags only — the flag layer of §8's chain. Environment equivalents are
/// applied by [`resolve_with`], which is what keeps flag-beats-env true in one
/// place instead of at each call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Presentation {
    /// The rung the ladder selected, or `None` when no ladder flag was passed.
    pub verbosity: Option<Verbosity>,
    /// `--no-color`.
    pub no_color: bool,
    /// `--no-input`: never prompt, whatever stderr is attached to.
    pub no_input: bool,
    /// `-y --yes`: the caller has pre-answered the confirmation a `destructive`
    /// verb would otherwise refuse for (§5).
    pub yes: bool,
}

/// The resolved output mode: what to say, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Mode {
    /// The resolved rung.
    pub verbosity: Verbosity,
    /// Whether stderr may carry colour.
    pub color: bool,
    /// Whether the run is unattended: no prompting, no decoration.
    pub machine: bool,
    /// Whether a `destructive` operation has been confirmed (§5's `-y --yes`).
    ///
    /// Resolved here rather than read per verb so the answer to "may this
    /// invocation destroy something" has one derivation, beside the other §4
    /// signals it belongs with.
    pub confirmed: bool,
}

impl Default for Mode {
    /// The mode to report an error under when resolution itself failed.
    ///
    /// Loud, uncoloured, unattended — the reading that cannot hide a message.
    fn default() -> Mode {
        Mode {
            verbosity: Verbosity::DEFAULT,
            color: false,
            machine: true,
            // Never confirmed by default: the mode used when resolution itself
            // failed must not be the one that authorizes a removal.
            confirmed: false,
        }
    }
}

/// Read one environment variable, treating an empty value as **unset**.
///
/// Not a convenience: `BATTEN_QUIET=` in a CI file means "I cleared this", and
/// reading an empty string as a trigger is how an unset override silently
/// applies. The same reading [`crate::resolve`] uses for its own layers.
fn present(env: &dyn Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    env(key).filter(|value| !value.is_empty())
}

/// Resolve the output mode from the real environment and the real terminals.
///
/// # Errors
///
/// Returns a [`UsageError`] when `BATTEN_LOG_LEVEL` names no rung — a bad
/// override is refused rather than rounded to a default, because silently
/// choosing `normal` for a typo would hide the very setting the caller asked
/// for.
pub fn resolve(flags: &Presentation) -> Result<Mode> {
    use std::io::IsTerminal;
    resolve_with(
        flags,
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
        &|key| std::env::var(key).ok(),
    )
}

/// Resolve the output mode from explicit inputs.
///
/// The TTY booleans and the environment reader are parameters rather than
/// ambient reads so the attended halves of §4 are testable without a PTY, and so
/// the production path needs no test-only branch (CLOUD-107 drives the real
/// terminal cases).
///
/// `stdout_tty` is read and deliberately governs **nothing but the record**:
/// stdout is the answer channel, so a terminal there must not add colour to a
/// document a caller may be parsing. Keeping the parameter means the asymmetry
/// is visible rather than an omission.
///
/// # Errors
///
/// As [`resolve`].
pub fn resolve_with(
    flags: &Presentation,
    stdout_tty: bool,
    stderr_tty: bool,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Mode> {
    let _ = stdout_tty;
    // Flag beats env (§8). The env value is parsed even when a flag won, so a
    // typo is still refused rather than becoming invisible behind a flag.
    let from_env = match present(env, LOG_LEVEL_ENV) {
        Some(token) => Some(Verbosity::from_token(&token).ok_or_else(|| {
            UsageError::raise(format!(
                "{LOG_LEVEL_ENV}: {token:?} names no verbosity; expected one of {}",
                Verbosity::ALL
                    .iter()
                    .map(|rung| rung.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?),
        None => None,
    };
    let verbosity = flags.verbosity.or(from_env).unwrap_or(Verbosity::DEFAULT);

    let no_color = flags.no_color || present(env, NO_COLOR_ENV).is_some();
    let no_input = flags.no_input || present(env, NO_INPUT_ENV).is_some();
    // Flag or env, the same disjunction every presentation boolean uses. It
    // never interacts with `machine`: attendedness says whether a prompt could
    // be answered, and this says whether the answer was already given.
    let confirmed = flags.yes || present(env, YES_ENV).is_some();

    // §4: absence of a terminal is the primary signal, and every other one only
    // ever forces machine mode — never back out of it. `TERM=dumb` is a terminal
    // that has told us it cannot render, which is the same answer as no terminal.
    let machine = !stderr_tty
        || no_input
        || present(env, "CI").is_some()
        || present(env, "TERM").as_deref() == Some("dumb")
        || present(env, "NO_COLOR").is_some();

    // `CLICOLOR_FORCE` is the one signal that overrides the absence of a
    // terminal, which is the whole point of it: a caller piping into a pager
    // that renders ANSI is asking for colour explicitly.
    let color = present(env, "CLICOLOR_FORCE").is_some()
        || (!no_color
            && present(env, "NO_COLOR").is_none()
            && present(env, "CLICOLOR").as_deref() != Some("0")
            && stderr_tty
            && !machine);

    Ok(Mode {
        verbosity,
        color,
        machine,
        confirmed,
    })
}

/// `BATTEN_LOG_LEVEL`, the one environment equivalent the ladder carries.
///
/// One variable rather than five booleans, and §3's "a key where it makes sense"
/// is what settles it: on a command line the ladder's tie-break is *position*,
/// and the environment has none — so `BATTEN_QUIET` and `BATTEN_VERBOSE` both
/// set would reintroduce exactly the ambiguity the ladder exists to remove.
pub const LOG_LEVEL_ENV: &str = "BATTEN_LOG_LEVEL";
/// `BATTEN_NO_COLOR`, the env equivalent of `--no-color`.
pub const NO_COLOR_ENV: &str = "BATTEN_NO_COLOR";
/// `BATTEN_NO_INPUT`, the env equivalent of `--no-input`.
pub const NO_INPUT_ENV: &str = "BATTEN_NO_INPUT";
/// `BATTEN_YES`, the env equivalent of `-y --yes`.
pub const YES_ENV: &str = "BATTEN_YES";

/// The ladder flags, as the raw-argv scan recognises them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ladder {
    Fixed(Verbosity),
    Named,
}

/// The ladder flag a token selects, if it is one.
fn ladder_of(token: &str) -> Option<Ladder> {
    match token {
        "--silent" => Some(Ladder::Fixed(Verbosity::Silent)),
        "--quiet" | "-q" => Some(Ladder::Fixed(Verbosity::Quiet)),
        "--verbose" | "-v" => Some(Ladder::Fixed(Verbosity::Verbose)),
        "--debug" => Some(Ladder::Fixed(Verbosity::Debug)),
        "--trace" => Some(Ladder::Fixed(Verbosity::Trace)),
        "--log-level" => Some(Ladder::Named),
        _ => None,
    }
}

/// Split a clustered short run (`-vv`, `-qv`) into its individual flags.
///
/// `clap` accepts the cluster, so the scan has to as well or `-vv` would select
/// nothing while the parser accepted it — a divergence visible only as a rung
/// that quietly did not apply. Only the counted ladder shorts cluster; anything
/// else passes through untouched.
fn expand_clusters<I, S>(argv: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut out = Vec::new();
    for raw in argv {
        let token = raw.as_ref().to_string_lossy().into_owned();
        let clustered = token.len() > 2
            && token.starts_with('-')
            && !token.starts_with("--")
            && token
                .chars()
                .skip(1)
                .all(|letter| letter == 'q' || letter == 'v');
        if clustered {
            out.extend(token.chars().skip(1).map(|letter| format!("-{letter}")));
        } else {
            out.push(token);
        }
    }
    out
}

impl Presentation {
    /// Read the presentation flags out of a raw argument list, in order.
    ///
    /// The rightmost ladder flag wins and its own consecutive repetitions step
    /// further from `normal`; see the module docs for why position is read here
    /// rather than from `clap`.
    ///
    /// A value-consuming flag's value is skipped so it can never be mistaken for
    /// a ladder token, and which spellings those are is **derived** from
    /// [`surface::consumes_a_value`] rather than listed again.
    #[must_use]
    pub fn from_argv<I, S>(argv: I) -> Presentation
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let tokens = expand_clusters(argv);
        let mut flags = Presentation::default();
        let mut last: Option<(Ladder, u8)> = None;
        let mut named: Option<Verbosity> = None;
        let mut index = 0;

        while let Some(raw) = tokens.get(index) {
            index += 1;
            // `--` ends Batten's argv and begins another program's (`batten exec`).
            // Everything past it is the child's, so scanning on would let a wrapped
            // command's own `-v` select Batten's verbosity rung — measured, before
            // this stop existed, on `batten exec -- cargo test -v`.
            if raw == "--" {
                break;
            }
            // `--log-level=trace` and `--log-level trace` are the same setting.
            let (token, inline) = match raw.split_once('=') {
                Some((name, value)) if name.starts_with("--") => {
                    (name.to_owned(), Some(value.to_owned()))
                }
                _ => (raw.clone(), None),
            };
            match token.as_str() {
                "--no-color" => {
                    flags.no_color = true;
                    continue;
                }
                "--no-input" => {
                    flags.no_input = true;
                    continue;
                }
                // Both spellings, because `expand_clusters` splits `-vy` into
                // `-v -y` and a caller writing the short form gets the same
                // answer as one writing the long.
                "--yes" | "-y" => {
                    flags.yes = true;
                    continue;
                }
                _ => {}
            }
            match ladder_of(&token) {
                Some(Ladder::Named) => {
                    let value = if inline.is_some() {
                        inline
                    } else {
                        let value = tokens.get(index).cloned();
                        index += 1;
                        value
                    };
                    // An unparseable token here is left as "no rung selected";
                    // `clap`'s own value parser is what refuses it, with the
                    // usage message it has already composed.
                    named = value.as_deref().and_then(Verbosity::from_token);
                    last = Some((Ladder::Named, 1));
                }
                Some(rung) => {
                    last = match last {
                        Some((previous, count)) if previous == rung => {
                            Some((rung, count.saturating_add(1)))
                        }
                        _ => Some((rung, 1)),
                    };
                }
                // Not a ladder flag: skip a value it consumes, so a value
                // spelled like a rung can never select one.
                None => {
                    if inline.is_none() && surface::consumes_a_value(&token) {
                        index += 1;
                    }
                }
            }
        }
        flags.verbosity = match last {
            Some((Ladder::Fixed(rung), count)) => Some(rung.further(count.saturating_sub(1))),
            Some((Ladder::Named, _)) => named,
            None => None,
        };
        flags
    }
}

/// Say something on stderr, if the resolved rung admits it.
///
/// The gated channel: progress, explanation, and warnings. `rung` is the
/// verbosity at which the message becomes worth saying, so a `Normal` message is
/// suppressed by `-q` and a `Verbose` one appears only when asked for.
///
/// # Errors
///
/// Propagates the writer's error.
pub fn message(
    mode: Mode,
    rung: Verbosity,
    err: &mut dyn Write,
    text: &str,
) -> std::io::Result<()> {
    if !mode.verbosity.admits(rung) {
        return Ok(());
    }
    writeln!(err, "batten: {text}")
}

/// Report a failure on stderr. **Never gated.**
///
/// Exit `1` is defined as *fail loud, do not block*: it is an answer about the
/// invocation, and a caller that asked for `--silent` asked for less chatter,
/// not for a bare non-zero code with no reason. `mode` is consulted for colour
/// only.
///
/// # Errors
///
/// Propagates the writer's error.
pub fn error(mode: Mode, err: &mut dyn Write, text: &str) -> std::io::Result<()> {
    if mode.color {
        writeln!(err, "\x1b[31mbatten:\x1b[0m {text}")
    } else {
        writeln!(err, "batten: {text}")
    }
}

/// Write a mediation verdict on stderr, unprefixed and **never gated**.
///
/// A hook host hands stderr back to the model as the refusal reason, so a
/// `batten: ` prefix there reads as a tool crash and a suppressed one reads as
/// an unexplained deny. Uncoloured for the same reason: the reason is consumed
/// by a program.
///
/// # Errors
///
/// Propagates the writer's error.
pub fn verdict(err: &mut dyn Write, text: &str) -> std::io::Result<()> {
    writeln!(err, "{text}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// An environment reader over an explicit list, recording every key read.
    struct Env {
        values: Vec<(&'static str, &'static str)>,
        read: RefCell<Vec<String>>,
    }

    impl Env {
        fn new(values: &[(&'static str, &'static str)]) -> Env {
            Env {
                values: values.to_vec(),
                read: RefCell::new(Vec::new()),
            }
        }

        fn reader(&self) -> impl Fn(&str) -> Option<String> + '_ {
            |key: &str| {
                self.read.borrow_mut().push(key.to_owned());
                self.values
                    .iter()
                    .find(|(name, _)| *name == key)
                    .map(|(_, value)| (*value).to_owned())
            }
        }
    }

    fn mode(values: &[(&'static str, &'static str)], stderr_tty: bool) -> Mode {
        let env = Env::new(values);
        resolve_with(&Presentation::default(), false, stderr_tty, &env.reader()).unwrap()
    }

    #[test]
    fn the_ladder_is_a_total_order_over_all() {
        // The comparison in `admits` is only meaningful if `ALL` is sorted and
        // has no duplicate — otherwise a rung would admit itself and not its
        // neighbour, which is unobservable without this.
        let mut sorted = Verbosity::ALL.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, Verbosity::ALL.to_vec());
    }

    #[test]
    fn every_rung_round_trips_through_its_token() {
        for rung in Verbosity::ALL {
            assert_eq!(Verbosity::from_token(rung.as_str()), Some(*rung));
        }
        assert_eq!(Verbosity::from_token("chatty"), None);
    }

    #[test]
    fn repetition_steps_one_rung_further_from_normal() {
        assert_eq!(Verbosity::Verbose.further(0), Verbosity::Verbose);
        assert_eq!(Verbosity::Verbose.further(1), Verbosity::Debug);
        assert_eq!(Verbosity::Verbose.further(2), Verbosity::Trace);
        // Clamped, never an error: asking for more than the ladder has is a
        // request for "as much as possible".
        assert_eq!(Verbosity::Verbose.further(9), Verbosity::Trace);
        assert_eq!(Verbosity::Quiet.further(1), Verbosity::Silent);
        assert_eq!(Verbosity::Quiet.further(9), Verbosity::Silent);
        // Normal has no direction to step in, which is why no flag selects it.
        assert_eq!(Verbosity::DEFAULT.further(3), Verbosity::DEFAULT);
    }

    #[test]
    fn machine_mode_is_forced_by_every_signal() {
        // Acceptance (a). Each signal alone is enough; none of them can turn
        // machine mode back off, which is the direction that matters.
        assert!(mode(&[], false).machine, "no terminal");
        assert!(mode(&[("CI", "1")], true).machine, "CI");
        assert!(mode(&[("TERM", "dumb")], true).machine, "TERM=dumb");
        assert!(mode(&[("NO_COLOR", "1")], true).machine, "NO_COLOR");
        let flags = Presentation {
            no_input: true,
            ..Presentation::default()
        };
        let env = Env::new(&[]);
        assert!(
            resolve_with(&flags, true, true, &env.reader())
                .unwrap()
                .machine,
            "--no-input"
        );
    }

    #[test]
    fn every_declared_signal_is_actually_read() {
        // A documented signal nobody consults is the CLOUD-31 defect class: it
        // describes behaviour that silently does not happen.
        let env = Env::new(&[]);
        resolve_with(&Presentation::default(), true, true, &env.reader()).unwrap();
        let read = env.read.borrow();
        for signal in SIGNALS {
            assert!(read.iter().any(|key| key == signal), "{signal} is not read");
        }
    }

    #[test]
    fn an_empty_signal_is_unset_not_a_trigger() {
        // `CI=` in a shell profile means "cleared". Reading it as set is how an
        // unset override silently applies.
        assert!(!mode(&[("CI", "")], true).machine);
        assert!(mode(&[("NO_COLOR", "")], true).color);
    }

    #[test]
    fn a_piped_stream_resolves_to_no_colour() {
        // Acceptance (b): the unattended default is plain.
        assert!(!mode(&[], false).color);
        assert!(mode(&[], true).color, "an attended stderr may colour");
    }

    #[test]
    fn forced_colour_overrides_an_absent_terminal() {
        assert!(mode(&[("CLICOLOR_FORCE", "1")], false).color);
        assert!(!mode(&[("CLICOLOR", "0")], true).color);
    }

    #[test]
    fn an_unparseable_log_level_env_value_is_a_usage_error() {
        let env = Env::new(&[(LOG_LEVEL_ENV, "chatty")]);
        let err = resolve_with(&Presentation::default(), false, false, &env.reader())
            .expect_err("a bogus rung is refused");
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a bad override is exit 1, never a rounded default: {err}"
        );
    }

    #[test]
    fn a_flag_beats_the_environment_but_a_typo_is_still_refused() {
        let env = Env::new(&[(LOG_LEVEL_ENV, "trace")]);
        let flags = Presentation {
            verbosity: Some(Verbosity::Quiet),
            ..Presentation::default()
        };
        assert_eq!(
            resolve_with(&flags, false, false, &env.reader())
                .unwrap()
                .verbosity,
            Verbosity::Quiet
        );
        let env = Env::new(&[(LOG_LEVEL_ENV, "chatty")]);
        assert!(resolve_with(&flags, false, false, &env.reader()).is_err());
    }

    #[test]
    fn every_presentation_env_reaches_the_resolved_mode() {
        let base = mode(&[], true);
        assert_ne!(
            mode(&[(LOG_LEVEL_ENV, "trace")], true).verbosity,
            base.verbosity
        );
        assert_ne!(mode(&[(NO_COLOR_ENV, "1")], true).color, base.color);
        assert_ne!(mode(&[(NO_INPUT_ENV, "1")], true).machine, base.machine);
    }

    // -- The argv scan: position is the tie-break. --

    fn ladder(argv: &[&str]) -> Option<Verbosity> {
        Presentation::from_argv(argv).verbosity
    }

    #[test]
    fn no_ladder_flag_selects_no_rung() {
        assert_eq!(ladder(&["check"]), None);
    }

    #[test]
    fn the_last_ladder_flag_wins_across_the_subcommand_boundary() {
        // Acceptance (c), and the discriminator a `clap`-index implementation
        // would pass while broken: the two rungs sit on opposite sides of the
        // verb, where clap's own indices tie.
        assert_eq!(
            ladder(&["--verbose", "check", "--quiet"]),
            Some(Verbosity::Quiet)
        );
        assert_eq!(
            ladder(&["--quiet", "check", "--verbose"]),
            Some(Verbosity::Verbose)
        );
        assert_ne!(
            ladder(&["-q", "check", "-v"]),
            ladder(&["-v", "check", "-q"]),
            "the two orders must not resolve identically"
        );
    }

    #[test]
    fn repeating_a_flag_reaches_the_next_tier() {
        assert_eq!(ladder(&["-v", "-v", "check"]), Some(Verbosity::Debug));
        assert_eq!(ladder(&["-q", "-q", "check"]), Some(Verbosity::Silent));
        // A different flag in between resets the run, because the last flag is
        // the one that selected the rung.
        assert_eq!(
            ladder(&["-v", "-q", "-v", "check"]),
            Some(Verbosity::Verbose)
        );
    }

    #[test]
    fn the_named_rung_is_read_in_both_spellings() {
        assert_eq!(ladder(&["--log-level", "debug"]), Some(Verbosity::Debug));
        assert_eq!(ladder(&["--log-level=debug"]), Some(Verbosity::Debug));
    }

    #[test]
    fn a_value_is_never_mistaken_for_a_ladder_flag() {
        // Derived from the surface, so a new value-taking flag needs no edit
        // here: `--strictness` consumes its token, and a value spelled like a
        // rung must not select one.
        assert_eq!(ladder(&["--strictness", "strict", "check"]), None);
        assert_eq!(ladder(&["--config-from", "-v", "check"]), None);
    }

    #[test]
    fn the_scan_stops_at_the_argv_separator() {
        // A wrapped command's flags are not Batten's. Without this, `batten exec --
        // cargo test -v` raised Batten's verbosity and the child still got its
        // flag, so the rung moved for a reason nobody typed.
        assert_eq!(ladder(&["exec", "--", "cargo", "test", "-v"]), None);
        assert_eq!(ladder(&["exec", "--", "sh", "-c", "--silent"]), None);
        // Batten's own flags before the separator still count.
        assert_eq!(
            ladder(&["-q", "exec", "--", "cargo", "test", "-v"]),
            Some(Verbosity::Quiet)
        );
    }

    #[test]
    fn the_presentation_booleans_are_read_anywhere_on_the_line() {
        let flags = Presentation::from_argv(["check", "--no-color", "--no-input"]);
        assert!(flags.no_color && flags.no_input);
    }

    // -- What the ladder may and may not silence. --

    #[test]
    fn silent_suppresses_messages_but_never_a_verdict() {
        let quiet = Mode {
            verbosity: Verbosity::Silent,
            ..Mode::default()
        };
        let mut buffer = Vec::new();
        message(quiet, Verbosity::Normal, &mut buffer, "checking").unwrap();
        assert!(buffer.is_empty(), "a normal message is silenced");
        verdict(&mut buffer, "Refused by a-rule: because").unwrap();
        assert!(
            String::from_utf8(buffer).unwrap().starts_with("Refused by"),
            "a verdict is never gated, and never prefixed"
        );
    }

    #[test]
    fn a_usage_error_is_loud_even_under_silent() {
        // The bundle-wide invariant: exit 1 is "fail loud, do not block", and
        // several gates read the message rather than the code.
        let quiet = Mode {
            verbosity: Verbosity::Silent,
            ..Mode::default()
        };
        let mut buffer = Vec::new();
        error(quiet, &mut buffer, "no config found").unwrap();
        assert!(!buffer.is_empty(), "a usage error is never silenced");
    }

    #[test]
    fn a_message_appears_once_its_rung_is_admitted() {
        let loud = Mode {
            verbosity: Verbosity::Verbose,
            ..Mode::default()
        };
        let mut buffer = Vec::new();
        message(loud, Verbosity::Verbose, &mut buffer, "resolving").unwrap();
        assert!(String::from_utf8(buffer).unwrap().contains("resolving"));
    }

    #[test]
    fn colour_is_the_only_thing_a_mode_changes_about_an_error() {
        let plain = Mode::default();
        let coloured = Mode {
            color: true,
            ..Mode::default()
        };
        let mut a = Vec::new();
        let mut b = Vec::new();
        error(plain, &mut a, "boom").unwrap();
        error(coloured, &mut b, "boom").unwrap();
        assert_ne!(a, b);
        assert!(String::from_utf8(a).unwrap().contains("boom"));
        assert!(String::from_utf8(b).unwrap().contains("boom"));
    }
}
