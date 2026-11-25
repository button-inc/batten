//! The vendored preset catalog (CLOUD-2789): every preset's manifest, as data.
//!
//! The catalog is what the config model's schema names when it lists the
//! presets a row may enable, so it sits below the model. What a preset does
//! with its manifest (ejecting a module, admitting a verdict, resolving one
//! against a consumer's rows) stays in [`crate::preset`], which reads this.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What a route offers the reader.
///
/// **A closed set, deliberately.** The whole defect is a remedy nobody can
/// check; an open `kind` string would put it straight back, because a typo'd
/// kind would be a route that resolves to nothing and refuses nothing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    /// Run something. `target` is the command.
    Command,
    /// Read something in this tree. `target` is a repo-relative path.
    Document,
    /// Take it to the tracker. `target` is the issue key.
    Issue,
    /// Ask for the refusal to be lifted. `target` is unread; `precondition` is
    /// what the asker must be able to state, and is required (CLOUD-1051 reads
    /// it to generate the questions an admission answers).
    Override,
}

impl RouteKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::Command => "command",
            RouteKind::Document => "document",
            RouteKind::Issue => "issue",
            RouteKind::Override => "override",
        }
    }
}

/// What the boundary may DO about a class, beyond naming it (CLOUD-1639).
///
/// **Every refusal in this tree is advice**: a class, its pointers, and routes
/// the agent must walk itself. Two outcomes the field treats as first-class are
/// unrepresentable — *repaired, re-run* and *repaired, proceed* — and
/// [`crate::config_model::Rule::fix`] has existed for them since CLOUD-81, executed by
/// nothing.
///
/// # THE DEFAULT IS `advice`, AND THAT IS WHAT MAKES THIS ADDITIVE
///
/// Absent means today's behaviour, so 200-odd declared classes keep it without
/// restating it and no consumer config changes meaning under an engine that
/// gained this column. `Retry` and `Silent` are opt-in per class and each owes
/// something extra at load — see [`validate`].
///
/// # WHY `retry` IS THE DEFAULT POSTURE FOR A REPAIR AND `silent` THE EXCEPTION
///
/// Not a preference. pre-commit's hook that modifies files FAILS the run and the
/// caller re-runs over the new bytes — there is no silent path (SRC-041); Ruff
/// makes the caller choose with `--exit-non-zero-on-fix` (SRC-047); Kubernetes
/// mutating webhooks apply silently but write `auditAnnotations` (SRC-042). **No
/// surveyed system applies silently and leaves no record.** Measured on agents:
/// feedback-then-retry converged 86.6% against 79.8% for block-and-retry at no
/// utility loss, while silent server-side rewrite converged 96.9% and cost 22.3%
/// utility (SRC-059). So `Silent` owes a stated reason and a record, and
/// [`validate`] refuses one that declares neither.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Applicability {
    /// Name the class and its routes; the agent acts. Every class's behaviour
    /// before CLOUD-1639, and the default.
    #[default]
    Advice,
    /// The boundary repaired what it refused; the identical call should be
    /// re-issued. Still a refusal — exit `2` — because the call as made did not
    /// happen, and reporting it as an allow would be the silent-rewrite posture
    /// wearing a retry's name.
    Retry,
    /// The boundary repaired it and let the call through, owing a record.
    ///
    /// The exception, and it owes `no_retry_reason` on the row that declares it:
    /// a repair the caller never learns about is the 22.3% utility cost SRC-059
    /// measured, so the reason a retry was rejected has to be somebody's stated
    /// decision rather than a default.
    Silent,
}

impl Applicability {
    #[must_use]
    pub fn repairs(&self) -> bool {
        !self.is_default()
    }
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Applicability::Advice => "advice",
            Applicability::Retry => "retry",
            Applicability::Silent => "silent",
        }
    }
}

impl Applicability {
    /// Whether this is the default, for `skip_serializing_if`.
    ///
    /// Keeps `-J` byte-identical for the 200-odd classes that declare nothing,
    /// which is what makes the column additive on the machine surface too.
    ///
    /// BESIDE ITS TYPE because serde names it by path from `config_model`'s
    /// attributes, where no extension trait's import reaches (CLOUD-2793).
    #[must_use]
    pub const fn is_default(&self) -> bool {
        matches!(self, Self::Advice)
    }
}

/// One vendored class, in the shape a `const` table can hold.
///
/// A mirror of [`DeclaredVerdict`] over `&'static str`, because that type owns
/// `String`s and cannot be a `const`. [`vendored`] converts. The alternative —
/// building the table at runtime from literals — puts the same data one
/// indirection further from the reader for nothing.
#[derive(Debug)]
pub struct VendoredVerdict {
    /// The three-word class token.
    pub id: &'static str,
    /// The one-line summary.
    pub gloss: &'static str,
    /// The prose a reader dereferences through `batten policy explain`.
    pub class: &'static str,
    /// The declared remedies.
    pub routes: &'static [VendoredRoute],
    /// What the boundary may do about it (CLOUD-1639).
    ///
    /// A plain field with no default, unlike the consumer table's: a `const`
    /// initialiser cannot omit one, and spelling `Applicability::Advice` on every
    /// vendored row is what makes the ones that are NOT advice visible in a diff
    /// rather than inferred from an absence.
    pub applicability: Applicability,
}

/// One vendored route. See [`VendoredVerdict`].
#[derive(Debug)]
pub struct VendoredRoute {
    /// The route's own three-word id.
    pub id: &'static str,
    /// Which kind of remedy it is.
    pub kind: RouteKind,
    /// What it points at.
    pub target: &'static str,
    /// The condition an override route states.
    pub precondition: Option<&'static str>,
}

/// The receipt family recording a head whose wait stopped red (CLOUD-2270).
///
/// Branch-keyed, `red-head.<slug>`, and REPLACED rather than appended: it
/// answers "what does this branch's head owe a push", which is current state,
/// never history. `red-head` reads it as a mediated fact.
///
/// Also the PRESET's name, by construction rather than coincidence: the
/// manifest spells itself with this constant, so the landing's "is the preset
/// enabled" lookup and the record cannot be renamed apart.
pub const RED_HEAD: &str = "red-head";

/// One module inside a preset, with the surface it decides.
///
/// A struct rather than a `(RuleScope, &str, &str)` tuple because the two string
/// fields are not interchangeable and a tuple lets them be swapped silently: a
/// pointer in the source position compiles, loads, and produces a bundle whose
/// every rule body is a comment. Named fields make that unwritable.
#[derive(Debug)]
#[non_exhaustive]
pub struct PresetModule {
    /// The surface this module reads — `input.tree.*` or `input.call`/`facts`.
    pub scope: RuleScope,
    /// The CI provider whose expression language this module reads, or `None`
    /// where it reads none (CLOUD-1625).
    ///
    /// **PER MODULE RATHER THAN PER MANIFEST, and that is CLOUD-1672's lesson
    /// applied before it had to be learned twice.** `scope` was a manifest field
    /// once — true of every preset that existed when it was written, and false
    /// the moment one preset had something to say about two surfaces. The same
    /// is already true here: the `mise` preset's
    /// `action-version-matches-the-pin` matches a step's `uses:` coordinate and
    /// so reads one provider's workflow language, while its sibling `task-over-executable`
    /// decides mise tasks and cares about no provider at all. A manifest-level
    /// field would have to call that preset GitHub-specific and switch off a
    /// module that works everywhere.
    ///
    /// **`None` is a measured answer, not an unsurveyed one**: it says this
    /// module reads no provider's language, which is why it applies anywhere.
    ///
    /// Decided at LOAD rather than inside the module: a preset cannot read
    /// consumer data — `data.batten.*` is undefined for it — so no Rego
    /// conditional could ask "am I on the right provider".
    pub provider: Option<&'static str>,
    /// `<preset:name>/….rego`, the pointer a refusal prints.
    pub pointer: &'static str,
    /// The module source, `include_str!`d at build time.
    pub embedded_source: &'static str,
}

/// How a preset's tool installs a consumer's chosen environments (CLOUD-2633).
///
/// The derived `[[startup]]` row is `env <selector>=<envs> <install_env…>
/// <program> <check…>` decided by silence, and the same prefix before
/// `<program> <repair…>`. The check and the repair run under ONE environment so
/// the repair installs exactly the set the check found missing — an env the
/// consumer did not list is in neither, so it is never installed.
#[derive(Debug)]
#[non_exhaustive]
pub struct Install {
    /// The program both argvs invoke.
    pub program: &'static str,
    /// The environment variable naming which environments the tool loads on top
    /// of its base configuration.
    pub selector: &'static str,
    /// How the selector joins more than one environment.
    pub separator: &'static str,
    /// The operands that list what is outstanding and say nothing when nothing
    /// is, so the row is decided by [`crate::config_model::Decided::SilentExit`].
    pub check: &'static [&'static str],
    /// The operands that install what is outstanding, non-interactively.
    pub repair: &'static [&'static str],
    /// Where the tool keeps what it installs (CLOUD-2840): the environment
    /// variable naming its data directory, and the path under `$HOME` it
    /// defaults to. A program resolving under it is one the install puts there,
    /// so while the install runs such a program may be a shim with nothing
    /// behind it yet.
    pub data_dir: (&'static str, &'static str),
}

/// One vendored preset, declared once.
#[derive(Debug)]
#[non_exhaustive]
pub struct Manifest {
    /// The name a consumer enables, and the only thing they could know before.
    pub name: &'static str,
    /// The manifest's own version.
    ///
    /// Separate from the crate version deliberately, and for the reason
    /// `spec::SPEC_VERSION` is separate: a version moving with the binary says
    /// "the binary changed", which the release tag already says. This moves when
    /// what the preset DECIDES changes.
    ///
    /// **Semver, never a bare integer** (CLOUD-2822), so a consumer can tell
    /// which way the decision moved:
    ///
    /// - **major**: a module refuses something it admitted;
    /// - **minor**: it admits more, or a verdict gains a route;
    /// - **patch**: prose only.
    ///
    /// The level is the author's to declare. `preset_versions.lock` pins each
    /// version to a digest of what the preset decides, so a source changed under
    /// an unchanged version fails the suite and the bump shows in the diff.
    ///
    /// The integer counter this replaced reads as `0.0.N`: it promised no stable
    /// major, so each of its bumps is an increment below `1.0.0`.
    pub version: semver::Version,
    /// Whether the config a new repository starts from names this preset
    /// (CLOUD-2628).
    ///
    /// `false` is an opinionated ban a consumer opts into knowingly: the starter,
    /// the example config, `init` and `doctor` never suggest it, and
    /// `the_starter_config_names_every_shipped_preset` holds the starter to naming
    /// exactly the suggested ones.
    pub suggested: bool,
    /// The toolchain install this preset contributes to `[[startup]]`, or `None`
    /// where it installs nothing (CLOUD-2633).
    ///
    /// Only the TOOL's vocabulary lives here — which program, how it lists what
    /// is missing, how it installs, and how it is told which environments to
    /// load. Which environments, and the flags an install runs under, are the
    /// consumer's facts and arrive on the enabling row (`environments`,
    /// `install_env`), never as literals in this crate (non-negotiable rule 1).
    pub install: Option<Install>,
    /// The modules, each declaring the surface IT decides.
    ///
    /// **The scope is per module rather than per manifest, and that is the whole
    /// of CLOUD-1672's engine half.** It used to be one `scope` on the manifest,
    /// which said a preset decides exactly one surface — true of every preset
    /// that existed when it was written, and false the moment a subject has
    /// something to say about both. `mise` is that subject: whether an agent
    /// reproduces a task's argv is a question about a CALL, and whether the
    /// toolchain a workflow installs matches the version the tree pins is a
    /// question about the TREE. They are one preset because they are one
    /// concern, and a consumer enabling `mise` should not have to know that the
    /// engine once could not express that.
    ///
    /// What the manifest-level field bought is preserved rather than dropped:
    /// enabling a preset at a scope none of its modules decide is still refused
    /// at LOAD, by `decides` below, and the refusal now names the scopes the
    /// preset DOES decide instead of a single one. A row selects the modules at
    /// its own scope, so a tree module never loads under a mediated row —
    /// without that selection it would read `input.tree` on the call surface and
    /// trip `check_tree_paths_are_emittable`, which is the guard working and not
    /// a shape to rely on.
    ///
    /// The pointer is `<preset:name>/…` rather than a filesystem path: a preset
    /// has no path in the consumer's tree, and printing one sends a reader
    /// looking for a file that is not there.
    pub modules: &'static [PresetModule],
    /// The refusal classes these modules raise, with their glosses and remedies.
    ///
    /// Declared HERE rather than in `verdict.rs`'s native table, which is the
    /// change that makes the registry's two directions reachable for a preset:
    /// a token a module raises that no row here declares, and a row here that no
    /// module raises, are both findings a manifest can now express.
    pub verdicts: &'static [VendoredVerdict],
    /// The `[[pattern]]` ids these modules would cite if they could.
    ///
    /// **The declaration site CLOUD-934 needs, and deliberately not its fix.** A
    /// preset reaches a consumer who wrote no `[[pattern]]` rows, so
    /// `data.batten.patterns["x"]` resolves to undefined there and a preset
    /// citing one decides nothing while loading clean — which is why the
    /// exemption exists and why a preset still writes its literal inline.
    /// Listing the ids is what makes the exemption countable instead of
    /// invisible; closing it is CLOUD-934's row and this one does not do its work.
    pub patterns: &'static [&'static str],
}

impl Manifest {
    /// The digest of everything this preset decides: each module's pointer, scope
    /// and source, every verdict and route it ships, and its pattern rows. Its
    /// name, version and whether the starter suggests it are not decisions, so
    /// they are not hashed, and neither are a module's `#MUTANT` rows: they name
    /// this crate's own mutation suite and an eject strips them
    /// ([`decided_lines`]), so they decide nothing a consumer runs.
    ///
    /// `Debug` over static data is a stable rendering within one source tree,
    /// which is all the lock needs: it compares this tree's manifests with the
    /// table this tree commits.
    #[must_use]
    pub fn digest(&self) -> String {
        use sha2::{Digest as _, Sha256};
        use std::fmt::Write as _;

        let mut hasher = Sha256::new();
        for module in self.modules {
            hasher.update(
                format!(
                    "{:?}|{:?}|{:?}|",
                    module.scope, module.provider, module.pointer
                )
                .as_bytes(),
            );
            for line in decided_lines(module.embedded_source) {
                hasher.update(line.as_bytes());
                hasher.update(b"\n");
            }
            hasher.update([1]);
        }
        hasher.update([0]);
        hasher.update(format!("{:?}", self.verdicts).as_bytes());
        hasher.update([0]);
        hasher.update(format!("{:?}", self.patterns).as_bytes());
        hasher
            .finalize()
            .iter()
            .fold(String::new(), |mut hex, byte| {
                let _ = write!(hex, "{byte:02x}");
                hex
            })
    }
}

/// A module's lines without its `#MUTANT`/`#MUTANT-SUITE` rows: the text an
/// eject writes and the digest hashes, so the two cannot disagree on what a
/// preset decides.
pub(crate) fn decided_lines(source: &str) -> impl Iterator<Item = &str> {
    source.lines().filter(|line| !line.starts_with("#MUTANT"))
}

/// The committed table pinning each preset version to its digest (CLOUD-2822).
pub const VERSIONS_LOCK: &str = include_str!("preset_versions.lock");

/// Every disagreement between `manifests` and the `lock` table, one line each,
/// naming the preset, its version and both digests.
///
/// A manifest must have a row at its own version, and that row's digest must be
/// the manifest's. Rows for older versions stay as history and are not judged.
#[must_use]
pub fn version_drift(lock: &str, manifests: &[Manifest]) -> Vec<String> {
    let rows: Vec<(&str, &str, &str)> = lock
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut columns = line.split_whitespace();
            Some((columns.next()?, columns.next()?, columns.next()?))
        })
        .collect();
    let mut drift = Vec::new();
    for manifest in manifests {
        let version = manifest.version.to_string();
        let digest = manifest.digest();
        match rows
            .iter()
            .find(|(name, at, _)| *name == manifest.name && *at == version)
        {
            None => drift.push(format!(
                "{} {version} has no row in preset_versions.lock: add `{} {version} {digest}`",
                manifest.name, manifest.name
            )),
            Some((_, _, recorded)) if *recorded != digest => drift.push(format!(
                "{} {version} changed what it decides without a version bump: recorded {recorded}, now {digest}",
                manifest.name
            )),
            Some(_) => {}
        }
    }
    drift
}

/// The git calls the host decides (CLOUD-2768): ONE module in TWO bundles. The
/// `git` preset's grant withholds itself from these calls, and the
/// `claude-code-cloud` mode grant yields on them; a bundle compiles only its own
/// preset's modules, so each ships this one rather than a copy of the predicate.
const GIT_HOST_DECIDED: PresetModule = PresetModule {
    scope: RuleScope::MediatedCall,
    provider: None,
    pointer: "<preset:git>/host-decided.rego",
    embedded_source: include_str!("policy/presets/git/host-decided.rego"),
};

/// Every vendored preset, in a stable order.
///
/// The ONE authority. `preset_names`, the modules a preset ships, and the
/// presets' half of the vendored verdict registry are all read off this table —
/// never a hand-maintained second list, which is `surface::SURFACE`'s discipline
/// and the reason a preset cannot be enabled that does not exist.
///
/// An opt-in ban is never suggested by the config a repository starts from
/// (CLOUD-2628).
pub const MANIFESTS: &[Manifest] = &[
    // CLOUD-843, carrying CLOUD-441's decision out of a consumer module. A
    // check's verdict on one commit is its latest run, absent is no veto and
    // "not yet" is never a pass. The record is `batten record query`'s, under the
    // family name the module reads; which commit, which repository and which
    // check names are the consumer's `[[forge.query]]` row, so nothing here names
    // a repository, an analyzer or a check.
    //
    // ITS OWN PRESET RATHER THAN A MODULE OF A WIDER CI BUNDLE, and the engine is
    // the reason. A row selects a preset's modules by scope and provider, never
    // one by one, so this per-commit gate beside a scheduled report would make
    // each row's `--fail-on-warning` fail on the other's findings — and two tree
    // rows over one preset collide on its predicate ids at load.
    Manifest {
        name: "check-verdict",
        version: semver::Version::new(0, 0, 2),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::Tree,
            // Reads a record, not a workflow document, so no provider's
            // expression language. The conclusion words are the forge's
            // check-run vocabulary; on a forge speaking another one every run
            // reads as no answer yet, which fails closed rather than clean.
            provider: None,
            pointer: "<preset:check-verdict>/latest-run-decides.rego",
            embedded_source: include_str!("policy/presets/check-verdict/latest-run-decides.rego"),
        }],
        verdicts: &[
            VendoredVerdict {
                id: "check grade red",
                gloss: "a check's latest run on this commit concluded with an objection",
                class: "The check graded the commit and objected. The pointer is the check's name \
and its conclusion, never its report: read the run's own details page and fix it locally. A \
later run of the same name supersedes this one, so an older success does not answer for it.",
                routes: &[read("source read first", "the check-run's details page")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "check grade early",
                gloss: "a check has no verdict on this commit yet: running, skipped or cancelled",
                class: "Not an answer, and so never a pass: a run still in flight, or one that \
completed without judging anything. A skipped or cancelled run cannot be waited out, since \
nothing further is minted for it; re-read the commit's check-runs once the check has graded it, \
or give it a fresh run.",
                routes: &[run(
                    "task run first",
                    "batten record query check-runs, for the same commit, then this rule again",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "check read partial",
                gloss: "the check-runs record is a truncated window, lacks one closing line, or holds a torn row",
                class: "A part of a commit's check-runs is never judged as all of them. Three \
shapes are partial. A truncated window: the run that decides a name may sit past the page \
budget, so raise the query's page budget, or narrow it to the names that carry a verdict, and \
read it again. A record with no single closing line, or a row torn mid-JSON: something other \
than the query wrote or cut the family, so no page budget clears it; find that writer, stop it \
writing the family, and re-mint the record from the query.",
                routes: &[
                    read("source read first", "the query row that writes the family"),
                    read(
                        "record read first",
                        "every writer of the family besides its query row",
                    ),
                    run(
                        "task run first",
                        "batten record query check-runs, for the same commit, then this rule again",
                    ),
                ],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    Manifest {
        name: "ci-hygiene",
        version: semver::Version::new(0, 1, 2),
        suggested: true,
        install: None,
        modules: &[
            PresetModule {
                scope: RuleScope::Tree,
                // Matches `github.event.pull_request.draft == false` and keys on
                // documents carrying a `jobs:` mapping — GitHub's workflow
                // shape. GitLab names jobs at the top level, Buildkite uses
                // `steps:`, a Jenkinsfile is not YAML: on any of them the set is
                // empty and every rule here refuses nothing (CLOUD-1625).
                provider: Some("github-actions"),
                pointer: "<preset:ci-hygiene>/spend-is-authorised.rego",
                embedded_source: include_str!("policy/presets/ci-hygiene/spend-is-authorised.rego"),
            },
            PresetModule {
                scope: RuleScope::Tree,
                // `github.event_name`, `github.event.comment.body` and
                // `github.event.workflow_run` — the same language, same reason.
                provider: Some("github-actions"),
                pointer: "<preset:ci-hygiene>/wiring-can-be-reached.rego",
                embedded_source: include_str!(
                    "policy/presets/ci-hygiene/wiring-can-be-reached.rego"
                ),
            },
        ],
        verdicts: &[
            VendoredVerdict {
                id: "workflow parse unseen",
                gloss: "a declared workflow would not parse, so no rule here could read it",
                class: "Could-not-look, and deliberately not spelled the same way as absent. Absent is \
not-applicable — this tree runs no such workflow — while unparsed means the boundary tried and \
failed. Every rule in this preset iterates the documents that DID parse, so without this the \
module reports green over exactly the file it could not read. Its own class rather than the one \
`mise` raises for the same state, because the registry declares a class once and could not \
otherwise say which preset raises it.",
                routes: &[read(
                    "source read first",
                    "the workflow that would not parse",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "cache build loose",
                gloss: "a cache-warming build recompiles and writes nothing on every run",
                class: "A build that compiles to fill a cache and runs nothing judges nothing, which is \
why it is exempt from parity rules — and that exemption is what makes it easy to leave running \
for nothing. Measured: two cache entries carrying the same key across five merges, each cycle \
compiling for ~145s and saving nothing, because the restore skips saving when the key already \
exists. One condition reading the restore's hit flag is the whole fix.",
                routes: &[read("source read first", "the compile step")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "cache name unknown",
                gloss: "the cache guard names a step that does not exist, so it admits every run",
                class: "The other direction of the same defect, and it has the same symptom with no \
signal. If the action stops emitting the hit flag the expression is empty, the guard holds, and \
the compile runs — wasteful, but visible in the bill. If the step id is dropped or renamed while \
the guard keeps naming it, the expression is ALSO empty and the build silently reverts to \
compiling every time. So the class names both halves: the guard must be present, and the step it \
reads must exist.",
                routes: &[read("source read first", "the restore step")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "event bind loose",
                gloss: "a comment predicate fires from anywhere in a body anyone can write",
                class: "An unanchored substring test fires from mid-sentence, from inside backticks, from \
a quoted block. That makes the repository's own writing ABOUT a trigger an invocation of it, and \
every artifact that has to name the token in order to be about it a live round. The class is the \
unanchored read of a body anyone can write, not the one token read that way.",
                routes: &[read("source read first", "the job condition")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "event reach dead",
                gloss: "a declared trigger starts a run in which every job skips",
                class: "The trigger exists and does nothing: the run list shows a run, and only the job's \
conclusion says it did not happen. Measured on one lane where a manual trigger was added so it \
could be exercised without waiting on a late cron, and every job's condition still admitted only \
the two original events. Judged only where a condition MENTIONS the event name at all, since a \
workflow that does not discriminate by event answers for every trigger it declares.",
                routes: &[read("source read first", "the job conditions")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "input render dropped",
                gloss: "an unquoted comment truncates a value before it ever reaches the forge",
                class: "YAML opens a comment at an unquoted space-hash, so a value carrying an \
interpolation after one parses to the bare text before it and the rest is discarded. Measured: \
one workflow carried exactly that for a day and 30 consecutive runs reported a title equal to the \
workflow name, so a caller keying on the interpolated value could never match. Linters pass over \
the line because a comment is legal YAML, and review reads it as the thing it was meant to be. \
Read pre-parse, because the parse is what destroys the evidence. Quoting the value is the fix.",
                routes: &[read("source read first", "the truncated line")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "job require unseen",
                gloss: "a fan-in enumerates its own dependencies and has gone stale",
                class: "Branch protection points at one aggregating job so that adding a leg never needs \
a ruleset change — which only holds if that job's assertion follows its dependency list by \
itself. Measured: a fan-in enumerated three of its four dependencies, so a red fourth left green \
the one check the host requires. A set-wide predicate cannot go stale, because it names nothing.",
                routes: &[read("source read first", "the fan-in job")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "job run early",
                gloss: "a job spends a runner on a pull request still being verified locally",
                class: "A draft says the author is still verifying locally, and it is also the lever a \
red run pulls: a lander that re-drafts stops further spend while the failure is diagnosed. A \
single job missing the guard defeats both, and the run it buys is one nobody reads. Measured on \
one repository: a workflow triggered by any pull request touching a workflow file spent a runner \
on every push to a draft for its whole life, and re-drafting did not close the tap.",
                routes: &[read("source read first", "the job's condition")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "job start same",
                gloss: "two scheduled workflows contend for the same runners at the same minute",
                class: "Every scheduled workflow's header tends to claim a staggered slot and nothing \
checks it, so two pairs drifted onto the same minute and the second pair landed after the first \
was found. Compared as LITERAL expressions rather than firing times: an every-30-minutes \
schedule genuinely overlaps every hourly slot, and flagging that would make the class fire \
forever on a workflow doing nothing wrong.",
                routes: &[read("source read first", "the schedule trigger")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "merge run early",
                gloss: "a comment-triggered merge delegates the draft question to the ruleset",
                class: "A draft head grades no checks where every pull-request workflow is draft-gated, \
and a branch ruleset admits that empty set as satisfying required-checks-green. So a merge path \
that never reads the draft state has no draft check at all, and can advance the trunk to a commit \
CI never ran on. Deciding not to ask is not the same as asking.",
                routes: &[read("source read first", "the merge job")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "review watch missing",
                gloss: "a draft-gated workflow can never be superseded once it skips",
                class: "Omitting `types:` defaults to `[opened, synchronize, reopened]`. Where the jobs \
are draft-gated, a pull request created as a draft mints a skipped run on `opened`, and with no \
`ready_for_review` there is no event left that could replace it — a waiter correctly refuses to \
read a skip as an answer and polls forever. Measured as a deadlock across two pull requests at \
once, both fully green but for one such name.",
                routes: &[read(
                    "source read first",
                    "the pull_request trigger's types",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "workflow declare missing",
                gloss: "a workflow can have two runs racing at all",
                class: "Superseding is the pull-request half of this and is not the whole of it: a \
comment- or schedule-triggered workflow never reaches that guard, so the property that matters \
off the landing path — that a workflow cannot race itself — reaches none of them. Measured: N \
concurrent comment invocations ran N concurrent attempts to advance a trunk branch, at 245 \
refusals against 6 merges in half an hour. A scheduled workflow must NOT cancel its own previous \
tick, so declaring a group is all this asks.",
                routes: &[read("source read first", "the workflow")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "workflow run loose",
                gloss: "a branch scope written where filtering is already too late",
                class: "A job condition is evaluated AFTER the run exists, so a branch scope expressed \
only there creates a run and then skips it. Measured on one lane: 1131 inserted-and-skipped runs \
in 25 hours — no runner minutes, which is why it survived, but 46% of every run in the \
repository, enough that paginating the run list stops being stable. The filter belongs on the \
trigger, where it is free.",
                routes: &[read("source read first", "the workflow_run trigger")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "workflow run twice",
                gloss: "a pull-request workflow pays out a run its own next push made obsolete",
                class: "A landing lap rebases and pushes. Without `cancel-in-progress` the superseded \
commit's run is billed in full for a verdict nobody will read, and a lander loses the ability to \
cancel a doomed run by simply pushing the next one. Declaring the group is not enough — the \
value is what does the work, and it is a boolean rather than the string `true`.",
                routes: &[read(
                    "source read first",
                    "the workflow's concurrency block",
                )],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    // CLOUD-843. What the CI signal says about a landing loop over a window: it
    // stays linear (one matrix per landing, run to green), and a required job's
    // failure reaches a verdict. The records are `batten record divergence`'s and
    // `batten record nonverdict`'s, under the families those verbs name; every
    // consumer fact — workflows, roster, fan-in, verdict spellings — was spent by
    // the producer, so nothing here names one. Two modules, ONE enabling row: a
    // consumer that runs only one producer has only one family, and the other
    // module is silent.
    Manifest {
        name: "ci-signal",
        version: semver::Version::new(0, 0, 2),
        suggested: true,
        install: None,
        modules: &[
            PresetModule {
                scope: RuleScope::Tree,
                // Reads a record of counts, not a workflow document: no provider's
                // expression language is in it.
                provider: None,
                pointer: "<preset:ci-signal>/landing-stays-linear.rego",
                embedded_source: include_str!("policy/presets/ci-signal/landing-stays-linear.rego"),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:ci-signal>/required-failures-reach-a-verdict.rego",
                embedded_source: include_str!(
                    "policy/presets/ci-signal/required-failures-reach-a-verdict.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                // A job key two spaces under `jobs:`, a job-level `timeout-minutes:`
                // at four, and a matrix leg reported as `<key> (<axis>)` are GitHub
                // Actions' grammar and its jobs endpoint's naming. Another provider's
                // documents carry no `jobs:` mapping in that shape, so the module
                // would read no budget and report a clean tree it never read
                // (CLOUD-1625).
                provider: Some("github-actions"),
                pointer: "<preset:ci-signal>/timeout-tracks-its-measurement.rego",
                embedded_source: include_str!(
                    "policy/presets/ci-signal/timeout-tracks-its-measurement.rego"
                ),
            },
        ],
        verdicts: &[
            VendoredVerdict {
                id: "lane read partial",
                gloss: "the measurement could not read part of its window, so a green verdict would cover \
less than it claims",
                class: "A runs endpoint that caps pagination while still reporting the true total lets a \
walk that stops on a short page read a PREFIX and look like a clean finish. Measured: 1000 of 1446 \
runs collected, reporting zero fast-forward refusals over a window carrying 598. Narrow the window.",
                routes: &[run(
                    "task run first",
                    "batten record divergence --ci-workflow <file> --land-workflow <file>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "lane count spent",
                gloss: "the landing loop bought more CI matrices per landing than its budget",
                class: "The ideal is 1.00 — one matrix, run to green, landed. The budget is 2.00 because \
the second run is a lease precondition cancelling an unauthorised matrix, which is the mechanism \
working.",
                routes: &[run(
                    "task run first",
                    "batten record divergence --ci-workflow <file> --land-workflow <file>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "lane grade red",
                gloss: "red CI runs per landing are over budget",
                class: "A red run means local verification was skipped or disagreed with CI, and each one \
spent a full matrix to say so.",
                routes: &[run(
                    "task run first",
                    "batten record divergence --ci-workflow <file> --land-workflow <file>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "lane reach late",
                gloss: "cancelled runs have a median lifetime past the budget",
                class: "LATENCY, NEVER COUNT. An early cancellation is a lease precondition stopping an \
unauthorised matrix for ~20 runner-seconds instead of billing ~500; a late one is a matrix billed \
for a verdict nobody reads.",
                routes: &[run(
                    "task run first",
                    "batten record divergence --ci-workflow <file> --land-workflow <file>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "lease guard dropped",
                gloss: "more CI matrices ran concurrently than the lease admits",
                class: "Landing is serialised behind a lease, so concurrency above the admitted-successor \
bound means something is spending CI without holding it.",
                routes: &[run(
                    "task run first",
                    "batten record divergence --ci-workflow <file> --land-workflow <file>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "lane measure late",
                gloss: "runs waited past the budget at p90 before starting",
                class: "The runner pool saturating, which is a different defect from contention and must \
not be read as one.",
                routes: &[run(
                    "task run first",
                    "batten record divergence --ci-workflow <file> --land-workflow <file>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "job measure late",
                gloss: "individual matrix legs waited past the budget at p90 before starting",
                class: "A run's own figure is its FIRST job's start, so this is the one that sees a leg \
queueing behind its siblings — the two disagreeing is what tells a wide matrix apart from a \
saturated pool.",
                routes: &[run(
                    "task run first",
                    "batten record divergence --ci-workflow <file> --land-workflow <file>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "branch reach stale",
                gloss: "the fast-forward bot refused a branch that had gone behind",
                class: "A refusal means the branch went behind before the bot answered — the thundering \
herd a landing lease exists to remove (243:5 before, 0:5 after). Any refusal at all is a \
divergence, so the budget is zero.",
                routes: &[run(
                    "task run first",
                    "batten record divergence --ci-workflow <file> --land-workflow <file>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "job read partial",
                gloss: "the scan could not read part of its window, so a green verdict would cover less \
than it claims",
                class: "A run that measured two of three paths and reported green over the two is exactly \
the partial-coverage false green. It fires whatever the count is, because a budget met over part \
of a window is a budget met over nothing in particular. A persistent read failure is a token or \
rate-limit problem, not a clean window.",
                routes: &[run(
                    "task run first",
                    "batten record nonverdict --required-check <job> --verdict-step <prefix>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "job answer missing",
                gloss: "a required job failed before reaching any verdict-bearing step",
                class: "The run spent its minutes, redded the branch, and answered nothing. Every \
occurrence then costs a human or an agent the time to discover it was never a verdict at all — \
measured as an agent sent to reproduce a lint failure that passed locally because the lint never \
ran.",
                routes: &[run(
                    "task run first",
                    "batten record nonverdict --required-check <job> --verdict-step <prefix>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "bound pin loose",
                gloss: "a job's declared timeout sits well above what its measurement justifies",
                class: "A budget is a ceiling rather than a target, so headroom is correct and a slack \
allowance keeps this off a job that merely got a little faster. Past that allowance the number has \
gone slack, which is the direction a report that only complained about tightness would let rot \
upward forever. Nothing is broken and no branch is at fault: re-derive the number and commit the \
new comment.",
                routes: &[run(
                    "task run first",
                    "the writer the `drift-runs` and `drift-jobs` `[[record]]` rows name, \
                     which re-takes the run window before it re-walks the jobs",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "bound pin wrong",
                gloss: "a job's measurement has outgrown its declared timeout",
                class: "The p95 of recent successful runs, times the headroom multiplier, is already \
above the committed budget. Raise it before it starts failing healthy runs — this is the direction \
that turns into a red job nobody caused.",
                routes: &[run(
                    "task run first",
                    "the writer the `drift-runs` and `drift-jobs` `[[record]]` rows name, \
                     which re-takes the run window before it re-walks the jobs",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "bound pin stale",
                gloss: "a dated debt entry now has a usable sample and can become a measured budget",
                class: "The prompt, never the conversion. A bot re-baselining the number it is supposed \
to defend is the one move a budget exists to forbid, so this reports that the debt is now \
convertible and a deliberate commit does the converting.",
                routes: &[run(
                    "task run first",
                    "the writer the `drift-runs` and `drift-jobs` `[[record]]` rows name, \
                     which re-takes the run window before it re-walks the jobs",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "bound measure partial",
                gloss: "too few successful runs to characterise a job, or a measurement that did not \
close, so no budget is proposed",
                class: "Below the minimum a job is uncharacterised rather than fast, and saying so is \
itself the useful signal: jobs that run weekly or on release have a handful of runs in any window, \
so a naive percentile would compute a confident value from two samples and propose tightening a \
release job on it. A family present without exactly one closing line was torn by something other \
than its producer, which writes whole or removes, and reads the same way.",
                routes: &[run(
                    "task run first",
                    "the writer the `drift-runs` and `drift-jobs` `[[record]]` rows name, \
                     which re-takes the run window before it re-walks the jobs",
                )],
                applicability: Applicability::Advice,
            },
        ],
        // Every module writes the grammar it cites inline, for the reason
        // `Manifest::patterns` gives: `whole-number` for the two record readers,
        // GitHub Actions' job and timeout lines for the budget reader.
        patterns: &[
            "whole-number",
            "workflow-job-key",
            "workflow-top-level-key",
            "job-timeout-line",
            "timeout-budget-grandfathered",
        ],
    },
    // CLOUD-1949. The host never halts on a prompt: in plan mode a call reads or
    // is refused, and a read — or a `batten` lifecycle verb outside plan mode —
    // is pre-approved. Claude Code's tool names and plan-file path are the
    // host's vocabulary, which a vendor preset may carry and the core may not.
    //
    // VERSION 2 (CLOUD-843): the preset gained its TREE half, whether the host
    // honours the committed MCP permission rules at all. The settings file, the
    // project file and the rule grammar are the same host vocabulary; the
    // coverage it reads is the consumer's own authority, found by shape.
    //
    // VERSION 3 (CLOUD-2157): a backgrounded call that names no timeout is
    // rewritten to the host's maximum.
    // VERSION 0.1.0, a minor bump (admits more): `dispatch-is-preapproved`
    // grants at `permission-request` and `permission-denied` as well as at
    // pre-tool, in every mode but plan (71a7be4b0). The source changed under
    // 0.0.4, which `every_manifest_matches_its_recorded_digest` refused.
    // VERSION 1.0.0, a major bump (refuses what it admitted): the read grant
    // delegates to the engine's read-only library (CLOUD-2840), which refuses a
    // live assignment (`PATH=./bin ls`), a program spelled with a path outside
    // the system directories, an assigning reader onto a sensitive name, and a
    // gawk directive, all of which 0.1.0 granted.
    Manifest {
        name: "claude-code-cloud",
        version: semver::Version::new(1, 0, 0),
        suggested: true,
        install: None,
        modules: &[
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:claude-code-cloud>/mcp-grants-are-honoured.rego",
                embedded_source: include_str!(
                    "policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:claude-code-cloud>/allowed-call-is-preapproved.rego",
                embedded_source: include_str!(
                    "policy/presets/claude-code-cloud/allowed-call-is-preapproved.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:claude-code-cloud>/subagent-is-preapproved.rego",
                embedded_source: include_str!(
                    "policy/presets/claude-code-cloud/subagent-is-preapproved.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:claude-code-cloud>/unwatch-is-preapproved.rego",
                embedded_source: include_str!(
                    "policy/presets/claude-code-cloud/unwatch-is-preapproved.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:claude-code-cloud>/plan-mode-refuses-writes.rego",
                embedded_source: include_str!(
                    "policy/presets/claude-code-cloud/plan-mode-refuses-writes.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:claude-code-cloud>/write-is-preapproved.rego",
                embedded_source: include_str!(
                    "policy/presets/claude-code-cloud/write-is-preapproved.rego"
                ),
            },
            // CLOUD-2157: a backgrounded call that names no timeout runs with
            // the host's maximum, carried on the grant above it.
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:claude-code-cloud>/background-timeout-is-maximal.rego",
                embedded_source: include_str!(
                    "policy/presets/claude-code-cloud/background-timeout-is-maximal.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:claude-code-cloud>/read-only-is-preapproved.rego",
                embedded_source: include_str!(
                    "policy/presets/claude-code-cloud/read-only-is-preapproved.rego"
                ),
            },
            // The git calls the mode grant below yields on (CLOUD-2768), the
            // same module the `git` preset ships.
            GIT_HOST_DECIDED,
            // LAST, so a call a narrower module also grants is named by that
            // module: the first grant found is the one the host is told.
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:claude-code-cloud>/auto-mode-is-preapproved.rego",
                embedded_source: include_str!(
                    "policy/presets/claude-code-cloud/auto-mode-is-preapproved.rego"
                ),
            },
        ],
        verdicts: &[
            VendoredVerdict {
                id: "plan write refused",
                gloss: "a call that is not a read was made while the host is in plan mode",
                class: "Plan mode is a promise that nothing changes until the plan is approved. The \
host enforces it by asking the operator, and a session halted on a prompt is the failure this \
preset exists to remove — so the call is refused instead, and nobody has to answer anything. A \
read, the plan file itself, and leaving plan mode are never refused.",
                routes: &[run("plan run first", "ExitPlanMode, then make the call")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "grant spelling wrong",
                gloss: "an MCP allow rule the host skips, so it grants nothing",
                class: "The host matches an MCP permission rule by server name, and a glob in the \
server segment, or a bare `*`, is not a name: the rule is skipped with a warning and grants \
nothing. Its only symptom is an approval prompt on every call, which reads as harness behaviour \
rather than as a settings bug.",
                routes: &[run(
                    "rule fix first",
                    "name the server literally in the host's settings file (`mcp__<server>` or \
`mcp__<server>__<tool>`); a tool-segment glob after a literal server is fine",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "grant name missing",
                gloss: "an enabled MCP server no allow rule names, so every call to it prompts",
                class: "`enabledMcpjsonServers` turns a project server on, and turning it on grants \
none of its tools. A server enabled with no allow rule naming it is attached and unusable \
unattended: every call stops for a human. Measured on one consumer, whose code-navigation server \
shipped exactly that way.",
                routes: &[run(
                    "grant add first",
                    "add an allow rule naming the server in the host's settings file, or stop \
enabling it",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "connector deny loose",
                gloss: "a deny spelled with one host-supplied server name, which the host renames away",
                class: "A host-supplied connector's exposed name is chosen per registration \
episode — the same connector was measured under three prefixes. A deny rule naming one of those \
spellings reads as a prohibition and enforces nothing the moment the connector comes back under \
another. What survives the rename is a `mediated_call` row keyed on the tool's own name, which \
matches the tool segment whatever the server is called.",
                routes: &[run(
                    "rule cover first",
                    "add a `mediated_call` `[[rule]]` whose `tool` is the denied tool's suffix, \
so the refusal holds under any server spelling",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "grant read unread",
                gloss: "a permission or project file was declared and would not parse, so nothing in it was judged",
                class: "Could-not-look, and never a clean tree. An absent settings or project file \
is a repository with nothing to check; one that exists and will not parse is a file the gate \
tried to read and could not, and reading that as \"no defects\" is the vacuous pass every \
could-not-look arm exists to refuse.",
                routes: &[run(
                    "path fix first",
                    "make the named file parse as JSON again, then re-run `batten check`",
                )],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    Manifest {
        name: "commit-hygiene",
        // 2: the commit is git's projected subcommand, not a `commit` word anywhere
        // in its argv (CLOUD-2813).
        version: semver::Version::new(0, 0, 2),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::MediatedCall,
            provider: None,
            pointer: "<preset:commit-hygiene>/no-empty-commit.rego",
            embedded_source: include_str!("policy/presets/commit-hygiene/no-empty-commit.rego"),
        }],
        verdicts: &[VendoredVerdict {
            id: "commit ship empty",
            gloss: "an empty commit records that somebody wanted a new SHA",
            class: "A commit records a change. The reachable use of an empty one is kicking a \
pipeline, which spends a run to re-ask a question the previous run already answered and \
leaves a commit in the history no reader can act on. If the goal is a fresh run, re-run \
the pipeline.",
            routes: &[run("task run first", "re-run the pipeline")],
            applicability: Applicability::Advice,
        }],
        patterns: &[],
    },
    Manifest {
        name: "landing-loop",
        version: semver::Version::new(0, 0, 2),
        suggested: true,
        install: None,
        modules: &[
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:landing-loop>/graded-head-is-not-regraded.rego",
                embedded_source: include_str!(
                    "policy/presets/landing-loop/graded-head-is-not-regraded.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:landing-loop>/already-landed-work-is-not-relanded.rego",
                embedded_source: include_str!(
                    "policy/presets/landing-loop/already-landed-work-is-not-relanded.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:landing-loop>/lease-authorises-the-branch.rego",
                embedded_source: include_str!(
                    "policy/presets/landing-loop/lease-authorises-the-branch.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:landing-loop>/rebase-conflict-stops-the-lap.rego",
                embedded_source: include_str!(
                    "policy/presets/landing-loop/rebase-conflict-stops-the-lap.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:landing-loop>/lap-waits-on-one-answer.rego",
                embedded_source: include_str!(
                    "policy/presets/landing-loop/lap-waits-on-one-answer.rego"
                ),
            },
        ],
        verdicts: &[
            VendoredVerdict {
                id: "head grade twice",
                gloss: "the forge already judged this commit and a second run would re-ask it",
                class: "A commit that has not changed cannot get a different verdict, so a second \
run over it buys an answer that is already recorded and spends the metered tier to do it. \
Measured on one consumer's landing bot over a half hour: 400 runs, 248 executed, against 5 \
merges. Read the recorded verdict rather than asking for it again; if the intent was to \
judge different work, the commit is what has to change.",
                routes: &[
                    read("source read first", "the forge record for this commit"),
                    // THE PRECONDITION IS THE WHOLE OF THIS ROUTE. A re-grade is
                    // legitimate when the recorded verdict is about the RUNNER rather
                    // than about the commit — a lost agent, an evicted node, an
                    // infrastructure fault — because that verdict answers a question
                    // nobody asked. It is not legitimate because the answer was
                    // unwelcome, which is the case this condition exists to exclude.
                    admit(
                        "path admit first",
                        "the recorded verdict is about a runner fault rather than about this commit",
                    ),
                ],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "lease grant other",
                gloss: "a live landing lease names a different branch, and no reservation names this one",
                class: "A landing lease is how a fleet keeps two branches from buying overlapping CI for \
a trunk only one of them can fast-forward onto. This branch is neither the holder nor the \
successor admitted behind it, so a matrix spent now is a matrix the holder's merge invalidates. \
Wait for the lease to lapse or be released, or reserve the slot behind the holder — the loop that \
does both lives outside the engine, which only reads the answer. Every reading this refusal \
cannot take ALLOWS: an unreadable lease stops every job in the fleet, where waving one matrix \
through costs one matrix.",
                routes: &[
                    read(
                        "lease read first",
                        "the lease grading recorded for this branch",
                    ),
                    // The wedged holder, and it is narrow on purpose. The lease grades
                    // LIVENESS rather than PROGRESS (CLOUD-499), so a holder that beats
                    // steadily while making none holds forever and starves the fleet.
                    // That is the case this admits, and it is not "the wait was
                    // inconvenient" — a holder that is merely slow is the mechanism
                    // working.
                    admit(
                        "lease admit first",
                        "the holder is wedged rather than slow — it is beating without advancing, so waiting for a lapse it keeps renewing starves the fleet indefinitely",
                    ),
                ],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "patch ship twice",
                gloss: "the target already carries this branch's changes, so landing them again buys nothing",
                class: "A landing attempt over work the target already has runs a matrix, holds the \
fleet's landing slot while it does, and merges a no-op or a conflict. The answer is decided by \
PATCH IDENTITY rather than by reachability, which is what makes it trustworthy here: a rebased, \
squash-merged or cherry-picked branch leaves the same change on the target under a different \
commit with no ancestry path back, and on a fast-forward trunk that is the ordinary way work \
lands. Close the branch, or rebase onto the target and see what is genuinely left.",
                routes: &[
                    read("record read first", "the landing verdict for this target"),
                    // The one legitimate re-land, and it is narrow on purpose. Patch
                    // identity answers about CONTENT, so deliberately re-applying a
                    // change the target once carried and later reverted is
                    // indistinguishable from never having landed it — the same bytes,
                    // arriving for a different reason. That is the case this admits, and
                    // it is not "the answer was inconvenient".
                    admit(
                        "patch admit first",
                        "the change is being deliberately re-applied after the target reverted it, so identical content is the intent rather than a duplicate",
                    ),
                ],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "replay halt conflict",
                gloss: "the lap's replay conflicted, so the head it would push was never completed",
                class: "Landing is a loop and one step of it needs a person: a replay that \
conflicts is two authors having changed the same lines, and choosing between them is a \
judgement no gate makes. What is refused is not the conflict — conflicts are the mechanism \
working, and frequent laps are what keep each one to a single resolvable increment — but a \
lap CONTINUING past one, which pushes, spends a matrix or fast-forwards a head whose replay \
never finished. A merge strategy makes that outcome reachable and reports success while \
doing it, which is why the wrong move here is the one reached for to make the loop always \
succeed. Resolve the conflict, then lap again.",
                routes: &[
                    read("record read first", "the replay outcome this lap recorded"),
                    // The one legitimate continuation, and it is narrow on purpose.
                    // A conflict a LATER lap replayed cleanly is already resolved and
                    // the module reads the last line for exactly that reason — so
                    // this admits only the case where the resolution happened outside
                    // the loop's own record, never "the conflict was inconvenient".
                    admit(
                        "replay admit first",
                        "the conflict was resolved outside this lap's record, so the head being pushed is a completed replay rather than a half-applied one",
                    ),
                ],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "wait read both",
                gloss: "the lap read an answer from both sides of a race the design gives one answer",
                class: "A landing lap's wait is a race: it asks whether the commit is green and \
whether the commit is still landable at once, and whichever answers first decides while the \
loser's answer is VOIDED. That is the economy rather than a detail — the moment the base \
advances, the run in flight is spend for a verdict nobody will read, and the next lap's push \
supersedes it through the forge's own cancel-in-progress, which is why nothing cancels it by \
hand. A lap that reads both sides has thrown that away, and it still lands green work most of \
the time, so no test over the happy path can see it. Act on the answer that arrived first and \
abandon the other unread.",
                routes: &[
                    read("record read first", "the wait outcomes this lap recorded"),
                    // The narrow legitimate case, and it is about the RECORD
                    // rather than about the wait: a lap resumed after a reap can
                    // carry the previous attempt's answer beside its own, which
                    // is two answers with only one race behind them. It is not
                    // "both answers were interesting".
                    admit(
                        "wait admit first",
                        "the second answer belongs to an earlier attempt this lap resumed rather than to a second arm of the same race",
                    ),
                ],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    // The task runner's own receipt, read as an alias table (CLOUD-946).
    //
    // BESIDE `pinned-toolchain` RATHER THAN INSIDE IT, and the difference is the
    // affordance rather than the subject. That preset asks whether a program was
    // reached around the pin and can only name the program; this one reads a
    // receipt mapping task NAME to argv, so its refusal names the task to run
    // instead. A caller told a program was reached loosely has to go and find
    // which task wraps it; a caller told the task's name has the remedy in the
    // refusal.
    //
    // NO PATTERNS, and that is honest rather than an omission: the predicate is
    // set membership over words the boundary already parsed, so there is no
    // concept here with a spelling. `.claude/rules/policy-modules.md`'s preset
    // exemption is therefore unexercised — nothing is inline because nothing is
    // a regex.
    Manifest {
        name: "mise",
        version: semver::Version::new(0, 0, 3),
        suggested: true,
        // THE TOOL'S VOCABULARY, NONE OF THE CONSUMER'S (CLOUD-2633). The base
        // configuration always loads; `MISE_ENV` adds exactly the listed
        // environments' files on top, so an env nobody listed is never read and
        // never installed. `--missing` names what is outstanding and is silent
        // otherwise, which is what makes it a gate rather than a reporter
        // (CLOUD-1454). Dependencies a tool's backend needs install in the same
        // run, because they are tools of the same set.
        install: Some(Install {
            program: "mise",
            selector: "MISE_ENV",
            separator: ",",
            check: &["ls", "--current", "--missing"],
            repair: &["install", "--yes"],
            // `installs/` and `shims/` both live here: a shim on PATH resolves
            // before the tool behind it is installed.
            data_dir: ("MISE_DATA_DIR", ".local/share/mise"),
        }),
        // TWO SURFACES, ONE CONCERN (CLOUD-1672). This is the manifest that made
        // the per-module scope necessary, and the reason is that "mise" is a
        // subject rather than a surface. Whether an agent reproduces a task's
        // argv instead of running the task is a question about a CALL. Whether
        // the toolchain a workflow installs is the one the tree pins is a
        // question about the TREE. Splitting them into two presets would make a
        // consumer enable two things to get one concern, and would put the split
        // where the engine's old limit was rather than where the subject's is.
        modules: &[
            PresetModule {
                scope: RuleScope::MediatedCall,
                // Decides whether an agent reproduced a task's argv. No CI
                // provider is involved, so it applies everywhere.
                provider: None,
                pointer: "<preset:mise>/task-over-executable.rego",
                embedded_source: include_str!("policy/presets/mise/task-over-executable.rego"),
            },
            PresetModule {
                scope: RuleScope::Tree,
                // **THIS PAIR IS WHY `provider` IS PER MODULE** (CLOUD-1625).
                // This one matches a step's `uses: jdx/mise-action@<sha>`, so it
                // reads one provider's workflow language, while the sibling
                // above cares about no provider at all. A
                // manifest-level field would have to call the whole `mise`
                // preset GitHub-specific and switch off a module that works on
                // every host — the exact mistake CLOUD-1672 corrected for
                // `scope`, one subject later.
                provider: Some("github-actions"),
                pointer: "<preset:mise>/action-version-matches-the-pin.rego",
                embedded_source: include_str!(
                    "policy/presets/mise/action-version-matches-the-pin.rego"
                ),
            },
        ],
        verdicts: &[
            VendoredVerdict {
                id: "task reach loose",
                gloss: "a task's own program was reached directly rather than through the task",
                class: "A project that defines a task has already decided how that work is \
invoked — which program, which arguments, and which environment composes around it. \
Running the task's program directly reproduces the argv and drops the rest, and the \
failure that produces looks like the failure being investigated rather than like a wrong \
invocation. The refusal names the task because the mapping it reads is task to argv: the \
remedy is in the finding rather than a file the reader has to go and search.",
                routes: &[run(
                    "task run first",
                    "the task the refusal names, through the task runner",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "job pin other",
                gloss: "a job installs a toolchain version that disagrees with the one the tree pins",
                class: "A pinned toolchain is pinned so that every machine running this commit runs the \
same one. The action that installs it in CI resolves its own version independently, so a \
repository can declare one toolchain and run another with nothing comparing them — two \
authorities on one number, which is the disagreement pinning exists to remove. Measured: a \
consumer pinned its toolchain by version and digest, the action resolved a newer release whose \
asset could not be fetched, and every job of every workflow died in the install step inside \
eleven seconds; the release that followed published its schema and none of its binaries. The \
pin was committed and correct throughout and simply did not reach that layer. The remedy is to \
declare the version at the step so the install is the pin rather than a resolution.",
                routes: &[read("pin read first", "the row that pins the tool")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "job pin missing",
                gloss: "a job installs a pinned toolchain without saying which version",
                class: "The other direction of the same defect, and the one that actually fires, because \
an absent version reads as a default rather than as a decision. It is not a milder form of a \
wrong version: it hands the choice to the installer, which makes the toolchain a property of \
WHEN the job ran instead of what the commit says — so two runs of one commit can differ, and \
the run that breaks is the one that happened to start after an upstream release. Conditioned on \
the tool being pinned somewhere in the tree: a project that pins nothing is not asked to match \
something that does not exist.",
                routes: &[read("pin read first", "the row that pins the tool")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "workflow parse unread",
                gloss: "a declared workflow would not parse, so nothing could be compared over it",
                class: "Could-not-look, and it is deliberately not spelled the same way as absent. Absent \
is not-applicable — there is no such workflow — while unparsed means the boundary tried and \
failed. A module that iterates only the documents it could read reports green over the file it \
could not, which is a gate reporting on a surface it never saw.",
                routes: &[read(
                    "source read first",
                    "the workflow that would not parse",
                )],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    Manifest {
        name: "pinned-toolchain",
        version: semver::Version::new(0, 0, 2),
        suggested: true,
        install: None,
        modules: &[
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:pinned-toolchain>/pinned-program-via-the-pin.rego",
                embedded_source: include_str!(
                    "policy/presets/pinned-toolchain/pinned-program-via-the-pin.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:pinned-toolchain>/pinned-program-probed-bare.rego",
                embedded_source: include_str!(
                    "policy/presets/pinned-toolchain/pinned-program-probed-bare.rego"
                ),
            },
        ],
        verdicts: &[
            VendoredVerdict {
                id: "pin reach loose",
                gloss: "a program the project's pin provides was reached around the pin",
                class: "The pinned toolchain is what makes one machine's run mean anything about \
another's, and it supplies an ENVIRONMENT as well as a binary. A program reached around \
it runs a different version, or the same version without the variables the project sets \
— and the failure that produces looks like the failure being investigated rather than \
like a wrong invocation. Measured on one consumer: sixty runs of a test suite died on an \
unset variable instead of on the assertion, and the report that followed was published \
as three claims about the tree, all false.",
                routes: &[run("task run first", "mise exec -- <program>")],
                applicability: Applicability::Advice,
            },
            // THE PROBE HALF, AND A SEPARATE CLASS ON PURPOSE (CLOUD-1256).
            //
            // Not `pin reach loose`: nothing was bypassed. A pin was rendered
            // INVISIBLE — the probe ran, answered correctly about the bare PATH,
            // and the caller read the empty answer as "this tool is not installed
            // here". A class a reader looks up has to name what happened, and
            // "reached around the pin" describes a different event.
            VendoredVerdict {
                id: "pin probe bare",
                gloss: "a presence probe asked the bare PATH about a program the pin provides",
                class: "A probe like `command -v` reports what the CURRENT PATH resolves, which is a \
correct answer to a question the caller did not mean to ask. Nothing a pin provides is on the bare \
PATH — nor should it be — so for a pinned tool the answer is empty, and empty does not read as \
\"not on this PATH\", it reads as \"not installed here\". Measured on one consumer: a session probed \
for a forge client, got nothing, and routed three operations onto the documented last-resort path, \
where one of them failed outright on a credential that could not perform it. The pinned route then \
succeeded first try. The probe is not wrong, it is under-scoped, which is why this is advice rather \
than a refusal — a deny here would refuse a correct shell habit.",
                routes: &[run(
                    "probe run first",
                    "ask the pin instead — its own `which` answers about the toolchain the project \
declares, and a probe inside the pin's environment is already correct",
                )],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    // CLOUD-843's `release-hygiene`: a published release's checksum manifest
    // tells the truth about the release. The record is `batten record release`'s,
    // read by KIND rather than by family name, because the family is the
    // consumer's to declare. Which assets a release must carry is read off each
    // consumer's own build workflow, so that half stays in the consumer's module.
    Manifest {
        name: "release-hygiene",
        version: semver::Version::new(0, 0, 2),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::Tree,
            // Reads a record `batten record release` writes; no CI provider's
            // expression language is involved, so it applies anywhere.
            provider: None,
            pointer: "<preset:release-hygiene>/checksums-cover-the-release.rego",
            embedded_source: include_str!(
                "policy/presets/release-hygiene/checksums-cover-the-release.rego"
            ),
        }],
        verdicts: &[
            VendoredVerdict {
                id: "release pin broken",
                gloss: "a release's checksum manifest is missing, lists itself, covers nothing, omits or orphans an asset, or disagrees on bytes",
                class: "A manifest a packager cannot trust pins nothing. Uploads are routinely \
idempotent and a failed leg is recovered by re-running it, so an asset can be replaced after the \
manifest was cut, and nothing downstream notices: every consumer verifying against the manifest \
either fails for a reason that looks like tampering or, where the manifest omits the asset, \
verifies nothing at all. Re-derive the manifest from the release as it now stands and re-upload \
it.",
                routes: &[run(
                    "sums run first",
                    "batten release sums <tag> --manifest <name>, then upload the manifest it writes",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "release record torn",
                gloss: "a release record carries no census, or one that disagrees with its lines",
                class: "A record torn mid-write judges part of a release as if it were all of it: \
a manifest check over half the asset list reports the other half as neither covered nor missing. \
The census closes the record and counts every kind above it, so a disagreement is a finding about \
the record rather than a verdict about the release. Record it again.",
                routes: &[run(
                    "record run first",
                    "batten record release <tag> --manifest <name>",
                )],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    // CLOUD-2279's `engine-hygiene`: a consumer's engine pin is no further
    // behind the latest release than the consumer allows. The thresholds are
    // the producer's (`batten engine outdated --record`), because a preset
    // cannot read a consumer's numbers; the module reads the verdict line by
    // KIND, the family being the consumer's to declare.
    Manifest {
        name: "engine-hygiene",
        version: semver::Version::new(0, 0, 1),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::Tree,
            // Reads a record `batten engine outdated` writes; no CI provider's
            // expression language is involved, so it applies anywhere.
            provider: None,
            pointer: "<preset:engine-hygiene>/engine-pin-fresh.rego",
            embedded_source: include_str!("policy/presets/engine-hygiene/engine-pin-fresh.rego"),
        }],
        verdicts: &[VendoredVerdict {
            id: "release pin stale",
            gloss: "the engine pin is more releases or days behind the latest release than the consumer allows",
            class: "A pin left behind still runs, so nothing else says it is stale: the consumer \
judges its work with an engine whose fixes and gates it does not have, and the distance only grows. \
`batten engine outdated --record` measured the pin against the release `main` pins, with the \
consumer's own thresholds, and found it past them. Bring every batten declaration forward in one \
step.",
            routes: &[run("update run first", "batten engine update")],
            applicability: Applicability::Advice,
        }],
        patterns: &[],
    },
    // #1276's lint half of CLOUD-2777: a `:=` whose right side can be undefined,
    // which regorus's bytecode binds as `Undefined` where the interpreter fails
    // the body. Reads `Fact::Units` over the Rego the row declares; names no
    // consumer path (rule 1).
    Manifest {
        name: "rego-hygiene",
        version: semver::Version::new(0, 0, 1),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::Tree,
            provider: None,
            pointer: "<preset:rego-hygiene>/binding-is-defined.rego",
            embedded_source: include_str!("policy/presets/rego-hygiene/binding-is-defined.rego"),
        }],
        verdicts: &[VendoredVerdict {
            id: "module bind partial",
            gloss: "a Rego `:=` binds a right side that can be undefined",
            class: "Rego fails a body at a `:=` whose right side is undefined, and so do OPA and \
regorus's interpreter; regorus's bytecode compiler drops that guard after `:=` alone, so the \
statement binds `Undefined` and the body runs on. The two evaluators then decide differently over \
the same input, and a `_ := e` written to assert that `e` is defined asserts nothing. The right \
side here is a lookup, a call to a helper of the same module with no `default` and no `else`, or \
the left side is `_`.",
            routes: &[
                run(
                    "source edit first",
                    "bind with `=` (unification keeps the guard on both evaluators, `_ = e` \
included)",
                ),
                run(
                    "default add first",
                    "give the helper a `default` or an `else` body, so every call has a value",
                ),
            ],
            applicability: Applicability::Advice,
        }],
        patterns: &[],
    },
    // Version 2 (CLOUD-1994) adds the line-unit ban, lifted out of the consumer
    // module it was written as. Its facts — which manifests, keys, unit headers,
    // workflow globs and exempt files — are the consumer's `[census.shell]`
    // table, found by shape in the documents the row declares, so the preset
    // names none.
    //
    // Version 3 (CLOUD-2335) adds the write-time arm: a mediated module refusing
    // a write that authors shell, over the `shell-introduced` fact the hook
    // decides with the same detector. A second row at `mediated_call` enables it.
    // CLOUD-2628 rides the same version, since both ship in one release: the ban
    // refuses shell's PRESENCE by default — a consumer declaring no
    // `[census.shell]` included — admitting only a generated-table entry, and
    // judges growth alone under `mode = "migrate"` or a legacy `exempt` list.
    // SUGGESTED HERE, where #1278 (CLOUD-2628) made it an opt-in no starter
    // names: shell should never have been addable, and generated shell enters
    // through the generated table (owner, 2026-11-22), so the ban is what a
    // repository starts from, not a preset it has to find.
    Manifest {
        name: "shell-hygiene",
        // 3 (CLOUD-2335): the write-time arm, a mediated module refusing a
        // write that authors shell over the `shell-introduced` fact the hook
        // decides with the same detector. A second row at `mediated_call`
        // enables it.
        version: semver::Version::new(0, 0, 4),
        suggested: true,
        install: None,
        modules: &[
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:shell-hygiene>/shebang-names-its-language.rego",
                embedded_source: include_str!(
                    "policy/presets/shell-hygiene/shebang-names-its-language.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:shell-hygiene>/sibling-resolves.rego",
                embedded_source: include_str!("policy/presets/shell-hygiene/sibling-resolves.rego"),
            },
            PresetModule {
                scope: RuleScope::Tree,
                // Reads a workflow's `run:` steps, but only in the files the
                // consumer's own `[census.shell] workflows` globs name — the
                // declaration is what says "these files carry `run:` steps", the
                // same contract `batten census shell` reads them under. Its
                // manifest and file arms read no provider at all.
                provider: None,
                pointer: "<preset:shell-hygiene>/no-new-shell.rego",
                embedded_source: include_str!("policy/presets/shell-hygiene/no-new-shell.rego"),
            },
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:shell-hygiene>/no-shell-written.rego",
                embedded_source: include_str!("policy/presets/shell-hygiene/no-shell-written.rego"),
            },
        ],
        verdicts: &[
            VendoredVerdict {
                id: "program name unnamed",
                gloss: "the file runs a shell and its name does not say so",
                class: "Every instrument that selects by extension — a formatter, a linter, a \
CI path filter — covers this file silently and exits 0. A green run over it therefore \
means nothing was looked at rather than nothing was found, which is worse than a red \
one. Name the language in the filename, or declare the file's coverage another way.",
                routes: &[run("patch run first", "git mv")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "program resolve missing",
                gloss: "a run-time sibling path is computed and the tree carries no such file",
                class: "The shape resolves a path beside the running program and then guards it \
with a test that exits 0, so the reference does not fail — it goes silent, and the \
behaviour it was reaching for simply never happens. A path that must exist should be \
asserted rather than tested.",
                routes: &[read("source read first", "the computed path")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "task write refused",
                gloss: "a declared manifest's shell code lines rose against the base",
                class: "This repository has declared where its shell lives and that it writes no \
more. A command key's shell lines — every code line of a triple-quoted body, and each one-line \
value or array entry carrying shell syntax — may fall and may never rise. Counted in lines rather \
than bodies because a body count reads a 245-line body as one, and relocating whole programs into \
command strings then reads as the surface shrinking. Put the decision in a policy module, the \
fetch in a declared recorder, and the glue in an argv command; what is left over is a verb.",
                routes: &[read(
                    "source read first",
                    "the manifest's grown unit and the census declaration",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "task add refused",
                gloss: "a manifest unit that carried no shell at the base carries some now",
                class: "The arm relocation cannot offset: moving a body into a new unit while deleting \
a bigger one elsewhere keeps the line count level and still gives a unit shell it did not have. \
The pointer is the unit's header. Deleting shell is always free, and an edit inside a body that \
does not grow it is admitted, so a fix to an existing body lands; a new one does not.",
                routes: &[read("source read first", "the unit's header")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "step write refused",
                gloss: "a declared workflow's run: shell lines rose against the base",
                class: "A workflow step is where a shell line is the native spelling, which is why the \
step itself stays allowed and a single-command step is not counted. What is counted is the shell \
around it: every code line of a `run: |` or `run: >` block and every one-liner carrying shell \
syntax. Move the logic into a declared task or the engine and call it from the step.",
                routes: &[read("source read first", "the workflow's grown step")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "shell place refused",
                gloss: "a migrating repository added a shell file its census does not admit",
                class: "A `.sh`, `.bash` or `.bats` path, or a file whose first line names a shell, \
was added while the census declares `mode = \"migrate\"` or still carries a legacy `exempt` list. \
Migrating means existing shell may shrink and no new shell arrives: the files the census admits \
are its legacy exempt globs and its generated table, and widening either is a reviewed change to \
the committed config. Anything else is a verb, a module or a recorder.",
                routes: &[read(
                    "source read first",
                    "the census declaration's generated table",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "shell present refused",
                gloss: "the tree carries shell that no generated-table entry admits",
                class: "This repository enabled the shell ban without declaring that it is \
migrating, so shell is refused wherever it is: a shell file, a declared manifest's shell command \
lines, a declared workflow's shell steps. The only shell admitted is a file a \
`[[census.shell.generated]]` entry covers, naming the generator that writes it and the test that \
holds its bytes. Port the rest, or declare `mode = \"migrate\"` while it is ported.",
                routes: &[read(
                    "source read first",
                    "the census declaration and the shell it points at",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "file write refused",
                gloss: "an existing shell file's code lines rose against the base",
                class: "Under migration, existing shell may shrink and may never grow: a shell \
file edited on this branch carries more code lines than its base, or became shell by gaining a \
shebang. Deleting shell is always free, and an edit that does not grow the file lands. Put the \
new logic in a verb, a module or an argv task.",
                routes: &[read("source read first", "the grown shell file")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "shell path missing",
                gloss: "a generated-table entry's glob matches no tracked file",
                class: "Each `[[census.shell.generated]]` entry admits shell a generator writes, \
so an entry with nothing behind it is an admission waiting for a file nobody reviewed. The table \
is held in both directions: shell outside it is refused, and an entry covering no tracked path is \
refused too. Delete the entry, or correct its glob.",
                routes: &[read("source read first", "the generated entry's glob")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "shell test missing",
                gloss: "a generated-table entry's check names a test its file does not hold",
                class: "A generated entry admits shell because a named test holds the generator's \
bytes; `check = \"<test file>::<test name>\"` must point at a file one of whose lines carries the \
test name. An absent file or a name no line holds is a check nothing runs, so the admission \
stands on nothing. Point the entry at the test that pins the generated bytes.",
                routes: &[read("source read first", "the generated entry's check")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "shell spawn refused",
                gloss: "engine source spawns a shell no spawn-table row declares",
                class: "A string-literal argv outside test code runs a shell: `Command::new(\"sh\")`, \
an `(\"sh\", \"-c\")` pair, or an interpreter handed an inline script. The engine runs programs, not \
shell, so the only spawn admitted is one a `[[census.shell.spawn]]` row declares, naming the file, \
the function and the external format that forces a shell, with its citation. Spawn the program \
directly with its argv instead.",
                routes: &[read("source read first", "the spawn site")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "shell spawn missing",
                gloss: "a spawn-table row names a function that spawns no shell",
                class: "Each `[[census.shell.spawn]]` row admits one function's shell spawn, so a \
row whose function spawns none is an admission waiting for a spawn nobody reviewed. The table is \
held in both directions. Delete the row, or correct its path or function.",
                routes: &[read(
                    "source read first",
                    "the census declaration's spawn table",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "shell write refused",
                gloss: "a write would create a shell file or put a shell shebang on line 1",
                class: "This repository has stopped writing shell, and the write is where that is \
cheapest to hear: the tree arms would refuse the same file at verify, after the work around it was \
built. A write that creates a shell-named file, or puts a shebang naming a shell on a file whose \
first line named none, is refused; an edit to a file that already starts with one is the tree \
arms' to judge. The agent's own commands are never judged here, only what the repository would \
commit.",
                routes: &[read(
                    "source write first",
                    "write it as Rust, a `batten` verb, or an argv task",
                )],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    // CLOUD-843. The board's own claims held to what the tree and the forge
    // already say: a Done that no release carries, a Done over a pull request
    // still open, a duplicate close taken in its target's operation, a deferral
    // with no owner, and a body that never closes what its branch served.
    //
    // EVERY MODULE READS A FAMILY `record derive` WRITES, and the family names are
    // the engine's rather than a consumer's: `crate::tracker_reading` owns both
    // the names and the line shapes, so nothing here names a consumer fact. A
    // consumer declares one `[[record]]` row per family it produces, as for any
    // record a module reads.
    //
    // ONE ROW JUDGES ALL FIVE, which is safe only because the producer clears
    // every tracker family before it reads: the store then holds the answer to
    // the question just asked and nothing older (`record::run_derive`).
    // CLOUD-1221 (P14 of CLOUD-843) folded the BOARD half into this entry rather
    // than a second `Manifest` of the same name, which `no_preset_is_declared_twice`
    // refuses: a column that lies, a cyclic or unfetched relation, a gloss the
    // board contradicts, an unready ready queue, a citation naming nothing. Those
    // five read the `board-*` families `batten board check` writes and evaluates
    // in process; `crate::board_check` owns their names, so nothing here names a
    // consumer fact either.
    Manifest {
        name: "tracker-hygiene",
        version: semver::Version::new(0, 0, 2),
        suggested: true,
        install: None,
        modules: &[
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:tracker-hygiene>/closing-key-closes.rego",
                embedded_source: include_str!(
                    "policy/presets/tracker-hygiene/closing-key-closes.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:tracker-hygiene>/deferral-has-an-owner.rego",
                embedded_source: include_str!(
                    "policy/presets/tracker-hygiene/deferral-has-an-owner.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:tracker-hygiene>/done-has-no-open-pull.rego",
                embedded_source: include_str!(
                    "policy/presets/tracker-hygiene/done-has-no-open-pull.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:tracker-hygiene>/done-is-released.rego",
                embedded_source: include_str!(
                    "policy/presets/tracker-hygiene/done-is-released.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:tracker-hygiene>/duplicate-close-is-argued.rego",
                embedded_source: include_str!(
                    "policy/presets/tracker-hygiene/duplicate-close-is-argued.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:tracker-hygiene>/shipping-is-not-sufficient.rego",
                embedded_source: include_str!(
                    "policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:tracker-hygiene>/board-columns-tell-the-truth.rego",
                embedded_source: include_str!(
                    "policy/presets/tracker-hygiene/board-columns-tell-the-truth.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:tracker-hygiene>/board-graph-is-acyclic.rego",
                embedded_source: include_str!(
                    "policy/presets/tracker-hygiene/board-graph-is-acyclic.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:tracker-hygiene>/board-claims-agree.rego",
                embedded_source: include_str!(
                    "policy/presets/tracker-hygiene/board-claims-agree.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:tracker-hygiene>/board-frontier-is-ready.rego",
                embedded_source: include_str!(
                    "policy/presets/tracker-hygiene/board-frontier-is-ready.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:tracker-hygiene>/board-citations-resolve.rego",
                embedded_source: include_str!(
                    "policy/presets/tracker-hygiene/board-citations-resolve.rego"
                ),
            },
        ],
        verdicts: &[
            VendoredVerdict {
                id: "diff key missing",
                gloss: "the pull request body names its issue but never in closing form, so the merge moves nothing",
                class: "A tracker's merged-event automation fires only for a closing pull request: a \
trailer-only reference merges and never moves the row, where a closing keyword moves it in \
seconds. Write the closing keyword before the key, or a line-anchored hold marker if this pull \
request is not meant to complete it.",
                routes: &[run(
                    "task run first",
                    "write the closing keyword, then record the body again with `batten record derive closing-key`",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "diff key dropped",
                gloss: "the pull request body closes some of the keys its commits served and strands the rest",
                class: "A served key the body does not close never reaches review while its work is on \
the trunk. Close each one, or name it on a hold marker line to decline just that one.",
                routes: &[run(
                    "task run first",
                    "close the stranded key, then record the body again with `batten record derive closing-key`",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "diff read partial",
                gloss: "the closing-key record is missing one of its four readings",
                class: "A record missing a reading decides over part of the answer, so it is refused \
rather than judged.",
                routes: &[run(
                    "task run first",
                    "record the body again with `batten record derive closing-key`",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "prose own unnamed",
                gloss: "a pull-request paragraph defers a decision and names no owning issue besides the one it claims",
                class: "A pull-request body is not a durable home: nothing sweeps merged bodies, and the \
board is what others read. File the decision and name its key in the same paragraph; the key \
this pull request claims names the work in hand, not a home for what it leaves open.",
                routes: &[run(
                    "task run first",
                    "file the owning issue, name it in the paragraph, then record the body again with `batten record derive deferral`",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "prose read partial",
                gloss: "the deferral record carries no closing census, or one that disagrees with its lines",
                class: "A record torn mid-write judges part of a body as if it were all of it.",
                routes: &[run(
                    "task run first",
                    "record the body again with `batten record derive deferral`",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "issue ship early",
                gloss: "an issue is headed for Done while one of its own pull requests is still open",
                class: "A merged pull request completes a diff, and a board reading it as completing an \
issue is right only when the issue carries one. Every pull request an issue carries has to have \
landed or been closed before the issue is done, and a draft is open. The refusal is arithmetic: \
whether the merged ones did the work is not judged.",
                routes: &[read(
                    "record read first",
                    "the open pull request the refusal names",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "issue point missing",
                gloss: "an issue is headed for Done and carries no pull request at all",
                class: "Review already requires a linked pull request, so Done cannot need less. An \
issue with none either shipped nothing or links its work somewhere the gate cannot read.",
                routes: &[read("record read first", "the issue's attachments")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "issue list partial",
                gloss: "the done-pr record carries no closing census, or one that disagrees with its lines",
                class: "A record torn mid-write judges part of a board as if it were all of it.",
                routes: &[run(
                    "task run first",
                    "record the board again with `batten record derive done-pr`",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "issue ship ahead",
                gloss: "an issue reads Done while its commits are on the trunk and no release contains them",
                class: "Done means released, and landed-but-unreleased is review. Refs come from commit \
messages, so a ref inside a release cannot confirm a Done — but a ref on the trunk that no \
release tag reaches is conclusive: nothing shipped it.",
                routes: &[read(
                    "record read first",
                    "the release that has not been cut",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "issue read partial",
                gloss: "the done record carries no closing census, or one that disagrees with its lines",
                class: "A record torn mid-write judges part of a board as if it were all of it. The \
census is written last and counts the lines above it, so a missing or wrong one is a write that \
did not finish rather than a clean board.",
                routes: &[run(
                    "task run first",
                    "record the board again with `batten record derive done`",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "issue ship held",
                gloss: "a release shipped this row, and it holds itself open: shipping is necessary for Done, not sufficient",
                class: "A row in review carries the hold marker in its own description. The tag \
contains its work, and the row still says it is not finished. Resolve the hold, or strike the \
marker, before moving it to Done.",
                routes: &[read("record read first", "the row's description")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "issue ship refused",
                gloss: "a release shipped this row, and the board gate rejects its column: fix the board before moving it",
                class: "Review to Done is a conjunction: the tag must have shipped the row AND the \
board must be labelling it honestly. The second half is the board gate's own verdict, forwarded \
by the producer rather than re-derived, and the pointer names the rule it raised.",
                routes: &[run("task run first", "batten board check")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "tag read partial",
                gloss: "the released record carries no closing census, or one that disagrees with its lines",
                class: "A record torn mid-write judges part of a release as if it were all of it.",
                routes: &[run(
                    "task run first",
                    "record the release again with `batten record derive released`",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "issue grade twice",
                gloss: "a duplicate close was decided in the same operation as its target's own close",
                class: "Whether two rows contradict is not computable, and this does not claim to. A \
duplicate close whose target entered a completed state in the same second is two decisions taken \
as one, and one was never argued. Argue the close on its own: either the rows really say the same \
thing, or the closed one carries a finding about the survivor and needs reopening.",
                routes: &[read("record read first", "both rows the pointer names")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "issue count partial",
                gloss: "the duplicate-close record carries no closing census, or one that disagrees with its lines",
                class: "A record torn mid-write judges part of a board as if it were all of it. The \
census is written last and counts the lines above it.",
                routes: &[run(
                    "task run first",
                    "record the board again with `batten record derive duplicate-close`",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "issue state wrong",
                gloss: "a board column, relation or status gloss says something the board contradicts",
                class: "A column is a claim about the work, and the board is the surface everyone \
else reads it from. Pulled means somebody has it; landed means a pull request is attached unless \
the row declares it lands no commit; a started row names its phase; the ready queue holds only \
rows whose Ready block passes; the blocked-by relation has no cycle; and a body glossing another \
row's column agrees with the board. The pointer names the row and the rule, never the body.",
                routes: &[read("source read first", "the row the pointer names")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "issue judge partial",
                gloss: "the piped payload set is too thin to judge, so the board has not been judged",
                class: "Could-not-look, and it outranks a refusal: a verdict over a set only partly \
read is not a verdict, because the next action is a re-fetch after which more refusals may \
appear. A row without its relations, attachments, milestone or description, a blocker, parent \
or claimed row the set does not carry, and a claimed column nobody piped occupies are each this \
class, keyed to the set when the set is what is short.",
                routes: &[read(
                    "source read first",
                    "the rows the pointer names, fetched again with relations and attachments",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "path point missing",
                gloss: "a Ready block cites a test or a path the tree does not carry",
                class: "This checks existence, never relevance. A cited test must be carried by \
the declared corpus — a fixture quoting the citation is not the thing cited — and a cited path \
must exist or be marked prospective beside its own path. A marked path an ancestor deleted is \
refused anyway: history may refute a marker and is never asked to grant one.",
                routes: &[read(
                    "source read first",
                    "the Ready block's live obligations clause",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "source point wrong",
                gloss: "a clause citation in the tree names a clause its issue does not carry",
                class: "A citation of a clause that is not there points a reader at nothing. Cite \
the clause that holds the content, or the issue's own clause if it moved. A sparse clause set is \
not a defect; only the citation of an absent clause is.",
                routes: &[read("source read first", "the cited issue's Ready block")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "source point unread",
                gloss: "a clause citation names an issue the piped set does not carry",
                class: "Could-not-look, never a pass: an unfetched issue looks exactly like a clean \
one. Fetch the cited issue and pipe the set again.",
                routes: &[read("source read first", "the cited issue, fetched")],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    // CLOUD-843's `supply-chain`: what a release and a commit claim about where
    // they came from is checkable. ONE MANIFEST FOR THE WHOLE BUNDLE: the SBOM
    // readings (`binary-inventory-is-lockfile-bound.rego`, `cargo list empty`,
    // `cargo list wrong`) are further modules and verdicts in THIS entry, never a
    // second `Manifest` of the same name — `no_preset_is_declared_twice` refuses
    // that, and `find` would answer with whichever came first. Each module binds
    // its own `package` so their helpers cannot collide. These two read records
    // the ENGINE's own producers write under the producer's name (`record derive
    // signing-posture`, `record attestation`), and git facts a row declares, so no
    // consumer fact travels inside one.
    Manifest {
        name: "supply-chain",
        version: semver::Version::new(0, 0, 3),
        suggested: true,
        install: None,
        modules: &[
            PresetModule {
                scope: RuleScope::Tree,
                // A forge's attestation endpoint answered through the engine's
                // producer, never a workflow's expression language.
                provider: None,
                pointer: "<preset:supply-chain>/attestation-is-verified.rego",
                embedded_source: include_str!(
                    "policy/presets/supply-chain/attestation-is-verified.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                // git's own config scopes and commit headers; no CI provider.
                provider: None,
                pointer: "<preset:supply-chain>/signer-is-verifiable.rego",
                embedded_source: include_str!(
                    "policy/presets/supply-chain/signer-is-verifiable.rego"
                ),
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:supply-chain>/binary-inventory-is-lockfile-bound.rego",
                embedded_source: include_str!(
                    "policy/presets/supply-chain/binary-inventory-is-lockfile-bound.rego"
                ),
            },
        ],
        verdicts: &[
            VendoredVerdict {
                id: "release ship unsafe",
                gloss: "a release archive's binary carries no verifiable provenance",
                class: "The verifier refused the executable inside a published archive while the \
platform DOES offer attestation for this repository. That is a release to fix rather than a gap \
to report, and the two are told apart by the attestations endpoint's own status code: 200 with an \
empty list where the feature exists, 404 on the resource where it does not. The subject is the \
BINARY and not the archive, because a release attests the executable so that repackaging cannot \
launder the claim.",
                routes: &[run(
                    "record run first",
                    "batten record attestation <tag> --binary <name>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "release carry missing",
                gloss: "a release archive carries no executable to verify",
                class: "The archive unpacked and held no binary of the declared name, so there was \
nothing for the verifier to judge. A packaging problem rather than a provenance one, and its own \
class for that reason: collapsing it into the unverified finding would send a reader after a \
signing identity when the build matrix dropped a file.",
                routes: &[run(
                    "record run first",
                    "batten record attestation <tag> --binary <name>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "release list empty",
                gloss: "the producer looked at a tag and found no archive on it",
                class: "A green verdict over a release carrying nothing would be about nothing. \
Present-and-empty and absent are different readings and must not collapse: an absent record is \
the producer unable to look, where this is the producer having looked and found a tag with no \
archives.",
                routes: &[run(
                    "record run first",
                    "batten record attestation <tag> --binary <name>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "config carry unsafe",
                gloss: "signing is on in this checkout with a signer whose key cannot be verified or reproduced",
                class: "NOT A VERDICT ABOUT SIGNING, which is good. It is about a signature that \
LOOKS like provenance and carries none: a key whose public half cannot be read, or a signer under \
a directory the environment reclaims. The refusal is the CONFLICT — something turns signing on and \
no local `false` answers it — never the mere absence of a local override, because a CI runner has \
no launcher and an absent local value is correct there.",
                routes: &[run("repair run first", "batten attribution signing")],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "commit carry unsafe",
                gloss: "a commit in range carries a gpgsig from a key this repository cannot verify or reproduce",
                class: "The posture already produced one. Config can be repaired AFTER a commit was \
written, so a repaired checkout still carries what it signed before the repair — and those are \
exactly what must not land. That is why this is a separate class from the config one rather than \
the same finding twice: repairing the config clears that arm and leaves this one firing. Rewrite \
the range unsigned, or publish the key's public half so the signature becomes verifiable.",
                routes: &[read(
                    "module read first",
                    "<preset:supply-chain>/signer-is-verifiable.rego",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "cargo list empty",
                gloss: "a binary's inventory recovered fewer than two rust-crate packages",
                class: "0 is a build that lost its `cargo auditable` wrapper, 1 is the binary \
cataloging only itself; both are an empty document that exits 0, and a gate that checks nothing \
must not report green. Rebuild the binary through the wrapper and scan it again.",
                routes: &[run(
                    "task run first",
                    "batten sbom --binary <binary> --target <triple>",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "cargo list wrong",
                gloss: "a binary's inventory names a crate the lockfile does not declare",
                class: "Subset, never equality: the lockfile spans every target's build and dev \
dependencies. A recovered crate outside it means the binary was not built from this lockfile.",
                routes: &[run(
                    "task run first",
                    "batten sbom --binary <binary> --target <triple>",
                )],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    // A leased push naming no expected value is a force (git-push(1): its
    // protection "is trivially defeated" by a background fetch). Its own bundle
    // rather than a second `trunk-based` module, the CLOUD-2273 precedent: an
    // enabling row is named for the one class it raises, so adding a class to
    // `trunk-based` would break every consumer row named `trunk push forced`.
    // Moved from a repository-local module (plan item 4c).
    Manifest {
        name: "lease-asserted",
        version: semver::Version::new(0, 0, 1),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::MediatedCall,
            provider: None,
            pointer: "<preset:lease-asserted>/lease-unasserted.rego",
            embedded_source: include_str!("policy/presets/lease-asserted/lease-unasserted.rego"),
        }],
        verdicts: &[VendoredVerdict {
            id: "branch write unnamed",
            gloss: "a push that overwrites the remote without having said what it expects to find",
            class: "A leased push naming no expected value (`--force-with-lease`, or \
`--force-with-lease=<ref>`) compares against this clone's remote-tracking ref, so `git fetch` \
followed by the push compares EQUAL and overwrites the commit the fetch just brought in; \
git-push(1) says its protection \"is trivially defeated if some background process is updating \
refs\". The explicit `=<ref>:<sha>` form is not this class, because naming the sha IS the \
assertion and a stale one is refused by git; nor is a lease with `--force-if-includes`, which \
git refuses unless the remote-tracking tip was integrated locally.",
            routes: &[
                run(
                    "patch run first",
                    "git fetch, then rebase onto what is there",
                ),
                run(
                    "task run other",
                    "git push --force-with-lease=<ref>:<sha> — name the commit you expect to replace",
                ),
                admit(
                    "path admit first",
                    "the history being replaced is this clone's own and no other clone has \
fetched it, so there is no expected value to name that a reader could check",
                ),
            ],
            applicability: Applicability::Advice,
        }],
        patterns: &[],
    },
    Manifest {
        name: "trunk-based",
        version: semver::Version::new(0, 0, 1),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::MediatedCall,
            provider: None,
            pointer: "<preset:trunk-based>/no-force-push.rego",
            embedded_source: include_str!("policy/presets/trunk-based/no-force-push.rego"),
        }],
        verdicts: &[VendoredVerdict {
            id: "trunk push forced",
            gloss: "a force push rewrites a shared branch under whoever already fetched it",
            class: "Rewriting a published branch invalidates every checkout of it that \
already exists, and the holder finds out by having their next pull fail in a way that \
looks like their own mistake. An asserted `--force-with-lease=<ref>:<sha>` refuses when the \
remote moved, which is the same operation with the one check that makes it safe.",
            // THE EXPLICIT FORM, never the bare flag (CLOUD-2057): a bare
            // `--force-with-lease` compares against this clone's tracking ref and
            // is itself refused by `branch write unsafe`, so naming it here sent a
            // refused reader straight into a second refusal.
            routes: &[run(
                "patch run first",
                "git push --force-with-lease=<ref>:<sha>",
            )],
            applicability: Applicability::Advice,
        }],
        patterns: &[],
    },
    // CLOUD-2273: the call that makes the merge commit a linear trunk refuses at
    // the fast-forward, refused where it is one command to undo. Its own bundle
    // rather than a second `trunk-based` module, so each enabling row is named
    // for the one class it raises.
    Manifest {
        name: "linear-history",
        // 2: `git rebase --rebase-merges` (`-r`) is refused too, since it replays
        // a branch's merge commits as merge commits (CLOUD-2813).
        version: semver::Version::new(0, 0, 2),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::MediatedCall,
            provider: None,
            pointer: "<preset:linear-history>/no-merge-into-branch.rego",
            embedded_source: include_str!(
                "policy/presets/linear-history/no-merge-into-branch.rego"
            ),
        }],
        verdicts: &[VendoredVerdict {
            id: "commit write loose",
            gloss: "a merge or a merging pull wove a commit a linear trunk will refuse",
            class: "A trunk requiring linear history refuses a merge commit at the \
fast-forward, after CI has run. `git merge <ref>` writes one, so does `git pull` without \
`--rebase`, and `git rebase --rebase-merges` keeps the ones a branch already has; replaying the \
branch onto what it should follow makes the same change as a line. The usual cause is a push \
refused because the branch's own remote moved: that is rebased onto the fetched head, never \
merged with it.",
            routes: &[
                run("patch run first", "batten land replay <base>"),
                run(
                    "branch write first",
                    "a refused push: git fetch origin <branch>, git rebase FETCH_HEAD, then git \
push --force-with-lease=<branch>:<the head you rebased onto>",
                ),
            ],
            applicability: Applicability::Advice,
        }],
        patterns: &[],
    },
    // Plan step 3 / CLOUD-2821: Rust code quality judged against a base, from
    // facts the engine measures. First module: the module graph's M-score never
    // falls and its largest cycle never grows, which retires `modules.lock`
    // (Decoupling Level and propagation cost are reported, not gated: see the
    // module's header for the evidence).
    Manifest {
        name: "rust-quality",
        version: semver::Version::new(0, 0, 1),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::Tree,
            provider: None,
            pointer: "<preset:rust-quality>/decoupling-level.rego",
            embedded_source: include_str!("policy/presets/rust-quality/decoupling-level.rego"),
        }],
        verdicts: &[
            VendoredVerdict {
                id: "module score dropped",
                gloss: "the change lowers the module graph's M-score against its base",
                class: "M-score (Pisch et al., ESEM 2024) scores a module graph from 0 to 1: \
small modules, few dependencies from lower layers into each, and sparse edges inside each \
score higher. Over 1,220 releases it tracked maintenance effort and stayed stable where \
Decoupling Level and propagation cost were distorted by size and isolated files, so adding \
unconnected files cannot satisfy it. Cut the new edge, or move or inject what it reached.",
                routes: &[run(
                    "edge cut first",
                    "remove the new `use`/qualified path the change added, move the item it \
names into a module below both, or inject it (a trait or fn parameter in place of the \
dependency; Lakos, Large-Scale C++ Vol. I, sections 3.5 and 3.7.5)",
                )],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "module cycle grown",
                gloss: "the change grows the largest cycle of files in the module graph",
                class: "Files that depend on each other in a cycle can only be understood, \
built and tested together. Cycles among files had the most impact on maintenance burden in \
a 1,252-project study (ICSE 2025), and acyclic dependencies are a design imperative (Lakos, \
Large-Scale C++ Vol. I, 2.2.24). The change joined more files to the largest cycle; break \
the edge that closed it.",
                routes: &[run(
                    "cycle cut first",
                    "find the edge the change added from a file below back into one above, \
and remove it, move the item down, or inject it",
                )],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    // CLOUD-2812 / CLOUD-2798: a Rust workspace's crate graph is reviewable
    // data. Each package's allowed reach is a consumer `[[pattern]]` row
    // `crate-allow-<package>`; the module reads the `crate-reach` record and
    // refuses a reached member the row does not admit, or a package with no
    // row. No crate name is compiled here (rule 1).
    Manifest {
        name: "rust",
        version: semver::Version::new(0, 0, 2),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::Tree,
            provider: None,
            pointer: "<preset:rust>/crate-reach.rego",
            embedded_source: include_str!("policy/presets/rust/crate-reach.rego"),
        }],
        verdicts: &[
            VendoredVerdict {
                id: "crate reach unknown",
                gloss: "a workspace crate reaches one its crate-allow pattern does not admit",
                class: "A crate boundary is the one dependency rule the compiler enforces, \
so a `Cargo.toml` edit that adds an edge can turn a wide crate graph back into a deep one \
with nothing saying so; \"the most important property of a crate is which crates it doesn't \
(transitively) depend on\" (Kladov, Fast Rust Builds). The package's `crate-allow-<package>` \
pattern is the reviewed record of what it may reach, and the record shows it reaching a \
workspace package the pattern does not match. Both packages are named.",
                routes: &[
                    run(
                        "edge cut first",
                        "remove the dependency from the package's `Cargo.toml`, or move what \
uses it into a package its pattern admits",
                    ),
                    run(
                        "pattern add other",
                        "widen `crate-allow-<package>` in `batten.toml` when the edge is the \
design, in the same change that adds it",
                    ),
                    run(
                        "crate cut other",
                        "batten modules cut --dry-run <from> <name> <module>..., then again \
without --dry-run",
                    ),
                ],
                applicability: Applicability::Advice,
            },
            VendoredVerdict {
                id: "crate declare missing",
                gloss: "a workspace crate has no crate-allow pattern",
                class: "Every workspace package declares what it may reach, so a new crate \
cannot dodge the reach gate by being undeclared. The record shows a package with no \
`crate-allow-<package>` pattern in `batten.toml`.",
                routes: &[run(
                    "pattern add first",
                    "add a `[[pattern]]` row `crate-allow-<package>` whose regex matches the \
workspace packages it may reach, `^$` for none",
                )],
                applicability: Applicability::Advice,
            },
        ],
        patterns: &[],
    },
    // CLOUD-2270: a push replacing a head whose wait stopped red erases the
    // failed checks' verdicts, so each one's log is read before the push. The
    // record is the `red-head` fact `land` writes; its own bundle, so the row
    // enabling it names the one class it raises.
    Manifest {
        name: RED_HEAD,
        version: semver::Version::new(0, 1, 1),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::MediatedCall,
            provider: None,
            pointer: "<preset:red-head>/no-push-over-unread-red.rego",
            embedded_source: include_str!("policy/presets/red-head/no-push-over-unread-red.rego"),
        }],
        verdicts: &[VendoredVerdict {
            id: "job read unread",
            gloss: "a push would replace a red head whose failed checks were never read",
            class: "When a landing stops red, the failed checks' logs say why, and a push \
replacing that head starts a new run that buries them. Reading one failure and pushing \
erases the others, and a check still running at the stop reports on a head nobody will \
look at again. Read each named failed job's log first; reading is what admits the push.",
            routes: &[
                run(
                    "job read first",
                    "batten mcp call github get_job_logs '{\"owner\":\"<owner>\",\"repo\":\"<repo>\",\"job_id\":<id>,\"return_content\":true}'",
                ),
                // A FAILED CHECK NO ACTIONS JOB RUNS has a check run and no log,
                // so its read is the run itself (review of #1180).
                run(
                    "job read other",
                    "batten mcp call github get_check_run '{\"owner\":\"<owner>\",\"repo\":\"<repo>\",\"check_run_id\":<id>}'",
                ),
            ],
            applicability: Applicability::Advice,
        }],
        patterns: &[],
    },
    // EVERY GIT CALL BATTEN ALLOWS IS PUT TO NO ONE (CLOUD-2057). One module and
    // no verdicts: it never refuses, it only stops the host re-deciding a call
    // the engine already allowed. Destructive calls are left to the host.
    Manifest {
        name: "git",
        // 0.0.3, a patch: the destructive-call predicate moved into the shared
        // `host-decided.rego` (e0675d432) and decides the same calls.
        version: semver::Version::new(0, 0, 3),
        suggested: true,
        install: None,
        modules: &[
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:git>/git-call-is-preapproved.rego",
                embedded_source: include_str!("policy/presets/git/git-call-is-preapproved.rego"),
            },
            // WHICH git calls the host decides (CLOUD-2768): shipped here and in
            // `claude-code-cloud`, so both grants read one predicate.
            GIT_HOST_DECIDED,
        ],
        verdicts: &[],
        patterns: &[],
    },
    // CLOUD-2383. A session's first plan is refused once, with the operator's own
    // correction as the reason, and the next is admitted. Claude Code's plan-exit
    // tool is the host's vocabulary, which a vendor preset may carry.
    //
    // ITS OWN PRESET RATHER THAN A `claude-code-cloud` MODULE, for the row that
    // enables it. A preset row compiles every module the preset ships at its
    // scope, so a module added there rides the consumer's existing row — and that
    // row is named after the one class the preset used to raise. An engine that
    // ships the module refuses the old name; an engine that does not refuses any
    // other. Here the enabling row is new and raises one class, so it carries
    // that class's name under every engine.
    //
    // It reads `input.facts.extracted["plan-exits"]`, which the enabling row
    // declares; a row that declares no extract leaves the module deciding nothing.
    Manifest {
        name: "claude-code-plan",
        version: semver::Version::new(0, 0, 1),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::MediatedCall,
            provider: None,
            pointer: "<preset:claude-code-plan>/first-plan-is-pressure-tested.rego",
            embedded_source: include_str!(
                "policy/presets/claude-code-plan/first-plan-is-pressure-tested.rego"
            ),
        }],
        verdicts: &[VendoredVerdict {
            id: "plan check first",
            gloss: "verify, pressure test, validate; present corrected plan",
            class: "A session's first plan is built from reports nobody re-read against the \
tree, and the pass that corrects it re-reads with tools: every cited path, symbol and line opened, \
every number reproduced, the plan handed to a reader that did not write it. Refused once per \
session, by a count of presentations in its transcript; the next is admitted.",
            routes: &[run(
                "plan read first",
                "re-read every pointer the plan cites, reproduce its numbers, have an isolated \
reader check it, then present the corrected plan",
            )],
            applicability: Applicability::Advice,
        }],
        patterns: &[],
    },
    // A sibling-session dispatch whose message fails the brief lint is refused
    // (CLOUD-2858). Its own preset for `claude-code-plan`'s reason: a deny class
    // added to `claude-code-cloud` would rename the consumer's existing row.
    Manifest {
        name: "claude-code-dispatch",
        version: semver::Version::new(0, 0, 1),
        suggested: true,
        install: None,
        modules: &[PresetModule {
            scope: RuleScope::MediatedCall,
            provider: None,
            pointer: "<preset:claude-code-dispatch>/dispatch-brief-is-linted.rego",
            embedded_source: include_str!(
                "policy/presets/claude-code-dispatch/dispatch-brief-is-linted.rego"
            ),
        }],
        verdicts: &[VendoredVerdict {
            id: "dispatch brief refused",
            gloss: "a session dispatch whose message fails the brief lint",
            class: "A message that starts or steers another session is the whole of what \
that session knows. `batten lint brief` checks it carries every required section and a runnable \
check; a message that fails is refused here, by the gate and never by a human, and the refusal \
names each section that is missing or carries no command. A message that passes is granted like \
any call the engine allows (CLOUD-2858).",
            routes: &[run(
                "brief fix first",
                "add each section the refusal names, with a fenced command under `check`, and \
confirm with `batten lint brief`",
            )],
            applicability: Applicability::Advice,
        }],
        patterns: &[],
    },
];

/// Every vendored preset's name, in a stable order.
#[must_use]
pub fn names() -> Vec<&'static str> {
    MANIFESTS.iter().map(|manifest| manifest.name).collect()
}

/// The manifest for a named preset, or `None` when nothing ships under it.
#[must_use]
pub fn find(name: &str) -> Option<&'static Manifest> {
    MANIFESTS.iter().find(|manifest| manifest.name == name)
}

/// Which file domain a rule evaluates over — *where a rule looks*, never what a
/// match does (CLOUD-61).
///
/// Scope and severity are two independent keys on a [`Rule`], deliberately: the
/// question "which files does this gate watch" and the question "what happens
/// when it matches" ([`RuleSeverity`]) are different axes, and conflating them
/// is the config bug this type makes inexpressible. Neither vocabulary
/// deserializes as the other, so a severity token in the `scope` key (or the
/// reverse) is a usage error (exit `1`), never a silent reinterpretation.
///
/// Marked `#[non_exhaustive]` like [`RuleKind`]: the git change-set / protected
/// / unlanded domains (CLOUD-36, CLOUD-37) slot in as new variants without a
/// breaking change. The default is pinned as data —
/// [`tests::scope_default_is_pinned`] asserts it — so it is an explicit,
/// per-field default rather than an implicit fallback buried in code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleScope {
    /// The whole working tree: every file the walk yields. The pinned default.
    #[default]
    Tree,
    /// The single command `batten hook` is adjudicating — not a file domain at
    /// all, which is why a rule declaring it reads no `glob`.
    ///
    /// Spelled `mediated_call` rather than `command` on purpose: `command` is
    /// already a [`RuleKind`] token meaning "run this", and one word meaning two
    /// unrelated things across two keys is the cross-vocabulary confusion
    /// [`tests::severity_and_scope_vocabularies_do_not_cross`] exists to prevent.
    MediatedCall,
}

impl RuleScope {
    pub const ALL: &'static [RuleScope] = &[RuleScope::Tree, RuleScope::MediatedCall];
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RuleScope::Tree => "tree",
            RuleScope::MediatedCall => "mediated_call",
        }
    }
}

/// A `command`-kind route, which is most of them.
#[must_use]
pub const fn run(id: &'static str, target: &'static str) -> VendoredRoute {
    VendoredRoute {
        id,
        kind: RouteKind::Command,
        target,
        precondition: None,
    }
}

/// A `document`-kind route.
#[must_use]
pub const fn read(id: &'static str, target: &'static str) -> VendoredRoute {
    VendoredRoute {
        id,
        kind: RouteKind::Document,
        target,
        precondition: None,
    }
}

/// An `override`-kind route, which is the only kind whose precondition is
/// REQUIRED rather than optional.
///
/// `target` is deliberately absent: [`RouteKind::Override`]'s own doc says it is
/// unread, and the precondition is the whole payload — it is what
/// [`crate::admission::questions_for`] renders the first question from. A helper
/// that took a target would invite one to be written and then silently ignored.
#[must_use]
pub const fn admit(id: &'static str, precondition: &'static str) -> VendoredRoute {
    VendoredRoute {
        id,
        kind: RouteKind::Override,
        target: "",
        precondition: Some(precondition),
    }
}

#[cfg(test)]
mod tests {
    use super::{MANIFESTS, Manifest, PresetModule, RuleScope, VERSIONS_LOCK, version_drift};

    /// Fails by: a preset whose modules, verdicts or patterns changed while its
    /// version stood still, or a version bumped with no row recorded for it.
    #[test]
    fn every_manifest_matches_its_recorded_digest() {
        let drift = version_drift(VERSIONS_LOCK, MANIFESTS);
        assert!(drift.is_empty(), "{}", drift.join("\n"));
    }

    const BEFORE: &[PresetModule] = &[PresetModule {
        scope: RuleScope::Tree,
        provider: None,
        pointer: "<preset:fixture>/a.rego",
        embedded_source: "package a\n",
    }];
    const AFTER: &[PresetModule] = &[PresetModule {
        scope: RuleScope::Tree,
        provider: None,
        pointer: "<preset:fixture>/a.rego",
        embedded_source: "package a\nrefused if { true }\n",
    }];

    fn fixture(version: semver::Version, modules: &'static [PresetModule]) -> Manifest {
        Manifest {
            name: "fixture",
            version,
            suggested: false,
            install: None,
            modules,
            verdicts: &[],
            patterns: &[],
        }
    }

    /// Fails by: a source change under an unchanged version passing, a bump with
    /// no new row passing, or a recorded bump refused.
    #[test]
    fn a_source_change_without_a_bump_is_refused() {
        let first = fixture(semver::Version::new(1, 0, 0), BEFORE);
        let lock = format!("fixture 1.0.0 {}\n", first.digest());
        assert!(version_drift(&lock, &[first]).is_empty());

        let edited = fixture(semver::Version::new(1, 0, 0), AFTER);
        let drift = version_drift(&lock, &[edited]);
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert!(drift[0].contains("without a version bump"), "{drift:?}");

        let bumped = fixture(semver::Version::new(2, 0, 0), AFTER);
        let digest = bumped.digest();
        let drift = version_drift(&lock, &[bumped]);
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert!(drift[0].contains("has no row"), "{drift:?}");

        let recorded = format!("{lock}fixture 2.0.0 {digest}\n");
        let bumped = fixture(semver::Version::new(2, 0, 0), AFTER);
        assert!(version_drift(&recorded, &[bumped]).is_empty());
    }

    /// Fails by: a comment line read as a row (`!line.is_empty() &&
    /// !line.starts_with('#')` joined with `||`), so a commented-out row whose
    /// first word is the preset's name stands in for the row it is not.
    #[test]
    fn a_commented_out_row_is_no_row() {
        let commented = Manifest {
            name: "#fixture",
            ..fixture(semver::Version::new(1, 0, 0), BEFORE)
        };
        let lock = format!("#fixture 1.0.0 {}\n\n", commented.digest());
        let drift = version_drift(&lock, &[commented]);
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert!(drift[0].contains("has no row"), "{drift:?}");
    }

    const MUTANT_ROW: &[PresetModule] = &[PresetModule {
        scope: RuleScope::Tree,
        provider: None,
        pointer: "<preset:fixture>/a.rego",
        embedded_source: "#MUTANT-SUITE fixture\n#MUTANT a.rego true false\npackage a\n",
    }];

    /// Fails by: a `#MUTANT`/`#MUTANT-SUITE` row moving the digest. Those rows
    /// name this crate's own mutation suite and an eject strips them, so they
    /// decide nothing a consumer runs and must not demand a version bump. The
    /// module text itself still does: `AFTER` keeps its own digest.
    #[test]
    fn a_mutant_row_is_not_part_of_the_digest() {
        let plain = fixture(semver::Version::new(1, 0, 0), BEFORE).digest();
        let with_rows = fixture(semver::Version::new(1, 0, 0), MUTANT_ROW).digest();
        assert_eq!(plain, with_rows);
        let decided = fixture(semver::Version::new(1, 0, 0), AFTER).digest();
        assert_ne!(plain, decided);
    }
}
