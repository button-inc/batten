//! One manifest per vendored preset: its identity, the modules it ships with the
//! surface each decides, and the refusal vocabulary they raise (CLOUD-1181).
//!
//! # Why this module exists rather than three tables
//!
//! A preset used to be three unrelated `const`s that nothing tied together: the
//! name-to-modules table in `policy.rs`, its verdict rows sitting inside
//! `verdict.rs`'s `VENDORED` under a comment, and a branch exempting it from the
//! `[[pattern]]` refusal. Nothing declared a preset, so a preset carried no
//! identity beyond its name, no version, and — the load-bearing omission — no
//! SCOPE. (It carried one scope for the manifest from CLOUD-1181 until
//! CLOUD-1672 moved it onto each module; the paragraph below is why it had to
//! exist at all, and `Manifest::modules` is why it could not stay singular.)
//!
//! Scope is where the silence costs most. `rules/policy-modules.md`
//! opens on the class: a module reading a key from the wrong surface evaluates,
//! reads undefined, refuses nothing, and *"a dead gate and a clean tree are
//! byte-identical on the decision surface"*. A consumer enabling a preset could
//! not see which surface it decided, so that mistake was theirs to make blind.
//!
//! # The inversion this ends
//!
//! Every place a preset was exempted from a rule a consumer module obeys, it was
//! exempted **because there was nowhere to write the declaration** — not because
//! the rule did not apply. A preset ships to every consumer while a consumer
//! module reaches one, so those exemptions were pointed the wrong way. The
//! manifest is the place, and it turns exemptions into declarations.
//!
//! # THIS DOES NOT OPEN THE NETWORK, AND THE MANIFEST IS NOT PERMISSION TO
//!
//! CLOUD-129 rejected remote policy fetch and that verdict is **unchanged**.
//! Every manifest here is `include_str!`d at build time: no network, no
//! registry, no trust-on-first-use, and the bytes ship inside the binary the
//! operator already trusts, under the same checksum as everything else in it.
//! A manifest is a declaration FORMAT. Whether a preset may arrive from outside
//! the binary is CLOUD-970's question, and a manifest is what makes that
//! question askable — before this, a third-party preset had no shape to arrive
//! in, so the trust question could not even be posed. Read no further permission
//! into it than that.
//!
//! # Rule 1 binds a manifest exactly as it binds a preset source
//!
//! A field may describe a PRACTICE and may never name a path, a task, a tracker
//! key or an entity. This file is under `crates/**`, so `batten.toml`'s rule-1
//! `forbid` rows already scan it on every gate invocation;
//! `manifests_are_inside_the_rule_one_glob` asserts that coverage rather than
//! leaving it true by accident.

use crate::rules::RuleExt as _;
use std::collections::BTreeSet;
use std::path::Path;

use crate::config_model::{Rule, RuleKind};
use crate::error::UsageError;
use crate::preset_catalog::Manifest;
use crate::preset_catalog::PresetModule;
use crate::preset_catalog::RuleScope;
use crate::preset_catalog::find;
use crate::preset_catalog::names;

/// `PresetModule` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).
pub trait PresetModuleExt: Sized {
    /// The source an engine compiles: the embedded one, or under the
    /// `preset-overlay` feature the mutated copy a mutation sweep wrote to
    /// `$BATTEN_PRESET_OVERLAY/<preset>/<module>.rego`, where one is there.
    ///
    /// A BUILD FEATURE, NEVER A RUNTIME SWITCH ALONE: a variable that swapped a
    /// shipped rule for a file would let the caller under judgement rewrite the
    /// rules it is judged by. Only the sweep's own suite build enables it, so the
    /// suite runs against a mutated module without recompiling the crate per row
    /// (`MUTANT_OVERLAY_*`, declared by the consumer's task runner).
    #[must_use]
    fn text(&self) -> std::borrow::Cow<'static, str>;

    /// The module's name: its file stem, as a row's `except` and
    /// `batten preset eject` spell it (CLOUD-2290).
    #[must_use]
    fn name(&self) -> &'static str;
}

impl PresetModuleExt for PresetModule {
    fn text(&self) -> std::borrow::Cow<'static, str> {
        #[cfg(feature = "preset-overlay")]
        if let Some(dir) = std::env::var_os("BATTEN_PRESET_OVERLAY")
            && let Some(relative) = self.pointer.strip_prefix("<preset:")
            && let Ok(text) = crate::fsio::read_to_string(
                std::path::Path::new(&dir).join(relative.replacen('>', "", 1)),
            )
        {
            return std::borrow::Cow::Owned(text);
        }
        std::borrow::Cow::Borrowed(self.source)
    }

    fn name(&self) -> &'static str {
        let file = self.pointer.rsplit('/').next().unwrap_or(self.pointer);
        file.strip_suffix(".rego").unwrap_or(file)
    }
}

/// `Manifest` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).
pub trait ManifestExt: Sized {
    /// Whether any module here decides `scope`.
    ///
    /// The load-time question `policy::load` asks. It replaces an equality
    /// against one manifest-level scope, and the difference is that a preset
    /// spanning two surfaces answers yes to both rather than having to pick.
    #[must_use]
    fn decides(&self, scope: RuleScope) -> bool;

    /// The surfaces this preset decides, in manifest order, without repeats.
    ///
    /// Used to NAME the alternatives in a refusal. A consumer who enabled the
    /// wrong scope is told which ones exist rather than being left to read a
    /// table inside the binary they cannot open — the gap CLOUD-1181 recorded
    /// and which a single scope could only half answer.
    #[must_use]
    fn scopes(&self) -> Vec<RuleScope>;

    /// The modules deciding `scope`, as `(pointer, source)` for the compiler.
    ///
    /// **Selection, not filtering for tidiness.** A module compiled at the wrong
    /// surface reads keys the engine never builds there, and Rego reads undefined
    /// as "this body does not hold" — a dead gate byte-identical to a clean tree.
    /// `check_tree_paths_are_emittable` catches that today, and this keeps the
    /// case from arising rather than relying on a downstream guard to notice.
    #[must_use]
    fn modules_at(&self, scope: RuleScope) -> Vec<(String, String)>;

    /// [`Manifest::modules_at`], narrowed to what this consumer's provider can
    /// decide (CLOUD-1625).
    ///
    /// **A module reading no provider's language applies everywhere**, which is
    /// what `None` on the module means and why it is not filtered out. A module
    /// that DOES read one applies only where the row declares that same
    /// provider — off it, the module matches nothing and would report the clean
    /// tree it never read.
    ///
    /// Filtering rather than refusing the whole preset is what lets `mise` keep
    /// deciding task argv on a host whose workflow language its sibling module
    /// cannot read. The caller refuses when this comes back EMPTY, because a row
    /// compiling no modules is a rule that decides nothing.
    ///
    /// A module named in `except` is skipped (CLOUD-2290), so a local copy of
    /// it can claim its ids. Whether every name in `except` exists is the
    /// caller's question, asked before this.
    #[must_use]
    fn modules_for(
        &self,
        scope: RuleScope,
        provider: Option<&str>,
        except: &[String],
    ) -> Vec<(String, String)>;

    /// The module named `name`, if this preset ships one.
    #[must_use]
    fn module(&self, name: &str) -> Option<&'static PresetModule>;

    /// The modules that must leave the binary together with `module` for
    /// either side to compile (CLOUD-2290).
    ///
    /// Modules at one scope compile into ONE engine, so a helper one defines is
    /// callable from another: `plan-mode-refuses-writes` calls `read_only` and
    /// `unwatch_method`, which its siblings define. Ejecting a module alone
    /// would leave the copy calling helpers that are not in its bundle, and
    /// ejecting a helper's definer alone would leave the vendored caller calling
    /// one that is gone. So the closure is the CONNECTED COMPONENT of the
    /// reference graph at the module's scope — what it calls, what calls it,
    /// transitively — which is the smallest set both halves still compile from.
    ///
    /// A reference is a whole-word use, outside comments, of a helper another
    /// module defines at column zero. Reading Rego as text can over-include, a
    /// helper's name also used as a local, and never under-includes a call; an
    /// over-included module is one more file copied, not a bundle that fails.
    #[must_use]
    fn closure(&self, module: &PresetModule) -> Vec<&'static PresetModule>;

    /// What the modules at this scope read, for a refusal that names both sides.
    ///
    /// Deduplicated and ordered by the module table so the message is
    /// byte-stable (§6). A module reading no provider's language renders as
    /// `no provider`, which is an answer rather than an omission.
    #[must_use]
    fn providers_at(&self, scope: RuleScope) -> Vec<&'static str>;
}

impl ManifestExt for Manifest {
    fn decides(&self, scope: RuleScope) -> bool {
        self.modules.iter().any(|module| module.scope == scope)
    }

    fn scopes(&self) -> Vec<RuleScope> {
        let mut seen: Vec<RuleScope> = Vec::new();
        for module in self.modules {
            if !seen.contains(&module.scope) {
                seen.push(module.scope);
            }
        }
        seen
    }

    fn modules_at(&self, scope: RuleScope) -> Vec<(String, String)> {
        self.modules
            .iter()
            .filter(|module| module.scope == scope)
            .map(|module| (module.pointer.to_owned(), module.text().into_owned()))
            .collect()
    }

    fn modules_for(
        &self,
        scope: RuleScope,
        provider: Option<&str>,
        except: &[String],
    ) -> Vec<(String, String)> {
        self.modules
            .iter()
            .filter(|module| module.scope == scope)
            .filter(|module| match module.provider {
                None => true,
                Some(reads) => provider == Some(reads),
            })
            .filter(|module| !except.iter().any(|name| name == module.name()))
            .map(|module| (module.pointer.to_owned(), module.text().into_owned()))
            .collect()
    }

    fn module(&self, name: &str) -> Option<&'static PresetModule> {
        self.modules.iter().find(|module| module.name() == name)
    }

    fn closure(&self, module: &PresetModule) -> Vec<&'static PresetModule> {
        let peers: Vec<&'static PresetModule> = self
            .modules
            .iter()
            .filter(|peer| peer.scope == module.scope)
            .collect();
        let defined: Vec<BTreeSet<String>> = peers
            .iter()
            .map(|peer| helpers_defined(peer.source))
            .collect();
        let code: Vec<String> = peers.iter().map(|peer| uncommented(peer.source)).collect();
        // A SHARED ID IS AN EDGE TOO. Two modules may each add to one
        // `rules contains` id (`call grant now` has two), and `claim_ids`
        // refuses an id two bundles declare, so splitting them collides.
        let ids: Vec<BTreeSet<String>> = peers
            .iter()
            .map(|peer| crate::policy::finding_ids(peer.source))
            .collect();
        let linked = |a: usize, b: usize| {
            a != b
                && (defined[b].iter().any(|name| uses(&code[a], name))
                    || defined[a].iter().any(|name| uses(&code[b], name))
                    || !ids[a].is_disjoint(&ids[b]))
        };
        let mut member: Vec<bool> = peers
            .iter()
            .map(|peer| peer.pointer == module.pointer)
            .collect();
        let mut grew = true;
        while grew {
            grew = false;
            for candidate in 0..peers.len() {
                if member[candidate] {
                    continue;
                }
                if (0..peers.len()).any(|held| member[held] && linked(held, candidate)) {
                    member[candidate] = true;
                    grew = true;
                }
            }
        }
        peers
            .into_iter()
            .zip(member)
            .filter_map(|(peer, held)| held.then_some(peer))
            .collect()
    }

    fn providers_at(&self, scope: RuleScope) -> Vec<&'static str> {
        let mut seen: Vec<&'static str> = Vec::new();
        for module in self.modules.iter().filter(|m| m.scope == scope) {
            let reads = module.provider.unwrap_or("no provider");
            if !seen.contains(&reads) {
                seen.push(reads);
            }
        }
        seen
    }
}

/// The helpers a module defines at column zero: functions and complete rules,
/// never the `contains` sets every module adds to (`rules`, `violation`, …),
/// which the engine aggregates rather than any module calling another's.
fn helpers_defined(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in source.lines() {
        let name: String = line
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty()
            || !line.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
            || matches!(name.as_str(), "package" | "import" | "default")
            || name.starts_with("test_")
        {
            continue;
        }
        let rest = line[name.len()..].trim_start();
        // A function is kept with its `(`, so only a call matches it: a test
        // helper named `call(…)` must not link every module reading `input.call`.
        if rest.starts_with('(') {
            names.insert(format!("{name}("));
        } else if rest.starts_with(":=")
            || rest.starts_with("if ")
            || rest.starts_with("if{")
            || (rest.starts_with('=') && !rest.starts_with("=="))
        {
            names.insert(name);
        }
    }
    names
}

/// The source with every `#` comment removed, so a comment naming a helper
/// links nothing.
fn uncommented(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `name` — a rule, or a function spelled with its `(` — occurs in
/// `code` as a whole word that is not a field (`input.call` is no use of a
/// helper named `call`).
fn uses(code: &str, name: &str) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.';
    code.match_indices(name).any(|(at, _)| {
        let before = code[..at].chars().next_back();
        let after = code[at + name.len()..].chars().next();
        !before.is_some_and(word) && (name.ends_with('(') || !after.is_some_and(word))
    })
}

/// The header line `batten preset eject` writes first into every copy, and the
/// one `batten check` reads back to find a copy behind its preset.
const EJECTED: &str = "# batten-ejected: ";

/// What an ejected file's header records: the preset, the module and the
/// manifest version it was copied at. `None` for a file no eject wrote.
#[must_use]
///
/// The version is semver. A header an older binary wrote carries a bare integer
/// `N`, which reads as `0.0.N`: an integer counter promised no stable major, so
/// the faithful translation is an increment below `1.0.0`, never a major.
pub fn ejected_from(source: &str) -> Option<(String, String, semver::Version)> {
    let header = source.lines().find_map(|line| line.strip_prefix(EJECTED))?;
    let (target, version) = header.split_once(" version ")?;
    let (preset, module) = target.split_once('/')?;
    let version = version.trim();
    let version = semver::Version::parse(version)
        .ok()
        .or_else(|| Some(semver::Version::new(0, 0, version.parse().ok()?)))?;
    Some((preset.to_owned(), module.to_owned(), version))
}

/// The copy of `module` an eject writes: the header, then the vendored source
/// without the `#MUTANT` rows, which name a suite inside this crate that the
/// consumer does not have.
fn ejected_source(manifest: &Manifest, module: &PresetModule) -> String {
    let mut text = format!(
        "{EJECTED}{}/{} version {}\n\
         # Copied out of the vendored preset by `batten preset eject`, and this repository's\n\
         # own now. `batten check` warns once the binary ships a newer version of the preset.\n",
        manifest.name,
        module.name(),
        manifest.version,
    );
    for line in module.source.lines() {
        if line.starts_with("#MUTANT") {
            continue;
        }
        text.push_str(line);
        text.push('\n');
    }
    text
}

/// What one `batten preset eject` wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ejection {
    /// The files written, repository-relative, in manifest order.
    pub written: Vec<String>,
    /// The preset row that now excepts them.
    pub row: String,
    /// The row that loads the copies.
    pub copies: String,
    /// Whether this eject appended `copies` rather than finding it.
    pub added: bool,
}

/// Copy a vendored module and its call closure into `policy/<preset>/`, and
/// switch the vendored ones off in favour of the copies (CLOUD-2290).
///
/// Everything is decided before anything is written: an unknown name, a
/// preset no row enables at the module's scope, a copy already on disk, or a
/// copy row at another scope is refused with nothing changed.
///
/// # Errors
///
/// A [`UsageError`] for any of the refusals above; an internal error when a file
/// or `config` cannot be written.
pub fn eject(root: &Path, config: &Path, rules: &[Rule], target: &str) -> anyhow::Result<Ejection> {
    let (preset, name) = target.split_once('/').ok_or_else(|| {
        UsageError::raise(format!(
            "preset eject: `{target}` is not `<preset>/<module>`"
        ))
    })?;
    let manifest = find(preset).ok_or_else(|| {
        UsageError::raise(format!(
            "preset eject: this binary ships no preset `{preset}`; the ones it does are {}",
            names().join(", ")
        ))
    })?;
    let module = manifest.module(name).ok_or_else(|| {
        let shipped: Vec<&str> = manifest.modules.iter().map(PresetModule::name).collect();
        UsageError::raise(format!(
            "preset eject: `{preset}` ships no module `{name}`; it ships {}",
            shipped.join(", ")
        ))
    })?;
    let enabling: Vec<&Rule> = rules
        .iter()
        .filter(|rule| {
            rule.kind == RuleKind::Policy
                && rule.preset.as_deref() == Some(preset)
                && rule.scope == module.scope
        })
        .collect();
    let [row] = enabling.as_slice() else {
        return Err(UsageError::raise(format!(
            "preset eject: {} rows enable `{preset}` at scope `{}`, and an eject edits exactly one",
            enabling.len(),
            module.scope.as_str()
        )));
    };
    let folder = format!("policy/{preset}");
    let existing = rules
        .iter()
        .find(|rule| rule.bundle.as_deref() == Some(folder.as_str()));
    if let Some(other) = existing.filter(|rule| rule.scope != module.scope) {
        return Err(UsageError::raise(format!(
            "preset eject: `{folder}` is already loaded by rule `{}` at scope `{}`, and `{name}` \
             decides `{}`; one folder compiles at one scope",
            other.id,
            other.scope.as_str(),
            module.scope.as_str()
        )));
    }
    let closure = manifest.closure(module);
    let written: Vec<String> = closure
        .iter()
        .map(|member| format!("{folder}/{}.rego", member.name()))
        .collect();
    if let Some(present) = written.iter().find(|path| root.join(path).exists()) {
        return Err(UsageError::raise(format!(
            "preset eject: `{present}` already exists; this repository already holds a copy"
        )));
    }
    let copies_id = format!("{preset} ejected");
    if existing.is_none() && rules.iter().any(|rule| rule.id == copies_id) {
        return Err(UsageError::raise(format!(
            "preset eject: a rule already has the id `{copies_id}` the copies' row would take"
        )));
    }

    std::fs::create_dir_all(root.join(&folder))?;
    for (member, path) in closure.iter().zip(&written) {
        crate::durable::replace(root.join(path), ejected_source(manifest, member))?;
    }

    let mut except: Vec<String> = row.except.clone();
    except.extend(closure.iter().map(|member| member.name().to_owned()));
    except.sort();
    except.dedup();
    let mut edits = vec![crate::config_edit::Edit::InRow {
        array: String::from("rule"),
        id: row.id.clone(),
        edits: vec![crate::config_edit::Edit::Set {
            path: vec![String::from("except")],
            value: crate::config_edit::Scalar::Strings(except),
        }],
    }];
    let copies = existing.map_or(copies_id, |rule| rule.id.clone());
    if existing.is_none() {
        edits.push(crate::config_edit::Edit::AppendRow {
            array: String::from("rule"),
            fields: copy_row(row, &copies, &folder),
        });
    }
    crate::config_edit::apply_file(crate::config_edit::Format::Toml, config, &edits)?;
    Ok(Ejection {
        written,
        row: row.id.clone(),
        copies,
        added: existing.is_none(),
    })
}

/// The row that loads the copies: the preset row's scope, severity, remedy and
/// declared inputs, with `bundle` where `preset` was.
fn copy_row(row: &Rule, id: &str, folder: &str) -> Vec<(String, crate::config_edit::Scalar)> {
    use crate::config_edit::Scalar;
    let mut fields = vec![
        (String::from("id"), Scalar::String(id.to_owned())),
        (String::from("kind"), Scalar::String(String::from("policy"))),
        (
            String::from("scope"),
            Scalar::String(row.scope.as_str().to_owned()),
        ),
        (String::from("bundle"), Scalar::String(folder.to_owned())),
        (
            String::from("severity"),
            Scalar::String(row.severity().as_str().to_owned()),
        ),
    ];
    if let Some(reason) = &row.no_fix_reason {
        fields.push((
            String::from("no_fix_reason"),
            Scalar::String(reason.clone()),
        ));
    }
    let selectors = [
        ("documents", &row.documents),
        ("sources", &row.sources),
        ("line_sources", &row.line_sources),
        ("invocation_sources", &row.invocation_sources),
        ("use_sources", &row.use_sources),
        ("unit_sources", &row.unit_sources),
        ("delta_sources", &row.delta_sources),
    ];
    for (key, values) in selectors {
        if !values.is_empty() {
            fields.push((key.to_owned(), Scalar::Strings(values.clone())));
        }
    }
    fields
}

/// The `claude-code-cloud` modules that read the host's permission mode, as
/// `(pointer, source)` pairs `policy::compile` takes (CLOUD-2201).
///
/// Selected out of the preset by name rather than re-included, so a session with
/// no authority judges a call by the same bytes a consumer enabling the preset
/// does. `unwatch-is-preapproved` rides along because the plan rule reads its
/// `unwatch_method`.
#[must_use]
pub fn mode_sources() -> Vec<(String, String)> {
    const MODE: [&str; 4] = [
        "read-only-is-preapproved.rego",
        "unwatch-is-preapproved.rego",
        "plan-mode-refuses-writes.rego",
        "auto-mode-is-preapproved.rego",
    ];
    find("claude-code-cloud")
        .map(|manifest| {
            manifest
                .modules
                .iter()
                .filter(|module| MODE.iter().any(|name| module.pointer.ends_with(name)))
                .map(|module| (module.pointer.to_owned(), module.text().into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{eject, ejected_from, ejected_source, helpers_defined, mode_sources, uses};
    #[cfg(test)]
    use crate::config_check::preset::verdict_rows;
    use crate::config_model::Rule;
    #[cfg(test)]
    use crate::preset::ManifestExt as _;
    #[cfg(test)]
    use crate::preset::PresetModuleExt as _;
    use crate::preset_catalog::RuleScope;
    use crate::preset_catalog::{MANIFESTS, Manifest, PresetModule, find, names};

    use std::collections::BTreeSet;

    /// A preset of four modules: `a` defines a helper `b` calls, `d` stands
    /// alone at the same scope, `c` decides the other surface, and `b` reads a
    /// provider's language.
    const FIXTURE: Manifest = Manifest {
        name: "fixture",
        version: semver::Version::new(3, 1, 0),
        suggested: true,
        modules: &[
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:fixture>/a.rego",
                source: "package a\n#MUTANT row|s@x@y@|case\nhelper(x) if { x }\n",
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: Some("github"),
                pointer: "<preset:fixture>/b.rego",
                source: "package b\nrules contains \"x\" if { helper(1) }\n",
            },
            PresetModule {
                scope: RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:fixture>/c.rego",
                source: "package c\n",
            },
            PresetModule {
                scope: RuleScope::Tree,
                provider: None,
                pointer: "<preset:fixture>/d.rego",
                source: "package d\n# helper(1) in a comment links nothing\nlone := 1\n",
            },
        ],
        verdicts: &[],
        patterns: &[],
    };

    fn pointers(pairs: &[(String, String)]) -> Vec<&str> {
        pairs.iter().map(|(pointer, _)| pointer.as_str()).collect()
    }

    #[test]
    fn a_manifest_answers_for_its_modules_by_scope_provider_and_name() {
        let a = &FIXTURE.modules[0];
        assert_eq!(a.name(), "a");
        assert!(FIXTURE.decides(RuleScope::Tree));
        assert!(FIXTURE.decides(RuleScope::MediatedCall));
        assert_eq!(
            FIXTURE.scopes(),
            vec![RuleScope::Tree, RuleScope::MediatedCall]
        );
        assert_eq!(
            pointers(&FIXTURE.modules_at(RuleScope::Tree)),
            vec![
                "<preset:fixture>/a.rego",
                "<preset:fixture>/b.rego",
                "<preset:fixture>/d.rego"
            ]
        );
        assert_eq!(
            FIXTURE.modules_at(RuleScope::MediatedCall),
            vec![(
                "<preset:fixture>/c.rego".to_owned(),
                "package c\n".to_owned()
            )]
        );
        assert_eq!(
            pointers(&FIXTURE.modules_for(RuleScope::Tree, None, &["d".to_owned()])),
            vec!["<preset:fixture>/a.rego"]
        );
        assert_eq!(
            pointers(&FIXTURE.modules_for(RuleScope::Tree, Some("github"), &[])),
            vec![
                "<preset:fixture>/a.rego",
                "<preset:fixture>/b.rego",
                "<preset:fixture>/d.rego"
            ]
        );
        assert_eq!(
            FIXTURE.module("d").map(|module| module.pointer),
            Some("<preset:fixture>/d.rego")
        );
        assert!(FIXTURE.module("e").is_none());
        assert_eq!(
            FIXTURE.providers_at(RuleScope::Tree),
            vec!["no provider", "github"]
        );
        assert_eq!(
            FIXTURE.providers_at(RuleScope::MediatedCall),
            vec!["no provider"]
        );
    }

    /// The closure is the connected component of helper use at one scope: the
    /// definer and its caller, never the module that only names it in a comment.
    #[test]
    fn a_closure_is_every_module_linked_by_a_helper_and_nothing_else() {
        let closure = |at: usize| -> Vec<&str> {
            FIXTURE
                .closure(&FIXTURE.modules[at])
                .iter()
                .map(|module| module.name())
                .collect()
        };
        assert_eq!(closure(0), vec!["a", "b"]);
        assert_eq!(closure(1), vec!["a", "b"]);
        assert_eq!(closure(3), vec!["d"]);
        assert_eq!(closure(2), vec!["c"]);
    }

    #[test]
    fn a_helper_is_a_column_zero_function_or_complete_rule_and_a_use_is_a_whole_word() {
        let source = "package p\nimport rego.v1\ndefault allow := false\nf(x) if { x }\n\
                      flag := true\nset if { true }\nsame = 1\nequal == 1\ntest_case if { true }\n\
                      rules contains \"x\" if { f(1) }\n  indented := 1\n\
                      _private := 1\nUpper := 1\ndefault := 1\n";
        assert_eq!(
            helpers_defined(source),
            BTreeSet::from([
                "_private".to_owned(),
                "f(".to_owned(),
                "flag".to_owned(),
                "same".to_owned(),
                "set".to_owned()
            ])
        );
        assert!(uses("x := flag", "flag"));
        assert!(uses("y := f(2)", "f("));
        assert!(!uses("x := flagged", "flag"));
        assert!(!uses("x := input.flag", "flag"));
        assert!(!uses("x := my_flag", "flag"));
    }

    #[test]
    fn an_ejected_copy_records_where_it_came_from_and_drops_the_mutant_rows() {
        let copy = ejected_source(&FIXTURE, &FIXTURE.modules[0]);
        assert!(
            copy.starts_with("# batten-ejected: fixture/a version 3.1.0\n"),
            "{copy}"
        );
        assert!(!copy.contains("#MUTANT"), "{copy}");
        assert!(copy.ends_with("helper(x) if { x }\n"), "{copy}");
        assert_eq!(
            ejected_from(&copy),
            Some((
                "fixture".to_owned(),
                "a".to_owned(),
                semver::Version::new(3, 1, 0)
            ))
        );
        assert_eq!(ejected_from("package a\n"), None);
        assert_eq!(
            ejected_from("# batten-ejected: fixture/a version 2\n"),
            Some((
                "fixture".to_owned(),
                "a".to_owned(),
                semver::Version::new(0, 0, 2)
            )),
            "a header an integer-versioned binary wrote reads as 0.0.N"
        );
        assert_eq!(
            ejected_from("# batten-ejected: fixture/a version two\n"),
            None
        );
    }

    #[test]
    fn every_vendored_preset_is_found_by_name_and_declares_its_classes() {
        assert_eq!(names().len(), MANIFESTS.len());
        let git = find("git").expect("git ships");
        assert!(git.decides(RuleScope::MediatedCall));
        assert!(!git.decides(RuleScope::Tree), "git ships no tree module");
        for name in names() {
            assert_eq!(find(name).map(|manifest| manifest.name), Some(name));
        }
        assert!(find("no-such-preset").is_none());
        let declared: usize = MANIFESTS
            .iter()
            .map(|manifest| manifest.verdicts.len())
            .sum();
        assert_eq!(verdict_rows().len(), declared);
        assert_eq!(mode_sources().len(), 4);
    }

    fn rule(text: &str) -> Rule {
        toml::from_str(text).expect("the fixture row loads")
    }

    const GIT_ROW: &str = "id = \"git calls\"\nkind = \"policy\"\nscope = \"mediated_call\"\n\
                           preset = \"git\"\nseverity = \"deny\"\n";

    /// An eject copies the module, excepts it on the one enabling row, and
    /// appends the row loading the copy; every refusal changes nothing.
    #[test]
    fn an_eject_copies_the_module_and_switches_the_vendored_one_off() {
        let root = crate::scratch::scratch("preset-eject");
        let config = root.join("batten.toml");
        let text = format!("version = 1\n\n[[rule]]\n{GIT_ROW}");
        std::fs::write(&config, &text).unwrap();
        let target = "git/git-call-is-preapproved";
        let tree_row = rule(
            &GIT_ROW
                .replace("mediated_call", "tree")
                .replace("git calls", "t"),
        );
        let shape_row = rule(&GIT_ROW.replace("policy", "shape").replace("git calls", "s"));

        let refused = |rules: &[Rule]| {
            assert!(eject(&root, &config, rules, target).is_err());
            assert_eq!(crate::fsio::read_to_string(&config).unwrap(), text);
        };
        refused(&[rule(GIT_ROW), rule(&GIT_ROW.replace("git calls", "again"))]);
        refused(&[
            rule(GIT_ROW),
            rule(&format!(
                "{}bundle = \"policy/git\"\n",
                GIT_ROW
                    .replace("mediated_call", "tree")
                    .replace("git calls", "b")
            )),
        ]);
        refused(&[
            rule(GIT_ROW),
            rule(
                &GIT_ROW
                    .replace("git calls", "git ejected")
                    .replace("preset = \"git\"", "preset = \"other\""),
            ),
        ]);

        let done = eject(
            &root,
            &config,
            &[rule(GIT_ROW), tree_row, shape_row],
            target,
        )
        .unwrap();
        assert_eq!(
            done.written,
            vec!["policy/git/git-call-is-preapproved.rego"]
        );
        assert_eq!(
            (done.row.as_str(), done.copies.as_str(), done.added),
            ("git calls", "git ejected", true)
        );
        let copy = crate::fsio::read_to_string(root.join(&done.written[0])).unwrap();
        assert!(copy.starts_with("# batten-ejected: git/git-call-is-preapproved version "));
        let edited = crate::fsio::read_to_string(&config).unwrap();
        assert!(
            edited.contains("except = [\"git-call-is-preapproved\"]"),
            "{edited}"
        );
        assert!(edited.contains("bundle = \"policy/git\""), "{edited}");
        assert!(
            !edited.contains("documents"),
            "no empty selector is copied: {edited}"
        );
        assert!(
            eject(&root, &config, &[rule(GIT_ROW)], target).is_err(),
            "a copy already on disk"
        );
    }

    /// No `command` route's target begins with the verb it renders under
    /// (CLOUD-1470). `render_route` prefixes every command target with `run `,
    /// so a target that already began `run ` rendered as `run run …` once the
    /// advisory channel started printing routes.
    #[test]
    fn no_command_route_repeats_the_verb_it_renders_under() {
        let doubled: Vec<&str> = MANIFESTS
            .iter()
            .flat_map(|manifest| manifest.verdicts.iter())
            .filter(|entry| {
                entry.routes.iter().any(|route| {
                    route.kind == crate::preset_catalog::RouteKind::Command
                        && route.target.starts_with("run ")
                })
            })
            .map(|entry| entry.id)
            .collect();
        assert!(
            doubled.is_empty(),
            "routes render as `run run …`: {doubled:?}"
        );
    }

    /// Every class a preset's modules raise is declared by its own manifest.
    ///
    /// The direction a consumer module already gets from `check_verdicts_are_declared`,
    /// now reachable for a preset because there is somewhere to declare it.
    /// Before the manifest a preset's rows lived in another module's table under
    /// a comment, so this question had no side to ask.
    ///
    /// Read from the module SOURCE, which is the only honest reading: the
    /// alternative is to trust that the manifest and the modules agree, which is
    /// the assumption the manifest exists to remove.
    #[test]
    fn every_class_a_preset_raises_is_declared_by_its_own_manifest() {
        for manifest in MANIFESTS {
            let declared: BTreeSet<&str> = manifest.verdicts.iter().map(|entry| entry.id).collect();
            for module in manifest.modules {
                for token in raised_in(module.source) {
                    assert!(
                        declared.contains(token.as_str()),
                        "`{}` raises `{token}` in `{}`, which its manifest does not \
                         declare — the refusal would carry no gloss and no route",
                        manifest.name,
                        module.pointer
                    );
                }
            }
        }
    }

    /// And the mirror: a class no module raises fails.
    ///
    /// The anti-vacuity direction the `[[verdict]]` registry already enforces
    /// in-tree and which a preset was exempt from, not because the rule did not
    /// apply but because there was nowhere to write the declaration. A class no
    /// gate reaches reads as coverage while its routes have never been walked.
    #[test]
    fn every_class_a_manifest_declares_is_raised_by_one_of_its_modules() {
        for manifest in MANIFESTS {
            let raised: BTreeSet<String> = manifest
                .modules
                .iter()
                .flat_map(|module| raised_in(module.source))
                .collect();
            for entry in manifest.verdicts {
                assert!(
                    raised.contains(entry.id),
                    "`{}` declares `{}`, which none of its modules raise",
                    manifest.name,
                    entry.id
                );
            }
        }
    }

    /// One name, one manifest.
    #[test]
    fn no_preset_is_declared_twice() {
        let mut seen = names();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(before, seen.len(), "two manifests share a preset name");
    }

    /// A class belongs to exactly one preset.
    ///
    /// Two manifests declaring one token would collide in the registry, and
    /// `policy` refuses a collision between the vendored and consumer halves
    /// rather than within the vendored half — so nothing else asks this.
    #[test]
    fn no_class_is_declared_by_two_presets() {
        let mut seen: Vec<&str> = MANIFESTS
            .iter()
            .flat_map(|manifest| manifest.verdicts.iter().map(|entry| entry.id))
            .collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "a class is declared by two presets, so the registry cannot say which raises it"
        );
    }

    /// Every occurrence of a provider's expression language in a rule BODY, as
    /// `(module pointer, line)` pairs — the `.rego` half of the rule-1 scan.
    ///
    /// # The three exemptions, each load-bearing in one direction
    ///
    /// A `github.event` occurrence is a violation unless it is (1) on a comment
    /// line, (2) inside a `test_*` rule, or (3) a fixture line under an `"if":`
    /// key. Clauses 2 and 3 are not conveniences: a module that matches GitHub
    /// syntax must carry fixtures written IN that syntax, because they are the
    /// tests of the thing being tested. Without the exemptions this scan would
    /// report every such module's own suite and be switched off; with them it
    /// reports exactly the rule bodies that READ the provider.
    fn provider_syntax_sites() -> Vec<(&'static str, usize)> {
        let mut found = Vec::new();
        for manifest in MANIFESTS {
            for module in manifest.modules {
                let mut in_test_rule = false;
                for (index, line) in module.source.lines().enumerate() {
                    let trimmed = line.trim_start();
                    // A rule header at column zero opens a rule; `test_` opens one
                    // this scan does not read. Tracked by header rather than by
                    // brace depth because Rego bodies are `if { … }` blocks whose
                    // closing line is column zero too, so the next header is what
                    // ends the previous rule either way.
                    if !line.starts_with([' ', '\t', '#']) && !line.is_empty() {
                        in_test_rule = line.starts_with("test_");
                    }
                    if trimmed.starts_with('#') || in_test_rule {
                        continue;
                    }
                    // A fixture line under an `"if":` key is data the module is
                    // matching AGAINST, not language it reads.
                    if trimmed.starts_with("\"if\":") || trimmed.contains("\"if\":") {
                        continue;
                    }
                    if line.contains("github.event") {
                        found.push((module.source, index + 1));
                    }
                }
            }
        }
        found
    }

    /// **A module reading a provider's expression language declares that
    /// provider** (CLOUD-1625).
    ///
    /// The `.rego` arm of non-negotiable rule 1, and the mechanism rule 2 owes
    /// the `provider` column: without it the next module to match `github.event`
    /// ships with `provider: None`, loads for every consumer on every host, and
    /// reports a clean tree it never read — which is the exact state this row
    /// exists to end, re-entered one module later.
    ///
    /// The scan does NOT forbid the syntax. Six sites carry it today and all six
    /// are legitimate; what they owe is the declaration beside them.
    #[test]
    fn a_module_reading_provider_syntax_declares_that_provider() {
        let declared: Vec<&'static str> = MANIFESTS
            .iter()
            .flat_map(|manifest| manifest.modules)
            .filter(|module| module.provider.is_some())
            .map(|module| module.source)
            .collect();

        let undeclared: Vec<usize> = provider_syntax_sites()
            .into_iter()
            .filter(|(source, _)| !declared.contains(source))
            .map(|(_, line)| line)
            .collect();

        assert!(
            undeclared.is_empty(),
            "a preset module reads a CI provider's expression language and declares \
             no `provider`, so it would compile for a consumer on any host and match \
             nothing there; lines: {undeclared:?}"
        );
    }

    /// The anti-vacuity mirror, in the direction that matters.
    ///
    /// Without it the case above is satisfied by a scan that finds NOTHING — the
    /// dead-gate shape this whole row is about, and the one a `.rego` scan is
    /// most likely to take, since a discriminator that over-exempts is
    /// byte-identical to a clean tree. Six is the measured count; the assertion
    /// is that the scan still sees the syntax it is supposed to see, so an
    /// exemption widened later fails here rather than quietly reporting green.
    #[test]
    fn the_provider_scan_still_sees_the_syntax_it_exempts_around() {
        let sites = provider_syntax_sites();
        assert!(
            sites.len() >= 6,
            "the scan must still find the rule bodies that read the provider, or its \
             exemptions have swallowed the subject: {sites:?}"
        );
    }

    /// Rule 1 reaches a manifest as it reaches a preset source.
    ///
    /// Asserted rather than assumed, per the row: this file is under `crates/**`
    /// so `batten.toml`'s rule-1 `forbid` rows already scan it, and what is
    /// checked here is that the file is where that glob can see it.
    #[test]
    fn manifests_are_inside_the_rule_one_glob() {
        let here = std::path::Path::new(file!());
        assert!(
            here.starts_with("crates"),
            "the manifests must live where rule 1's glob reaches them, not at {}",
            here.display()
        );
    }

    /// The classes a module raises, read from its source.
    ///
    /// A refusal is `{rule, verdict, subjects}` and its class is a STRING
    /// LITERAL under `verdict` (`rules/policy-modules.md`), so what is
    /// matched is that SHAPE: a `"rule":` key, then the `"verdict":` that
    /// follows it in the same object.
    ///
    /// AN EARLIER VERSION MATCHED `"verdict":` ANYWHERE AND CLAIMED OVER-READING
    /// WAS THE SAFE DIRECTION. It is not, and the assertion above said so
    /// immediately: `landing-loop`'s own test fixtures build landing records
    /// whose rows carry a `verdict` COLUMN, so `landed` and three siblings read
    /// as raised classes and the manifest was accused of not declaring them.
    /// Over-reading makes the raised-set too big, which fails the first
    /// assertion on inputs that raise nothing — the noisy direction, not the
    /// safe one.
    ///
    /// It also declines to read a COMPOSED verdict (`"verdict": columns[1]`),
    /// and that is correct rather than a gap: the ABI refuses a class composed
    /// at runtime, because a class a reader cannot look up is not a class.
    fn raised_in(source: &str) -> Vec<String> {
        let mut found = Vec::new();
        for rest in source.split("\"rule\":").skip(1) {
            let Some(after) = rest.find("\"verdict\": \"") else {
                continue;
            };
            let tail = &rest[after + "\"verdict\": \"".len()..];
            // Only when the `verdict` key belongs to the SAME object: a later
            // block's key would be past the object's close.
            if rest[..after].contains("\n}") {
                continue;
            }
            if let Some(end) = tail.find('"') {
                found.push(tail[..end].to_owned());
            }
        }
        found
    }
}
