//! G4: whether the server gate the release path rests on actually holds
//! (CLOUD-2033).
//!
//! `batten release settings` reads the repository's rulesets and release
//! settings and names every item still owed:
//!
//! * the trunk's ruleset refuses non-fast-forward writes;
//! * a tag ruleset on `v*` restricts updates;
//! * no ruleset among them has a bypass actor;
//! * immutable releases are enabled.
//!
//! NO `release-path` RULESET IS OWED (CLOUD-2319). `final` is the trunk's one
//! required check, and the seal in it ([`crate::release_path::seals`]) is what
//! holds an unverified pin off the trunk. A second required status on the trunk
//! and a probe ruleset beside it duplicated that, put a branch-protection change
//! on the release path, and held every release while it was never made.
//!
//! [`owed`] is pure over what the shell read.

use crate::release::Get;

/// What G4 read about the repository's settings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Facts {
    /// Whether the trunk's rules refuse a non-fast-forward write.
    pub trunk_non_fast_forward: bool,
    /// Whether a ruleset on `v*` tags restricts updates.
    pub tags_restrict_updates: bool,
    /// The rulesets carrying a bypass actor, by name.
    pub bypassed: Vec<String>,
    /// Whether immutable releases are enabled.
    pub immutable_releases: bool,
}

/// Every item still owed, each a pointer; empty when the server gate holds.
//MUTANT-SUITE crates/batten/tests/it/release_verify.rs
//MUTANT bypass-actor-admitted|s@^            .map(\x7cname\x7c format!("the ruleset {name} has a bypass actor")),$@            .take(0).map(\x7cname\x7c format!("the ruleset {name} has a bypass actor")),@|settings_name_every_owed_item
#[must_use]
pub fn owed(facts: &Facts) -> Vec<String> {
    let mut owed = Vec::new();
    if !facts.trunk_non_fast_forward {
        owed.push(String::from(
            "the trunk's ruleset does not refuse a non-fast-forward write",
        ));
    }
    if !facts.tags_restrict_updates {
        owed.push(String::from("no tag ruleset on v* restricts updates"));
    }
    owed.extend(
        facts
            .bypassed
            .iter()
            .map(|name| format!("the ruleset {name} has a bypass actor")),
    );
    if !facts.immutable_releases {
        owed.push(String::from("immutable releases are not enabled"));
    }
    owed
}

/// The forge's answer at `path` parsed as JSON, `Ok(None)` on a 404, or the
/// could-not-look pointer.
fn json_at(get: Get<'_>, path: &str) -> Result<Option<serde_json::Value>, String> {
    let answer = get(path).ok_or_else(|| format!("{path} did not answer"))?;
    if answer.status == 404 {
        return Ok(None);
    }
    if !answer.is_reading() {
        return Err(format!("{path} answered {}", answer.status));
    }
    serde_json::from_str(&answer.body)
        .map(Some)
        .map_err(|_| format!("{path} is not JSON"))
}

/// Whether `conditions` target `refs/heads/<branch>` (or the default branch,
/// when `branch` is the trunk) by an include pattern.
fn targets(ruleset: &serde_json::Value, wanted: &[String]) -> bool {
    ruleset
        .pointer("/conditions/ref_name/include")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .any(|pattern| wanted.iter().any(|want| want == pattern))
}

/// Read every fact [`owed`] decides over.
///
/// # Errors
///
/// The could-not-look pointer.
pub fn read(slug: &str, trunk: &str, get: Get<'_>) -> Result<Facts, String> {
    let list = format!("repos/{slug}/rulesets?includes_parents=false&per_page=100");
    let listed = json_at(get, &list)?.ok_or_else(|| format!("{list} answered 404"))?;
    let mut facts = Facts::default();
    let trunk_names = [
        String::from("~DEFAULT_BRANCH"),
        format!("refs/heads/{trunk}"),
    ];
    for summary in listed.as_array().into_iter().flatten() {
        let Some(id) = summary.get("id").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let path = format!("repos/{slug}/rulesets/{id}");
        let ruleset = json_at(get, &path)?.ok_or_else(|| format!("{path} answered 404"))?;
        if ruleset
            .get("enforcement")
            .and_then(serde_json::Value::as_str)
            != Some("active")
        {
            continue;
        }
        let name = ruleset
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unnamed")
            .to_owned();
        let target = ruleset
            .get("target")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("branch");
        let has = |kind: &str| {
            ruleset
                .get("rules")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .any(|rule| rule.get("type").and_then(serde_json::Value::as_str) == Some(kind))
        };
        let guards_trunk = target == "branch" && targets(&ruleset, &trunk_names);
        let guards_tags = target == "tag" && targets(&ruleset, &[String::from("refs/tags/v*")]);
        if guards_trunk {
            facts.trunk_non_fast_forward |= has("non_fast_forward");
        }
        if guards_tags {
            facts.tags_restrict_updates |= has("update");
        }
        let bypassed = ruleset
            .get("bypass_actors")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|actors| !actors.is_empty());
        if (guards_trunk || guards_tags) && bypassed {
            facts.bypassed.push(name);
        }
    }
    let immutable = format!("repos/{slug}/immutable-releases");
    facts.immutable_releases = json_at(get, &immutable)?.is_some_and(|value| {
        value.get("enabled").and_then(serde_json::Value::as_bool) != Some(false)
    });
    Ok(facts)
}

/// `batten release settings [--last-run <workflow>]`: exit 0 when nothing is
/// owed, 2 naming every owed item, 3 when it could not look. With
/// `--last-run`, the answer is instead whether the `settings` job of that
/// guard workflow's last completed run on the trunk succeeded — the read the
/// cut and the release PR gate on, which needs no administration credential.
///
/// # Errors
///
/// Only a failed write to `out` or `err`.
pub fn run_settings(
    last_run: Option<&str>,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::ExitCode> {
    let Some(slug) = crate::repo_slug(std::path::Path::new(".")) else {
        writeln!(
            err,
            "batten: release settings: could not look: no forge remote names the repository"
        )?;
        return Ok(crate::ExitCode::Internal);
    };
    let trunk = match crate::worktree::declared_trunk(std::path::Path::new(".")) {
        Ok(Some(trunk)) => trunk.short,
        Ok(None) => {
            writeln!(
                err,
                "batten: release settings: could not look: {}",
                crate::worktree::NO_TRUNK
            )?;
            return Ok(crate::ExitCode::Internal);
        }
        Err(why) => {
            writeln!(err, "batten: release settings: could not look: {why}")?;
            return Ok(crate::ExitCode::Internal);
        }
    };
    let get = |path: &str| crate::rest::get(path, None);
    if let Some(workflow) = last_run {
        return match crate::release_state::settings_green(&slug, &trunk, workflow, &get) {
            Ok(true) => {
                writeln!(
                    out,
                    "release settings: {workflow}'s last settings job is green"
                )?;
                Ok(crate::ExitCode::Success)
            }
            Ok(false) => {
                writeln!(
                    err,
                    "release settings: {workflow}'s last settings job is not green"
                )?;
                Ok(crate::ExitCode::Violation)
            }
            Err(why) => {
                writeln!(err, "batten: release settings: could not look: {why}")?;
                Ok(crate::ExitCode::Internal)
            }
        };
    }
    let items = match read(&slug, &trunk, &get) {
        Ok(facts) => owed(&facts),
        Err(why) => {
            writeln!(err, "batten: release settings: could not look: {why}")?;
            return Ok(crate::ExitCode::Internal);
        }
    };
    if items.is_empty() {
        writeln!(out, "release settings: the server gate holds")?;
        return Ok(crate::ExitCode::Success);
    }
    for item in items {
        writeln!(err, "release settings: owed: {item}")?;
    }
    Ok(crate::ExitCode::Violation)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn answer(status: u16, body: &str) -> crate::rest::Answer {
        crate::rest::Answer {
            status,
            etag: None,
            poll_floor: None,
            backoff: None,
            body: body.to_owned(),
            headers: std::collections::BTreeMap::new(),
        }
    }

    /// The probe's whole chain over the fixture seam (CLOUD-2509): seeded at
    /// the trunk's head, a commit made on it, and the write's answer graded.
    fn probe_over(
        case: &str,
        seeded: u16,
        written: u16,
        verdict: &str,
    ) -> Result<Option<String>, String> {
        let dir = crate::rest::routed(
            case,
            &[
                (
                    "GET https://api.github.com/repos/o/r/git/ref/heads/release-path-probe",
                    404,
                    "{}",
                ),
                (
                    "GET https://api.github.com/repos/o/r/git/ref/heads/main",
                    200,
                    r#"{"object":{"sha":"h"}}"#,
                ),
                (
                    "POST https://api.github.com/repos/o/r/git/refs",
                    seeded,
                    "{}",
                ),
                (
                    "GET https://api.github.com/repos/o/r/git/commits/h",
                    200,
                    r#"{"tree":{"sha":"t"}}"#,
                ),
                (
                    "POST https://api.github.com/repos/o/r/git/commits",
                    201,
                    r#"{"sha":"p"}"#,
                ),
                (
                    "PATCH https://api.github.com/repos/o/r/git/refs/heads/release-path-probe",
                    written,
                    verdict,
                ),
            ],
        );
        let get = |path: &str| crate::rest::get(path, None);
        crate::rest::with_fixture(&dir, || probe("o/r", "main", &get))
    }

    #[test]
    fn a_probe_refused_by_a_ruleset_holds_and_an_accepted_one_does_not() {
        assert_eq!(
            probe_over("probe-held", 201, 422, "Repository rule violations found"),
            Ok(None)
        );
        let accepted = probe_over("probe-accepted", 201, 200, "{}")
            .unwrap()
            .unwrap();
        assert!(accepted.contains("answered 200"), "{accepted}");
        assert_eq!(
            probe_over("probe-unseeded", 500, 200, "{}"),
            Err(String::from("seeding release-path-probe answered 500"))
        );
    }

    /// Every path answers from `routes` by exact match, and 404 otherwise.
    fn forge(
        routes: Vec<(String, String)>,
    ) -> impl Fn(&str) -> Option<crate::rest::Answer> + use<> {
        move |path: &str| {
            Some(
                routes
                    .iter()
                    .find(|(at, _)| at == path)
                    .map_or_else(|| answer(404, "{}"), |(_, body)| answer(200, body)),
            )
        }
    }

    #[test]
    fn a_forge_read_is_json_none_on_404_or_could_not_look() {
        assert_eq!(
            json_at(&|_: &str| Some(answer(200, r#"{"a":1}"#)), "p").unwrap(),
            Some(serde_json::json!({"a": 1}))
        );
        assert_eq!(
            json_at(&|_: &str| Some(answer(404, "x")), "p").unwrap(),
            None
        );
        assert!(json_at(&|_: &str| Some(answer(500, "{}")), "p").is_err());
        assert!(json_at(&|_: &str| Some(answer(200, "x")), "p").is_err());
        assert!(json_at(&|_: &str| None, "p").is_err());
    }

    #[test]
    fn a_ruleset_targets_a_branch_only_by_an_include_pattern() {
        let ruleset = serde_json::json!({"conditions": {"ref_name": {
            "include": ["refs/heads/main"], "exclude": ["refs/heads/other"]}}});
        assert!(targets(&ruleset, &[String::from("refs/heads/main")]));
        assert!(!targets(&ruleset, &[String::from("refs/heads/other")]));
    }

    #[test]
    fn the_settings_are_read_from_every_active_ruleset_and_the_release_setting() {
        let slug = "o/r";
        let ruleset = |id: u64, body: serde_json::Value| {
            (format!("repos/{slug}/rulesets/{id}"), body.to_string())
        };
        let routes = vec![
            (
                format!("repos/{slug}/rulesets?includes_parents=false&per_page=100"),
                String::from(r#"[{"id":1},{"id":2},{"id":3},{"id":4},{"name":"no id"}]"#),
            ),
            ruleset(
                1,
                serde_json::json!({"name": "trunk", "enforcement": "active", "target": "branch",
                    "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
                    "rules": [{"type": "non_fast_forward"}],
                    "bypass_actors": []}),
            ),
            ruleset(
                2,
                serde_json::json!({"name": "admins", "enforcement": "active",
                    "conditions": {"ref_name": {"include": ["refs/heads/main"]}},
                    "rules": [{"type": "deletion"}],
                    "bypass_actors": [{"actor_id": 1}]}),
            ),
            ruleset(
                3,
                serde_json::json!({"name": "tags", "enforcement": "active", "target": "tag",
                    "conditions": {"ref_name": {"include": ["refs/tags/v*"]}},
                    "rules": [{"type": "update"}], "bypass_actors": []}),
            ),
            ruleset(
                4,
                serde_json::json!({"name": "off", "enforcement": "disabled", "target": "branch",
                    "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
                    "rules": [], "bypass_actors": [{"actor_id": 2}]}),
            ),
            (
                format!("repos/{slug}/immutable-releases"),
                String::from(r#"{"enabled": true}"#),
            ),
        ];
        let facts = read(slug, "main", &forge(routes.clone())).unwrap();
        assert_eq!(
            facts,
            Facts {
                trunk_non_fast_forward: true,
                tags_restrict_updates: true,
                bypassed: vec![String::from("admins")],
                immutable_releases: true,
            }
        );
        let mut off = routes;
        off.pop();
        off.push((
            format!("repos/{slug}/immutable-releases"),
            String::from(r#"{"enabled": false}"#),
        ));
        assert!(!read(slug, "main", &forge(off)).unwrap().immutable_releases);
    }

    /// A ruleset guards only the kind of ref it targets: a tag ruleset naming
    /// the trunk, or a branch ruleset naming the release tags, guards nothing.
    #[test]
    fn a_ruleset_naming_a_ref_of_the_other_kind_guards_nothing() {
        let slug = "o/r";
        let routes = vec![
            (
                format!("repos/{slug}/rulesets?includes_parents=false&per_page=100"),
                String::from(r#"[{"id":1},{"id":2}]"#),
            ),
            (
                format!("repos/{slug}/rulesets/1"),
                serde_json::json!({"name": "tag", "enforcement": "active", "target": "tag",
                    "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
                    "rules": [{"type": "non_fast_forward"}],
                    "bypass_actors": [{"actor_id": 1}]})
                .to_string(),
            ),
            (
                format!("repos/{slug}/rulesets/2"),
                serde_json::json!({"name": "branch", "enforcement": "active", "target": "branch",
                    "conditions": {"ref_name": {"include": ["refs/tags/v*"]}},
                    "rules": [{"type": "update"}], "bypass_actors": [{"actor_id": 1}]})
                .to_string(),
            ),
        ];
        assert_eq!(
            read(slug, "main", &forge(routes)).unwrap(),
            Facts::default()
        );
    }
}
