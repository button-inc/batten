# Plan: CLOUD-2765, the plan-check skill

## Goal

- A1 `skills/plan-check/SKILL.md` exists with `name: plan-check` and passes the frontmatter rule `prompt declare partial`.
- A2 The skill is inside the 300-line budget and its vendor path is a symlink to it.
- A3 Every `skills/*/evals/evals.json` is well formed, and `plan-check` carries six seeded cases of six classes.
- A4 The validator brief is report-only and fixes the reply's shape.

## Steps

- S1 Write `skills/plan-check/SKILL.md`: the P0 to P3 ladder and the closing line. Serves A1, A2.
- S2 Link `.claude/skills/plan-check/SKILL.md` to `../../../skills/plan-check/SKILL.md`. Serves A2.
- S3 Write `skills/plan-check/references/plan-validator-brief.md` in the shape of `skills/groom/references/validator-brief.md`. Serves A4.
- S4 Write this plan as `evals/base-plan.md` and six seeded cases in `evals/evals.json`. Serves A3.
- S5 Add `every_evals_file_is_well_formed` to `crates/batten/tests/it/skill_contract.rs`, with a negative fixture. Serves A3.

## First failing test

`crates/batten/tests/it/skill_contract.rs`, `every_evals_file_is_well_formed`: today no `plan-check` evals file exists, so the six-case assertion fails.

## Commands

- `mise exec -- cargo nextest run -p batten -E 'binary(it) & test(skill_contract)'`
- `batten check --rule 'prompt declare partial'`

## Out of scope

- Holding edits until the skill has run: the plan-phase row.
- What a plan must carry across a compaction: the plan-and-clear row.
- Any change to `groom`.

## Unknown

- How many seeded defects the isolated read finds against a self-check: measured on the row before Done.

## Validation

The validator's reply goes here, as plain text.
