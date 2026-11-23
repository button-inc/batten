# Replay ledger candidates — PR #1276 (CLOUD-2789)

The 118 rows `batten test replay --base origin/main` refuses at `c5951a1f6`
(merge base `fa67fcdb`), after every replay defect found was fixed on this
branch. Each row's base body was spliced into HEAD and either did not compile
against HEAD's code (`compile`) or ran and failed while HEAD's own body passed
in the same tree (`run`).

For each row: the exact pair the replay prints, what changed, and whether the
HEAD test is at least as strong as the base one. **Not every row is.** Rows
marked `WEAKER` or `GONE` lose coverage, and say what; rows marked `CHANGED`
assert a deliberately different behaviour. No row has been written to
`.batten/asked.jsonl`: each group is for the owner to answer.

The causing commit is the one that removed the base body's first changed line
(`git log -S` over `fa67fcdb..c5951a1f6`); where HEAD only added lines, the
commit is named from the field or argument the line adds.

## c6a7b69e9 — `warn` splits into `advise` and `record`

- `test-expectation-changed crates/batten-core/src/severity.rs::tests::ask_is_a_disposition_rather_than_a_fourth_rank` — a new non-rank severity, `Record`, joins `Ask`; the count becomes ranks + 2 and `Record`'s row resolves to `Advise`. At least as strong: asserts both dispositions.
- `test-expectation-changed crates/batten-core/src/severity.rs::tests::cross_axis_token_is_rejected` — `RuleSeverity::Warn` renamed `Advise`. Same assertion.
- `test-expectation-changed crates/batten-core/src/severity.rs::tests::severity_round_trips_through_toml` — the TOML token `warn` becomes `advise`. Same round trip.
- `test-expectation-changed crates/batten-core/src/severity.rs::tests::the_name_collision_trap_is_pinned` — `Warn` → `Advise`. Same assertion.
- `test-expectation-changed crates/batten-core/src/severity.rs::tests::the_promoted_rank_is_the_one_a_deny_already_reaches` — `Warn` → `Advise`. Same assertion.
- `test-expectation-changed crates/batten-core/src/severity.rs::tests::vocabulary_is_byte_stable` — the pinned vocabulary is `["allow", "advise", "deny"]`. Same byte-stability check, new words.
- `test-expectation-changed crates/batten/tests/policy_modules.rs::a_predicate_severity_naming_an_unpublished_id_is_refused_at_load` — `Warn` → `Advise` in the fixture. Same assertion.
- `test-expectation-changed crates/batten/tests/it/preapprove.rs::a_worktree_spawn_is_refused_in_auto` — CHANGED: now run with `CLAUDE_CODE_REMOTE=true` (a disposable host) and read from every emitted document. Whether a non-disposable host is still refused is no longer asserted here.

## 2a9ac01cb — source scans read every workspace crate

All nine: the scan read `crates/batten/src` (or its `tests/`) only; HEAD reads every workspace crate through `common::engine_sources()` / `test_sources()` / `rust_sources()`. At least as strong: the same predicate over a superset of files.

- `test-expectation-changed crates/batten/tests/it/document_facts.rs::no_artifact_name_reaches_the_core`
- `test-expectation-changed crates/batten/tests/it/document_facts.rs::the_stated_residue_is_a_ratchet_and_not_a_suppression`
- `test-expectation-changed crates/batten/tests/it/mcp_dispatch.rs::this_change_introduces_no_consumer_identifier_into_the_crate`
- `test-expectation-changed crates/batten/tests/it/primitives.rs::every_path_override_is_composed_with_join_paths`
- `test-expectation-changed crates/batten/tests/it/primitives.rs::every_path_valued_toml_key_uses_a_literal_string`
- `test-expectation-changed crates/batten/tests/it/primitives.rs::every_permission_drop_asserts_its_own_premise`
- `test-expectation-changed crates/batten/tests/it/primitives.rs::no_suite_sets_the_state_dir_variables_itself`
- `test-expectation-changed crates/batten/tests/it/scratch_names.rs::no_two_cases_can_reach_one_scratch_directory`
- `test-expectation-changed crates/batten/tests/it/stub_portability.rs::every_executed_test_stub_is_portable`

## 14df00c87 — every census reads every crate, and decides on the tree

- `test-expectation-changed crates/batten/tests/it/cli.rs::the_committed_delegating_rule_spawns_nothing_when_its_glob_misses` — the committed row's glob is `**`, not `crates/**`, so the miss is now an IGNORED file; `.output()` → `.streamed_output()`. At least as strong: the row covers every tracked path, and the case still proves a miss spawns nothing.
- `test-expectation-changed crates/batten/tests/it/cli.rs::the_committed_repo_config_gates_a_repository` — the expected refusal names `**` instead of `crates/**`. Same assertion over the wider glob.
- `test-expectation-changed crates/batten/tests/it/cross_check.rs::the_check_is_still_target_scoped_so_the_flag_widened_coverage` — CHANGED: base required every check to carry `--workspace`; HEAD collects the packages and exclusions the checks name and asserts over those. The owner should confirm the per-package form still covers the whole workspace.
- `test-expectation-changed crates/batten/tests/it/emission_census.rs::every_advisory_push_carries_a_class` — scans every crate's engine sources instead of `crates/batten/src`. At least as strong.
- `test-expectation-changed crates/batten/tests/it/emission_census.rs::every_refusal_id_the_engine_raises_resolves` — same widening. At least as strong.
- `test-expectation-changed crates/batten/tests/it/emission_census.rs::no_finding_label_is_spelled_outside_the_projection` — same widening. At least as strong.
- `test-expectation-changed crates/batten/tests/it/narrow_adoption.rs::the_network_callers_are_the_declared_ones_and_nothing_else` — every crate, and call nodes on the syntax tree instead of a substring. At least as strong: wider scope, and no comment or string can satisfy it.
- `test-expectation-changed crates/batten/tests/it/verdict_registry.rs::a_vendored_preset_loads_with_no_consumer_rows_at_all` — the call fixture gains the projected `subcommand` the preset now reads. Same assertion.
- `test-expectation-changed crates/batten/tests/it/verdict_registry.rs::every_native_class_is_raised_by_production_code` — every crate, and a `#[cfg(test)]` ancestor on the syntax tree instead of cutting the text at the first `#[cfg(test)]`. At least as strong.

## 30ae3aff2 — shim retirement (paths), with the API changes these rows also carry

The paths now resolve in the replay; each row fails on the change named.

- `test-expectation-changed crates/batten/src/hook.rs::tests::a_read_route_no_declared_source_resolves_is_dropped` — `Redirect`/`McpConfig`/`McpSource` moved to `config_model`; `Policy::from_resolved` takes a fifth argument (an MCP-server predicate). Same assertion.
- `test-expectation-changed crates/batten/src/policy.rs::tests::an_ejected_copy_is_paired_with_the_vendored_module_its_header_names` — `preset::find` → `preset_catalog::find`; a module's `source` field is now `text()`. Same assertion.
- `test-expectation-changed crates/batten/src/rules.rs::tests::a_copy_behind_its_preset_warns` — the manifest version is a `semver::Version` (1c07e2098), so "behind" is `0.0.0` rather than `shipped - 1`. At least as strong: still a copy behind the shipped version, and `shipped > 0.0.0` is still asserted.
- `test-expectation-changed crates/batten/src/rules.rs::tests::only_a_policy_row_off_the_hook_is_checked_for_a_stale_copy` — same `0.0.0` spelling; a row gains `half: None`. Same assertion.
- `test-expectation-changed crates/batten/tests/it/call_arguments.rs::a_keyed_row_excluded_by_its_modifier_does_not_supply_the_base` — `Harness` moved to `config_model`; `from_resolved` takes the MCP-server predicate. Same assertion.
- `test-expectation-changed crates/batten/tests/it/policy_presets.rs::an_ejected_module_behind_the_manifest_version_is_reported` — `preset_catalog::find`, and a semver `0.0.0` for "behind". Same assertion.
- `test-expectation-changed crates/batten/tests/it/policy_presets.rs::an_excepted_module_lets_a_local_copy_load_without_collision` — `preset_catalog::find`; `source` → `text()`. Same assertion.
- `test-expectation-changed crates/batten/tests/it/policy_presets.rs::every_advertised_preset_name_actually_loads` — `preset_names` moved to `config_model`; one row per preset becomes a row at EVERY real scope (`rows_at_real_scopes`). At least as strong: more scopes.
- `test-expectation-changed crates/batten/tests/it/policy_presets.rs::every_preset_loads_at_the_scope_it_is_enabled_with` — same: every real scope. At least as strong.
- `test-expectation-changed crates/batten/tests/it/policy_presets.rs::every_shipped_preset_passes_its_own_suite` — same: every real scope; `policy::test` takes a fourth argument. At least as strong.
- `test-expectation-changed crates/batten/tests/it/policy_presets.rs::every_shipped_preset_publishes_its_ids` — same: every real scope. At least as strong.

## 2e71bb127 — a cited carrier table says which fields reach a shell

All eight: `manifest_lines` takes a third argument, the carrier (`None` here), and `ShellCensus` gains `carrier`. Same assertions.

- `test-expectation-changed crates/batten/src/census.rs::tests::a_body_counts_its_code_lines_and_skips_comments_and_blanks`
- `test-expectation-changed crates/batten/src/census.rs::tests::a_plain_argv_is_not_shell_and_a_pipeline_is`
- `test-expectation-changed crates/batten/src/census.rs::tests::a_second_key_is_read_on_the_same_terms`
- `test-expectation-changed crates/batten/src/census.rs::tests::an_array_closer_is_searched_for_after_its_opening_line`
- `test-expectation-changed crates/batten/src/census.rs::tests::an_array_entry_counts_only_when_it_carries_shell`
- `test-expectation-changed crates/batten/src/census.rs::tests::an_array_opening_line_is_never_one_of_its_entries`
- `test-expectation-changed crates/batten/src/census.rs::tests::an_inert_declaration_is_refused`
- `test-expectation-changed crates/batten/src/census.rs::tests::exempt_paths_are_measured_apart_at_their_own_count`

## c4db93004 — one detector decides shell on the rable AST

- `test-expectation-changed crates/batten/src/census.rs::tests::a_block_ends_at_the_first_line_at_or_left_of_its_key` — CHANGED: a folded block is fed as its source lines, and a one-command block is no longer shell. The fixture grows to pin both.
- `test-expectation-changed crates/batten/src/census.rs::tests::a_body_that_closes_on_its_opening_line_is_no_body` — `manifest_lines` third argument. Same assertion.
- `test-expectation-changed crates/batten/src/census.rs::tests::units_are_named_by_their_header_and_lone_lines_stand_alone` — CHANGED: unit `a` counts 2 (a two-line body), and the fixture adds a line; `carrier: None`.
- `test-expectation-changed crates/batten/tests/it/shell_banned.rs::a_body_moved_into_a_new_task_is_refused_even_when_the_total_falls` — CHANGED: the moved body is two commands, since a one-command body is argv to the detector and would give no finding. Same refusal over a body that is still shell.
- `test-expectation-changed crates/batten/tests/it/shell_banned.rs::a_manifest_whose_base_is_not_text_is_judged_against_nothing` — CHANGED, same reason: two-line bodies.
- `test-expectation-changed crates/batten/tests/it/shell_banned.rs::a_task_body_grown_by_one_line_is_refused` — CHANGED, same reason: grows 2 → 3 lines instead of 1 → 2.
- `test-expectation-changed crates/batten/tests/it/verify_chain.rs::every_step_is_argv` — `census::shell_syntax` → `shell_logic::logic(..)` is `Verdict::Argv`. At least as strong: the AST detector decides, and its verdict is printed.

## 2f2ba053f — a row is this branch's claim only when every live PR on it is

All four: `live_pr: Option<String>` becomes `live_prs: Vec<String>`. Same assertions over the list.

- `test-expectation-changed crates/batten/src/claim.rs::tests::a_merged_pull_request_is_a_predecessor_rather_than_a_competitor`
- `test-expectation-changed crates/batten/src/claim.rs::tests::an_open_pull_request_still_refuses_and_an_absent_state_refuses_too`
- `test-expectation-changed crates/batten/src/receipt.rs::tests::the_base_line_matches_what_the_minter_writes`
- `test-expectation-changed crates/batten/src/receipt.rs::tests::the_branch_receipt_filename_matches_the_minter`

## f4d99f554 — the confinement scans read every workspace crate again

- `test-expectation-changed crates/batten-core/src/git.rs::tests::gix_is_confined_to_the_git_modules` — every crate, and a git module is named by its path in this crate, not its file name. At least as strong.
- `test-expectation-changed crates/batten-core/src/git.rs::tests::no_gix_gap_primitive_survives` — every crate, but WEAKER in one respect: comments and `#[cfg(test)]` items are now skipped on the syntax tree, so a retired token in a test or a comment no longer fails it. The comment says this was deliberate (CLOUD-2666).
- `test-expectation-changed crates/batten-core/src/git.rs::tests::no_module_assembles_its_own_git_argv` — every crate but `git.rs` itself. At least as strong.
- `test-expectation-changed crates/batten-core/src/git.rs::tests::no_second_git_invoker_exists` — every crate's `src/`, nothing exempt. At least as strong.
- `test-expectation-changed crates/batten-core/src/git.rs::tests::no_second_repo_root_resolver_exists` — every crate's `src/` and `tests/`. At least as strong.

## 8c2606c22 — a cited interpreter table catches a script handed to a program

All five: the fixture gains a `perl` unit (an inline script handed to an interpreter), so the manifest count goes 9 → 10 and the total 20 → 21. At least as strong: one more shape counted.

- `test-expectation-changed crates/batten/tests/it/census_shell.rs::a_linked_worktree_is_measured_and_not_the_main_checkout_beside_it`
- `test-expectation-changed crates/batten/tests/it/census_shell.rs::the_ban_counts_the_manifest_exactly_as_the_census_does`
- `test-expectation-changed crates/batten/tests/it/census_shell.rs::the_census_counts_the_fixture_as_the_shapes_say`
- `test-expectation-changed crates/batten/tests/it/census_shell.rs::the_pointer_lines_carry_no_body`
- `test-expectation-changed crates/batten/tests/it/census_shell.rs::the_tasks_the_ban_says_gained_shell_are_the_units_the_census_names`

## 73de834e7 — a Cargo row selects exactly its own case, in its suite's binary

All four: each `#MUTANT` row names its case exactly (`…_is_refused`), and HEAD also asserts the sweep's stderr counts (a row defect apart from survivors; "1 of 1 … survived"). At least as strong: extra assertions.

- `test-expectation-changed crates/batten/tests/it/mutate.rs::a_row_that_mutates_its_own_declaration_is_refused_not_reported_as_a_survivor`
- `test-expectation-changed crates/batten/tests/it/mutate.rs::anti_vacuity_a_mutation_that_changes_nothing_is_not_a_pass`
- `test-expectation-changed crates/batten/tests/it/mutate.rs::the_defect_a_mutation_the_suite_does_not_catch_fails`
- `test-expectation-changed crates/batten/tests/it/mutate.rs::the_tree_is_restored_between_rows_so_a_gate_is_judged_against_a_pristine_sibling`

## 9e1741c63 — there is no PAT here; the proxy is the route

All three GONE: the provision-fence mechanism these cases exercised was retired with the PAT route, so the cases were deleted with it. No HEAD test covers a provision fence, because there is none.

- `test-removed crates/batten/tests/it/egress_fencing.rs::a_deleted_provision_fence_is_refused`
- `test-removed crates/batten/tests/it/egress_fencing.rs::a_provision_fence_on_only_the_upper_case_spelling_is_refused`
- `test-removed crates/batten/tests/it/egress_fencing.rs::a_provision_fence_that_no_longer_names_the_resolver_host_is_refused`

## 6b79edf5e — liveness compares the recorded cmdline, never a program path

All three: `Alive` loses `program_root`, and `abandoned` its program-root argument. Same assertions about liveness and reaping.

- `test-expectation-changed crates/batten-base/src/task.rs::tests::a_dead_registrant_is_abandoned_and_carries_its_group`
- `test-expectation-changed crates/batten-base/src/task.rs::tests::alive_reads_each_record_against_its_process`
- `test-expectation-changed crates/batten-base/src/task.rs::tests::an_unreadable_registry_reaps_nothing`

## 79aaf3189 — a preset a test embeds is never judged through the overlay

All three: a preset module's `source` becomes `pointer` / `text()`. Same assertions.

- `test-expectation-changed crates/batten/src/preset.rs::tests::a_module_reading_provider_syntax_declares_that_provider`
- `test-expectation-changed crates/batten/src/preset.rs::tests::every_class_a_manifest_declares_is_raised_by_one_of_its_modules`
- `test-expectation-changed crates/batten/src/preset.rs::tests::every_class_a_preset_raises_is_declared_by_its_own_manifest`

## b0036c6df — the `uses` fact sees qualified paths

- `test-expectation-changed crates/batten/tests/it/module_closure.rs::no_module_reaches_deeper_than_the_recorded_worst` — CHANGED: the deepest module is the deepest that is not the crate root (`LIB`). The root is no longer held to the recorded worst.
- `test-expectation-changed crates/batten/tests/it/use_graph.rs::the_hidden_edges_resolve_to_the_module_the_text_never_names` — the file `trust.rs` is now `trust_pin.rs`. Same assertion.
- `test-expectation-changed crates/batten/tests/it/use_graph.rs::the_syntactic_tier_diverges_in_two_classes` — CHANGED: qualified-path edges (no `use` line) are excluded from the population, and the split's root shims are read as phantom edges by design.

## b9d51c36e — `Vocabulary`'s slot methods beside the type

- `test-expectation-changed crates/batten/src/config.rs::tests::every_typed_config_table_has_a_validation_call_site` — `Config` moved to `config_model.rs`, so the scan reads that file for the tables and `config.rs` for the validators. Same assertion, split across its two homes.
- `test-expectation-changed crates/batten/src/trust.rs::tests::every_rule_column_exemption_names_a_real_column_and_a_reason` — `include_str!("rules.rs")` → `include_str!("config_model.rs")`, where the rule columns now live. Same assertion.

## 25756dc3f — a land stage is never run twice

Both: the refused command `… mise run ci` / `mise run verify` becomes `… git commit -m 'fix: x'`, because `gate run twice` now answers a stage run by hand first. At least as strong: the same `HK_SKIP_STEPS` carve is refused, on a command no other row claims.

- `test-expectation-changed crates/batten/tests/it/hook_skip_local.rs::the_carve_with_a_step_appended_is_refused`
- `test-expectation-changed crates/batten/tests/it/hook_skip_local.rs::the_retired_carve_is_refused_like_any_other`

## acea9574a — plan mode admits flag-checked reads

- `test-expectation-changed crates/batten/tests/it/preapprove.rs::a_plan_mode_batten_mcp_read_is_allowed_and_a_write_is_not` — the write is asserted denied both mediated (`batten mcp call`) and direct (`mcp__Linear__save_issue`), each by its decision. At least as strong.
- `test-expectation-changed crates/batten/tests/it/preapprove.rs::a_plan_mode_write_is_refused` — the commit message conforms (`'fix: x'`) so the commit-subject row does not answer first. Same assertion.

## 0db68bda6 — every commit-time step judges the staged files

Both: `acquire_declared(_measured)` takes a fourth argument (the staged files); `Declared` moved to `config_check::rules` with new fields. Same assertions.

- `test-expectation-changed crates/batten/src/rules.rs::tests::only_a_tree_policy_rows_documents_are_acquired_and_costed`
- `test-expectation-changed crates/batten/src/rules.rs::tests::two_rows_over_one_glob_each_get_their_own_form`

## 131ebb5ad — every selector reads a mediated call as the call it mediates

Both: `selects` takes a slice of tool names instead of one. Same assertions.

- `test-expectation-changed crates/batten/src/handler.rs::tests::a_matcher_narrows_the_event_to_the_calls_it_names`
- `test-expectation-changed crates/batten/src/handler.rs::tests::selects_is_the_narrowing_that_makes_pre_tool_affordable`

## aff560c0e — fold each shard entry once

Both: the store gains a `folded` map. Same assertions.

- `test-expectation-changed crates/batten/src/journal.rs::tests::a_newer_store_is_read_only_never_an_error`
- `test-expectation-changed crates/batten/src/journal.rs::tests::migrate_upgrades_an_older_store_and_is_the_only_upgrade`

## f106834ac — hook takes the mcp answer injected

Both: `Policy::from_resolved` takes the MCP-server predicate. Same assertions.

- `test-expectation-changed crates/batten/src/hook.rs::tests::a_registered_module_is_protected_iff_the_gate_is_declared`
- `test-expectation-changed crates/batten/src/hook.rs::tests::a_resolved_policy_keeps_only_the_mediated_rows`

## Single rows

- 599961fdd — `test-expectation-changed crates/batten/tests/it/shell_banned.rs::the_exemption_set_is_exactly_the_files_that_must_be_shell` — WEAKER: the exemption set gains `completions/batten.fish` and `completions/batten.zsh`, marked TEMPORARY and already admitted by the owner in `.batten/asked.jsonl` (`dbd96081`) until plan step 14 swaps them for `[[census.shell.generated]]` rows.
- d3f286e17 — `test-expectation-changed crates/batten/src/trust.rs::tests::narrowing_the_shell_census_is_a_weakening_and_widening_it_is_not` — CHANGED: a census arriving with an `exempt` list is no longer a tightening (CLOUD-2628: no census means presence, and `exempt` reads as migrate), so HEAD expects `census.shell.mode[migrate]` where base expected no weakening.
- 1c07e2098 — `test-expectation-changed crates/batten/src/preset.rs::tests::an_ejected_copy_records_where_it_came_from_and_drops_the_mutant_rows` — the ejected header's version is semver (`3.1.0`), and HEAD also asserts an old integer header. At least as strong.
- 068c3aacc — `test-expectation-changed crates/batten/tests/it/mutate.rs::a_deleted_preset_module_sweeps_its_gate` — the presets directory is a constant, and the row names `preset_passes_always`. Same assertion.
- 0024da9c5 — `test-expectation-changed crates/batten/src/rules.rs::tests::a_policy_row_is_skipped_only_when_its_declared_selectors_select_nothing` — `policy_rule` returns a `Result` (a rule that could not look errors); a row gains `half: None`. At least as strong: HEAD also asserts no fault.
- 0e99b6f30 — `test-expectation-changed crates/batten/src/attribution.rs::tests::a_blank_half_of_the_identity_is_refused` — `identity` is an `Option`. Same assertion.
- 0f11c25ca — `test-expectation-changed crates/batten/tests/it/hook_skip_local.rs::a_local_step_skip_is_refused` — the commit message conforms (`'fix: x'`). Same assertion.
- 12861b0bb — `test-expectation-changed crates/batten/tests/it/land_verify_advice.rs::a_refused_gate_renders_its_verdict_with_its_cause` — the expected advice text is "fix the cause the gate log names, then run the lap again". Same assertion, new words.
- 2202d87db — `test-expectation-changed crates/batten/tests/it/land_verify_advice.rs::the_gate_that_refused_is_shown_saying_why` — the gate log is read through the one view pointer (`gate_log_view`). Same assertion.
- 229841f43 — `test-removed crates/batten/tests/it/turn_cross_check.rs::a_pattern_no_row_declares_is_refused_before_anything_starts` — GONE: the per-turn detached cross-check was retired, and its case with it.
- 65f434af6 — `test-expectation-changed crates/batten/src/perf.rs::tests::a_test_only_commit_keeps_the_binary_source_key` — the fixture commits through `gitwrite` instead of spawning `git`, and writes the manifest the closure walk starts from. Same assertion.
- 8a23b080e — `test-expectation-changed crates/batten/src/rules.rs::tests::two_crate_roots_resolve_no_edge_at_all` — `project_uses` takes a key function. Same assertion.
- a702bd7ba — `test-expectation-changed crates/batten-base/src/rest.rs::tests::an_undeclared_forge_yields_no_credential_rather_than_a_default` — the forge gains `source` rows (empty here). Same assertion.
- c2bd509f6 — `test-expectation-changed crates/batten/src/policy.rs::tests::bytecode_answers_with_or_without_a_scope_and_once_per_input_within_one` — `policy::test` takes a fourth argument. Same assertion.
- cd63b09c7 — `test-expectation-changed crates/batten/tests/it/policy_cache.rs::bytecode_answers_as_the_interpreter_does` — a checked load is bytecode and keeps its interpreter; HEAD asserts both. At least as strong.
- def868f78 — `test-expectation-changed crates/batten/tests/it/perf_pair.rs::a_measurement_times_every_path_off_its_release_build` — the measured paths grow by the commit-time hook steps (`cargo-fmt`, `taplo`, `merge-conflict-markers`, `conventional-commit`, …), so the old count of 7 no longer holds. At least as strong: more paths timed.

## No first lost line (HEAD only added lines)

- `test-expectation-changed crates/batten-base/src/background.rs::tests::an_unanswered_entry_is_kept_for_a_day_and_dropped_after` — `Pending` gains `head`. Same assertion.
- `test-expectation-changed crates/batten-base/src/task.rs::tests::an_entry_gone_before_its_read_is_skipped` — `Alive` loses `program_root` (6b79edf5e); the read goes through `fsio`. Same assertion.
- `test-expectation-changed crates/batten/src/mutate.rs::tests::unlooked_counts_only_the_could_not_look_findings` — the count gains `recorded`. Same assertion.
- `test-expectation-changed crates/batten/src/rules.rs::tests::a_reference_row_reports_the_token_its_register_lacks` — rows gain `shell` and `half`. Same assertion.
- `test-expectation-changed crates/batten/src/rules.rs::tests::every_citer_shape_gathers_its_tokens` — rows gain `shell` and `half`. Same assertion.
- `test-expectation-changed crates/batten/tests/it/obligations_bound.rs::the_committed_row_is_the_one_these_cases_exercise` — the row's glob is `crates/*/{tests,examples}/…` (0c6a0c4c), so HEAD asserts a glob MATCHES this case file instead of naming the directory. At least as strong: a match, not a substring.
