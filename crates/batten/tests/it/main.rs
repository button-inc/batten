//! The one integration test target (CLOUD-1210).
//!
//! # Why one target rather than 144
//!
//! Cargo autodiscovers a test target per top-level `tests/*.rs`, and rustc
//! relinks the whole dependency closure — gix, regorus, syn, clap, jsonschema,
//! hyper/rustls — into each one. Measured on this container before this change:
//! `target/debug/deps` held **147 extension-less artifacts**, and a rebuild after
//! editing one `src/*.rs` spent roughly **144 targets x ~1.0s at 4-wide ~ 36s of
//! linking** out of 48s total.
//!
//! matklad states the defect and the remedy in *Delete Cargo Integration Tests*:
//! "rustc needs to repeatedly re-link the library crate with each of the
//! integration tests", and the recommended layout for a large codebase is exactly
//! this file plus one module per former file. Cargo's own repository made the
//! same move and measured test compile time down 3x and on-disk artifacts down
//! 5x.
//!
//! # What it does NOT change, said here because the row withdrew two over-claims
//!
//! Nothing a test can observe. nextest runs **each test in a separate process**,
//! so isolation is a property of the runner rather than of the target boundary —
//! `target_consolidation.rs` asserts that rather than resting on the citation.
//! It does not reduce the number of test PROCESSES, and it does not touch the run
//! phase, which is separately measured at 4.01x parallel efficiency on 4 cores.
//! This is a build-time and a bytes change, and nothing else.
//!
//! # Adding a test file
//!
//! Add it HERE, as a `mod` line, never as a new top-level `crates/batten/tests/*.rs`
//! — that would mint a second target and undo this. `policy/test-targets.rego`
//! refuses one, and `.claude/rules/toolchain.md`'s retirement shape now lands its
//! tier in this group.

// Panicking on setup failure is the idiomatic way for a test to fail loudly, and
// the former per-file allowances are preserved on each module below.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod claim_carry;
mod common;

mod acceptance_corpus;
mod acquisition_metric;
mod acquisition_sweep;
mod admission;
mod advisory_drain;
mod agent_facts;
mod ambient_authority;
mod attribution;
mod authority_replay;
mod baseline;
mod bats_invocation;
mod board_receipts;
mod board_record;
mod board_state_claim;
mod bot_lane;
mod bundle;
mod bypass_scrub;
mod call_arguments;
mod call_background_flag;
mod call_ceiling;
mod capture_fidelity;
mod captured_facts;
mod checks_green;
mod ci_cache_declared;
mod ci_hygiene;
mod ci_parity;
mod ci_suite_lane;
mod claim;
mod claim_order;
mod claim_receipt;
mod cli;
mod commit;
mod commit_admission;
mod commit_meta_facts;
mod config_authority_boundary;
mod config_base_ref_reading;
mod config_deprecations;
mod config_epoch;
mod config_fault_class;
mod config_in_directory;
mod config_lint;
mod config_provenance;
mod config_schema;
mod config_show;
mod config_trust;
mod connector_allow_door;
mod connector_not_granted;
mod connector_verbs;
mod container_health;
mod contract_drift;
mod decision_record;
mod defects;
mod derived_facts;
mod design_audit;
mod dev_profile;
mod doctor;
mod document_facts;
mod document_read_count;
mod done_not_landed;
mod enforce_journal;
mod extension_surfaces;
mod external_facts;
mod extracted_facts;
mod fact_record_keying;
mod facts;
mod fail_on_warning;
mod filed_here;
mod fixture_repos;
mod forced_push;
mod forge_facts;
mod fuzz_corpus;
mod gh_guard;
mod git_facts;
mod glob_exclusion;
mod guardrail_bypass;
mod harness_grant;
mod harness_wiring;
mod history_facts;
mod hk_fix_selection;
mod hook_cost;
mod hook_profile;
mod hook_skip_local;
mod hook_worktree_root;
mod identity_churn;
mod identity_precedence;
mod init;
mod inverted_board_cases;
mod issue_key;
mod judge_kind;
mod land;
mod lease_record;
mod lock_complete;
mod mcp_dispatch;
mod mediated_admission;
mod mediated_verbs;
mod memories;
mod memory_injection;
mod minted_facts;
mod mise_pin_agreement;
mod mutate;
mod mutation_declared_case;
mod narrow_adoption;
mod obligations_bound;
mod perf_assert;
mod perf_compare;
mod perf_pair;
mod pinned_programs;
mod pipeline_shapes;
mod plan_complete;
mod pointer_only;
mod policy_engine_count;
mod policy_input_narrowing;
mod policy_input_schema;
mod policy_presets;
mod policy_severity;
mod policy_test_suite;
mod policy_tree;
mod policy_whole_set;
mod pr_partition_restated;
mod pr_watch;
mod prebuilt_lint;
mod preset_manifest;
mod preset_segments;
mod primitives;
mod privileged_lane;
mod process_group;
mod prose_only;
mod prospective_facts;
mod provision;
mod ratchet;
mod raw_tracker_read;
mod ready;
mod rebase;
mod reclaim_report_once;
mod record_closes;
mod redirect_resolves;
mod reference_coverage;
mod refusal_ceiling;
mod remedy_authorship;
mod repetition;
mod retirement_doctrine;
mod review_answered;
mod review_dispatched;
mod rule_cost_census;
mod rule_cost_rung;
mod rules_builtin_claims;
mod rules_drift;
mod run_shape;
mod run_shape_guard_door;
mod runner_verdict;
mod sbom_inventory;
mod scanner_taxonomy;
mod secrets_kind;
mod semver_gate;
mod session_drain;
mod session_provisioning;
mod shell_retirement;
mod shell_retirement_cost;
mod shell_write_advisory;
mod singleton;
mod sinks;
mod skill_contract;
mod sleep_ban;
mod snapshots;
mod spawn_ceilings;
mod spawn_census;
mod staged_facts;
mod startup;
mod stop_posture;
mod submodule;
mod suite_subjects;
mod surface;
mod symbols;
mod target_consolidation;
mod target_prune;
mod task_prose;
mod task_receipt;
mod task_registry;
mod test_targets;
mod todo_promotion;
mod tool_selector;
mod tool_verdict_facts;
mod use_graph;
mod verdict_registry;
mod verdict_vocabulary;
mod waivers;
mod walker;
mod wiring_reclaim;
mod zero_config;
