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
//! refuses one, and `rules/toolchain.md`'s retirement shape now lands its
//! tier in this group.

// A TIER THAT EXECUTES A `mise.toml` TASK BODY IS UNIX-ONLY, marked `#[cfg(unix)]`
// on its `mod` line below. Its subject is a POSIX bash program run through
// `common::task_command`, and that program never runs on Windows: the bats suites
// these tiers retired ran in the Linux `bats` job alone. On the `windows` leg,
// native `jq.exe` writes CRLF and receives a mangled `\\`, so the tier judged
// the leg rather than the task (CLOUD-1923, measured on #962 at `771651df`).
// `cfg-gated-test` exempts a case whose subject does not exist off unix, and this
// is that case at module scope rather than per `#[test]`.

// Panicking on setup failure is the idiomatic way for a test to fail loudly, and
// the former per-file allowances are preserved on each module below.
#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Every allocation this binary makes, counted (CLOUD-2022).
///
/// A cost case asserts over a COUNT, never a clock: `stats_alloc::Region` over an
/// in-process call is the same number on every runner, where a wall-clock ratio
/// failed green trees at 8.1x on Windows and 10.4x on macOS. nextest runs each
/// case in its own process, so the process-wide counter belongs to one case.
#[global_allocator]
pub(crate) static ALLOCATOR: &stats_alloc::StatsAlloc<std::alloc::System> =
    &stats_alloc::INSTRUMENTED_SYSTEM;

mod abandon_matrix;
mod acceptance_corpus;
mod acquisition_metric;
mod acquisition_sweep;
mod address_resolve;
mod address_transport;
mod adjudicate_absent;
mod admission;
mod admission_narrowing;
mod advisory_drain;
mod agent_capabilities;
mod agent_facts;
mod agentic_record;
mod ambient_authority;
mod answer_operator;
mod ask_disposition;
mod assertion_gates;
mod attestation;
mod attribution;
mod attribution_provenance;
mod authority_replay;
mod awk_regex;
mod baseline;
mod bats_invocation;
mod bench_tokens;
#[cfg(unix)]
mod board_payloads;
mod board_receipts;
mod board_record;
mod board_state_claim;
#[cfg(unix)]
mod board_sweep;
mod bot_lane;
mod branch_age;
mod bundle;
mod bypass_precondition;
mod bypass_scrub;
mod call_arguments;
mod call_background_flag;
mod call_ceiling;
mod cap_drift;
mod capture_fidelity;
mod captured_facts;
mod cfg_gated_test;
mod checks_green;
#[cfg(unix)]
mod checksums;
mod ci_cache_declared;
mod ci_hygiene;
mod ci_parity;
mod ci_slow_needed;
mod ci_suite_lane;
mod ci_suites;
mod ci_tools;
mod claim;
mod claim_carry;
mod claim_order;
mod claim_race;
mod claim_receipt;
mod claimed_keys;
mod cli;
#[cfg(unix)]
mod closing_key;
mod coderabbit_config;
mod commit;
mod commit_admission;
mod commit_arm_sequencing;
mod commit_meta_facts;
mod common;
mod config_authority_boundary;
mod config_base_ref_reading;
mod config_deprecations;
mod config_edit;
mod config_epoch;
mod config_fault_class;
mod config_forward_compatible;
mod config_in_directory;
mod config_lint;
mod config_provenance;
mod config_schema;
mod config_show;
mod config_skew;
mod config_trust;
#[cfg(unix)]
mod connector_allow;
mod connector_allow_door;
mod connector_bound;
mod connector_not_granted;
mod connector_verbs;
mod container_health;
mod content_address;
mod contract_drift;
mod could_not_look_laundered;
mod dead_capability;
mod decision_record;
mod defects;
#[cfg(unix)]
mod deferral;
mod derived_facts;
mod design_audit;
mod dev_profile;
mod digest_major_agreement;
mod doctor;
mod doctor_session;
mod doctor_target;
mod document_facts;
mod document_read_count;
#[cfg(unix)]
mod done;
mod done_not_landed;
#[cfg(unix)]
mod done_pr_check;
#[cfg(unix)]
mod duplicate_close;
mod durable_write;
mod egress_fencing;
mod emission_census;
mod enforce_journal;
mod evaluator_closure;
mod evaluator_io_probe;
mod exec_lock;
mod extension_surfaces;
mod external_facts;
mod extracted_facts;
mod fact_record_keying;
mod facts;
mod fail_on_warning;
mod filed_here;
#[cfg(unix)]
mod finding_sink;
mod fixture_forks;
mod fixture_repos;
mod forced_push;
mod forge_facts;
mod forge_window;
mod frontmatter_gates;
mod fuzz_corpus;
mod gh_guard;
#[cfg(unix)]
mod gh_preflight;
mod git_facts;
mod glob_containment;
mod glob_exclusion;
mod guardrail_bypass;
mod handler_dispatch;
mod harness_grant;
mod harness_wiring;
mod history_drop;
mod history_facts;
mod hk_contract;
mod hk_evidence;
mod hk_fix_selection;
mod hk_observation;
mod hk_plan;
mod hook_cost;
mod hook_pin_check;
mod hook_profile;
mod hook_skip_local;
mod hook_worktree_root;
mod identity_churn;
mod identity_precedence;
#[cfg(unix)]
mod in_progress_drain;
mod init;
mod install_local;
mod install_web;
mod inverted_board_cases;
mod issue_key;
mod judge_kind;
mod land;
mod land_divergence;
mod land_entry_gates;
mod land_forge_reads;
mod land_hand_stepping;
mod land_lap;
mod land_propose;
mod land_speculation;
mod land_verify_advice;
mod landed_check;
mod landing_roster;
mod lease_health;
mod lease_lifecycle;
mod lease_namespace_premise;
mod lease_precondition;
mod lease_record;
mod license_table;
#[cfg(unix)]
mod linear_check;
#[cfg(unix)]
mod lint_deno;
mod locator_index;
mod lock_complete;
mod macos_link;
#[cfg(unix)]
mod mcp_allow;
#[cfg(unix)]
mod mcp_attach;
mod mcp_dispatch;
mod mcp_reduce_array;
mod mcp_spawn;
mod mcp_timeout_budget;
mod mediated_admission;
mod mediated_verbs;
mod memories;
mod memory_injection;
mod minted_facts;
mod mise_action_floor;
mod mise_pin_agreement;
mod mise_preset;
mod module_closure;
mod module_map;
mod msrv_pin_agreement;
mod mutate;
mod mutation_declared_case;
mod named_paths;
mod narrow_adoption;
mod nextest_slow;
mod no_doctests;
mod nonverdict;
#[cfg(unix)]
mod ntia;
mod obligations_bound;
mod one_pr;
mod outcome_advice;
mod perf_assert;
mod perf_compare;
mod perf_pair;
mod perf_series;
mod pinned_programs;
mod pipefail_grep;
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
#[cfg(unix)]
mod pr_unsubscribed;
mod pr_watch;
mod preapprove;
mod prebuilt_lint;
mod preset_manifest;
mod preset_segments;
mod primitives;
mod privileged_lane;
mod process_group;
mod prose_only;
mod prospective_facts;
mod provision;
mod prune_watch;
mod publish_credential;
mod punt_receipt;
mod ratchet;
mod raw_tracker_read;
mod ready;
mod rebase;
mod receipt_clean;
mod receipt_verified;
mod reclaim_census;
mod reclaim_report_once;
mod record_closes;
mod record_families;
mod redirect_resolves;
mod reference_coverage;
mod refusal_ceiling;
mod refusal_render_bench;
#[cfg(unix)]
mod release_assets;
#[cfg(unix)]
mod release_backfill;
#[cfg(unix)]
mod release_due;
mod release_install;
mod release_provision_parity;
mod release_token_precedence;
mod release_tracking;
#[cfg(unix)]
mod released;
mod remedy_authorship;
mod remedy_payload_source;
#[cfg(unix)]
mod render_cli;
mod repaired_arms;
mod repetition;
mod report_only;
mod retirement_doctrine;
mod review_answered;
mod review_dispatched;
mod review_receipt_delta;
mod rule_cost_census;
mod rule_cost_rung;
mod rules_builtin_claims;
mod rules_drift;
mod run_arg_shape;
mod run_shape;
mod run_shape_guard_door;
mod runner_verdict;
mod rust_paths_check;
#[cfg(unix)]
mod sbom_binary;
mod sbom_inventory;
#[cfg(unix)]
mod sbom_producer;
mod scanner_taxonomy;
mod scratch_hygiene;
mod scratch_names;
mod secret_redaction;
mod secrets_kind;
mod semver_gate;
mod session_drain;
mod session_provisioning;
mod shell_retirement;
mod shell_retirement_cost;
mod shell_write_advisory;
mod signing_posture;
mod singleton;
mod singleton_gate;
mod sinks;
mod skill_contract;
mod sleep_ban;
mod snapshots;
#[cfg(unix)]
mod sonar_gate;
mod spawn_ceilings;
mod spawn_census;
mod spawn_factory;
mod spawn_widening;
mod staged_facts;
mod startup;
mod startup_bootstrap;
#[cfg(unix)]
mod step_receipt;
mod stop_posture;
mod store_lifecycle;
mod submodule;
mod suite_cost_corpus;
mod suite_subjects;
mod surface;
mod symbols;
mod target_consolidation;
mod target_prune;
mod task_callable;
mod task_prose;
mod task_receipt;
mod task_registry;
mod test_cargo_path;
mod test_targets;
mod timeout_budget;
mod timeout_drift;
mod todo_promotion;
mod tool_selector;
mod tool_verdict_facts;
mod transcript_corpus;
mod transcript_stop_reason;
mod transcript_tool_result;
mod trunk_watch;
mod turn_cross_check;
mod use_graph;
mod verdict;
mod verdict_registry;
mod verdict_vocabulary;
mod verify_unprovisioned;
mod waivers;
mod walker;
mod wiring_disarm;
mod wiring_reclaim;
mod workflow_shell_census;
mod worktree_registration;
mod zero_config;
