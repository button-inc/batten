# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.51](https://github.com/button-inc/batten/compare/v0.0.50...v0.0.51) - 2026-08-10

### Added

- *(waiver)* add per-rule waivers that lapse on their own date

## [0.0.50](https://github.com/button-inc/batten/compare/v0.0.49...v0.0.50) - 2026-08-10

### Other

- *(readme)* document the three extension surfaces, with executed examples

## [0.0.49](https://github.com/button-inc/batten/compare/v0.0.48...v0.0.49) - 2026-08-10

### Added

- *(outputs)* promote a wrapped command's lying exit 0 to a failure

## [0.0.48](https://github.com/button-inc/batten/compare/v0.0.47...v0.0.48) - 2026-08-10

### Added

- *(capture)* tee `exec` output to a content-addressed out-of-tree store

## [0.0.47](https://github.com/button-inc/batten/compare/v0.0.46...v0.0.47) - 2026-08-10

### Added

- *(exec)* add the transparent passthrough verb the surface always declared

## [0.0.46](https://github.com/button-inc/batten/compare/v0.0.45...v0.0.46) - 2026-08-10

### Other

- *(cli)* derive the machine-output contract from the data_channel column

## [0.0.45](https://github.com/button-inc/batten/compare/v0.0.44...v0.0.45) - 2026-08-10

### Added

- *(cli)* add the standard flag ladder and the attended/unattended layer

## [0.0.44](https://github.com/button-inc/batten/compare/v0.0.43...v0.0.44) - 2026-08-10

### Added

- *(hook)* deny a mutating verb against a protected path, and name the mutation

## [0.0.43](https://github.com/button-inc/batten/compare/v0.0.42...v0.0.43) - 2026-08-09

### Added

- *(hook)* adjudicate mediated calls from a declarative rule table

## [0.0.42](https://github.com/button-inc/batten/compare/v0.0.41...v0.0.42) - 2026-08-09

### Fixed

- *(hook)* parse quoted spans into words instead of a sentinel

## [0.0.41](https://github.com/button-inc/batten/compare/v0.0.40...v0.0.41) - 2026-08-09

### Other

- *(hook)* pin the decision channel per harness with a fixture matrix

## [0.0.40](https://github.com/button-inc/batten/compare/v0.0.39...v0.0.40) - 2026-08-09

### Added

- *(config)* attribute every emitted config key, and put the full table behind --json

## [0.0.39](https://github.com/button-inc/batten/compare/v0.0.38...v0.0.39) - 2026-08-09

### Other

- *(corpus)* translate the predecessor acceptance corpus into a de-identified rule fixture

## [0.0.38](https://github.com/button-inc/batten/compare/v0.0.37...v0.0.38) - 2026-08-09

### Added

- *(gate)* discover a fixture-repo corpus, and collapse nine copies of the materializer

## [0.0.37](https://github.com/button-inc/batten/compare/v0.0.36...v0.0.37) - 2026-08-09

### Added

- *(rules)* re-run rule 1's grep on every gate, not once by hand

## [0.0.36](https://github.com/button-inc/batten/compare/v0.0.35...v0.0.36) - 2026-08-08

### Fixed

- *(config)* validate the marker table at load, and gate the class that hid it

## [0.0.35](https://github.com/button-inc/batten/compare/v0.0.34...v0.0.35) - 2026-08-08

### Fixed

- *(config)* validate the verb table at load, where nothing validated it at all
- *(markers)* tell "not UTF-8" apart from "cannot be read", as the contract says

## [0.0.34](https://github.com/button-inc/batten/compare/v0.0.33...v0.0.34) - 2026-08-08

### Fixed

- *(check)* an unreadable working authority is the maximal weakening, not an abort
- *(lint)* keep the key trust located a weakening by, so dedup cannot swallow one

## [0.0.33](https://github.com/button-inc/batten/compare/v0.0.32...v0.0.33) - 2026-08-08

### Added

- *(config)* hash the governing config surface into a config_epoch (CLOUD-32)

## [0.0.32](https://github.com/button-inc/batten/compare/v0.0.31...v0.0.32) - 2026-08-08

### Other

- *(fail-on-warning)* start each fixture from an empty directory

## [0.0.31](https://github.com/button-inc/batten/compare/v0.0.30...v0.0.31) - 2026-08-08

### Added

- *(doctor)* add the post-install self-check and render the exit table (CLOUD-66)

## [0.0.30](https://github.com/button-inc/batten/compare/v0.0.29...v0.0.30) - 2026-08-08

### Added

- *(config)* publish the two new tables in the JSON Schema
- *(tables)* count suppression markers and type mutating verbs, from config
- *(git)* decide merged-ness by patch identity, never by reachability

### Other

- *(git)* pin what cumulative evidence claims, and the fast-forward shape

## [0.0.29](https://github.com/button-inc/batten/compare/v0.0.28...v0.0.29) - 2026-08-08

### Added

- *(config)* name policy smells with `batten config lint` (CLOUD-87)

## [0.0.28](https://github.com/button-inc/batten/compare/v0.0.27...v0.0.28) - 2026-08-08

### Added

- *(config)* judge by a trusted base ref with --config-from (CLOUD-31)

## [0.0.27](https://github.com/button-inc/batten/compare/v0.0.26...v0.0.27) - 2026-08-08

### Added

- *(config)* derive and publish the batten.toml JSON Schema, gate min_batten_version (CLOUD-33)

## [0.0.26](https://github.com/button-inc/batten/compare/v0.0.25...v0.0.26) - 2026-08-08

### Added

- *(cli)* declare the command surface once, as data (CLOUD-27)

## [0.0.25](https://github.com/button-inc/batten/compare/v0.0.24...v0.0.25) - 2026-08-08

### Added

- *(check)* promote warn findings with one resolved fail_on_warning setting

### Other

- *(resolve)* lift the env and flag layer lookups out of the resolver

## [0.0.24](https://github.com/button-inc/batten/compare/v0.0.23...v0.0.24) - 2026-08-08

### Added

- *(rules)* three independent config-driven path sets

## [0.0.23](https://github.com/button-inc/batten/compare/v0.0.22...v0.0.23) - 2026-08-08

### Added

- [**breaking**] one exit table — 2 is the policy verdict, so hook has nothing to invert

### Other

- keep the always-loaded exit-contract rule inside the context budget

## [0.0.22](https://github.com/button-inc/batten/compare/v0.0.21...v0.0.22) - 2026-08-08

### Added

- *(git)* resolve the repo root via the common-dir finder

### Fixed

- *(receipt)* derive the state dir from the common-dir root, not the worktree

## [0.0.21](https://github.com/button-inc/batten/compare/v0.0.20...v0.0.21) - 2026-08-08

### Other

- *(readme)* claim the surveyed property, not the falsified one

## [0.0.20](https://github.com/button-inc/batten/compare/v0.0.19...v0.0.20) - 2026-08-07

### Added

- *(receipt)* SHA-keyed verification receipts, written and judged by the binary

## [0.0.19](https://github.com/button-inc/batten/compare/v0.0.18...v0.0.19) - 2026-08-07

### Added

- *(rules)* adopt cargo-deny's severity model — deny/warn/allow per rule

## [0.0.18](https://github.com/button-inc/batten/compare/v0.0.17...v0.0.18) - 2026-08-07

### Other

- *(scope)* a boundary that survives the roadmap, and the misuse cost named

## [0.0.17](https://github.com/button-inc/batten/compare/v0.0.16...v0.0.17) - 2026-08-07

### Added

- *(hook)* the adjudicator's first slice — envelope, parser, gh policy

## [0.0.16](https://github.com/button-inc/batten/compare/v0.0.15...v0.0.16) - 2026-08-07

### Added

- *(gate)* wire consumer #1 — batten check runs against its own repository

### Fixed

- *(cli)* bare invocation lists subcommands instead of exiting silently

### Other

- *(graph)* one authority per fact across the agent-facing doc graph
- *(contract)* the public contract states what ships, and plans the rest

## [0.0.15](https://github.com/button-inc/batten/compare/v0.0.14...v0.0.15) - 2026-08-07

### Added

- *(severity)* map the three severity axes through one rank table

## [0.0.14](https://github.com/button-inc/batten/compare/v0.0.13...v0.0.14) - 2026-08-07

### Fixed

- *(config)* treat an empty env override as unset and refuse authority-only local keys

## [0.0.13](https://github.com/button-inc/batten/compare/v0.0.12...v0.0.13) - 2026-08-07

### Other

- *(hooks)* format and validate every config format in the gate

## [0.0.12](https://github.com/button-inc/batten/compare/v0.0.11...v0.0.12) - 2026-08-07

### Other

- *(config)* drop the unread raise_only flag from SETTINGS

## [0.0.11](https://github.com/button-inc/batten/compare/v0.0.10...v0.0.11) - 2026-08-07

### Added

- *(config)* resolve batten.toml layers with a raise-only clamp

## [0.0.10](https://github.com/button-inc/batten/compare/v0.0.9...v0.0.10) - 2026-08-07

### Added

- *(identity)* add the finding-identity fingerprint kernel (CLOUD-123)

## [0.0.9](https://github.com/button-inc/batten/compare/v0.0.8...v0.0.9) - 2026-08-07

### Added

- *(rules)* add a command rule kind for dynamic checks

## [0.0.8](https://github.com/button-inc/batten/compare/v0.0.7...v0.0.8) - 2026-08-07

### Added

- *(check)* split process-spawning rules onto a non-read verb

## [0.0.7](https://github.com/button-inc/batten/compare/v0.0.6...v0.0.7) - 2026-08-07

### Other

- update Cargo.toml dependencies

## [0.0.6](https://github.com/button-inc/batten/compare/v0.0.5...v0.0.6) - 2026-08-06

### Other

- *(deps)* auto-land Dependabot PRs on green CI

## [0.0.5](https://github.com/button-inc/batten/compare/v0.0.4...v0.0.5) - 2026-08-06

### Added

- *(check)* add rule and check engine with a static forbid kind
- *(state)* derive the out-of-tree state path from the repo name

### Other

- *(check)* derive unit-test scratch dir at runtime
- *(exit)* assert the exit-code contract as a table

## [0.0.4](https://github.com/button-inc/batten/compare/v0.0.3...v0.0.4) - 2026-08-06

### Added

- *(config)* add the batten.toml loader and `config show`

## [0.0.3](https://github.com/button-inc/batten/compare/v0.0.2...v0.0.3) - 2026-08-06

### Added

- *(cli)* emit the command surface as data via `batten spec`

## [0.0.2](https://github.com/button-inc/batten/compare/v0.0.1...v0.0.2) - 2026-08-06

### Fixed

- *(exit)* set internal-error exit code to 3

### Other

- relicense Batten to Apache-2.0 only

## [0.0.1](https://github.com/button-inc/batten/compare/v0.0.0...v0.0.1) - 2026-08-06

### Fixed

- tie exit-code fallback to Internal instead of a bare literal

### Other

- release v0.0.0

## [0.0.0](https://github.com/button-inc/batten/releases/tag/v0.0.0) - 2026-08-05

### Other

- scaffold Batten repo-agnostic policy engine
