# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
