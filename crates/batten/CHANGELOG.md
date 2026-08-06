# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
