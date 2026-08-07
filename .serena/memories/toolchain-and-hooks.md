# Toolchain (mise) and git hooks (hk) — deep reference

Read when: adding/pinning a tool, adding a `[tasks]` command, touching `hk.pkl`
or the pre-commit/CI gate, or bumping the pinned `hk` version. AGENTS.md carries
the "use mise for everything" rule and the task list; this is the detail.

## mise is the single source

Install/pin every dev tool via `[tools]` (never a one-off brew/cargo install or
system binary); read/set env via `[env]` (never ad-hoc exports); run every
repeatable command as a `[tasks]` task via `mise run` (never bare `cargo …` or a
duplicated snippet in CI/hook). Define it in `mise.toml` first, then call through
mise — CI, hk, and your shell then run byte-identical commands.

Common tasks: `mise run test | lint | fmt | ci | cross-check`; `mise tasks` lists
all. `mise run fmt` is `hk fix --all` and `mise run ci` = `hooks` (`hk check
--all`) + `deny`, so the gate's step list lives in `hk.pkl` alone — there is no
second list in `mise.toml` to keep in sync. `mise run test` aggregates
`test:cargo` + `test:bats`.

## Keep the hooks fast — hk.pkl is living config

The pre-commit hook runs on every commit, so its latency is a constant tax.
Whenever you touch the hooks, add a task the hook runs, or bump `hk` in
`mise.toml`, re-check the hook is still optimal.

Mechanism (not prose-only): the `hk-version` gate (`mise run hk-version`, wired
into the shared hk `gate`, runs on both pre-commit and CI) **fails** if hk's
pinned version drifts between `mise.toml` and `hk.pkl`'s `amends` URL. The two
must move together on every bump — that failure lands you back in this config
when there may be new features to adopt.

Three hk features are the baseline — keep them:

- **`stash = "patch-file"`** — hooks check exactly what's staged; fixers never
  clobber unstaged work (faster than `git stash`, no index-lock races).
- **`check_first`** on fixer steps (e.g. `fmt`) — skip the write pass when clean.
- **`depends`** to chain compile-heavy cargo steps (`cargo-fmt → cargo-clippy →
test`) into one
  serial cargo build — parallel steps only serialize on the target-dir lock while
  oversubscribing the CPU.

The gate lives **once** in `hk.pkl` (the `gate` step mapping), run by two hooks:
`pre-commit` (fix mode) locally and `check` (check-only) on CI via `mise run
hooks` → `hk check --all`, which `mise run ci` depends on. So a misconfigured
step fails CI, not just a commit. Any new gate step belongs in `hk.pkl`, not
bolted onto CI separately. Before adding a step: check `Builtins` for one first — upstream
already carries the file selectors, batching, shebang detection and fix/check
split, and each builtin ships with its own tests. Take the builtin and override
only the command when this repo needs a stricter posture, so the selector logic
stays upstream. Hand-write a step only where no builtin exists; scope its `glob`
so it only fires on relevant files, and put repo-specific logic in a `mise` task
the step calls rather than inline. Adopt new `hk` release
features (batching, caching, scheduling) when they'd tighten this.
