# Recording an admission: the hook binary must be the branch build WHEN THE ANSWER ARRIVES

A weakening is admitted only by a `.batten/asked.jsonl` line (CLOUD-1078). The
line is written by `batten adjudicate` at the `AskUserQuestion` PostToolUse,
from the host's result. So the answer is recorded by whatever `batten` is on
PATH at the moment the answer arrives, not when the question was asked.

## The failure (measured 2026-09-30, CLOUD-843; three answers lost)

- **Symptom.** The owner answers, and `.batten/asked.jsonl` does not exist.
  `config lint` still refuses every pair. Nothing reports it: the recorder is
  silent on failure by design.
- **Cause.** The turn blocked on the question with nothing backgrounded, so the
  container was reclaimed. The new container's SessionStart ran the
  `session-batten` handler (`mise run session:batten` → `./install.sh`), which
  installed the latest RELEASE over the `install:local` branch build. The answer's
  PostToolUse then reached a release that predates the recorder. The session
  also resumes in plan mode, which LOOKS like a mode switch; it is not one.
- **Not the cause.** The recorder, `asked::entries`, and the host's result shape
  `{questions, answers}` all worked. A throwaway tier fed the host's exact result
  through `record_asked_for_test` and got 4 entries and 4 written.

## Diagnose in three reads

- The hook binary's identity: `ls -la /root/.local/bin/batten`. The size
  differs from `target/release/batten`. Or a verb only the branch has, such as
  `batten perf latency --help`, exits non-zero.
- That the hook fired at all: the checkout's capture log
  (`~/.local/share/batten/<repo>-<digest>/captures/calls`) has an
  `"tool":"AskUserQuestion","event":"post-tool"` row. Its
  `capture-response-shape-unreadable` is EXPECTED for the object shape and is
  not the fault.
- The ledger itself: read `.batten/asked.jsonl` with the Read tool. `test -f` on
  the protected path is refused as `program-unknown`.

## The fix that worked

1. `mise run install:local`, then confirm the branch-only verb resolves.
2. **Start real, long work with `run_in_background` BEFORE asking**, for example
   the full nextest run. That keeps the container live while the question is
   open. Never use a `sleep` or a heartbeat: they are refused, and the work you
   owe anyway is the right occupant.
3. Ask, in the same turn.
4. Read `.batten/asked.jsonl` right after the answer. Expect one line per
   question, each answer starting with `Admit`. Then run `batten config lint
--config-from origin/main`, which must show every pair `(asked)` and exit 0.

## Durable fix, owed

`session:batten` overwrites a local build that the branch installed on purpose.
The repair: `install:local` records the installed digest, and `install.sh` keeps
a destination binary that matches it. The gap closes by itself once a release
carries the recorder, which is #1042's bootstrap note. Until then, every
admission on a branch that changes the recorder or its callers depends on
steps 1–4.
