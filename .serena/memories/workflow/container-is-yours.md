# The container is yours alone

**No human can run a command in this container, open a shell in it, or restart
its session for you.** The operator sees chat and the PR; they cannot reach the
filesystem, the binaries or the processes. So a step that needs a command is
yours whatever state the container is in. Telling the human to run something
here, or to "restart the session", hands back the one kind of step nobody else
can take. It is the purest form of AGENTS.md's punt, and `turn ask early`
(`policy/turn-ask.rego`) names it (CLOUD-2117).

## Measured

PR #1102, 2026-10-05: `land` replayed onto a `main` whose `batten.toml` pinned a
newer engine than the installed one. The hook refused every call
`engine-cannot-adjudicate`, including the `./install.sh` its own remedy named.
Two final messages then told the operator to run the install or restart the
session. The operator caught both; the gate was silent on both.

## When every call is refused, the exits are still yours

Work down this list; never stop at "blocked" and never hand it over.

1. **Read the refusal's own Fix clause.** The unloadable-config floor
   (`recoverable_without_rules`, `crates/batten/src/lib.rs`) always admits a
   `Read`, an inert search (`Grep`/`Glob`), and an `Edit`/`Write` of
   `batten.toml` or `batten.local.toml`.
2. **A pin newer than the binary: run `batten engine update`, spelled whole.**
   Since CLOUD-2116 the floor admits exactly that command, and the skew refusal
   names it.
3. **Before that fix is installed, the pin line itself is the exit.** Edit the
   pin to the build the hook is running, so the engine loads for one step; do
   the repair (install the tree's build, replay onto `main`); then edit the pin
   line back so no commit carries it. Measured 2026-10-07, and two traps on it:
   - **A non-hook `batten` self-updates to the pin at startup** (CLOUD-2063).
     While the pin is edited down, any task that runs `batten` downgrades
     `~/.local/bin/batten` to that pin. Install the build you want LAST, after
     every task that ran under the edited pin.
   - **Do the shell steps in one command.** Each command is judged before it
     runs, so `git stash && batten land replay main && git stash pop` passes on
     one load; a later command meets whatever pin the tree then holds.
4. **A config fault: repair the file with the admitted `Edit`**, then carry on.
5. If none of these opens a route, the gate is wrongly refusing: repair it
   (AGENTS.md) and file it. Say what is blocked and what you are doing about it,
   never what the human should do.
