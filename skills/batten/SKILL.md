---
name: batten
description: How to work in a repository gated by Batten — when to consult `batten check` versus trust the hook, how to read a pointer-only finding without re-running anything, what a deny is telling you, and how to read a verification receipt. Use when a Batten hook denies a call, when a `batten` command reports a finding, or before claiming work is done in a repository that has a batten.toml.
---

# Working with Batten

Batten is a completion gate. It answers conformance questions about the
repository's own state — is this ref on `main`? did the required checks conclude
green for this exact SHA? does a verification receipt still hold? — and it
answers them at the moment work is claimed to be done.

It is not an authorization system. There is no principal and no permission
model; the subject is always the repository.

## Three surfaces, and only one of them asks anything of you

| Surface      | Role     | What you do                                    |
| ------------ | -------- | ---------------------------------------------- |
| The **hook** | binds    | nothing — it fires on calls you cannot decline |
| The **CLI**  | consults | run it to learn the repository's verdict       |
| This skill   | disposes | tells you when consulting is worth the call    |

You are gated whether or not you read any of this. The hook fires before a call
runs and reads committed, out-of-band config that your context cannot influence.
So the question is never "may I skip the gate" — it is "what is the gate saying".

## Exit codes are the answer; output is a courtesy

| Code | Meaning                                                 |
| ---- | ------------------------------------------------------- |
| `0`  | clean — nothing to report; a mediated call is allowed   |
| `1`  | config or usage error — fail loud, do not block         |
| `2`  | policy verdict — a violation, or a mediated call denied |
| `3`  | internal error — fail loud, do not block                |

Two readings of this table are worth stating outright, because getting either
wrong sends you in the wrong direction:

**`1` is not a violation.** It means Batten could not do its job — a malformed
`batten.toml`, an unknown key, a verb handed a rule kind it refuses to run. Fix
the configuration. Nothing has been said about your work.

**A clean run prints nothing and exits `0`.** Silence is the verdict, not
evidence that nothing happened. Read the status, never the emptiness.

`1` and `3` are the only codes a Batten failure can produce, which is what makes
failing open structural: a broken Batten cannot block a call.

## When to run `check`, and when not to

Run it:

- before claiming a task is done;
- after changing `batten.toml`, or adding a rule;
- before pushing, so a failure costs a local run instead of a CI run.

Do not run it:

- **to second-guess a hook decision.** The hook adjudicated one _call_; `check`
  scans the _tree_. Those are different questions, and re-asking the wrong one
  buys nothing.
- **to see more of a finding.** There is no more — see below.

```console
$ batten check
$ echo $?
0
```

`batten enforce` is `check` plus the rule kinds that execute a configured
command. `check` refuses those deliberately, with exit `1` naming the verb that
runs them; that refusal is what keeps `check` structurally read-only, so it is
safe to run anywhere, any number of times.

## A finding is a pointer, never a payload

Findings name the rule and the location. They never carry the matched content —
not by omission, but by contract, because a check over sensitive content that
printed the content would leak exactly what it exists to catch.

```console
$ batten check -J
{
  "fail_on_warning": false,
  "findings": []
}
```

A populated `findings` entry carries `rule`, `path`, an optional `line`,
`severity`, `report`, and a stable `identity`.

`severity` is the committed rule's own rating. `report` is that rating after the
resolved `fail_on_warning` setting is applied — so a promoted warning reads
`"severity": "warn"` with `"report": "fail"`. Read `report` when you want to know
whether the run failed; read `severity` when you want to know what the authority
declared.

**So: open the file at `path:line`.** Do not re-run the command with more
verbosity hoping the content appears. It will not. The output is byte-stable for
identical input, which is the other half of the same design: an unchanged
repository renders identical bytes, so re-running produces the same text you
already have, at full cost, with nothing added.

Captured command output is content-addressed and addressed by a handle shaped
`<stream>:<digest>`. **No verb expands a handle today.** When one ships, this is
where it belongs; until then, do not construct a command to expand one.

## What a deny means

One verdict, two channels, because hosts differ:

- A host that reads an **in-band decision document** gets the document on stdout
  and exit `0`. The deny is inside the document.
- A host whose only channel is **process status** gets exit `2` with the reason
  on stderr.

Both are the same policy verdict. On the first kind of host, exit `0` from
`batten adjudicate` does not mean allowed — read the decision.

A real deny, in full:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Refused by gh-pr-merge: `gh pr merge` (like the merge button) rewrites commits under new SHAs, discarding the exact objects CI tested. Use `mise run land`, which comments /fast-forward so main advances to this branch's already-passed commits. Bypass with BATTEN_GH_GUARD_BYPASS=1."
  }
}
```

The reason is the whole explanation, and it is doing three jobs at once:

1. **naming the rule** (`gh-pr-merge`), so the verdict is traceable to committed
   config rather than to a mood;
2. **saying why**, in terms of the consequence, not the prohibition;
3. **naming what to do instead** (`mise run land`).

That third part is the point. A deny is a linter result, not a closed door — it
is designed to get you to right in one hop. **Read the reason and run the named
command.** Do not retry the denied call with different spelling, and do not go
looking for a way around it: the rule is committed config, and working around it
is working around the repository's own stated policy.

## Bypass hatches

Every deny names its own bypass, in the form `BATTEN_<GUARD>_BYPASS=1`. It
exists for the deliberate override — the case the rule's author did not foresee
and a human has decided about.

Reaching for the bypass before reading the fix pointer is the wrong first move,
and it is the one the audit trail is designed to catch: taking a bypass writes an
audit line. Use it when you mean it, and say why in the commit or the PR.

## Reading a receipt

A receipt is a claim that a named check passed, keyed to an exact commit, with an
expiry condition that is a git fact rather than a clock.

```console
$ batten receipt status verify
verify b1669d6f503804d7102754c992931a9c31359d6d stale-main
$ echo $?
2
```

```console
$ batten receipt status verify -J
{
  "check": "verify",
  "head": "b1669d6f503804d7102754c992931a9c31359d6d",
  "verdict": "stale-main"
}
```

Four verdicts, evaluated in this order — the first that matches wins:

| Verdict      | What happened                                                             |
| ------------ | ------------------------------------------------------------------------- |
| `missing`    | no receipt, unreadable, or recorded in a different clone or worktree      |
| `stale-head` | a receipt exists, but HEAD has moved since — an amend, a commit, a rebase |
| `stale-main` | HEAD matches, but the trunk it was judged against has moved               |
| `valid`      | the receipt attests to these exact bytes against this trunk               |

The ordering is the useful part. `missing` is checked before staleness, so a
receipt from another checkout is reported as absent rather than as stale — it
never attested to anything here.

**Why an amend invalidates a passing check:** the receipt attests to _those exact
bytes_. Amending produces different bytes, so the evidence no longer describes
what you have. Same for `stale-main`: "green against the trunk as it was" is not
"green against the trunk as it is", and the gap is where a semantic conflict
lives. A `stale-*` verdict is not a bug and not a reason to force anything — it
is the receipt correctly reporting that it no longer covers your work. Re-run the
check.

`batten receipt record <check>` writes one. Record what actually passed; a
receipt is evidence, and recording one for a check you did not run is the exact
false-completion signal this tool exists to kill.

## On an unfamiliar checkout, run `doctor` first

```console
$ batten doctor
config ok
git-repo ok
command-programs ok
pin-record ok
hook-handlers ok
plan-surface ok
doctor: 6 check(s), 0 failed
```

`doctor` reports whether Batten can run here at all, with `-J` for a machine
reading. It never returns `2`, deliberately: every failure it can report is the
config-or-usage class, and "this checkout is misconfigured" must never be read as
a policy denial.

A `command` row's program counts as reachable if it is on `PATH` **or** the
project's pin provides it — the spawn resolves it either way, so a probe that
asked only about bare `PATH` would report every pinned tool as missing.
`pin-record` is asked separately because a memo that stopped validating and a
tool that was never installed are different faults with different repairs.

**You do not have to remember to run it.** A container whose environment does not
match what the tree declares says so on the advisory channel at session start,
naming the failing checks and their subjects; a healthy one is silent.

## `batten startup` — the preconditions this repository declares

`doctor` answers whether Batten can run here. `batten startup` answers whether
this **container** is what the repository declared, off `[[startup]]` rows in
`batten.toml`: each is a `check` command whose exit code decides, plus the
`repair` that makes it so.

```console
$ batten startup
engine-reads-the-authority ok
hook-surfaces-are-battens failed not-provisioned
startup: 2 row(s), 1 failed
```

Bare, it decides and changes nothing. `batten startup --repair` runs each failing
row's repair and then **re-runs its check**, so a repair that exits zero having
fixed nothing is reported rather than believed:

```console
$ batten startup --repair
engine-reads-the-authority ok
hook-surfaces-are-battens ok repaired
startup: 2 row(s), 0 failed
```

`ok repaired` means this run moved that row. A row that keeps needing repair
every session is a row whose check is wrong, and the two renderings are what let
you see that.

The declared repairs also run on their own at session start — writing a `repair`
in the committed authority is the authorisation to run it — so `--repair` is for
provisioning a container out of band, which is what the committed `setup.sh`
does. A row with no `repair` is reported and never acted on.

What a row means is its `gloss` in `batten.toml`: the report is pointer-only, so
the id is all it carries.

## Overrides may tighten, never weaken

A repository has one committed authority, `batten.toml`. A consumer may add a
git-ignored `batten.local.toml`, plus environment and flag overrides, and those
layers are **raise-only**: they may add a rule or make one stricter. An attempt
to weaken or remove what the committed authority declares is refused with exit
`1` — refused, not silently applied.

So if a rule is in your way, the answer is never a local override. It is a change
to the committed authority, reviewed like any other change.

## Do not

- Re-run a command to see more output. Pointer-only is a contract; there is no
  more output to get.
- Read empty output as "it did not run". Read the exit code.
- Treat exit `1` as a policy finding. It means the gate could not run.
- Treat exit `0` from `batten adjudicate` as "allowed" on a host with an in-band
  decision channel. Read the decision document.
- Reach for a bypass before reading the fix pointer the deny already gave you.
- Record a receipt for a check you did not run.
- Weaken `batten.toml` to make a finding go away.
