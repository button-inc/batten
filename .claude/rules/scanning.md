---
paths:
  - "crates/**/*.rs"
  - "mise-tasks/*"
  - "tests/*.bats"
  - "hk.pkl"
  - ".github/workflows/*.yml"
---

# Choosing an instrument for a whole-tree question

These load when you are about to ask something about the whole tree rather than
about the file in front of you. The question decides the tool, and the three
questions are not interchangeable.

| the question                                                            | instrument                    |
| ----------------------------------------------------------------------- | ----------------------------- |
| does this file contain this literal string                              | `grep`                        |
| is this token in command position, inside a comment, or inside a string | a tree-sitter matcher         |
| which type does this name resolve to                                    | clippy, rust-analyzer, Serena |

Row two is the one the tree kept reaching past. Rows one and three both have a
habit behind them — `grep` is in every hand, and `.claude/rules/rust.md` already
routes the spawn census to name resolution — so a syntax question gets answered
by whichever neighbour is closest, and both neighbours are wrong for it.

## One question, three instruments, three different answers

The spawn census is the worked example, because all three were run over it.
`grep` for `Command::new` counted **14** sites; a syntax-only matcher counted
**11**, because a call expression looks the same whichever type it names; name
resolution found **9**. `surface.rs` imports `clap::Command` bare, so the token
names two different types in this crate, and no amount of scanning tells them
apart. CLOUD-743 records that pair of wrong turns; `rust.md` carries the standing
rule for that one case.

The second measurement is CLOUD-843's, and it is the one that makes this a rule
rather than an anecdote. Classifying the 82 gate-described `mise-tasks/` programs
by what each invokes: a substring pass gave 11 tree / 24 git / 31 tracker / 16
forge, and a command-position pass over the same files, comments stripped, gave
22 / 50 / 3 build / 7. `ci-local-parity` and `pipefail-grep-check` landed in the
forge bucket because the string appeared in a **comment**. Both passes were an
hour apart, and the substring one was nearly published as the campaign's scoping.

## The row names a class, and CLOUD-310 names the components

Row two is a tree-sitter matcher, not a product. CLOUD-310 evaluated the
candidates against this tree and returned a per-component disposition —
depend-on, pin-binary, clean-room or reject, component by component. That issue
is the authority: read it when you need to know which binary to reach for, and do
not re-derive the evaluation or copy it here. Naming the class rather than the
winner is also what makes this row survive the winner being replaced.

What has to travel with the recommendation is the scope of the rejection it
carries, because reading that rejection **without** its scope is how a correct
verdict about one class became cover for the wrong tool in another. **A matcher
CLI is rejected as a gate**, on a measured defect: the programs under
`mise-tasks/` carry no extension, so a run pointed at that directory scans
nothing and still exits `0` — a silent empty answer, which is worse than a wrong
one, because a gate that found nothing looks exactly like a gate that passed.
That is an argument against wiring such a CLI into `hk` and against trusting a
bare run over this tree. **It is not an argument against a tree-sitter matcher
for a syntax question**, run interactively with the language pinned, which is
still the right instrument for row two and still better than the `grep` that gets
reached for instead.

## This rule is feedforward, and its check only proves it exists

There is no honest exit code over "did the agent pick the right scanner": the
object a gate would have to decide over is a judgement, and non-negotiable rule 3
says a gate resolves to a command and an exit code, never a model verdict.

So the mechanism here is deliberately thin and is named for what it does.
`crates/batten/tests/scanner_taxonomy.rs` asserts that this file still names an
instrument for each of the three question classes and still states the
no-extension defect beside the recommendation — the same shape as
`spawn_census.rs`'s assertion that `clippy.toml` names the spawn type. It catches
**deletion and drift**. It does not catch misuse, it cannot, and a §7 claiming
otherwise would be the same defect this file is about (CLOUD-844).
