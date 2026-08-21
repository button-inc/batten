---
name: serena
description: Choosing the instrument for a code question — when a symbol tool answers something a text scanner cannot, and which of Read, Grep, Glob or Serena is the right reach. Use when navigating or editing code you have not already read, when about to search the tree, or when a shell text utility is about to be pointed at a repository path.
---

# Reaching for the right instrument

A question about code has a shape, and the shape decides the tool. Getting this
wrong is not a style problem: it returns a confidently wrong number.

`.claude/rules/scanning.md` is the authority on which class of question takes
which instrument, and it is not restated here. This skill is the **dispositional**
half — when to reach, and what each reach costs — for the tools themselves.

## The floor: three tools that are always right

| you want                          | reach for                          | not                               |
| --------------------------------- | ---------------------------------- | --------------------------------- |
| a file's contents, or part of one | `Read(file_path, offset, limit)`   | `cat`, `head -N`, `sed -n 'A,Bp'` |
| files containing a pattern        | `Grep(pattern, path, output_mode)` | `grep -rn`                        |
| paths matching a shape            | `Glob(pattern)`                    | `ls`, `find -name`                |

These need no language server, work on every file in the tree, and return
structured results the harness can act on. **A shell text utility aimed at a
repository path is the wrong instrument, not a shortcut** — it costs a subprocess,
returns bytes instead of structure, and its output has to be re-read to be used.

The same utilities **downstream of a pipe** are correct and stay correct:
`git log --oneline | grep -c CLOUD` is a filter over another command's output,
which no tool replaces. The distinction is the first segment, not the program.

## The ceiling: Serena answers what a scanner cannot

`grep` finds a token. Serena resolves a **name**. When the question is "which
type is this", "who calls this", or "what does this module expose", a text scan
does not approximate the answer — it produces a different one.

| question                   | tool                                                           |
| -------------------------- | -------------------------------------------------------------- |
| what does this file define | `get_symbols_overview`                                         |
| where is this symbol       | `find_symbol` (`Type/method` name paths, `depth` for children) |
| who references it          | `find_referencing_symbols`                                     |
| rename it everywhere       | `rename_symbol`                                                |
| replace a whole definition | `replace_symbol_body`                                          |

**The worked example is in this repository.** Counting `Command::new` sites:
`grep` said 14, a syntax-only matcher said 11, name resolution said 9.
`surface.rs` imports `clap::Command` bare, so the token names two different types
here and no amount of scanning separates them. Details and the standing rule for
that one case are in `.claude/rules/rust.md`.

## What Serena does and does not see

Coverage is `languages:` in `.serena/project.yml` **crossed with an
extension-based filename matcher**, and the second half is the one that surprises
people. A language being enabled does not mean its files are matched: bash is
`.sh`/`.bash` only, so an extensionless program is invisible however the list is
configured.

Check `.serena/project.yml` rather than assuming. If a file is outside coverage,
the floor above still applies in full — `Read`/`Grep`/`Glob` are correct on
100% of the tree.

## Cost, so the reach is deliberate

A cold container pays a full index before the first symbol answers, and there is
no persistent cache — every session pays it again. That is a reason to let the
index warm while doing something else, never a reason to reach for a scanner
instead: the wrong answer is not cheaper than a slow one.

Serena's tools may arrive **deferred**, callable only after a `ToolSearch`. That
is one extra call. It is not a reason to substitute a text scan for a name
resolution, and treating it as one is the measured failure this skill exists for.

## When Serena is broken rather than merely unreached

Everything above assumes a working server. Diagnosing one that is missing,
slow, or cross-linked across worktrees is a different task with a different
answer, and it has its own durable home: read `mem:serena-setup`, which carries
the two startup gates, the spawn ledger, and the log reads that decide between
them. Do not diagnose from configuration — that memory records every wrong turn
taken by reasoning about config instead of opening the log.
