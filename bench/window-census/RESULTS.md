# Window census (CLOUD-2141)

How many distinct gates one context window meets, what their output costs, and
what the agent's next call did after each refusal. Produced by
`crates/batten/examples/window-census.rs`; a report, never a gate.

## Run

```
mise exec -- cargo run --quiet -p batten --example window-census -- \
  ~/.claude/projects/-home-user-batten/d4be20b3-d139-5678-9058-251c1c585e05.jsonl \
  ~/.claude/projects/-home-user-batten/d4be20b3-d139-5678-9058-251c1c585e05/subagents/*.jsonl
```

One session (2026-10-07/08) and its thirteen subagents, each a context of its
own. Its earlier windows ran released engines v0.0.205 to v0.0.208; its last
ran the branch engine carrying CLOUD-2142 to CLOUD-2145. A window is the span
between two `SessionStart` records; a subagent transcript is one window.

| transcripts | windows |
| ----------: | ------: |
|          14 |      30 |

| distinct gates per window | value |
| ------------------------- | ----: |
| mean                      |   3.7 |
| p95                       |    28 |
| max                       |    28 |

| tokens per window (bytes/4) | mean |
| --------------------------- | ---: |
| full arms                   |  384 |
| pointer arms                |  764 |
| unlabelled                  | 3633 |

| refusals                | count | share |
| ----------------------- | ----: | ----: |
| all                     |    81 |  100% |
| unlabelled              |    27 |   33% |
| next call: Followed     |     0 |    0% |
| next call: Repeated     |     0 |    0% |
| next call: Dereferenced |     1 |    1% |
| next call: Other        |    80 |   99% |
| next call: Ended        |     0 |    0% |

## What it decides

**The cap stands, now measured.** 30 windows meets CLOUD-2141's threshold. The
p95 of distinct gates per window is 28, above CLOUD-2143's design point of 24,
so the per-gate cap is recomputed as `floor(4500 / 28)` = 160 tokens — the cap
CLOUD-2143 already holds.

**Every refusal since the baseline is labelled.** The 27 unlabelled refusals
are the baseline run's 27, all from windows on the released engines; the 47
refusals added since all parsed as findings (79% unlabelled then, 33% of the
larger set now).

**No refusal was followed by the route it printed**, and that reading now
counts the routes on the line itself, not only a class's declared ones. The
earlier instrument could not have seen a followed route: it ignored the line's
`run`/`read` routes and compared only whole lines, and every Bash call in this
session opens with a `cd`. Read by hand, the zero holds: after a refusal the
next call was an investigation (a Grep, a Read, a lookup) and the route came
later or not at all. That is this session's failure mode, measured.
