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

One session (2026-10-07/08, engines v0.0.205 and v0.0.206) and its eight
subagents, each a context of its own. A window is the span between two
`SessionStart` records; a subagent transcript is one window.

| transcripts | windows |
| ----------: | ------: |
|           9 |      17 |

| distinct gates per window | value |
| ------------------------- | ----: |
| mean                      |   0.6 |
| p95                       |     5 |
| max                       |     5 |

| tokens per window (bytes/4) | mean |
| --------------------------- | ---: |
| full arms                   |   55 |
| pointer arms                |   47 |
| unlabelled                  | 2250 |

| refusals                | count | share |
| ----------------------- | ----: | ----: |
| all                     |    34 |  100% |
| unlabelled              |    27 |   79% |
| next call: Followed     |     0 |    0% |
| next call: Repeated     |     0 |    0% |
| next call: Dereferenced |     1 |    3% |
| next call: Other        |    33 |   97% |
| next call: Ended        |     0 |    0% |

## What it decides

**Nothing yet about the cap.** 17 windows is below the 30 CLOUD-2141 requires,
so CLOUD-2143 keeps its design point (24 distinct gates, 160 tokens per doc).
Re-run over more transcripts and replace this file.

Two readings stand at this n, because they are counts rather than percentiles:

- **79% of refusals carry no labelled finding.** Most deny text reaching the
  agent is outside the finding grammar, so the once-per-window projection
  cannot see it — CLOUD-2078's population, measured.
- **No refusal was followed by its declared route.** The 33 "other" next calls
  include this session's own failure mode: acting on a refusal without reading
  what it pointed at.
