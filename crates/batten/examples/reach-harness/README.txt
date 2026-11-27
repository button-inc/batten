CLOUD-2904 offline reach/selection harness. Branch claude/cloud-2904-reach-harness,
based on 6285c4583 (the engine lap 26 ran). Diagnostic only: never to land.

Changes to the engine on this branch:
  crates/batten/src/mutate/schema.rs: `built_outputs` made pub; `selection_digest`
  prints `WHY\t<reason>\t<case>\t<name|probe digest>` to stderr on each None.
Examples: probe-diff.rs, key-diff.rs, tree-digest.rs (crates/batten/examples/).

S=<scratch dir>; R=~/.local/share/batten/<state>/mutate/schema/reach
P=~/.local/share/batten/<state>/mutate/schema/pristine
git worktree add $S/wt6285 claude/cloud-2904-reach-harness
git worktree add $S/wtb878 b878238b4
cd $S/wt6285 && CARGO_TARGET_DIR=<batten>/target mise exec -- cargo build -p batten \
  --example probe-diff --example key-diff --example tree-digest
X=<batten>/target/debug/examples

1. The 4-way table (2,719 / 212 / 270 / 5,984; posted d03aeaa3):
  git diff --name-only b878238b4 6285c4583 > $S/changed.txt
  F=$(git diff --name-only b878238b4 6285c4583 -- '*.rs')
  $X/probe-diff b878238b4 $F > $S/probes-old.tsv
  $X/probe-diff 6285c4583 $F > $S/probes-new.tsv
  python3 crates/batten/examples/reach-harness/classify.py $R $S/probes-old.tsv \
    $S/probes-new.tsv $S/changed.txt $S/unexplained.tsv

2. The 300-record sample (47/55/198; 64/38/198 over pristine; posted e9f271e6):
  cut -f3 $S/unexplained.tsv | shuf -n 300 --random-source=<(yes) > $S/sample.txt
  $X/key-diff $R $S/wt6285 $S/sample.txt 2> $S/why.txt > $S/kd-6285.tsv
  $X/key-diff $R $P $S/sample.txt $S/wt6285 2> $S/why-pristine.txt > $S/kd-pristine.tsv
  grep WHY $S/why.txt | cut -f2 | sort | uniq -c

3. The whole store (1,219 / 748 / 9,692 of 11,659 sealed):
  for f in $R/*/case; do cut -f1 $f; done > $S/all-cases.txt
  $X/key-diff $R $P $S/all-cases.txt $S/wt6285 2> $S/why-all.txt > $S/kd-all.tsv
  grep WHY $S/why-all.txt | cut -f2 | sort | uniq -c

4. Tree digests: $X/tree-digest $S/wt6285 $S/wtb878 $P

Caveat (provenance, CLOUD-2904 b1f42a48): the store's `tested` lines measured here
were written by an earlier held lap on another head and engine, so no stored digest
reproduced better than 64 of 300.
