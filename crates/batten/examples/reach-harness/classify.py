#!/usr/bin/env python3
"""CLOUD-2904 reach-reuse attribution, as posted on CLOUD-2904 (d03aeaa3).

Classifies every record of a reach store by two questions: did it run a
function whose probe digest changed between two trees, and does its `read`
list name a file that changed between them.

usage: classify.py REACH_DIR PROBES_OLD.tsv PROBES_NEW.tsv CHANGED.txt [UNEXPLAINED_OUT.tsv]
  PROBES_*.tsv  from `probe-diff <rev> <changed .rs files>` (file, digest, head)
  CHANGED.txt   from `git diff --name-only <old> <new>`
"""
import collections, os, sys

reach, old_tsv, new_tsv, changed_txt = sys.argv[1:5]
out = open(sys.argv[5], "w") if len(sys.argv) > 5 else None
old = {l.split("\t")[1] for l in open(old_tsv)}
new = {}
for l in open(new_tsv):
    f, d, h = l.rstrip("\n").split("\t", 2)
    new[d] = (f, h)
fresh = {d: v for d, v in new.items() if d not in old}
changed = set(open(changed_txt).read().split())
cats, by, reads = collections.Counter(), collections.Counter(), collections.Counter()
for r in os.listdir(reach):
    rp, dp = os.path.join(reach, r, "read"), os.path.join(reach, r, "depends")
    if not (os.path.exists(rp) and os.path.exists(dp)):
        cats["untraced/no-record"] += 1
        continue
    rd = {l.split("\t")[0] for l in open(rp).read().split("\n") if l}
    fns = {l[1:] for l in open(dp).read().split("\n") if l.startswith("F")}
    hit, hr = fns & fresh.keys(), rd & changed
    cats[("fresh-fn" if hit else "no-fresh-fn", "reads-changed" if hr else "reads-unchanged")] += 1
    for h in hit:
        by[h] += 1
    for f in hr:
        reads[f] += 1
    if out and not hit and not hr:
        name, binary = open(os.path.join(reach, r, "case")).read().split("\t", 1)
        out.write(f"{r}\t{binary.strip()}\t{name}\n")
print("changed functions:", len(fresh))
for k, v in sorted(cats.items(), key=str):
    print(v, k)
print("--- most-run changed functions")
for h, n in by.most_common(25):
    print(n, *fresh[h])
print("--- most-read changed files")
for f, n in reads.most_common(15):
    print(n, f)
