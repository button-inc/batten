# Rule 3's scope: which model a gate may not consult

Read when: about to cite non-negotiable rule 3, call something "a classifier",
"an estimate" or "a judgement" as the reason a gate cannot exist, or design a
gate over prose, a transcript, a skill or an artifact. The authority is
principle 3 of the house-style spec; this memory is the reading of it, and the
failure it exists to stop.

## The line

Rule 3 forbids the **gated model's** verdict: the harness's own model, or any
model whose context the gated agent can reach. It never forbade "a model". A
**Batten-managed model is a command**, and may decide, when it is:

- pinned by digest, with deterministic (quantized, CPU) inference run by
  `batten`, so local and CI agree near the threshold;
- fed text the engine keeps — only a label from a closed set, or `null` for
  could-not-look, reaches a module; never a score, vector or span (embeddings
  are partly invertible);
- given a remedy that is an action (file it, spend an override, rerun the
  check), never "rephrase";
- measured: a committed labelled corpus pins its precision above the
  confidence threshold, so mutating the threshold or label map turns a case red.

An external `[judge]` is on the harness side of the line and stays advisory.
The spelling in the tree is `gated-model`; `prose name loose` refuses the
unqualified phrase.

## The failure

Restating the rule as "no model anywhere" — measured about forty times across the
tree before the 2026-11-10 ruling — ruled out CLOUD-1921's classifier, called a
false-positive threshold the forbidden kind of verdict (`ready.rs`), and declared the
engine could never read transcript prose (`rules/policy-modules.md`). The engine
may read text; text never crosses into a module (`turn.rs`'s `finding-citation`
boolean is the existing instance).

## Layering over a skill or step

Four verdicts, each with its own remedy, in this order:

1. the step was invoked (typed `Skill` call facts — the baseline, not a fallback);
2. the harness did not refuse it (`is_error` on its result);
3. it left its artifact;
4. the artifact is suitable — a deterministic gate first, a Batten-managed
   classifier only where no predicate can express the question.

An artifact gate alone cannot tell 1–3 apart, so it cannot name the remedy.
