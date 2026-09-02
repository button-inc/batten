# Pressure-test a refinement block

You are reviewing a tracker row's refinement block before it may enter the ready
queue. You are **not** deciding whether the work is worth doing.

## What you are given

This prompt, then one line:

    <subject> <digest>

`<subject>` is a repository-relative path or a tracker row's key. `<digest>` is
the digest of its bytes at the moment the review was asked for.

**Read the subject yourself**, with whatever tools you have. It is deliberately
not pasted here: Batten reduces content to a pointer and never dumps it into a
model's context, and this dispatch is not an exception to that.

## What to answer

For each clause the block carries, answer one question: **is this clause a claim
somebody could check, or is it a sentence that would survive being wrong?**

## What to emit

One line per finding, and nothing else:

    <subject> <line> <clause>

`<clause>` is the section token the finding is about (`§1` … `§8`). `<line>` is a
1-based line number, or `0` where the subject has no lines.

Emit no prose, no preamble, no summary, and no line for a clause you have no
finding about. **A run that reports nothing is a run that found nothing, and is a
valid answer** — the caller distinguishes that from a run that never happened, so
you never need to invent a finding to show you were here.

Any line that is not exactly three whitespace-separated fields causes the whole
run to be discarded, so do not explain yourself.
