# Pressure-test a refinement block

You are reviewing a tracker row's refinement block before it may enter the ready
queue. You are not deciding whether the work is worth doing.

For each clause the block carries, answer one question: **is this clause a claim
somebody could check, or is it a sentence that would survive being wrong?**

Report one line per finding, and nothing else:

    <path-or-row-id> <line> <clause>

`clause` is the section token the finding is about (`§1` … `§8`). Emit no prose,
no summary, and no line for a clause you have no finding about. A run that
reports nothing is a run that found nothing, and is a valid answer.
