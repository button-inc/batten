# How many INDEPENDENT session transcripts a host carries (CLOUD-388,
# CLOUD-651, ported off `mise-tasks/transcript-corpus-check.sh` under
# CLOUD-1717).
#
# THIS IS THE STEP, NEVER THE DECISION. It counts; whether the count is enough
# is `policy/transcript-corpus.rego`'s question. §5 makes `check` `read` and
# incapable of walking a host filesystem, so the census stays here.
#
# A `.py` SIBLING RATHER THAN A TASK BODY, for the reason `cargo_graph.py` gives:
# ten of the dying suite's seventeen cases are about WHAT COUNTS as an
# independent session, and they are the whole substance of the gate. Inlined into
# the task body they would be assertable by nothing;
# `crates/batten/tests/it/transcript_corpus.rs` drives this file directly, so
# they carry. `shell-retirement.rego:159-163` excludes `.py` from
# `under_mise_tasks`, so this adds no shell rule.
#
# WHAT COUNTS AS INDEPENDENT, and why it is not "one file, one session".
#
# A transcript is independent evidence when it belongs to a DIFFERENT session
# that a person actually drove. Three things therefore do not count:
#
#   a subagent stream — `isSidechain: true`. CLOUD-326's section 8.1 recorded
#   "one session plus five subagent transcripts" and correctly called that N=1;
#   counting the five would inflate the corpus with the orchestrator's own turns
#   wearing different file names.
#
#   a transcript with nobody in it — a `tool_result` also arrives as a `user`
#   record, and that is the harness handing work back rather than a person
#   speaking. The boundary test is `finding-sink-check`'s pass 1, reused rather
#   than re-derived.
#
#   the asking session — a literal fitted to the single transcript it was derived
#   from is the unmeasured-shape failure the method exists to prevent, so
#   counting yourself is worse than counting nothing.
#
# And two files carrying one session are one session: distinct SESSIONS, not
# distinct files.
#
# A LINE THIS BUILD CANNOT DECODE YIELDS NOTHING RATHER THAN A FAILURE TO LOOK.
# The format is a HOST's and it moves, so an undecodable line contributes no id
# instead of turning the whole census into could-not-look — `transcript.rs`'s
# forward-compatibility law, applied at the same boundary from this side.
#
# Output is the record's own lines, on stdout, for `batten record named`:
#
#   sessions <count>       independent sessions found
#   threshold <count>      what the caller asked for
#
# POINTER-ONLY IS A SECURITY PROPERTY HERE, not a style one (non-negotiable rule
# 4): two counts, never a path, never a session id, never a byte of any
# transcript. A transcript is the richest source of secrets this repository can
# be pointed at.

import json
import os
import sys


def authored_session_id(line):
    """The session id of an authored, non-sidechain user record, or None."""
    try:
        record = json.loads(line)
    except ValueError:
        # The host's format moves. An undecodable line is not a failed census.
        return None
    if not isinstance(record, dict):
        return None
    if record.get("isSidechain") is True:
        return None
    if record.get("type") != "user":
        return None
    content = (record.get("message") or {}).get("content")
    if isinstance(content, str):
        authored = True
    elif isinstance(content, list):
        authored = any(
            isinstance(block, dict) and block.get("type") == "text"
            for block in content
        )
    else:
        authored = False
    if not authored:
        return None
    return record.get("sessionId") or None


def census(root, exclude):
    """Distinct independent session ids under `root`, excluding `exclude`."""
    seen = set()
    # Sorted for byte-stability (house style section 6): the same root yields the
    # same count however the filesystem chose to order itself.
    for base, _, names in sorted(os.walk(root)):
        for name in sorted(names):
            if not name.endswith(".jsonl"):
                continue
            path = os.path.join(base, name)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        found = authored_session_id(line)
                        if found is None:
                            continue
                        # The FIRST authored id in the file identifies it; a file
                        # with none at all is a subagent stream or a transcript
                        # nobody was in.
                        if found != exclude:
                            seen.add(found)
                        break
            except OSError:
                # One unreadable file is not a failed census of the rest.
                continue
    return len(seen)


def main(argv):
    # ABSENT AND EMPTY ARE DIFFERENT CLAIMS about the exclusion, which is why the
    # argument is counted rather than defaulted. An argument that is PRESENT and
    # empty is a caller saying "exclude nothing"; an argument that is absent is a
    # caller saying nothing, and only then does the ambient session id apply.
    # Defaulting an explicit empty would launder one into the other.
    if len(argv) not in (3, 4):
        sys.stderr.write("usage: transcript_census.py <root> <threshold> [exclude]\n")
        return 2
    root, threshold = argv[1], argv[2]
    if not threshold.isdigit():
        sys.stderr.write("transcript-census: threshold must be a whole number\n")
        return 2
    if len(argv) == 4:
        exclude = argv[3] or None
    else:
        exclude = os.environ.get("BATTEN_SESSION_ID") or None
    if not os.path.isdir(root):
        # The question could not be asked. Write NOTHING — an absent record is
        # "the producer did not run", which must not be spelled the same way as
        # a root that was walked and held no transcripts.
        sys.stderr.write("transcript-census: no transcript root at %s\n" % root)
        return 2
    sys.stdout.write("sessions %d\n" % census(root, exclude))
    sys.stdout.write("threshold %s\n" % threshold)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
