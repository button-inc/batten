#!/usr/bin/env python3
"""What one rule reported, and whether it still names a remedy (CLOUD-909).

Its own file rather than a heredoc inside `replay.sh`, for the reason
`payload-field` exists: a shell script reading structured input either grows a
dependency on `jq` being on a by-path hook's PATH, or grows a hand-rolled parser
that is wrong about escapes. This is neither, and it is testable on its own.

Two questions, because the replay asks two things the same run has the answers to.

**The pointers** (default) — from `batten check -J`, filtered to one rule id.
That filter is what a `check --rule` flag would give: the fixture carries the
whole head config and only the migrated row's findings are the migration's
business. One pointer per line, sorted and deduplicated, `path:line` or `path`.
Nothing else from the finding travels: not the message, not the matched text
(non-negotiable rule 4).

**The remedy** (`--remedy`) — CLOUD-437's clause, and where it is read from was a
real finding rather than a detail. The obvious place is the refusal text, and it
is the WRONG place for a tree-scoped row: measured, `batten check` renders exactly
`path:line rule` and no remedy, because rule 4 is what its output contract IS. So
grepping the output for remedy prose would fail every faithful migration of a
tree gate. The remedy for such a row lives in its declaration — `reason`,
`no_fix_reason`, `redirect`, `policy_url` — and for a policy row it lives in the
module's own `msg`, which is why a row naming a `module` is read there too.

**Absent is could-not-look, never an empty answer** (the reading `Look` already
carries): an unreadable or unparseable input exits 3, and `replay.sh` reports that
as its own refusal rather than as "this rule found nothing" or "this rule has no
remedy". Collapsing the two would make a crashed engine look like a faithful
migration, which is the false green the replay exists to catch one level up.
"""

import json
import re
import sys
import tomllib

# A `msg` an author actually wrote, rather than the keyword appearing anywhere.
# Rego spells a refusal as `msg := "..."` or `msg = sprintf(...)`, so the anchor
# is the assignment and the test is that something non-empty follows it.
_MSG = re.compile(r"\bmsg\s*(?::=|=)\s*(\S.*)")

# The columns a row can carry a remedy in. `policy_url` counts: a refusal that
# points at the policy is naming where the remedy is, which is the clause's
# purpose rather than its letter.
_REMEDY_COLUMNS = ("reason", "no_fix_reason", "redirect", "policy_url")


def _usage() -> int:
    print(
        "usage: replay-pointers.py <check-json> <rule-id>\n"
        "       replay-pointers.py --remedy <repo-root> <rule-id>",
        file=sys.stderr,
    )
    return 2


def _pointers(document_path: str, rule: str) -> int:
    try:
        with open(document_path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return 3
    if not isinstance(document, dict):
        return 3
    findings = document.get("findings")
    # A document with no `findings` key at all is a shape this cannot read, which
    # is not the same as one carrying an empty list. The first is could-not-look;
    # the second is a real answer of "nothing".
    if not isinstance(findings, list):
        return 3
    pointers = set()
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("rule") != rule:
            continue
        path = finding.get("path", "")
        line = finding.get("line")
        pointers.add(f"{path}:{line}" if line else str(path))
    for pointer in sorted(pointers):
        print(pointer)
    return 0


def _remedy(root: str, rule: str) -> int:
    try:
        with open(f"{root}/batten.toml", "rb") as handle:
            config = tomllib.load(handle)
    except (OSError, ValueError):
        return 3
    rows = config.get("rule")
    if not isinstance(rows, list):
        return 3
    for row in rows:
        if not isinstance(row, dict) or row.get("id") != rule:
            continue
        for column in _REMEDY_COLUMNS:
            value = row.get(column)
            if isinstance(value, str) and value.strip():
                return 0
        module = row.get("module")
        if isinstance(module, str) and module:
            try:
                with open(f"{root}/{module}", encoding="utf-8") as handle:
                    text = handle.read()
            except OSError:
                # The row names a module this tree does not have. Could-not-look
                # rather than "no remedy": the migration is broken in a way the
                # pointer comparison will report far more usefully than this.
                return 3
            for match in _MSG.finditer(text):
                if match.group(1).strip(' "\''):
                    return 0
        # The row exists and names no remedy anywhere. That is the answer.
        return 1
    # No such row. The head config does not carry the rule the replay was told
    # to judge, which is a broken declaration rather than a missing remedy.
    return 3


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "--remedy":
        if len(argv) != 3:
            return _usage()
        return _remedy(argv[1], argv[2])
    if len(argv) != 2:
        return _usage()
    return _pointers(argv[0], argv[1])


if __name__ == "__main__":
    sys.exit(main())
