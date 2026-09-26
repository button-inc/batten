# A release's binaries carry build provenance (CLOUD-583, ported under CLOUD-1717).
#
# THE WHOLE DESIGN IS ONE DISTINCTION, and the retired program's header names it:
# `gh attestation verify` exits 1 both when an artifact has no provenance and when
# the platform never offered any, and those are opposite facts. The first is a
# release to fix; the second is a plan feature this private repository does not
# have. A gate that cannot tell them apart is worse than no gate, because it reds
# every release for a reason no branch causes.
#
# The control that separates them is the endpoint's own status code, and it stays
# the producer's reading: where attestation IS available an unknown digest answers
# 200 with an empty array, and 404 on the resource is the feature being absent.
# `[tasks.attestation-record]` probes with an all-zeros digest and records which.
#
# WHY THE SPAWN STAYS OUTSIDE, and it is not a convention. The verifier is a
# process — `gh attestation verify` over a binary unpacked from a downloaded
# archive — and house style §5 makes `check` `read` and structurally incapable of
# spawning one. So what moves in here is not the verification but the ADJUDICATION
# of what the verifier said, which is CLOUD-1559's reading rule: carry the
# decisions, not the steps. The download, the unpack and the verify are steps.
#
# A 404 POSTURE FIRES NOTHING, deliberately, and that is the ported behaviour
# rather than a gap. The retired program exited 0 and reported the gap, because
# nothing there is a claim about an artifact — `release-artifacts.yml` runs its
# attestation step `continue-on-error: true` for the same fact, so a release is
# published unattested BY DESIGN until the repository is public (CLOUD-585). The
# record being present with `posture 404` is what keeps that readable: it says the
# producer looked and the platform offers none, where an absent record says nobody
# looked at all.
#
# COULD-NOT-LOOK IS AN ABSENT RECORD, and every one of the retired program's exit-2
# arms is now the producer refusing at write time — no credential, no remote, a
# failed download, an unreadable status, a posture that is neither 200 nor 404. The
# producer refuses while its author is watching and writes nothing; this module
# then says nothing, which is the honest reading and not a pass. Carrying the
# shell's exit 2 in here would have made could-not-look a VIOLATION on the engine's
# contract, where 2 means a finding.
#MUTANT-SUITE crates/batten/tests/it/attestation.rs
#MUTANT unverified-passes|s@^\tentry.verdict == "unverified"$@\tfalse@|an_unverified_archive_is_reported_over_the_engines_projection
#MUTANT gap-judged-as-unverified|s@^\tposture == "200"$@\ttrue@|a_platform_gap_judges_nothing_even_with_archives_recorded
#MUTANT empty-tag-passes|s@^\tcount(archives) == 0$@\tfalse@|a_tag_carrying_no_archive_is_refused_rather_than_read_as_clean

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.attestation

import rego.v1

rules contains "release ship unsafe"

rules contains "release carry missing"

rules contains "release list empty"

# The producer's lines, or nothing. `recorded` being undefined is the
# could-not-look the header describes, and every rule below inherits it.
recorded := input.tree.records.attestation

# `posture <status>` — the one line that decides whether anything below is judged
# at all. One line, because the producer makes one probe.
posture := columns[1] if {
	some raw in recorded
	columns := split(raw, "\t")
	count(columns) == 2
	columns[0] == "posture"
}

# `archive <name> <verdict>` — one per archive the producer downloaded, carrying
# what the verifier said about the BINARY inside it.
#
# THE SUBJECT IS THE BINARY, NOT THE ARCHIVE, and that is the retired program's own
# correction to its issue's wording. `release-artifacts.yml` attests the binary
# deliberately, so that repackaging cannot launder the claim — verifying a
# `.tar.gz` would compute a digest nothing ever attested.
archives contains {"name": columns[1], "verdict": columns[2]} if {
	some raw in recorded
	columns := split(raw, "\t")
	count(columns) == 3
	columns[0] == "archive"
}

# An archive whose binary the verifier refused.
#
# GATED ON THE POSTURE, which is the distinction this module exists for: with the
# platform absent the verifier refuses everything, so firing here would report
# every release as unverifiable for a reason no branch causes.
violation contains {
	"rule": "release ship unsafe",
	"verdict": "release ship unsafe",
	"subjects": [{"artifact": entry.name}],
} if {
	posture == "200"
	some entry in archives
	entry.verdict == "unverified"
}

# An archive carrying no executable to verify at all.
#
# A DIFFERENT FINDING FROM THE ONE ABOVE rather than a variant of it: an archive
# whose binary failed verification is a provenance problem, and one carrying no
# binary is a packaging problem. Collapsing them would send a reader after a
# signing identity when the dist matrix dropped a file.
violation contains {
	"rule": "release carry missing",
	"verdict": "release carry missing",
	"subjects": [{"artifact": entry.name}],
} if {
	posture == "200"
	some entry in archives
	entry.verdict == "no-binary"
}

# A TAG THE PRODUCER LOOKED AT AND FOUND NO ARCHIVE ON. The retired program said
# why this is a refusal rather than a pass: "a green verdict would be about
# nothing". Present-and-empty and absent must not collapse, which is the same
# three-valued reading `posture` carries one rule up.
violation contains {
	"rule": "release list empty",
	"verdict": "release list empty",
} if {
	posture == "200"
	count(archives) == 0
}

# --- cases ---------------------------------------------------------------

tree(lines) := {"tree": {"records": {"attestation": lines}}}

available(lines) := tree(array.concat(["posture\t200"], lines))

test_an_unverified_archive_is_refused if {
	some v in violation with input as available(["archive\tbatten-x86_64.tar.gz\tunverified"])
	v.verdict == "release ship unsafe"
}

test_a_verified_archive_is_clean if {
	count(violation) == 0 with input as available(["archive\tbatten-x86_64.tar.gz\tverified"])
}

# POINTER, NEVER PAYLOAD: the asset name, never a bundle, a digest, or a byte of
# the verifier's report — the retired program's rule 4 boundary, kept.
test_the_finding_names_the_archive_and_nothing_else if {
	some v in violation with input as available(["archive\tbatten-x86_64.tar.gz\tunverified"])
	v.subjects == [{"artifact": "batten-x86_64.tar.gz"}]
}

test_an_archive_with_no_binary_is_its_own_finding if {
	some v in violation with input as available(["archive\tbatten-x86_64.tar.gz\tno-binary"])
	v.verdict == "release carry missing"
}

# THE GAP IS NOT A VERDICT (CLOUD-585). With the platform offering no attestation
# the verifier refuses every artifact, so judging here would red every release for
# a reason no branch causes.
test_a_platform_gap_judges_nothing if {
	count(violation) == 0 with input as tree([
		"posture\t404",
		"archive\tbatten-x86_64.tar.gz\tunverified",
	])
}

# AND THE GAP IS STILL A READING. This case is why `posture` is recorded at all
# rather than inferred from an empty archive list: a present 404 record says the
# producer looked, where the case below says nobody did.
test_a_gap_record_is_present_and_readable if {
	posture == "404" with input as tree(["posture\t404"])
}

test_no_record_at_all_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

test_a_tag_carrying_no_archive_is_refused if {
	some v in violation with input as tree(["posture\t200"])
	v.verdict == "release list empty"
}

# A LINE THIS READER CANNOT PARSE IS SKIPPED, the posture every other record reader
# here takes: the producer refuses a malformed line at write time, so an
# unparseable line at read time is a torn store. The surviving good line is part of
# the case — without it the record holds no archive and `release list empty` fires,
# which would let this pass for a reason that has nothing to do with skipping.
test_a_line_this_reader_cannot_parse_is_skipped if {
	count(violation) == 0 with input as available([
		"archive\tbatten-x86_64.tar.gz\tverified",
		"nonsense",
	])
}
