# A release's binaries carry build provenance (CLOUD-583, ported under CLOUD-1717,
# and moved into the `supply-chain` preset under CLOUD-843 with its producer
# retired onto `batten record attestation`).
#
# THE WHOLE DESIGN IS ONE DISTINCTION: the verifier refuses both an artifact with
# no provenance and every artifact on a platform that never offered any, and
# those are opposite facts. The first is a release to fix; the second is a plan
# feature the repository does not have. A gate that cannot tell them apart is
# worse than no gate, because it reds every release for a reason no branch causes.
#
# The control that separates them is the endpoint's own status code, and it stays
# the producer's reading: where attestation IS available an unknown digest answers
# 200 with an empty array, and 404 on the resource is the feature being absent.
# `batten record attestation` probes with an all-zeros digest and records which.
#
# WHY THE SPAWN STAYS OUTSIDE, and it is not a convention. The verifier is a
# process run over a binary unpacked from a downloaded archive, and house style §5
# makes `check` `read` and structurally incapable of spawning one. So what is here
# is not the verification but the ADJUDICATION of what the verifier said.
#
# A 404 POSTURE FIRES NOTHING, deliberately: nothing there is a claim about an
# artifact, and a release may be published unattested BY DESIGN while the
# platform offers none. The record being present with `posture 404` is what keeps
# that readable: the producer looked and the platform offers none, where an
# absent record says nobody looked at all.
#
# COULD-NOT-LOOK IS AN ABSENT RECORD: no credential, no remote, a failed download,
# an unreadable status, a posture neither 200 nor 404 — the producer answers exit
# 3 and removes any stale record, and this module then says nothing, which is the
# honest reading and not a pass.
#
# THE RECORD FAMILY IS THE PRODUCER'S NAME, not a consumer's: `attestation` is
# what `batten record attestation` writes, so reading it by name ships no
# consumer fact (rule 1). EVERY NAME IS PREFIXED `attestation_`, because a
# preset's modules share one engine.
#MUTANT-SUITE crates/batten/tests/it/attestation.rs
#MUTANT unverified-passes|s@^\tentry.verdict == "unverified"$@\tfalse@|an_unverified_archive_is_reported_over_the_engines_projection
#MUTANT gap-judged-as-unverified|s@^\tattestation_posture == "200"$@\ttrue@|a_platform_gap_judges_nothing_even_with_archives_recorded
#MUTANT empty-tag-passes|s@^\tcount(attestation_archives) == 0$@\tfalse@|a_tag_carrying_no_archive_is_refused_rather_than_read_as_clean

# METADATA
# description: |
#   Bound to the TREE surface: a row enabling this preset is `scope = "tree"`,
#   so it reads `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.supply_chain_attestation

import rego.v1

rules contains "release ship unsafe"

rules contains "release carry missing"

rules contains "release list empty"

# The producer's lines, or nothing. `attestation_recorded` being undefined is the
# could-not-look the header describes, and every rule below inherits it.
attestation_recorded := input.tree.records.attestation

# `posture <status>` — the one line that decides whether anything below is
# judged at all. One line, because the producer makes one probe.
attestation_posture := columns[1] if {
	some raw in attestation_recorded
	columns := split(raw, "\t")
	count(columns) == 2
	columns[0] == "posture"
}

# `archive <name> <verdict>` — one per archive the producer downloaded, carrying
# what the verifier said about the BINARY inside it.
#
# THE SUBJECT IS THE BINARY, NOT THE ARCHIVE, and that is the retired program's own
# correction to its issue's wording. A release attests the binary deliberately,
# so that repackaging cannot launder the claim — verifying a
# `.tar.gz` would compute a digest nothing ever attested.
#
# ONLY THE THREE VERDICTS THE PRODUCER WRITES (review of #962). A record store takes
# its input unvalidated, so `archive<TAB>x<TAB>unexpected` could join this
# set, match no violation below, and — being an archive — keep `release list
# empty` from firing: a clean reading over a record nothing understood. An
# unknown verdict is not an archive, so a record of nothing but unknowns reads
# as the empty list it is.
attestation_archives contains {"name": columns[1], "verdict": columns[2]} if {
	some raw in attestation_recorded
	columns := split(raw, "\t")
	count(columns) == 3
	columns[0] == "archive"
	columns[2] in {"verified", "unverified", "no-binary"}
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
	attestation_posture == "200"
	some entry in attestation_archives
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
	attestation_posture == "200"
	some entry in attestation_archives
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
	attestation_posture == "200"
	count(attestation_archives) == 0
}

# --- cases ---------------------------------------------------------------

attestation_tree(lines) := {"tree": {"records": {"attestation": lines}}}

attestation_available(lines) := attestation_tree(array.concat(["posture\t200"], lines))

test_an_unverified_archive_is_refused if {
	some v in violation with input as attestation_available(["archive\tbatten-x86_64.tar.gz\tunverified"])
	v.verdict == "release ship unsafe"
}

test_a_verified_archive_is_clean if {
	count(violation) == 0 with input as attestation_available(["archive\tbatten-x86_64.tar.gz\tverified"])
}

# POINTER, NEVER PAYLOAD: the asset name, never a bundle, a digest, or a byte of
# the verifier's report — the retired program's rule 4 boundary, kept.
test_the_finding_names_the_archive_and_nothing_else if {
	some v in violation with input as attestation_available(["archive\tbatten-x86_64.tar.gz\tunverified"])
	v.subjects == [{"artifact": "batten-x86_64.tar.gz"}]
}

test_an_archive_with_no_binary_is_its_own_finding if {
	some v in violation with input as attestation_available(["archive\tbatten-x86_64.tar.gz\tno-binary"])
	v.verdict == "release carry missing"
}

# THE GAP IS NOT A VERDICT (CLOUD-585). With the platform offering no attestation
# the verifier refuses every artifact, so judging here would red every release for
# a reason no branch causes.
test_a_platform_gap_judges_nothing if {
	count(violation) == 0 with input as attestation_tree([
		"posture\t404",
		"archive\tbatten-x86_64.tar.gz\tunverified",
	])
}

# AND THE GAP IS STILL A READING. This case is why the posture is recorded at all
# rather than inferred from an empty archive list: a present 404 record says the
# producer looked, where the case below says nobody did.
test_a_gap_record_is_present_and_readable if {
	attestation_posture == "404" with input as attestation_tree(["posture\t404"])
}

test_no_record_at_all_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

test_a_tag_carrying_no_archive_is_refused if {
	some v in violation with input as attestation_tree(["posture\t200"])
	v.verdict == "release list empty"
}

# A LINE THIS READER CANNOT PARSE IS SKIPPED, the posture every other record reader
# here takes: the producer refuses a malformed line at write time, so an
# unparseable line at read time is a torn store. The surviving good line is part of
# the case — without it the record holds no archive and `release list empty` fires,
# which would let this pass for a reason that has nothing to do with skipping.
test_a_line_this_reader_cannot_parse_is_skipped if {
	count(violation) == 0 with input as attestation_available([
		"archive\tbatten-x86_64.tar.gz\tverified",
		"nonsense",
	])
}
