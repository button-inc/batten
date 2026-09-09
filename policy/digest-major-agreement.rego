# METADATA
# description: |
#   The crypto crates this workspace declares for itself all resolve the same
#   `digest` major — CLOUD-767, ported from `mise-tasks/digest-major-agreement.sh`
#   under CLOUD-843.
#
#   THE RULE THIS REPLACES WAS A COMMENT, AND THE COMMENT WAS WRONG. The manifest
#   pinned one of these crates under a justification that read, in full, that the
#   next major "would put two majors of the same hashing substrate in the tree".
#   Measured on the trunk: the committed lockfile already carried both majors, the
#   second arriving transitively, and the claim had been false for as long as that
#   dependency had existed. Nothing noticed, and the pin it justified went on being
#   enforced by nobody but the reader. That is non-negotiable rule 2 stated from
#   the failure end — prose is feedforward only, and a decision with no exit code
#   is discovered by a bot proposing the bump it forbade.
#
#   WHAT IS ACTUALLY DECIDABLE, and the narrowing is the whole design. "One
#   `digest` major in the tree" is NOT it: a transitive dependency vendors what it
#   vendors, the workspace has no say, and a gate asserting it would be red on the
#   commit that introduced it and every commit after. A gate nobody can keep green
#   is switched off within a day, and switching it off takes the real rule with it.
#
#   The real rule is narrower and is true today: the crypto crates this workspace
#   declares FOR ITSELF must agree with each other. Both are
#   `[workspace.dependencies]` entries, both resolve a `digest`, and one expression
#   in the crate composes them — split them across majors and that type does not
#   exist. This direction does have a symptom; what it does not have is a symptom
#   BEFORE a runner is spent, which is what the gate buys.
#
#   READ FROM THE LOCKFILE, NEVER THE MANIFEST. A caret requirement is not a
#   resolution: which `digest` it lands on is the lockfile's answer and cannot be
#   derived from the manifest without re-implementing the resolver. The manifest is
#   consulted for ONE thing — which crates the workspace declares for itself —
#   because that is the question the lockfile cannot answer: it cannot tell a
#   direct dependency from a transitive one, and conflating the two is exactly the
#   mistake the old comment made.
#
#   A DEPENDENCY-OF-A-DEPENDENCY IS NOT OUR AGREEMENT TO KEEP. Other hashing crates
#   sit under a transitive parent and resolve whatever they resolve. They are
#   excluded by construction, being absent from `[workspace.dependencies]`.
#
#   THE NAMED SET IS DELIBERATE, not a sniff. "Does this crate depend on `digest`"
#   is a question about the whole registry, and answering it by scanning the lock
#   would silently widen to every transitive hasher the day one appeared.
#
#   BOTH LOCK SPELLINGS ARE HANDLED. A dependency entry is written bare when one
#   major is in the tree and versioned when several are; a bare entry is resolved
#   against the lock's own `digest` packages, and a bare entry beside SEVERAL
#   majors is a lockfile that does not describe itself rather than a verdict.
#
#   POINTER, NEVER PAYLOAD (rule 4): crate names and the majors they landed on.
#   Never a version requirement, never a manifest line, never a lock stanza.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.digest_major_agreement

import rego.v1

rules contains "digest-major-agreement"

manifest_path := "Cargo.toml"

lock_path := "Cargo.lock"

# The crates whose `digest` major must agree — the workspace's own composition
# decision, and one line long.
crypto_crates := {"hmac", "sha2"}

manifest_lines := lines if {
	lines := input.tree.lines[manifest_path]
}

lock_lines := lines if {
	lines := input.tree.lines[lock_path]
}

unquoted(text) := replace(text, "\"", "")

# --- which crates the workspace declares for itself --------------------------
#
# Scoped to the `[workspace.dependencies]` table alone, so a name in a comment, in
# another table, or as another table's key cannot enrol a crate the workspace does
# not own.
deps_start := i if {
	some i, line in manifest_lines
	startswith(line, "[workspace.dependencies]")
}

deps_end := e if {
	after := {j |
		some j, line in manifest_lines
		j > deps_start
		startswith(line, "[")
	}
	e := min(after)
}

deps_end := count(manifest_lines) if {
	deps_start
	not another_table_follows_deps
}

another_table_follows_deps if {
	some j, line in manifest_lines
	j > deps_start
	startswith(line, "[")
}

declared contains name if {
	some j, line in manifest_lines
	j > deps_start
	j < deps_end
	contains(line, "=")
	name := unquoted(trim_space(substring(line, 0, indexof(line, "="))))
	name != ""
}

# --- the lockfile's stanzas --------------------------------------------------

package_start contains i if {
	some i, line in lock_lines
	line == "[[package]]"
}

package_end(i) := e if {
	after := {j |
		some j in package_start
		j > i
	}
	e := min(after)
}

package_end(i) := count(lock_lines) if {
	i in package_start
	not another_package_after(i)
}

another_package_after(i) if {
	some j in package_start
	j > i
}

field(i, key) := value if {
	some j in numbers.range(i, package_end(i) - 1)
	startswith(lock_lines[j], concat("", [key, " = "]))
	value := unquoted(substring(lock_lines[j], count(key) + 3, -1))
}

# The major.minor of a semver string, which is what "major" means for a
# pre-1.0 crate: the leading zero is not the compatibility boundary.
line_of(version) := concat(".", [parts[0], parts[1]]) if {
	parts := split(version, ".")
	count(parts) >= 2
}

# Every `digest` package the lock carries, by its own major.
digest_majors contains line_of(field(i, "version")) if {
	some i in package_start
	field(i, "name") == "digest"
}

# The `digest` a crate's stanza names, as written. A dependency entry is an
# indented quoted scalar inside the stanza.
digest_entry(crate) := entry if {
	some i in package_start
	field(i, "name") == crate
	some j in numbers.range(i, package_end(i) - 1)
	startswith(lock_lines[j], " \"digest")
	entry := trim(trim_space(lock_lines[j]), "\",")
}

# The major it resolved to: written on the entry when several are in the tree,
# and taken from the lock's one `digest` package when the entry is bare.
resolved(crate) := line_of(split(digest_entry(crate), " ")[1]) if {
	count(split(digest_entry(crate), " ")) >= 2
}

resolved(crate) := major if {
	count(split(digest_entry(crate), " ")) == 1
	count(digest_majors) == 1
	some major in digest_majors
}

# The crates actually under judgement: declared for ourselves AND present in the
# lock.
judged contains crate if {
	some crate in crypto_crates
	crate in declared
	resolved(crate)
}

# --- the could-not-look arms -------------------------------------------------

# A crate the manifest declares and the lock resolves no `digest` for is a
# lockfile that does not describe the manifest, so nothing here can be decided.
violation contains {
	"rule": "digest-major-agreement",
	"verdict": "lock read unclear",
	"subjects": [{"artifact": crate}],
} if {
	lock_lines
	some crate in crypto_crates
	crate in declared
	not digest_entry(crate)
}

# A BARE entry beside several majors: the lock cannot say which one it meant.
violation contains {
	"rule": "digest-major-agreement",
	"verdict": "lock read unclear",
	"subjects": [{"artifact": crate}],
} if {
	some crate in crypto_crates
	crate in declared
	count(split(digest_entry(crate), " ")) == 1
	count(digest_majors) != 1
}

# --- the disagreement --------------------------------------------------------
#
# Fewer than two declared crates cannot disagree, and that is a legitimate state
# rather than a vacuous pass: the rule is about the workspace's OWN composition,
# and a workspace composing one crate has nothing to compose wrongly.
violation contains {
	"rule": "digest-major-agreement",
	"verdict": "version resolve other",
	"subjects": [{"artifact": sprintf("%s -> digest %s", [crate, resolved(crate)])}],
} if {
	count(judged) >= 2
	count({resolved(c) | some c in judged}) > 1
	some crate in judged
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE resolves the manifest
# and the lockfile into one map in a single evaluation — a `with input as` block
# fabricates exactly that map (CLOUD-845), and the whole judgement is the join:
# the manifest says which crates are OURS, the lock says what they resolved, and
# neither file can answer the other's question.
# `crates/batten/tests/it/digest_major_agreement.rs` is that tier.

tree(manifest, lock) := {"tree": {"lines": {"Cargo.toml": manifest, "Cargo.lock": lock}}}

workspace(names) := array.concat(
	array.concat(["[workspace.dependencies]"], [sprintf("%s = \"1\"", [n]) | some n in names]),
	["[workspace.lints]", "rust = {}"],
)

pkg(name, version, deps) := array.concat(
	array.concat(
		["[[package]]", sprintf("name = \"%s\"", [name]), sprintf("version = \"%s\"", [version]), "dependencies = ["],
		[sprintf(" \"%s\",", [d]) | some d in deps],
	),
	["]", ""],
)

test_both_crates_on_one_major_agree if {
	count(violation) == 0 with input as tree(
		workspace({"hmac", "sha2"}),
		array.concat(
			array.concat(pkg("digest", "0.10.7", []), pkg("hmac", "0.12.1", ["digest"])),
			pkg("sha2", "0.10.8", ["digest"]),
		),
	)
}

# THE HALF-BUMP: one crate moved and the other left behind, which is the state
# that makes the composed type stop existing.
test_a_split_across_majors_is_refused if {
	some v in violation with input as tree(
		workspace({"hmac", "sha2"}),
		array.concat(
			array.concat(
				array.concat(pkg("digest", "0.10.7", []), pkg("digest", "0.11.3", [])),
				pkg("hmac", "0.12.1", ["digest 0.10.7"]),
			),
			pkg("sha2", "0.11.0", ["digest 0.11.3"]),
		),
	)
	v.verdict == "version resolve other"
}

# A TRANSITIVE crate on another major is not our agreement to keep: the workspace
# has no say in what a dependency vendors, and a gate asserting otherwise is red
# forever and switched off within a day.
test_a_transitive_crate_on_another_major_is_not_ours if {
	count(violation) == 0 with input as tree(
		workspace({"hmac", "sha2"}),
		array.concat(
			array.concat(
				array.concat(pkg("digest", "0.10.7", []), pkg("digest", "0.11.3", [])),
				array.concat(pkg("hmac", "0.12.1", ["digest 0.10.7"]), pkg("sha2", "0.10.8", ["digest 0.10.7"])),
			),
			pkg("sha1-checked", "0.11.0", ["digest 0.11.3"]),
		),
	)
}

# Fewer than two declared crates cannot disagree.
test_one_declared_crate_cannot_disagree if {
	count(violation) == 0 with input as tree(
		workspace({"hmac"}),
		array.concat(pkg("digest", "0.10.7", []), pkg("hmac", "0.12.1", ["digest"])),
	)
}

# A declared crate the lock resolves no digest for is a lockfile that does not
# describe the manifest.
test_a_declared_crate_with_no_digest_entry_is_could_not_look if {
	some v in violation with input as tree(
		workspace({"hmac", "sha2"}),
		array.concat(
			array.concat(pkg("digest", "0.10.7", []), pkg("hmac", "0.12.1", ["digest"])),
			pkg("sha2", "0.10.8", ["cpufeatures"]),
		),
	)
	v.verdict == "lock read unclear"
}

# A BARE entry beside several majors cannot say which it meant.
test_a_bare_entry_beside_several_majors_is_could_not_look if {
	some v in violation with input as tree(
		workspace({"hmac", "sha2"}),
		array.concat(
			array.concat(
				array.concat(pkg("digest", "0.10.7", []), pkg("digest", "0.11.3", [])),
				pkg("hmac", "0.12.1", ["digest"]),
			),
			pkg("sha2", "0.10.8", ["digest 0.10.7"]),
		),
	)
	v.verdict == "lock read unclear"
}

#MUTANT-SUITE crates/batten/tests/it/digest_major_agreement.rs
#MUTANT reads-no-resolution|s@^\tcount({resolved(c) | some c in judged}) > 1$@\tfalse@|the_half_bump_is_refused
#MUTANT transitive-crate-enrolled|s@^\tcrate in declared$@\ttrue@|a_transitive_crate_on_another_major_is_not_ours
