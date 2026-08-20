#!/usr/bin/env bats
# CLOUD-767. The rule this gate carries used to be a comment in `Cargo.toml`, and
# the comment asserted something false: that pinning `hmac = "0.12"` kept one
# major of the hashing substrate in the tree. `gix-hash` had already put `sha2
# 0.11`/`digest 0.11` there. Nothing detected that, because nothing could — prose
# has no exit code.
#
# THE ROW THAT MATTERS IS `a-crate-gix-owns-is-not-ours`. The obvious gate — "one
# `digest` major in the lock" — is red on `main` today and on every commit since
# `gix` arrived, so it would be switched off within a day and the real rule would
# go with it. The narrow claim is the one that is both true now and false in the
# half-bump case, and that row is what pins the difference.
#
# Every case is offline: two fixture files and no network, no cargo, no registry.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/digest-major-agreement"
	MANIFEST="$BATS_TEST_TMPDIR/Cargo.toml"
	LOCK="$BATS_TEST_TMPDIR/Cargo.lock"
}

run_gate() { run "$GATE" --manifest "$MANIFEST" --lock "$LOCK"; }

# `declares <crate>...` writes a [workspace.dependencies] table. The caret
# requirements are deliberately the ones that do NOT determine the resolution —
# that is the whole reason the gate reads the lock instead.
declares() {
	printf '[workspace.dependencies]\n' >"$MANIFEST"
	local crate
	for crate in "$@"; do printf '%s = "0.1"\n' "$crate" >>"$MANIFEST"; done
}

# `resolves <crate> <digest-ref>` appends a [[package]] stanza naming the digest
# it depends on, in cargo's own spelling — `digest 0.10.7` when several majors
# are vendored, a bare `digest` when only one is.
resolves() {
	cat >>"$LOCK" <<-EOF

		[[package]]
		name = "$1"
		version = "9.9.9"
		source = "registry+https://github.com/rust-lang/crates.io-index"
		dependencies = [
		 "cfg-if",
		 "$2",
		]
	EOF
}

# `digest_package <version>...` appends a [[package]] stanza per digest major
# actually vendored, which is what resolves a bare reference.
digest_package() {
	local v
	for v in "$@"; do
		cat >>"$LOCK" <<-EOF

			[[package]]
			name = "digest"
			version = "$v"
			source = "registry+https://github.com/rust-lang/crates.io-index"
		EOF
	done
}

@test "the pair agreeing is the ordinary pass, and the verdict names the major" {
	declares hmac sha2
	digest_package 0.10.7 0.11.3
	resolves hmac "digest 0.10.7"
	resolves sha2 "digest 0.10.9"
	run_gate
	[ "$status" -eq 0 ]
	[[ "$output" == *"2 declared crypto crate(s), all on digest 0.10"* ]]
}

@test "THE HALF-BUMP IS REFUSED — one crate moved and the other left behind" {
	# `hmac = \"0.13\"` without `sha2 = \"0.11\"`, which is the shape the old
	# comment was groping at and the only thing it was ever right about.
	declares hmac sha2
	digest_package 0.10.7 0.11.3
	resolves hmac "digest 0.11.3"
	resolves sha2 "digest 0.10.9"
	run_gate
	[ "$status" -eq 1 ]
	[[ "$output" == *"resolved different digest majors"* ]]
	[[ "$output" == *"hmac -> digest 0.11"* ]]
	[[ "$output" == *"sha2 -> digest 0.10"* ]]
}

@test "the coordinated bump passes — moving BOTH is what the manifest asks for" {
	declares hmac sha2
	digest_package 0.10.7 0.11.3
	resolves hmac "digest 0.11.3"
	resolves sha2 "digest 0.11.3"
	run_gate
	[ "$status" -eq 0 ]
	[[ "$output" == *"all on digest 0.11"* ]]
}

@test "A CRATE GIX OWNS IS NOT OURS: a transitive hasher on the other major is ignored" {
	# The row this gate exists for. `sha1-checked` sits under `gix` on `digest
	# 0.11` while ours are on 0.10 — the exact state of `main`, which a
	# one-major-in-the-tree gate would call a violation and which is not one.
	declares hmac sha2
	digest_package 0.10.7 0.11.3
	resolves hmac "digest 0.10.7"
	resolves sha2 "digest 0.10.9"
	resolves sha1-checked "digest 0.11.3"
	run_gate
	[ "$status" -eq 0 ]
	[[ "$output" != *"sha1-checked"* ]]
}

@test "one declared crate cannot disagree with itself, and the gate says so" {
	declares hmac
	digest_package 0.10.7
	resolves hmac "digest"
	run_gate
	[ "$status" -eq 0 ]
	[[ "$output" == *"fewer than two can disagree"* ]]
}

@test "a bare digest reference resolves against the one major vendored" {
	# Cargo drops the version from the reference when there is nothing to
	# disambiguate, so the common single-major lockfile uses this spelling.
	declares hmac sha2
	digest_package 0.11.3
	resolves hmac "digest"
	resolves sha2 "digest"
	run_gate
	[ "$status" -eq 0 ]
	[[ "$output" == *"all on digest 0.11"* ]]
}

@test "COULD NOT LOOK, NEVER AGREEMENT: a declared crate absent from the lock is exit 2" {
	declares hmac sha2
	digest_package 0.10.7
	resolves hmac "digest"
	run_gate
	[ "$status" -eq 2 ]
	[[ "$output" == *"resolves no digest"* ]]
	[[ "$output" == *"sha2"* ]]
}

@test "an unreadable lockfile is exit 2, not a pass" {
	declares hmac sha2
	rm -f "$LOCK"
	run_gate
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot look"* ]]
}

@test "an unreadable manifest is exit 2, not a pass" {
	digest_package 0.10.7
	resolves hmac "digest"
	rm -f "$MANIFEST"
	run_gate
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot look"* ]]
}

@test "a name outside [workspace.dependencies] does not enrol the crate" {
	# `sha2` here is a lint key and a comment, not a dependency. Reading either as
	# a declaration would make the gate judge a crate the workspace never chose.
	{
		printf '[workspace.dependencies]\n'
		printf 'hmac = "0.1"\n'
		printf '\n[workspace.lints.rust]\n'
		printf 'sha2 = "warn"\n'
		printf '# sha2 = "0.10" is discussed here and declared nowhere\n'
	} >"$MANIFEST"
	digest_package 0.10.7 0.11.3
	resolves hmac "digest 0.10.7"
	resolves sha2 "digest 0.11.3"
	run_gate
	[ "$status" -eq 0 ]
	[[ "$output" == *"fewer than two can disagree"* ]]
}

@test "POINTER, NEVER PAYLOAD: the refusal carries no version requirement and no manifest line" {
	{
		printf '[workspace.dependencies]\n'
		printf 'hmac = "0.12" # SENTINELREQ\n'
		printf 'sha2 = "0.10"\n'
	} >"$MANIFEST"
	digest_package 0.10.7 0.11.3
	resolves hmac "digest 0.11.3"
	resolves sha2 "digest 0.10.9"
	run_gate
	[ "$status" -eq 1 ]
	[[ "$output" != *"SENTINELREQ"* ]]
	[[ "$output" != *'"0.12"'* ]]
}

@test "the gate writes nothing — it decides over two committed files" {
	declares hmac sha2
	digest_package 0.10.7
	resolves hmac "digest"
	resolves sha2 "digest"
	local before after
	before=$(cat "$MANIFEST" "$LOCK")
	run_gate
	[ "$status" -eq 0 ]
	after=$(cat "$MANIFEST" "$LOCK")
	[ "$before" = "$after" ]
}
