#!/usr/bin/env bats
# subject: mise-tasks/signing-posture
# CLOUD-669. The not-signing posture, in force rather than recorded.
#
# Every case runs inside a throwaway `git init`, because the subject IS git
# config and commit objects: a suite running in this repo's checkout would
# rewrite the developer's own `commit.gpgsign` and judge real history.
#
# The signing side is faked rather than driven through a real signer. A genuine
# `gpg.ssh.program` needs a key this suite must not create, and the predicate is
# "does the commit object carry a `gpgsig` header" — which `git commit-tree -S`
# cannot produce without one either. So a signed commit is synthesized by writing
# the header into the object directly, which is exactly what the gate reads.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/signing-posture"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	# `main` from the start, so no row has to force a branch into place later:
	# `no-branch-f-main` forbids that shape in a suite, and rightly — a `branch -f`
	# that escaped the fixture would move the real trunk.
	git -C "$REPO" init --quiet --initial-branch=main
	# Per fixture, never inherited: a CI runner carries no global identity.
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	git -C "$REPO" config commit.gpgsign false
	# A VERIFIABLE signer by default, set locally so the suite never inherits the
	# host's. Without this the rows passed because this container's own global
	# config happens to be broken — an environmental reason, not the gate's logic.
	printf 'ssh-ed25519 AAAAfake fixture\n' >"$BATS_TEST_TMPDIR/good.pub"
	git -C "$REPO" config user.signingkey "$BATS_TEST_TMPDIR/good.pub"
	git -C "$REPO" config gpg.ssh.program /usr/bin/ssh-keygen
	git -C "$REPO" commit -q --allow-empty -m base
	cd "$REPO" || return 1
	BASE=$(git rev-parse HEAD)
}

# The two measured shapes of "unverifiable", one helper each.
break_signer_empty_key() {
	: >"$BATS_TEST_TMPDIR/empty.pub"
	git config --local user.signingkey "$BATS_TEST_TMPDIR/empty.pub"
}
break_signer_ephemeral_program() {
	git config --local gpg.ssh.program /tmp/code-sign
}

# Write a commit object carrying a `gpgsig` header, the way a real signer would.
sign_head() {
	local parent tree sig obj
	parent=$(git rev-parse HEAD^)
	tree=$(git rev-parse HEAD^{tree})
	sig=$(printf -- '-----BEGIN SSH SIGNATURE-----\n ZmFrZQ==\n -----END SSH SIGNATURE-----')
	obj=$(
		{
			printf 'tree %s\nparent %s\n' "$tree" "$parent"
			printf 'author t <t@example.com> 1700000000 +0000\n'
			printf 'committer t <t@example.com> 1700000000 +0000\n'
			printf 'gpgsig %s\n\nsigned\n' "$sig"
		} | git hash-object -t commit -w --stdin
	)
	git reset --hard "$obj" --quiet
}

@test "an unsigned range with the override in place passes" {
	git commit -q --allow-empty -m work
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 0 ]
	[[ "$output" == *"unverifiable"* ]]
}

# THE ROW THAT PROVES THIS IS NOT AN ANTI-SIGNING GATE. Signing in CI with a
# published key is CLOUD-591's end state; a gate that refused it would be the
# wrong gate. A verifiable signer with signing ON must pass untouched.
@test "signing with a verifiable signer is left alone" {
	git config --local commit.gpgsign true
	git commit -q --allow-empty -m work --no-gpg-sign
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 0 ]
}

# THE ROW THAT WAS MISSING, and its absence hid a contradicted predicate. The row
# above commits with `--no-gpg-sign`, so it produces no `gpgsig` header and never
# reaches the commit scan at all — it could not have caught a scan that refused
# every signature regardless of signer, which is what the scan did. This one puts
# a real header in front of it with the signer left verifiable.
@test "a commit signed by a VERIFIABLE signer is left alone, header and all" {
	git config --local commit.gpgsign true
	# `--no-gpg-sign` then `sign_head`, never a real signer: the fixture's
	# `gpg.ssh.program` is a path that need not exist, and driving a genuine one
	# would need a private key this suite must not create. `sign_head` writes the
	# header the gate actually reads, which is the whole point of the helper.
	git commit -q --allow-empty -m work --no-gpg-sign
	sign_head
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 0 ]
}

@test "--repair leaves a verifiable signer alone rather than switching signing off" {
	git config --local commit.gpgsign true
	run "$GATE" --repair
	[ "$status" -eq 0 ]
	[ "$(git config --local --get commit.gpgsign)" = "true" ]
	[[ "$output" == *"verifiable"* ]]
}

@test "an empty signing key is what makes it unverifiable" {
	break_signer_empty_key
	git config --local commit.gpgsign true
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 1 ]
	[[ "$output" == *"empty file"* ]]
}

# The three shapes a bare `-s` accepted. A directory and an unreadable file both
# have a non-zero size, so `-s` alone called them healthy while the public half
# stayed unreadable — the condition the predicate exists to name.
@test "a signing key that is a directory is unverifiable" {
	mkdir -p "$BATS_TEST_TMPDIR/keydir"
	git config --local user.signingkey "$BATS_TEST_TMPDIR/keydir"
	git config --local commit.gpgsign true
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 1 ]
	[[ "$output" == *"not a regular file"* ]]
}

@test "a signing key this checkout cannot read is unverifiable" {
	if [ "$(id -u)" = 0 ]; then skip "root reads regardless of mode"; fi
	printf 'ssh-ed25519 AAAAfake fixture\n' >"$BATS_TEST_TMPDIR/locked.pub"
	chmod 000 "$BATS_TEST_TMPDIR/locked.pub"
	git config --local user.signingkey "$BATS_TEST_TMPDIR/locked.pub"
	git config --local commit.gpgsign true
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 1 ]
	[[ "$output" == *"cannot read"* ]]
}

@test "a signing key naming a path that does not exist is unverifiable" {
	git config --local user.signingkey "$BATS_TEST_TMPDIR/absent.pub"
	git config --local commit.gpgsign true
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 1 ]
	[[ "$output" == *"does not exist"* ]]
}

# THE FALSE POSITIVE THE FILE TESTS WOULD OTHERWISE CREATE. `gpg.format ssh`
# accepts the public key inline, and a literal IS the public half — the most
# publishable form there is. Testing it as a filename would report the healthiest
# configuration possible as broken.
@test "an inline public key is a literal, not a path, and is verifiable" {
	git config --local user.signingkey "ssh-ed25519 AAAAfake fixture"
	git config --local commit.gpgsign true
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 0 ]
}

@test "a signer under /tmp is unverifiable because the container reclaims it" {
	break_signer_ephemeral_program
	git config --local commit.gpgsign true
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 1 ]
	[[ "$output" == *"/tmp"* ]]
}

@test "a signed commit in range is refused, and named by short sha" {
	break_signer_ephemeral_program
	git commit -q --allow-empty -m work
	sign_head
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 1 ]
	[[ "$output" == *"carries a gpgsig"* ]]
	[[ "$output" == *"$(git rev-parse --short=8 HEAD)"* ]]
}

# THE ROW THAT KILLS THE CONFIG-ONLY PREDICATE. A checkout repaired AFTER a
# commit was written still carries that signed commit, and it is the commit that
# reaches `main`.
@test "repairing the config does not excuse a commit already signed" {
	break_signer_ephemeral_program
	git commit -q --allow-empty -m work
	sign_head
	git config --local commit.gpgsign false
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 1 ]
	[[ "$output" == *"carries a gpgsig"* ]]
}

# The override is owed only where something outside the checkout turns signing
# ON. `git -c` supplies the inherited value, since a suite must never write the
# developer's real global config.
@test "a missing override is refused when the environment sets signing globally" {
	git commit -q --allow-empty -m work
	break_signer_ephemeral_program
	git config --local --unset commit.gpgsign
	run env HOME="$BATS_TEST_TMPDIR/fakehome" bash -c '
		mkdir -p "$HOME"
		git config --global commit.gpgsign true
		exec "$1" --base "$2" --head HEAD' _ "$GATE" "$BASE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"unverifiable signer"* ]]
}

# THE CI ROW. A runner has no launcher and no global setting, so an absent local
# value is correct there. Demanding it unconditionally would red every CI run for
# a condition that cannot occur — the false-positive rate that gets a gate
# switched off.
@test "a missing override is NOT a finding when nothing sets signing globally" {
	git commit -q --allow-empty -m work
	git config --local --unset commit.gpgsign
	run env HOME="$BATS_TEST_TMPDIR/emptyhome" bash -c '
		mkdir -p "$HOME"
		exec "$1" --base "$2" --head HEAD' _ "$GATE" "$BASE"
	[ "$status" -eq 0 ]
}

@test "a local override set to true is refused when the signer is broken" {
	break_signer_empty_key
	git config --local commit.gpgsign true
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 1 ]
	[[ "$output" == *"unverifiable signer"* ]]
}

@test "--repair writes the override, local only" {
	break_signer_empty_key
	git config --local --unset commit.gpgsign
	run "$GATE" --repair
	[ "$status" -eq 0 ]
	[ "$(git config --local --get commit.gpgsign)" = "false" ]
}

@test "--repair is idempotent" {
	break_signer_empty_key
	run "$GATE" --repair
	[ "$status" -eq 0 ]
	run "$GATE" --repair
	[ "$status" -eq 0 ]
	[ "$(git config --local --get commit.gpgsign)" = "false" ]
}

@test "--repair never writes global config" {
	break_signer_empty_key
	local before
	before=$(git config --global --get commit.gpgsign 2>/dev/null || echo unset)
	run "$GATE" --repair
	[ "$status" -eq 0 ]
	[ "$(git config --global --get commit.gpgsign 2>/dev/null || echo unset)" = "$before" ]
}

# The excluded base is SIGNED and the signer is broken, so every ingredient of a
# refusal is present except being in range. Previously both commits here were
# unsigned, which passed whether or not the scan honoured `--base` at all.
@test "history before the range is never judged" {
	break_signer_ephemeral_program
	git commit -q --allow-empty -m work
	sign_head
	local newbase
	newbase=$(git rev-parse HEAD)
	git commit -q --allow-empty -m later
	run "$GATE" --base "$newbase" --head HEAD
	[ "$status" -eq 0 ]
	[[ "$output" != *"carries a gpgsig"* ]]
}

@test "outside a git repository it is exit 2, never a silent pass" {
	cd "$BATS_TEST_TMPDIR" || return 1
	mkdir -p notarepo
	cd notarepo || return 1
	run "$GATE"
	[ "$status" -eq 2 ]
}

# Pointer-only (non-negotiable 4): a signature is a credential artefact this repo
# does not control, so no part of one may reach the output.
@test "the refusal echoes no part of the signature block" {
	break_signer_ephemeral_program
	git commit -q --allow-empty -m work
	sign_head
	run "$GATE" --base "$BASE" --head HEAD
	[ "$status" -eq 1 ]
	[[ "$output" != *"BEGIN SSH SIGNATURE"* ]]
	[[ "$output" != *"ZmFrZQ"* ]]
}
