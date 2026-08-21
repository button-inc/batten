#!/usr/bin/env bash
#MISE description="Gate: the macOS targets actually LINK from Linux, which is what proves no dependency needs an Apple SDK"
#MISE depends=["doctor"]
#
# `cargo check` stops at codegen-to-metadata and never links, so it structurally
# cannot see a dependency that pulls in a macOS system framework. The release
# build would be the first thing to notice — after a tag was already cut.
#
# `macos-link-check` catches the known framework crates early and cheaply, but it
# reads a list and so is incomplete by construction. This closes that gap the
# only way that has no false negatives: link the thing. It either links or it
# does not.
#
# Runs as its own CI job, concurrently with `ci` and `cross`, and the Darwin
# triples were dropped from `cross-check` so nothing is checked twice. CI links
# ONE target (aarch64): the property being asserted belongs to the dependency
# graph, not the word size, so a second leg was duplicate work on the critical
# path. release-artifacts.yml still builds both Darwin targets, so an
# x86_64-only linker problem cannot reach a shipped artifact.
set -euo pipefail

target="${1:-${DARWIN_TARGET:-aarch64-apple-darwin}}"

case "$target" in
*-apple-darwin) ;;
*)
	echo "darwin-link: expected an *-apple-darwin target, got '${target}'" >&2
	exit 1
	;;
esac

# Receipt-gated (CLOUD-424). The target is key material — this task takes an
# argument, so a receipt for one triple must not answer for another.
if "$(dirname -- "${BASH_SOURCE[0]}")/step-receipt" check darwin-link --arg "$target"; then
	exit 0
fi

# Through the lock, not a bare `rustup target add`: a concurrent doctor (the
# outer verify DAG's, or the one hk's test:bats step spawns in a child mise
# process) would otherwise collide inside rustup and both would roll back
# (CLOUD-220).
"$(dirname "$0")/target-ensure.sh" "$target"
# zig supplies the Darwin linker; no Apple SDK is present, which is precisely the
# condition this gate asserts the tree still builds under.
cargo zigbuild --workspace --target "$target"
"$(dirname -- "${BASH_SOURCE[0]}")/step-receipt" record darwin-link --arg "$target" || true
echo "darwin-link: ${target} links with no macOS SDK"
