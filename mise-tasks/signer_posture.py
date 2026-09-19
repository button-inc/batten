# Whether a git signing configuration names a key anyone can verify (CLOUD-669,
# ported off `mise-tasks/signing-posture.sh` under CLOUD-1717).
#
# SIGNING IS GOOD, and this is not against it. A version of this that reads that
# way is wrong: signing in CI, with a key whose public half is published, is the
# desired end state and CLOUD-591 owns getting there. What it names is the
# narrower thing — a signature produced by a key that cannot be verified or
# reproduced, which is WORSE than no signature because it looks like provenance
# and carries none.
#
# TWO INDEPENDENT CONDITIONS, either of which makes a signature unverifiable by
# anyone, us included. Both were measured rather than assumed (2026-08-18):
#
#   * `gpg.ssh.program` resolves inside `/tmp`. The container reclaims it, so the
#     signer and whatever key it holds are not reproducible across sessions. A
#     signature nobody can re-verify later is provenance theatre.
#   * `user.signingkey` names a file that is empty or unreadable. The public half
#     cannot be read, so no `allowed_signers` entry can be derived from it and
#     nothing downstream can check the signature.
#
# A signer failing NEITHER test is left alone and signing stays on.
#
# A LITERAL KEY IS NOT A PATH. With `gpg.format ssh`, git accepts the public key
# inline (`ssh-ed25519 AAAA…`) or via a `key::` prefix as well as a filename. A
# literal is the MOST publishable form there is — it is already the public half —
# so testing it as a file would report the healthiest possible configuration as
# broken.
#
# FOUR FILE TESTS, NOT ONE, and that was a real defect rather than thoroughness.
# `-s` alone is true for anything non-empty that `stat` can size, including an
# unreadable file and a DIRECTORY — both of which leave the public half
# unreadable, which is the condition being named. Each test carries its own
# reason so the refusal says which one.
#
# ONE READING, TWO CALLERS: `[tasks.signing-posture-record]` writes the record
# from it, and `crates/batten/tests/it/signing_posture.rs` drives all seven arms.
# A copy of these branches in the tier would be the second authority
# `cargo_graph.py` was extracted to remove one gate over.
#
# Emits one line: `verifiable`, or `broken <reason>`.

import os
import sys

# The spellings git accepts for a key given INLINE rather than as a path.
LITERAL_PREFIXES = ("ssh-", "key::", "sk-ssh-", "sk-ecdsa-")


def posture(signingkey, program):
    if program.startswith("/tmp/"):
        return (
            "broken the signer resolves inside /tmp, which the container "
            "reclaims, so the key is not reproducible"
        )
    if signingkey == "" or signingkey.startswith(LITERAL_PREFIXES):
        return "verifiable"
    if not os.path.exists(signingkey):
        return (
            "broken user.signingkey names a path that does not exist, so the "
            "public half cannot be read or published"
        )
    if not os.path.isfile(signingkey):
        return (
            "broken user.signingkey names something that is not a regular file, "
            "so the public half cannot be read or published"
        )
    if not os.access(signingkey, os.R_OK):
        return (
            "broken user.signingkey names a file this checkout cannot read, so "
            "the public half cannot be read or published"
        )
    if os.path.getsize(signingkey) == 0:
        return (
            "broken user.signingkey names an empty file, so the public half "
            "cannot be read or published"
        )
    return "verifiable"


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: signer_posture.py <user.signingkey> <gpg.ssh.program>\n")
        return 2
    sys.stdout.write(posture(argv[1], argv[2]) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
