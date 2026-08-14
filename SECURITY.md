# Security Policy

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting** — open
<https://github.com/button-inc/batten/security/advisories/new>, or the _Report a
vulnerability_ button under the repository's **Security** tab. That channel is
private between you and the maintainers until an advisory is published, and it is
the only reporting route this project operates.

**Do not open a public issue for a suspected vulnerability.** The issue tracker is
world-readable once this repository is public, so filing there discloses the
problem before there is a fix.

A report is most useful with the version or commit SHA, the platform, the commands
that reproduce it, and what you expected instead.

## What to expect

A maintainer will acknowledge the report, then either accept it, ask for more
information, or explain why it is not a vulnerability. We will tell you when a fix
lands and in which release, and credit you in the advisory unless you ask us not
to. Batten is a small pre-1.0 project and sets no response-time guarantee.

## Supported versions

Batten is pre-1.0 and released from `main`. **Only the latest release is
supported**; fixes land there rather than being backported. Releases are cut by
[release-plz](https://release-plz.dev) from Conventional Commits, so a security fix
reaches a version as soon as one is cut.

## Scope

In scope: the `batten` binary and library in this repository, its published release
archives, and the workflows that produce them.

Out of scope: findings that require an attacker who can already write to the
repository or execute code on the machine running `batten` — that is inside the
trust boundary by construction. Batten's threat model is **honest error**, not a
hostile operator: the wrong entity, the wrong time, the wrong completion signal. A
configuration that grants weaker policy than intended is a bug and worth reporting;
an operator deliberately weakening their own `batten.toml` is not.

Reports against a dependency belong upstream first. `cargo-deny` gates this tree's
advisories on every run, so if an advisory exists we are already tracking it.
