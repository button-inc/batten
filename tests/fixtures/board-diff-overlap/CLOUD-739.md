`DIFF_CONFIG` (`git.rs:107`) pins 20 config keys via `-c` and `DIFF_FLAGS` (`:139`) 6 flags.
`landing` decides merged-ness by patch identity, never reachability (CLOUD-36).
That is re-derivable on `gix-diff` plus the `sha2` already vendored.
the rebase, squash and cherry-pick shapes `tests/primitives.rs`' keystone fixture already builds.
