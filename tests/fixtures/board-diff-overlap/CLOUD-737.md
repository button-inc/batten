Both Darwin release legs build on `ubuntu-latest` through `cargo-zigbuild`, with no Apple SDK (`release-artifacts.yml:101-104`).
`macos-link-check` exists to keep that buildable. `release-artifacts.yml:12-14` records the reasoning.
`libgit2-sys` declares a `links` key, so `macos-link-check` rule 1 excludes it outright today.
