{
  # The nix channel (CLOUD-2298): `nix run github:button-inc/batten`, or this
  # flake as an input. Built by nixpkgs' own Rust builder from the committed
  # Cargo.lock, so the dependency set is the one every other channel ships.
  description = "batten — agent-era completion gate";

  # The channel tarball nixos.org publishes, rather than `github:NixOS/nixpkgs`:
  # the same tree, fetched without the GitHub API, and pinned by flake.lock.
  inputs.nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # The version is the workspace manifest's, read rather than restated.
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
    in
    {
      packages = forAll (pkgs: rec {
        batten = pkgs.rustPlatform.buildRustPackage {
          pname = "batten";
          inherit version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          # THE BUILD'S IDENTITY WITHOUT GIT (CLOUD-2903): `src = self` carries no
          # `.git`, so `build.rs` is handed the commit second and the line, and
          # told the source IS the tracked tree so it folds the digest from it.
          # A flake build reports `<next>-dev.nix.<ts>+<digest>`: a source build
          # naming its tree, never the release (only `dist.yml` is that).
          BATTEN_BUILD_COMMITTED = toString (self.lastModified or 0);
          BATTEN_BUILD_LINE = "nix";
          BATTEN_BUILD_SOURCE_TRACKED = "1";
          cargoBuildFlags = [
            "--package"
            "batten"
            "--bin"
            "batten"
          ];
          # The suite runs in this repository's own CI; the package is the
          # binary, not a second test runner.
          doCheck = false;
          meta = {
            description = "Agent-era completion gate: repo-state conformance checks enforced at the agent's tool call";
            homepage = "https://github.com/button-inc/batten";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "batten";
          };
        };
        default = batten;
      });
    };
}
