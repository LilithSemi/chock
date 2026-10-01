{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flakever.url = "github:numinit/flakever";
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
      flakever,
      ...
    }@inputs:
    let
      inherit (nixpkgs) lib;

      nameValuePair = name: value: { inherit name value; };
      genAttrs = names: f: builtins.listToAttrs (map (n: nameValuePair n (f n)) names);
      allSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      manifestVersion =
        let
          matched = builtins.match ".*\n[ ]*\\.version = \"([^\"]+)\",.*" (builtins.readFile ./build.zig.zon);
        in
        if matched == null then throw "build.zig.zon has no .version to read" else builtins.head matched;

      flakeverConfig = flakever.lib.mkFlakever {
        inherit inputs;

        digits = [
          1
          2
          2
        ];
      };

      forAllSystems =
        f:
        genAttrs allSystems (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ self.overlays.default ];
            };
          }
        );

      treefmtEval = forAllSystems ({ pkgs, ... }: treefmt-nix.lib.evalModule pkgs (import ./treefmt.nix));
    in
    {
      # Only `-unstable` is stamped. A release candidate is named by a person
      # and cut once, so `0.1.0-rc1` must come out exactly as written.
      versionTemplate =
        if lib.hasSuffix "-unstable" manifestVersion then
          "${manifestVersion}-<lastModifiedDate>-<rev>"
        else
          manifestVersion;

      overlays.default = final: prev: {
        chock = final.callPackage ./pkgs/chock { flakever = flakeverConfig; };
      };

      devShells = forAllSystems (
        { pkgs, ... }:
        {
          default = pkgs.chock.shell;
        }
      );

      packages = forAllSystems (
        { system, pkgs, ... }:
        let
          # A guest is Linux whatever the host is, which is the whole reason the
          # microVM driver closes the Darwin gap. An aarch64 Mac's guest is
          # `aarch64-linux`, and building it needs a Linux builder.
          guestSystem = if lib.hasSuffix "-darwin" system then "aarch64-linux" else system;
          guest = import ./pkgs/chock/guest.nix {
            inherit lib;
            hostPkgs = pkgs;
            guestPkgs = import nixpkgs {
              system = guestSystem;
              overlays = [ self.overlays.default ];
            };
          };
        in
        {
          default = pkgs.chock;
          # The two things a microVM guest boots, each its own derivation, so a
          # release tarball carries them beside the binary. See
          # `docs/security/microvm.md`.
          guest-kernel = guest.kernel;
          guest-initrd = guest.initrd;
        }
      );

      formatter = forAllSystems ({ system, ... }: treefmtEval.${system}.config.build.wrapper);

      checks = forAllSystems (
        { system, pkgs, ... }:
        {
          inherit (pkgs) chock;
          formatting = treefmtEval.${system}.config.build.check self;
        }
      );
    };
}
