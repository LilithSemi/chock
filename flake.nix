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
      versionTemplate = "1.1pre-<lastModifiedDate>-<rev>";

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
        { pkgs, ... }:
        {
          default = pkgs.chock;
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
