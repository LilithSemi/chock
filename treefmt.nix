{ lib, pkgs, ... }:
{
  projectRootFile = "flake.nix";

  programs = {
    nixfmt.enable = true;
    zig.enable = true;
  };
}
