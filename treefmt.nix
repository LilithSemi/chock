{ lib, pkgs, ... }:
{
  projectRootFile = "flake.nix";

  programs = {
    actionlint.enable = true;
    nixfmt.enable = true;
    shellcheck = {
      enable = true;
      # Release scripts and the root direnv file intentionally have names
      # without shell extensions.
      includes = [
        ".envrc"
        ".github/scripts/*"
      ];
    };
    zig.enable = true;
  };
}
