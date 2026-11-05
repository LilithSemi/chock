{ lib, pkgs, ... }:
{
  projectRootFile = "flake.nix";

  programs = {
    actionlint.enable = true;
    nixfmt.enable = true;
    shellcheck = {
      enable = true;
      # Release scripts intentionally have command names without extensions.
      includes = [ ".github/scripts/*" ];
    };
    zig.enable = true;
  };
}
