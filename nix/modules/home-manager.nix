{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.chock;
in
{
  options.programs.chock = {
    enable = lib.mkEnableOption "Chock";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.chock;
      defaultText = lib.literalExpression "pkgs.chock";
      description = "The Chock package to install.";
    };

    daemonSocket = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/run/user/1000/chock/daemon.sock";
      description = ''
        Optional daemon socket used by Chock clients. When set, the module
        exports CHOCK_DAEMON in the user's session environment.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = lib.literalExpression "\${config.home.homeDirectory}/.config/chock/config.zon";
      description = ''
        Optional config.zon to install declaratively at
        ~/.config/chock/config.zon using Home Manager's normal file support.
        Home Manager stores this file in the Nix store; never put API tokens or
        other secrets in it. Keep credentials in Chock's private tokens.zon or
        a secret-file reference outside the store.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    home.packages = [ cfg.package ];

    home.sessionVariables = lib.mkIf (cfg.daemonSocket != null) {
      CHOCK_DAEMON = cfg.daemonSocket;
    };

    xdg.configFile."chock/config.zon" = lib.mkIf (cfg.configFile != null) {
      source = cfg.configFile;
    };
  };
}
