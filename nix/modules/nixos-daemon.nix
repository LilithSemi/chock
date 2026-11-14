{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.chock-daemon;
  oidcConfigured = cfg.oidcProvider != null || cfg.oidcIssuer != null || cfg.oidcClientId != null;
  oidcEnvironment =
    lib.optionalAttrs (cfg.oidcProvider != null) {
      CHOCK_OIDC_PROVIDER = cfg.oidcProvider;
    }
    // lib.optionalAttrs (cfg.oidcIssuer != null) {
      CHOCK_OIDC_ISSUER = cfg.oidcIssuer;
    }
    // lib.optionalAttrs (cfg.oidcClientId != null) {
      CHOCK_OIDC_CLIENT_ID = cfg.oidcClientId;
    }
    // lib.optionalAttrs (cfg.oidcDiscoveryUrl != null) {
      CHOCK_OIDC_DISCOVERY_URL = cfg.oidcDiscoveryUrl;
    }
    // lib.optionalAttrs (cfg.oidcAdminSubject != null) {
      CHOCK_OIDC_ADMIN_SUBJECT = cfg.oidcAdminSubject;
    };
  webArgs = [
    "--daemon"
    "unix:/run/chock-daemon/daemon.sock"
    "--socket"
    "/run/chock-web/serve.sock"
    "--socket-group"
    (if cfg.web.socketGroup == null then cfg.group else cfg.web.socketGroup)
  ]
  ++ lib.optionals (cfg.web.project != null) [
    "--project"
    cfg.web.project
  ]
  ++ lib.optionals (cfg.web.externalUrl != null) [
    "--external-url"
    cfg.web.externalUrl
  ]
  ++ lib.optionals cfg.web.allowHttp [ "--allow-http" ];
  waitForDaemonSocket = pkgs.writeShellScript "chock-web-wait-for-daemon" ''
    attempt=0
    while [ "$attempt" -lt 100 ]; do
      if [ -S /run/chock-daemon/daemon.sock ]; then
        exit 0
      fi
      attempt=$((attempt + 1))
      ${pkgs.coreutils}/bin/sleep 0.1
    done
    echo "chock-web: daemon socket did not become ready" >&2
    exit 1
  '';
in
{
  options.services.chock-daemon = {
    enable = lib.mkEnableOption "the Chock daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.chock;
      defaultText = lib.literalExpression "pkgs.chock";
      description = "The Chock package to run.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "chock";
      description = "System user that owns the daemon and its state.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "chock";
      description = "Primary group for the daemon user.";
    };

    environmentFiles = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "/run/secrets/chock-daemon.env" ];
      description = ''
        systemd EnvironmentFile entries for sensitive deployment values. Keep
        database passwords and other credentials out of Nix expressions.
      '';
    };

    extraEnvironment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = "Additional non-secret environment variables for chock daemon.";
    };

    gitAllowedHosts = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "git.example.org" ];
      description = "Exact HTTPS Git hostnames allowed for UI project provisioning.";
    };

    oidcProvider = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.enum [
          "kanidm"
          "authentik"
          "authelia"
        ]
      );
      default = null;
      description = "OIDC provider name, when daemon-side OIDC authorization is configured.";
    };

    oidcIssuer = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Exact OIDC issuer URL.";
    };

    oidcClientId = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "OIDC client ID.";
    };

    oidcDiscoveryUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional provider-specific OpenID Connect discovery URL.";
    };

    oidcAdminSubject = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Exact OIDC subject to bootstrap as instance administrator.";
    };

    web = {
      enable = lib.mkEnableOption "the Chock browser gateway";

      user = lib.mkOption {
        type = lib.types.str;
        default = "chock-web";
        description = "Unprivileged system user for the browser gateway, separate from the daemon user.";
      };

      environmentFiles = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "/run/secrets/chock-web.env" ];
        description = ''
          systemd EnvironmentFile entries available only to the browser
          gateway. Do not put OIDC client secrets or database credentials
          here; OIDC secrets belong only in daemon-private state.
        '';
      };

      project = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "/srv/chock/projects/example";
        description = "Optional default project directory for the browser gateway.";
      };

      socketGroup = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "nginx";
        description = ''
          Group allowed to reach the gateway's Unix socket, for a local reverse
          proxy. Configure externalUrl so browser cookie origins are checked.
        '';
      };

      externalUrl = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "https://chock.example.org";
        description = "Browser-facing origin used for OIDC callbacks and browser origin checks; HTTPS is required except for loopback HTTP or when allowHttp is enabled.";
      };

      allowHttp = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Permit a non-loopback HTTP externalUrl. This is unsafe on untrusted
          networks: browser credentials and OIDC callbacks are not protected
          by TLS. Prefer HTTPS or TLS termination at a trusted reverse proxy.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !cfg.web.enable || cfg.web.user != cfg.user;
        message = "services.chock-daemon.web.user must differ from the daemon user to preserve the secret boundary.";
      }
      {
        assertion =
          let
            present = map (value: value != null) [
              cfg.oidcProvider
              cfg.oidcIssuer
              cfg.oidcClientId
            ];
          in
          builtins.all (value: value == builtins.head present) present;
        message = "services.chock-daemon OIDC provider, issuer, and client ID must be set together.";
      }
      {
        assertion = cfg.oidcAdminSubject == null || oidcConfigured;
        message = "services.chock-daemon.oidcAdminSubject requires OIDC to be configured.";
      }
      {
        assertion = cfg.oidcDiscoveryUrl == null || oidcConfigured;
        message = "services.chock-daemon.oidcDiscoveryUrl requires OIDC to be configured.";
      }
      {
        assertion = cfg.web.socketGroup == null || cfg.web.externalUrl != null;
        message = "services.chock-daemon.web.socketGroup requires web.externalUrl so browser origins can be checked.";
      }
      {
        assertion = !cfg.web.allowHttp || cfg.web.externalUrl != null;
        message = "services.chock-daemon.web.allowHttp requires web.externalUrl.";
      }
    ];

    users.groups.${cfg.group} = { };
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = "/var/lib/chock";
      createHome = true;
      description = "Chock daemon service user";
    };
    users.users.${cfg.web.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = "/var/lib/chock-web";
      createHome = true;
      description = "Chock browser gateway user";
    };

    systemd.services.chock-daemon = {
      description = "Chock daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      # Project cloning and workspace setup run a bare `git`.
      path = [ pkgs.git ];
      environment = {
        HOME = "/var/lib/chock";
        XDG_STATE_HOME = "/var/lib";
        XDG_CONFIG_HOME = "/etc";
        SSL_CERT_FILE = config.security.pki.caBundle;
        CHOCK_GIT_ALLOWED_HOSTS = lib.concatStringsSep "," cfg.gitAllowedHosts;
      }
      // cfg.extraEnvironment
      // oidcEnvironment;
      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        StateDirectory = "chock";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "chock-daemon";
        RuntimeDirectoryMode = "0750";
        UMask = "0077";
        ExecStart = lib.escapeShellArgs (
          [
            "${cfg.package}/bin/chock"
            "daemon"
            "--socket"
            "/run/chock-daemon/daemon.sock"
          ]
          ++ lib.optionals cfg.web.enable [
            "--socket-group"
            cfg.group
          ]
        );
        Restart = "on-failure";
        RestartSec = "5s";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        ReadWritePaths = [
          "/var/lib/chock"
          "/run/chock-daemon"
        ];
      }
      // lib.optionalAttrs (cfg.environmentFiles != [ ]) {
        EnvironmentFile = cfg.environmentFiles;
      };
    };

    systemd.services.chock-web = lib.mkIf cfg.web.enable {
      description = "Chock browser gateway";
      wantedBy = [ "multi-user.target" ];
      after = [ "chock-daemon.service" ];
      requires = [ "chock-daemon.service" ];
      environment = {
        HOME = "/var/lib/chock-web";
        XDG_STATE_HOME = "/var/lib/chock-web/.local/state";
        XDG_CONFIG_HOME = "/etc";
        SSL_CERT_FILE = config.security.pki.caBundle;
      }
      // lib.optionalAttrs (cfg.web.externalUrl != null) {
        CHOCK_EXTERNAL_URL = cfg.web.externalUrl;
      };
      serviceConfig = {
        Type = "simple";
        User = cfg.web.user;
        Group = cfg.group;
        SupplementaryGroups = lib.optional (cfg.web.socketGroup != null) cfg.web.socketGroup;
        WorkingDirectory = if cfg.web.project == null then "/var/lib/chock-web" else cfg.web.project;
        RuntimeDirectory = "chock-web";
        # The socket's owner/group/mode is the access control; an external
        # proxy may use another group and only needs to traverse this directory.
        RuntimeDirectoryMode = "0711";
        StateDirectory = "chock-web";
        StateDirectoryMode = "0700";
        UMask = "0077";
        ExecStart = lib.escapeShellArgs (
          [
            "${cfg.package}/bin/chock"
            "serve"
          ]
          ++ webArgs
        );
        # `After=` orders process startup, not socket readiness. Wait for the
        # daemon's restricted control socket instead of relying on a failed
        # first launch and systemd's restart delay. The daemon control socket
        # is group-accessible only to the dedicated Chock service group.
        ExecStartPre = "${waitForDaemonSocket}";
        Restart = "on-failure";
        RestartSec = "5s";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        ReadWritePaths = [
          "/run/chock-web"
          "/run/chock-daemon"
        ];
      }
      // lib.optionalAttrs (cfg.web.environmentFiles != [ ]) {
        EnvironmentFile = cfg.web.environmentFiles;
      };
    };
  };
}
