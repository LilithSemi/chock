{
  lib,
  stdenv,
  mkShell,
  zig,
  zls,
  git,
  typescript,
  mcp-server-time,
  flakever,
  pkg-config,
  vulkan-loader,
  jdk17,
  gradle_8,
  pkgs,
}:
let
  # A reference MCP server over streamable HTTP, for test/core/mcp_remote_real.zig.
  # The transport is the mcp package's own, so the framing under test is not one
  # Chock wrote. The dev shell holds it and the package build does not, so
  # `nix build` skips that test the way it skips the stdio one.
  mcp-probe-http =
    pkgs.writers.writePython3Bin "mcp-probe-http"
      {
        libraries = [ pkgs.python3Packages.mcp ];
        flakeIgnore = [ "E501" ];
      }
      ''
        import sys

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("probe", host="127.0.0.1", port=int(sys.argv[1]))


        @mcp.tool()
        def echo(text: str) -> str:
            "Give back the text it was given."
            return text


        mcp.run(transport="streamable-http")
      '';

  androidEnv = pkgs.callPackage "${pkgs.path}/pkgs/development/mobile/androidenv" {
    inherit pkgs;
    licenseAccepted = true;
  };
  androidSdk =
    (androidEnv.composeAndroidPackages {
      platformVersions = [ "36" ];
      buildToolsVersions = [ "36.0.0" ];
      abiVersions = [
        "arm64-v8a"
        "x86_64"
      ];
      includeNDK = true;
      includeEmulator = false;
      includeSystemImages = false;
      includeCmake = false;
    }).androidsdk;
  jdk = jdk17;

  useAndroidSdk = pkgs.stdenv.hostPlatform.isLinux && pkgs.stdenv.hostPlatform.isx86_64;
in
stdenv.mkDerivation (finalAttrs: {
  pname = "chock";
  inherit (flakever) version;

  src = lib.cleanSource ../../.;

  zigDeps = zig.fetchDeps {
    inherit (finalAttrs) src pname version;
    hash = "sha256-VIASaK8Xg20tBWKl51s/v0AgGXeV1G6N4ugXNrge7Yc=";
  };

  nativeBuildInputs = [
    zig
    git
    typescript
  ];

  postConfigure = ''
    ln -s ${finalAttrs.zigDeps} "$ZIG_GLOBAL_CACHE_DIR/p"
  '';

  zigBuildFlags = [
    "-Dversion=${finalAttrs.version}"
  ];

  zigCheckFlags = finalAttrs.zigBuildFlags;

  doCheck = true;

  # Needed for unit tests
  __darwinAllowLocalNetworking = finalAttrs.doCheck;

  passthru.shell = mkShell {
    name = "chock-dev-shell";
    packages = [
      zig
      git
      zls
      typescript
      mcp-server-time
      mcp-probe-http
      pkg-config
      vulkan-loader
    ]
    ++ lib.optionals useAndroidSdk [
      androidSdk
      gradle_8
      jdk
    ];

    env = lib.optionalAttrs useAndroidSdk {
      JAVA_HOME = jdk.home;
      ANDROID_HOME = "${androidSdk}/libexec/android-sdk";
      ANDROID_NDK_ROOT = "${androidSdk}/libexec/android-sdk/ndk-bundle";
    };

    shellHook = lib.optionalString useAndroidSdk ''
      export GRADLE_OPTS="-Dorg.gradle.project.android.aapt2FromMavenOverride=$(echo "$ANDROID_HOME/build-tools/"*/aapt2) ''${GRADLE_OPTS:-}"
    '';
  };
})
