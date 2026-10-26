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
