{
  lib,
  stdenv,
  mkShell,
  zig,
  zls,
  git,
  typescript,
  tree-sitter,
  mcp-server-time,
  flakever,
  pkg-config,
  vulkan-loader,
  jdk17,
  gradle_8,
  pkgs,
  versionCheckHook,
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

        from mcp.server.mcpserver import MCPServer

        mcp = MCPServer("probe")


        @mcp.tool()
        def echo(text: str) -> str:
            "Give back the text it was given."
            return text


        mcp.run(
            transport="streamable-http",
            host="127.0.0.1",
            port=int(sys.argv[1]),
        )
      '';

  # One grammar a language, named after the language, for
  # test/core/ast_real.zig and for a project whose style rules name zig. A
  # symlinkJoin would collide: every grammar ships its library as "parser".
  treeSitterParsers = pkgs.runCommand "tree-sitter-parsers" { } ''
    mkdir -p $out
    ln -s ${pkgs.tree-sitter-grammars.tree-sitter-zig}/parser $out/zig.so
  '';

  # The same grammar again, this time inside a wasm module with tree-sitter's
  # runtime, for `style.engine = "wasm"` and for test/core/ast_agree.zig. The
  # C is compiled against the wasi headers, which declare a library this
  # module never links, and shim.zig answers what those declarations leave
  # undefined. One module a language, named after the language.
  astWasmModules = pkgs.runCommand "chock-ast-wasm-modules" { nativeBuildInputs = [ zig ]; } ''
    export HOME="$TMPDIR"
    export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-cache"
    runtime=${pkgs.tree-sitter.src}
    grammar=${pkgs.tree-sitter-grammars.tree-sitter-zig.src}

    cp ${./ast-wasm/shim.zig} shim.zig
    cp ${./ast-wasm/driver.c} driver.c
    {
      echo '#include <tree_sitter/api.h>'
      echo 'const TSLanguage *tree_sitter_zig(void);'
      echo 'const TSLanguage *ts_module_language(void) { return tree_sitter_zig(); }'
    } > lang.c

    for one in driver.c lang.c "$runtime/lib/src/lib.c" "$grammar/src/parser.c"; do
      zig cc -target wasm32-wasi -Os -c "$one" \
        -I "$runtime/lib/include" -I "$runtime/lib/src" -I "$grammar/src" \
        -o "$(basename "$one" .c).o"
    done

    mkdir -p $out
    # The two memory bounds are equal, so the module cannot grow and its heap
    # is every byte above what the linker placed.
    zig build-exe shim.zig driver.o lang.o lib.o parser.o \
      -target wasm32-freestanding -OReleaseSmall -fno-entry \
      --export=ast_input --export=ast_run --export=ast_rows \
      --initial-memory=67108864 --max-memory=67108864 \
      -femit-bin=$out/zig.wasm
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
    hash = "sha256-EKB48hSspw5yy/Mzh0gsM94TH7YYhnLkDkrgVGwjzP8=";
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

  doInstallCheck = true;

  nativeInstallCheckInputs = [ versionCheckHook ];
  versionCheckProgramArg = "--version";

  passthru = {
    shell = mkShell {
      name = "chock-dev-shell";
      packages = [
        zig
        git
        zls
        typescript
        mcp-server-time
        mcp-probe-http
        tree-sitter
        pkg-config
        vulkan-loader
      ]
      ++ lib.optionals useAndroidSdk [
        androidSdk
        gradle_8
        jdk
      ];

      env = {
        TREE_SITTER_PARSERS = "${treeSitterParsers}";
        CHOCK_PARSER_MODULES = "${astWasmModules}";
      }
      // lib.optionalAttrs useAndroidSdk {
        JAVA_HOME = jdk.home;
        ANDROID_HOME = "${androidSdk}/libexec/android-sdk";
        # Gradle refuses to build when ANDROID_HOME and ANDROID_SDK_ROOT name
        # different directories, and the host can already have the second one.
        ANDROID_SDK_ROOT = "${androidSdk}/libexec/android-sdk";
        ANDROID_NDK_ROOT = "${androidSdk}/libexec/android-sdk/ndk-bundle";
      };

      shellHook = lib.optionalString useAndroidSdk ''
        export GRADLE_OPTS="-Dorg.gradle.project.android.aapt2FromMavenOverride=$(echo "$ANDROID_HOME/build-tools/"*/aapt2) ''${GRADLE_OPTS:-}"
      '';
    };
  }
  // lib.optionalAttrs useAndroidSdk {
    android = finalAttrs.finalPackage.overrideAttrs (old: {
      pname = "chock-android";

      nativeBuildInputs = old.nativeBuildInputs ++ [
        androidSdk
        gradle_8
        jdk
      ];

      mitmCache = gradle_8.fetchDeps {
        pkg = finalAttrs.finalPackage.android;
        data = ./android-deps.json;
      };
      gradleUpdateScript = ''
        runHook preBuild
        zig build -Dtarget=aarch64-linux-android --release=safe
      '';

      env = (old.env or { }) // {
        JAVA_HOME = jdk.home;
        ANDROID_HOME = "${androidSdk}/libexec/android-sdk";
        ANDROID_NDK_ROOT = "${androidSdk}/libexec/android-sdk/ndk-bundle";
      };

      zigBuildFlags = old.zigBuildFlags ++ [ "-Dtarget=aarch64-linux-android" ];

      postConfigure = old.postConfigure + ''
        # Zig requires a URI scheme, while the Gradle dependency proxy exports
        # only host:port.
        if [[ "$http_proxy" != *://* ]]; then
          export http_proxy="http://$http_proxy"
          export https_proxy="http://$https_proxy"
        fi
      '';

      preBuild = ''
        export ANDROID_USER_HOME="$TMPDIR/android"
        mkdir -p "$ANDROID_USER_HOME"
        export GRADLE_OPTS="-Dorg.gradle.project.android.aapt2FromMavenOverride=$(echo "$ANDROID_HOME/build-tools/"*/aapt2) ''${GRADLE_OPTS:-}"
        # Phantom launches Gradle as a child process, so it cannot see the
        # setup hook's shell function that normally supplies these flags.
        if [[ -n "''${MITM_CACHE_CA:-}" ]]; then
          export GRADLE_OPTS="-Dhttp.proxyHost=$MITM_CACHE_HOST -Dhttp.proxyPort=$MITM_CACHE_PORT -Dhttps.proxyHost=$MITM_CACHE_HOST -Dhttps.proxyPort=$MITM_CACHE_PORT -Djavax.net.ssl.trustStore=$MITM_CACHE_KEYSTORE -Djavax.net.ssl.trustStorePassword=$MITM_CACHE_KS_PWD $GRADLE_OPTS"
        fi
      '';

      doCheck = false;
      doInstallCheck = false;
    });
  };

  meta = {
    description = "Auditable AI coding agent with a kernel-enforced sandbox";
    homepage = "https://chock.ws";
    license = lib.licenses.asl20;
    mainProgram = "chock";
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
      "aarch64-darwin"
    ];
  };
})
