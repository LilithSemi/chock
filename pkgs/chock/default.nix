{
  lib,
  stdenv,
  mkShell,
  zig,
  zls,
  git,
  mcp-server-time,
  flakever,
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "chock";
  inherit (flakever) version;

  src = lib.cleanSource ../../.;

  zigDeps = zig.fetchDeps {
    inherit (finalAttrs) src pname version;
    hash = "sha256-G4Z2514jkdo2v4Sd400YvFOYsVdbSrAiOEdRew52V9k=";
  };

  nativeBuildInputs = [
    zig
    git
  ];

  postConfigure = ''
    ln -s ${finalAttrs.zigDeps} "$ZIG_GLOBAL_CACHE_DIR/p"
  '';

  doCheck = true;

  # Needed for unit tests
  __darwinAllowLocalNetworking = finalAttrs.doCheck;

  passthru.shell = mkShell {
    name = "chock-dev-shell";
    packages = [
      zig
      git
      zls
      mcp-server-time
    ];
  };
})
