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
    hash = "sha256-m5KU+m4IHjeOintY0im0KKl9oSXMSOvWwT9TNmzdwcE=";
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
