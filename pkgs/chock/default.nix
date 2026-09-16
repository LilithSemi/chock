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
    hash = "sha256-tA/8mY7H6xfgBp0bC/xTCoXw3Ij/m+QIhwvRoVAgh+0=";
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
