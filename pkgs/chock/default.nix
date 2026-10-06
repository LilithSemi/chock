{
  lib,
  stdenv,
  mkShell,
  writeText,
  darwin,
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
    hash = "sha256-UY7sXCsQGNwHPQJhce6Y1ikd/rlLZ+9e3XkEhaV7olo=";
  };

  # **The hypervisor entitlement, which a Mac runs no microVM guest without.**
  # `hv_vm_create` answers `HV_DENIED` to a process that does not carry it, and
  # says nothing else, so a build that skipped this would look like a machine
  # with no hypervisor. An ad hoc signature carries it: no Developer ID is
  # needed. See `docs/security/microvm.md`.
  hypervisorEntitlement = writeText "chock-hypervisor.plist" ''
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
      <key>com.apple.security.hypervisor</key>
      <true/>
    </dict>
    </plist>
  '';

  nativeBuildInputs = [
    zig
    git
  ]
  # `codesign` is not in a Darwin build environment. sigtool's own takes
  # `--entitlements`, and the signature it writes is one the kernel honours.
  ++ lib.optional stdenv.hostPlatform.isDarwin darwin.sigtool;

  # **Last, because a Darwin fixup hook signs a binary that has no signature.**
  # Anything written before that hook runs would be replaced by it, and the
  # entitlement would be gone with it.
  postFixup = lib.optionalString stdenv.hostPlatform.isDarwin ''
    codesign --sign - --entitlements ${finalAttrs.hypervisorEntitlement} --force "$out/bin/chock"
  '';

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
      mcp-server-time
    ];
  };
})
