const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const gpu_drivers = b.option([]const u8, "gpu-drivers", "Specific GPU drivers to enable, defaults to Prism's choice.");

    const test_step = b.step("test", "Run all tests");

    const linux_only = target.result.os.tag == .linux;

    const version_text = b.option(
        []const u8,
        "version",
        "What this build calls itself, as a semantic version. Defaults to build.zig.zon.",
    ) orelse @import("build.zig.zon").version;

    // **The manifest, and never the option.** This value names the directory a
    // packaged plugin is installed into, which is a property of the source
    // tree and not of what an untagged build happened to call itself.
    const chock_version = std.SemanticVersion.parse(version_text) catch @panic("Version in build.zig.zon should parse");

    const chock_version_options = b.addOptions();
    chock_version_options.addOption([]const u8, "text", version_text);
    const chock_version_module = chock_version_options.createModule();

    // The sandbox for a tool call. It imports no other chock library. It has no
    // build.zig of its own, though: this root build script is the only thing that
    // builds and tests it.
    const chock_sandbox = b.addModule("chock-sandbox", .{
        .root_source_file = b.path("lib/chock-sandbox.zig"),
        .target = target,
        .optimize = optimize,
    });

    const sandbox_tests = b.addTest(.{ .root_module = chock_sandbox });
    const run_sandbox_tests = b.addRunArtifact(sandbox_tests);
    // Building a test binary for a foreign target already analyses every
    // declaration `std.testing.refAllDecls` reaches, which is how this
    // project checks a Darwin build: `zig build test -Dtarget=aarch64-macos`
    // compiles every module below for that target and skips only the run,
    // because a foreign binary cannot execute on this host. Without this
    // flag the same command would fail the whole build on the first module,
    // rather than compiling every one of them and reporting every error.
    // See `std.Build.Step.Run.skip_foreign_checks`'s own doc comment.
    run_sandbox_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_sandbox_tests.step);

    // The layer for the small number of primitives std.Io does not have. Like
    // chock-sandbox, it imports no other chock library and has no build.zig of
    // its own.
    const chock_io = b.addModule("chock-io", .{
        .root_source_file = b.path("lib/chock-io.zig"),
        .target = target,
        .optimize = optimize,
    });

    const io_tests = b.addTest(.{ .root_module = chock_io });
    const run_io_tests = b.addRunArtifact(io_tests);
    // Same reasoning as run_sandbox_tests above: a Darwin cross build compiles
    // chock-io/darwin/driver.zig for real, including its std.c calls, and only
    // skips running the resulting binary, which this host cannot execute.
    run_io_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_io_tests.step);

    // The event types and the session log. It imports chock-io, for the one pipe
    // lib/chock-proto/log.zig's own short write test needs; besides that it imports
    // no other chock library, the same rule chock-sandbox follows.
    const chock_proto = b.addModule("chock-proto", .{
        .root_source_file = b.path("lib/chock-proto.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "chock-io", .module = chock_io }},
    });

    const proto_tests = b.addTest(.{ .root_module = chock_proto });
    const run_proto_tests = b.addRunArtifact(proto_tests);
    run_proto_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_proto_tests.step);

    // A real second process for the log lock test: flock locks an open file
    // description, not a path, so proving a second process cannot take a lock the
    // first holds needs an actual second process, not a second Log value in the test
    // binary itself. Mirrors the sandbox probe below.
    const lock_helper = b.addExecutable(.{
        .name = "chock-proto-lock-helper",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/proto/lock_helper.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "chock-proto", .module = chock_proto }},
        }),
    });

    // Same reasoning as probe_path_options below: embed the helper's path as a build
    // time constant, since Zig 0.16's test runner cannot take it as a CLI argument.
    const lock_helper_path_options = b.addOptions();
    lock_helper_path_options.addOptionPath("lock_helper_path", lock_helper.getEmittedBin());

    const lock_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/proto/lock.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-proto", .module = chock_proto },
                .{ .name = "lock_helper_path", .module = lock_helper_path_options.createModule() },
            },
        }),
    });
    const run_lock_tests = b.addRunArtifact(lock_tests);
    run_lock_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_lock_tests.step);

    // The daemon's control protocol over a real socket, carrying a real log.
    // Its own test target for the reason test/proto/lock.zig is one: the tests
    // beside chock-proto drive the grammar over buffers, which is right and is
    // not enough. Only a real transport can say that a client which never opens
    // a log still gets bytes whose chain verifies, and that one client reaches a
    // unix socket and a port with no branch between them.
    //
    // No network: the unix socket lives in a temporary directory and the port is
    // one the kernel gave on 127.0.0.1, which is what test/core/fake_provider.zig
    // already does.
    const control_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/proto/control.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "chock-proto", .module = chock_proto }},
        }),
    });
    const run_control_tests = b.addRunArtifact(control_tests);
    run_control_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_control_tests.step);

    // The directory the sandbox mounts, and the git and overlay layers that
    // build it. Only chock-sandbox is forbidden from importing a library above
    // it. Nothing forbids chock-workspace from importing chock-sandbox, so this
    // imports chock-sandbox for the one Mount type a worktree's own mount list,
    // an overlay's own mount list, and Sandbox.spawn all need to agree on,
    // field for field.
    const chock_workspace = b.addModule("chock-workspace", .{
        .root_source_file = b.path("lib/chock-workspace.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "chock-sandbox", .module = chock_sandbox }},
    });

    // A real second process for overlay.zig's own tests: a real overlay mount needs
    // CAP_SYS_ADMIN over its own mount namespace, and entering a user namespace
    // needs a single threaded caller, so this cannot run inside the zig test binary
    // itself. Mirrors the sandbox probe above. This imports the chock_workspace
    // module built just above, not a second copy of it, so it calls the very same
    // Overlay.mounts the library ships, never a raw mount(2) call of its own that
    // could drift from it.
    const overlay_helper = b.addExecutable(.{
        .name = "chock-workspace-overlay-helper",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/workspace/overlay_helper.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-sandbox", .module = chock_sandbox },
                .{ .name = "chock-workspace", .module = chock_workspace },
            },
        }),
    });

    // Same reasoning as probe_path_options above: embed the helper's path as a
    // build time constant, since Zig 0.16's test runner cannot take it as a CLI
    // argument.
    const overlay_helper_path_options = b.addOptions();
    overlay_helper_path_options.addOptionPath("overlay_helper_path", overlay_helper.getEmittedBin());

    // A second module built from the same root file as chock_workspace above, only
    // for the test run: it adds the overlay_helper_path import overlay.zig's
    // own tests need. chock_workspace itself cannot carry that import,
    // because overlay_helper above is built from chock_workspace: giving
    // chock_workspace that import would make the two depend on each other.
    const workspace_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("lib/chock-workspace.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-sandbox", .module = chock_sandbox },
                .{ .name = "overlay_helper_path", .module = overlay_helper_path_options.createModule() },
            },
        }),
    });
    const run_workspace_tests = b.addRunArtifact(workspace_tests);
    run_workspace_tests.skip_foreign_checks = true;
    // Each git.zig test that makes a scratch repository sets its own
    // GIT_CEILING_DIRECTORIES for the git calls it makes, so this test run needs
    // nothing extra here: it behaves the same whether started from this build step
    // or from `zig test` directly.
    test_step.dependOn(&run_workspace_tests.step);

    // Linux only, by `linux_only` above: every test in test/workspace/escape.zig
    // spawns a probe through Sandbox.spawn and then asserts on what the mount
    // namespace, the bind mounts, and the Landlock rules refused. Sandbox.spawn
    // itself refuses on Darwin, with error.NoMountNamespace, so there is no
    // sandbox for these tests to try to escape from.
    // The escape probe's own path, as a build time constant. Declared here,
    // outside both `if (linux_only)` blocks that name it, because two suites
    // drive the same probe: test/workspace/escape.zig, just below, and
    // test/broker/actions.zig, further down. One probe, so the two suites can
    // never disagree about what a sandboxed process is actually allowed to do.
    // Null on a target that is not Linux, where neither suite is built at all.
    const escape_probe_path_module: ?*std.Build.Module = if (linux_only) probe: {
        // Like chock-sandbox-probe and chock-workspace-overlay-helper, this
        // needs a single threaded caller to call Sandbox.spawn, so it cannot
        // run inside the zig test binary itself. See
        // test/workspace/escape_probe.zig's own top comment.
        const workspace_escape_probe = b.addExecutable(.{
            .name = "chock-workspace-escape-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/workspace/escape_probe.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "chock-sandbox", .module = chock_sandbox }},
            }),
        });

        // Same reasoning as probe_path_options above: embed the helper's path as a
        // build time constant, since Zig 0.16's test runner cannot take it as a CLI
        // argument.
        const options = b.addOptions();
        options.addOptionPath("escape_probe_path", workspace_escape_probe.getEmittedBin());
        break :probe options.createModule();
    } else null;

    if (linux_only) {
        const workspace_escape_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/workspace/escape.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-workspace", .module = chock_workspace },
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                    .{ .name = "escape_probe_path", .module = escape_probe_path_module.? },
                },
            }),
        });
        const run_workspace_escape_tests = b.addRunArtifact(workspace_escape_tests);
        run_workspace_escape_tests.skip_foreign_checks = true;
        // Same reasoning as run_workspace_tests above: each test sets its own
        // GIT_CEILING_DIRECTORIES.
        test_step.dependOn(&run_workspace_escape_tests.step);
    }

    // What a session costs and what it may spend. It imports chock-proto for
    // the `Cost` and `Usage` types the log already carries, and nothing else:
    // it reads `chock.zon` and does arithmetic, so it needs no sandbox, no
    // workspace, and no session.
    const chock_cost = b.addModule("chock-cost", .{
        .root_source_file = b.path("lib/chock-cost.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "chock-proto", .module = chock_proto }},
    });

    const cost_tests = b.addTest(.{ .root_module = chock_cost });
    const run_cost_tests = b.addRunArtifact(cost_tests);
    // Same reasoning as run_sandbox_tests above.
    run_cost_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_cost_tests.step);

    // The neutral message type and the provider adapters. It imports
    // chock-proto for the message type: chock-proto already has a message type
    // with content parts for exactly this reason, so chock-provider re-exports
    // it instead of keeping a second copy that could drift from it.
    const chock_provider = b.addModule("chock-provider", .{
        .root_source_file = b.path("lib/chock-provider.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "chock-proto", .module = chock_proto }},
    });

    const provider_tests = b.addTest(.{ .root_module = chock_provider });
    const run_provider_tests = b.addRunArtifact(provider_tests);
    run_provider_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_provider_tests.step);

    // Client.zig's own tests need a real socket server, test/core/fake_provider.zig,
    // to drive std.http.Client against. Zig 0.16 refuses a relative @import that
    // reaches outside a file's own module, so lib/chock-provider/Client.zig cannot
    // import a file under test/ directly. This gives those tests their own module,
    // rooted at test/core/client.zig, which imports chock_provider by name and
    // fake_provider.zig by its own, in-bounds, relative path. Mirrors why
    // test/proto/lock.zig is its own test target instead of living inside chock-proto.
    const client_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "chock-provider", .module = chock_provider }},
        }),
    });
    const run_client_tests = b.addRunArtifact(client_tests);
    run_client_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_client_tests.step);

    // The seal over a session log's chain head, and the smart card that can hold
    // the key. Like chock-sandbox, chock-io and chock-policy, it imports no other
    // chock library: verification is std.crypto plus a public key, and a module
    // an auditor uses must not need the log reader, the workspace or a
    // credential store to be present. It links no platform library either, which
    // keeps `zig build` the only tool a build needs: see lib/chock-pcsc.zig's own
    // top comment for that decision and why the transport refuses instead.
    const chock_pcsc = b.addModule("chock-pcsc", .{
        .root_source_file = b.path("lib/chock-pcsc.zig"),
        .target = target,
        .optimize = optimize,
    });

    const pcsc_tests = b.addTest(.{ .root_module = chock_pcsc });
    const run_pcsc_tests = b.addRunArtifact(pcsc_tests);
    // Same reasoning as run_sandbox_tests above.
    run_pcsc_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_pcsc_tests.step);

    // The seal read against a real hash chain, and a certificate chain the
    // library itself must not carry. This is its own target for the reason
    // test/proto/lock.zig is: the tests need chock-proto, and chock-pcsc must
    // not import it. Nothing here needs a card, a reader or a daemon.
    const pcsc_verify_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/pcsc/verify.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-pcsc", .module = chock_pcsc },
                .{ .name = "chock-proto", .module = chock_proto },
            },
        }),
    });
    const run_pcsc_verify_tests = b.addRunArtifact(pcsc_verify_tests);
    run_pcsc_verify_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_pcsc_verify_tests.step);

    // The Linux transport against a real `pcscd`. Its own target because it
    // starts a daemon, which is the one thing every other test in this module
    // is built to avoid needing, and because a target that spawns a program
    // must be able to skip on a machine that has none. It still needs no card
    // and no reader: see the file's own top comment.
    const pcsc_daemon_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/pcsc/pcscd.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "chock-pcsc", .module = chock_pcsc }},
        }),
    });
    const run_pcsc_daemon_tests = b.addRunArtifact(pcsc_daemon_tests);
    run_pcsc_daemon_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_pcsc_daemon_tests.step);

    // The policy table the broker evaluates. Like chock-sandbox and chock-io,
    // it imports no other chock library and has no build.zig of its own: it
    // reads chock.zon and answers a question about one key, and nothing else in
    // Chock has to be present for that.
    const chock_policy = b.addModule("chock-policy", .{
        .root_source_file = b.path("lib/chock-policy.zig"),
        .target = target,
        .optimize = optimize,
    });

    const policy_tests = b.addTest(.{ .root_module = chock_policy });
    const run_policy_tests = b.addRunArtifact(policy_tests);
    // Same reasoning as run_sandbox_tests above.
    run_policy_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_policy_tests.step);

    // The broker: the actor that asks the user and then does the privileged
    // work itself. It imports chock-proto, because an approval travels as
    // events in the session log and not over a channel of its own, and
    // chock-policy, because the table is the broker's own state. It also
    // imports chock-workspace: five of the eight acts a broker can do are git
    // operations, and lib/chock-workspace/git.zig is the only file in Chock
    // that talks to git, so lib/chock-broker/actions.zig calls that one rather
    // than keeping a second spawn of git that could drift from it.
    // chock-workspace does not import chock-broker, so this makes no cycle. It
    // does not import chock-core: the loop calls the broker, never the other
    // way round, which is what lets the broker move into its own process later.
    //
    // It imports chock-sandbox for one type, `Sandbox.NetBroker`: the seam a
    // filtered sandbox asks for a connection through. The decision belongs
    // here, beside the policy table, and the mechanism belongs there, beside
    // the namespaces, so one of the two has to name the other.
    // chock-workspace already imports chock-sandbox for the same shape of
    // reason, and chock-sandbox imports no chock library at all, so this makes
    // no cycle. See lib/chock-broker/network.zig's own top comment.
    const chock_broker = b.addModule("chock-broker", .{
        .root_source_file = b.path("lib/chock-broker.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "chock-proto", .module = chock_proto },
            .{ .name = "chock-policy", .module = chock_policy },
            .{ .name = "chock-workspace", .module = chock_workspace },
            .{ .name = "chock-sandbox", .module = chock_sandbox },
            .{ .name = "chock-version", .module = chock_version_module },
        },
    });

    const broker_tests = b.addTest(.{ .root_module = chock_broker });
    const run_broker_tests = b.addRunArtifact(broker_tests);
    // Same reasoning as run_sandbox_tests above.
    run_broker_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_broker_tests.step);

    // Linux only, by `linux_only` above: every test in test/sandbox/escape.zig
    // asserts on a Landlock rule, a seccomp filter, a namespace, or a mount.
    // None of those exist on another target.
    //
    // **This block sits below chock-broker and not beside chock-sandbox, and
    // that is on purpose.** The filtered network tests need the real
    // `chock_broker.network.Network` over a real `chock_policy` table on the
    // parent side of a real `Sandbox.spawn`. A stand-in broker written inside
    // the probe would be a protocol tested only against something more
    // permissive than the thing that ships, which is one of the two shapes of
    // vacuous test this project has been caught by. The probe is a test
    // program and not a library, so it is free to import whatever a test
    // needs: test/broker/actions.zig already imports chock-sandbox for the
    // same reason in the other direction.
    if (linux_only) {
        const probe = b.addExecutable(.{
            .name = "chock-sandbox-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/probe.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                    .{ .name = "chock-broker", .module = chock_broker },
                    .{ .name = "chock-policy", .module = chock_policy },
                },
            }),
        });

        // The test needs the path of the probe program. Zig 0.16 removed the argv access
        // that would let addArtifactArg hand the path to a test at run time, and the
        // default test runner panics on any argv it does not recognize. Embed the path
        // as a build time constant instead.
        const probe_path_options = b.addOptions();
        probe_path_options.addOptionPath("probe_path", probe.getEmittedBin());

        const escape_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/escape.zig"),
                .target = target,
                .optimize = optimize,
                // `chock-sandbox` for one question only: the exit status a
                // probe answers with when this machine will not give it a
                // sandbox at all. See that suite's own `skipIfNothingMeasured`,
                // and `test/sandbox/darwin_escape.zig`, which takes the same
                // narrow import for `confinedAlready`.
                .imports = &.{
                    .{ .name = "probe_path", .module = probe_path_options.createModule() },
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                },
            }),
        });
        const run_escape_tests = b.addRunArtifact(escape_tests);
        run_escape_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_escape_tests.step);
    }

    // macOS only, and for the same reason the block above is Linux only: every
    // test in test/sandbox/darwin_escape.zig asserts on a Seatbelt profile that
    // was really applied by `sandbox_init`, and no other target has one.
    //
    // **It has to run on a real Mac, and a cross build must not look like it
    // did.** `run_sandbox_tests` and every other test target here set
    // `skip_foreign_checks`, so a binary the host cannot run is skipped and the
    // step still reports success. That is how a Darwin cross build from Linux
    // once passed while every Linux only suite inside it had been skipped. A
    // sandbox proved only by a skipped run step is worth nothing, so this one
    // leaves the flag off: on a host that cannot run the binary the step fails
    // rather than passing quietly.
    if (target.result.os.tag == .macos) {
        const darwin_probe = b.addExecutable(.{
            .name = "chock-sandbox-darwin-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/darwin_probe.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{.{ .name = "chock-sandbox", .module = chock_sandbox }},
            }),
        });

        const darwin_probe_path = b.addOptions();
        darwin_probe_path.addOptionPath("probe_path", darwin_probe.getEmittedBin());

        const darwin_escape_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/darwin_escape.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                // `chock-sandbox` for one question only: whether this process
                // is inside a profile already, which is the one state in which
                // none of these tests can be answered. See that suite's own
                // `requireOwnProfile`.
                .imports = &.{
                    .{ .name = "probe_path", .module = darwin_probe_path.createModule() },
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                },
            }),
        });
        test_step.dependOn(&b.addRunArtifact(darwin_escape_tests).step);

        // Finding 4 on macOS. `test/workspace/escape.zig` proves the same
        // boundary on Linux and cannot run here: it reads `/proc/self/fd` and
        // it asserts on a mount tree. `Layout.in_place` moves no path, so the
        // whole shape of the proof is different and needs a suite of its own.
        // `skip_foreign_checks` is left off for the same reason as the suite
        // above: a boundary proved only by a skipped run step is worth
        // nothing.
        const darwin_workspace_probe = b.addExecutable(.{
            .name = "chock-workspace-darwin-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/workspace/darwin_probe.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{.{ .name = "chock-sandbox", .module = chock_sandbox }},
            }),
        });

        const darwin_workspace_probe_path = b.addOptions();
        darwin_workspace_probe_path.addOptionPath("probe_path", darwin_workspace_probe.getEmittedBin());

        const darwin_workspace_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/workspace/darwin_escape.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    .{ .name = "darwin_workspace_probe_path", .module = darwin_workspace_probe_path.createModule() },
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                    .{ .name = "chock-workspace", .module = chock_workspace },
                },
            }),
        });
        test_step.dependOn(&b.addRunArtifact(darwin_workspace_tests).step);
    }

    // Linux only, by `linux_only` above. test/broker/actions.zig proves the
    // separation on a running system: the broker does an act the user approved,
    // and a real sandbox spawned after that act still cannot reach what the
    // broker reached. It drives the same escape probe test/workspace/escape.zig
    // drives, and Sandbox.spawn refuses on Darwin with error.NoMountNamespace,
    // so there is no sandbox for these tests to ask a question of there.
    if (linux_only) {
        // A real HTTP server on 127.0.0.1, the same one
        // lib/chock-provider/Client.zig's own tests drive. Named as a module
        // rather than reached by a relative path, because Zig 0.16 refuses a
        // relative @import that leaves a module's own root and
        // test/broker/actions.zig is its own root.
        const fake_provider = b.createModule(.{
            .root_source_file = b.path("test/core/fake_provider.zig"),
            .target = target,
            .optimize = optimize,
        });

        const broker_action_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/broker/actions.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-broker", .module = chock_broker },
                    .{ .name = "chock-policy", .module = chock_policy },
                    .{ .name = "chock-proto", .module = chock_proto },
                    .{ .name = "chock-workspace", .module = chock_workspace },
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                    .{ .name = "fake_provider", .module = fake_provider },
                    .{ .name = "escape_probe_path", .module = escape_probe_path_module.? },
                },
            }),
        });
        const run_broker_action_tests = b.addRunArtifact(broker_action_tests);
        run_broker_action_tests.skip_foreign_checks = true;
        // Same reasoning as run_workspace_tests above: each git test sets its
        // own GIT_CEILING_DIRECTORIES.
        test_step.dependOn(&run_broker_action_tests.step);

        // test/broker/git_shim.zig proves the honest half of the git shim on a
        // running system: the shim prevents a mistake and does not prevent an
        // attack, so it runs the real git by its absolute path with no shim
        // anywhere and shows the push still fails for want of a network. Its
        // own root, and it shares `test/broker/support.zig` with the actions
        // suite through a plain relative import, since both roots sit in the
        // same directory.
        const broker_shim_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/broker/git_shim.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-workspace", .module = chock_workspace },
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                    .{ .name = "escape_probe_path", .module = escape_probe_path_module.? },
                },
            }),
        });
        const run_broker_shim_tests = b.addRunArtifact(broker_shim_tests);
        run_broker_shim_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_broker_shim_tests.step);

        // test/broker/fetch.zig drives the fetch tool against real HTTP
        // servers on the loopback interface: a real redirect, a real hop the
        // policy refuses, and a real robots.txt. The unit tests beside
        // lib/chock-broker/fetch.zig touch no socket, so none of them can
        // prove that a denied hop is never opened.
        //
        // Linux only, and for its own reason rather than the sandbox one above:
        // a redirect that has to be refused needs two distinct hosts, and
        // 127.0.0.1 and 127.0.0.2 are both on `lo` on Linux and are not on
        // Darwin, where only 127.0.0.1 is configured.
        const broker_fetch_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/broker/fetch.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-broker", .module = chock_broker },
                    .{ .name = "chock-policy", .module = chock_policy },
                },
            }),
        });
        const run_broker_fetch_tests = b.addRunArtifact(broker_fetch_tests);
        run_broker_fetch_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_broker_fetch_tests.step);
    }

    // The provider instances a user configured, and where a credential for one
    // of them is found. Like chock-sandbox, chock-io and chock-policy, it
    // imports no other chock library and has no build.zig of its own: `chock
    // login` runs before a session, a workspace, or a sandbox exists, so it
    // must not need any of them.
    const chock_auth = b.addModule("chock-auth", .{
        .root_source_file = b.path("lib/chock-auth.zig"),
        .target = target,
        .optimize = optimize,
    });

    const auth_tests = b.addTest(.{ .root_module = chock_auth });
    const run_auth_tests = b.addRunArtifact(auth_tests);
    // Same reasoning as run_sandbox_tests above.
    run_auth_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_auth_tests.step);

    // check.zig's own tests need a real socket server, test/core/fake_provider.zig,
    // to drive std.http.Client against, and Zig 0.16 refuses a relative @import
    // that reaches outside a file's own module. Its own module, rooted beside
    // fake_provider.zig, for the same reason and in the same shape as
    // test/core/client.zig above.
    const auth_check_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/check.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "chock-auth", .module = chock_auth }},
        }),
    });
    const run_auth_check_tests = b.addRunArtifact(auth_check_tests);
    run_auth_check_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_auth_check_tests.step);

    // Two terminals running chock login at once, which is the ordinary case. The
    // store is shared through the filesystem, so the logins that race for it
    // have to be real processes: flock locks an open file description, and two
    // Store.put calls inside one test binary would contend correctly and say
    // nothing about two commands. See test/auth/concurrent.zig for the numbers
    // before and after.
    //
    // Linux only, because store.Driver is chosen at compile time and the Darwin
    // one is the Keychain: this test would write to the Keychain of whoever ran
    // the build. What it measures, the index and its lock, is the same code on
    // both.
    if (linux_only) {
        const login_helper = b.addExecutable(.{
            .name = "chock-auth-login-helper",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/auth/login_helper.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "chock-auth", .module = chock_auth }},
            }),
        });

        const login_helper_path_options = b.addOptions();
        login_helper_path_options.addOptionPath("login_helper_path", login_helper.getEmittedBin());

        const auth_concurrent_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/auth/concurrent.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-auth", .module = chock_auth },
                    .{ .name = "login_helper_path", .module = login_helper_path_options.createModule() },
                },
            }),
        });
        const run_auth_concurrent_tests = b.addRunArtifact(auth_concurrent_tests);
        run_auth_concurrent_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_auth_concurrent_tests.step);
    }

    // What a project's Nix dev shell states: the environment a tool call runs
    // with, and the store paths the sandbox mounts for it. Like chock-sandbox,
    // chock-io, chock-policy and chock-auth, it imports no other chock library:
    // a dev shell is evaluated before a session, a workspace, or a sandbox
    // exists, so it must not need any of them.
    const chock_nix = b.addModule("chock-nix", .{
        .root_source_file = b.path("lib/chock-nix.zig"),
        .target = target,
        .optimize = optimize,
    });

    const nix_tests = b.addTest(.{ .root_module = chock_nix });
    const run_nix_tests = b.addRunArtifact(nix_tests);
    // Same reasoning as run_sandbox_tests above.
    run_nix_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_nix_tests.step);

    // The sibling of chock-nix, for a person with no Nix: what a container
    // image states, and the directories the sandbox mounts for it. It answers
    // the same two questions and hands back the same shape of value. Like
    // chock-nix it imports no other chock library, for the same reason: an
    // image is read before a session, a workspace, or a sandbox exists.
    //
    // **A tool call never runs inside a container.** The image is a source of
    // files, exactly as a Nix closure is, and Chock's own sandbox is still the
    // whole boundary. See lib/chock-container.zig's own top comment for the
    // decision and the measurement behind it.
    const chock_container = b.addModule("chock-container", .{
        .root_source_file = b.path("lib/chock-container.zig"),
        .target = target,
        .optimize = optimize,
    });

    const container_tests = b.addTest(.{ .root_module = chock_container });
    const run_container_tests = b.addRunArtifact(container_tests);
    // Same reasoning as run_sandbox_tests above.
    run_container_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_container_tests.step);

    // The acceptance test, against a real container runtime and a real image.
    // Its own test target, and not a test beside the module, for the reason
    // this project learned the hard way: it once shipped an LSP client that had
    // never worked against a real server, because both stand-ins accepted what
    // no real one would. The tests beside the module drive parsers and
    // decisions over buffers, which is right and is not enough. Only a real
    // runtime can say that the commands are the right commands and that an
    // image really becomes a tree an unprivileged user can read.
    //
    // Every test here skips itself, rather than failing, on a machine with no
    // runtime or no network to fetch the image with. Linux only: the mount set
    // an image produces binds a target that is not its source, which
    // lib/chock-sandbox/darwin/driver.zig refuses by design.
    if (linux_only) {
        const container_real_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/container/real_runtime.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "chock-container", .module = chock_container }},
            }),
        });
        const run_container_real_tests = b.addRunArtifact(container_real_tests);
        run_container_real_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_container_real_tests.step);

        // The acceptance test for the central design decision: Chock's own
        // sandbox, over a root filesystem that came out of a container image,
        // with no container running. See test/container/sandbox.zig.
        //
        // A real Sandbox.spawn call needs a single threaded caller, the same
        // requirement every other sandbox probe in this project carries, so
        // the test binary never calls it. It starts this probe instead and
        // reads its exit status.
        const rootfs_probe = b.addExecutable(.{
            .name = "chock-container-rootfs-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/container/rootfs_probe.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "chock-sandbox", .module = chock_sandbox }},
            }),
        });

        // Same reasoning as every other probe path above: embed the probe's
        // path as a build time constant, since Zig 0.16's test runner cannot
        // take it as a CLI argument.
        const rootfs_probe_path_options = b.addOptions();
        rootfs_probe_path_options.addOptionPath("rootfs_probe_path", rootfs_probe.getEmittedBin());

        const container_sandbox_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/container/sandbox.zig"),
                .target = target,
                .optimize = optimize,
                // `chock-sandbox` for one question only: the exit status the
                // probe answers with when this machine will not give it a
                // sandbox at all. See that suite's own `runInside`.
                .imports = &.{
                    .{ .name = "chock-container", .module = chock_container },
                    .{ .name = "rootfs_probe_path", .module = rootfs_probe_path_options.createModule() },
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                },
            }),
        });
        const run_container_sandbox_tests = b.addRunArtifact(container_sandbox_tests);
        run_container_sandbox_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_container_sandbox_tests.step);

        // Two terminals on one project, which is the ordinary case. An image
        // cache is shared on purpose, so the sessions that race for it have to
        // be real processes: flock locks an open file description, and two
        // Image.load calls inside one test binary would contend correctly and
        // say nothing about two chock run commands. See
        // test/container/concurrent.zig for the numbers before and after.
        const load_helper = b.addExecutable(.{
            .name = "chock-container-load-helper",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/container/load_helper.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "chock-container", .module = chock_container }},
            }),
        });

        const load_helper_path_options = b.addOptions();
        load_helper_path_options.addOptionPath("load_helper_path", load_helper.getEmittedBin());

        const container_concurrent_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/container/concurrent.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "load_helper_path", .module = load_helper_path_options.createModule() },
                },
            }),
        });
        const run_container_concurrent_tests = b.addRunArtifact(container_concurrent_tests);
        run_container_concurrent_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_container_concurrent_tests.step);
    }

    // What a plugin host and a plugin guest both need: the types, the magic,
    // and the metadata format as pure functions over bytes. Like
    // chock-sandbox and chock-policy, it imports no other chock library, and
    // for a harder reason than they have: `chock-plugin-sdk` builds it into
    // every plugin, so it must compile for `wasm32-freestanding` where there
    // is no file, no socket, and no allocator worth having. That is also why
    // the call ABI lives here: both sides read one file for where an answer
    // is, and the guest half of it has to compile with no host at all.
    //
    // Declared before chock-core, which imports it: chock_core.plugin_module
    // reads a plugin out of a wasm module and reads its metadata with this
    // same library, so the host and the guest can never disagree about the
    // format.
    const chock_plugin_core = b.addModule("chock-plugin-core", .{
        .root_source_file = b.path("lib/chock-plugin-core.zig"),
        .target = target,
        .optimize = optimize,
    });

    const plugin_core_tests = b.addTest(.{ .root_module = chock_plugin_core });
    const run_plugin_core_tests = b.addRunArtifact(plugin_core_tests);
    // Same reasoning as run_sandbox_tests above.
    run_plugin_core_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_plugin_core_tests.step);

    // The tool definitions, the dispatch, and the two tools. See the design
    // spec sections 5, part of 10, and 13. This is the first library whose
    // output can change something on the machine, so it imports
    // chock-sandbox directly, the same way chock-workspace already does,
    // for the one Sandbox.Config and Sandbox.spawn every tool call goes
    // through. It also imports chock-proto directly, for the tool.call and
    // tool.result event types dispatch reads and builds, chock-provider,
    // for the tool definition shape a caller offers the model, and chock-io,
    // for the close-on-exec pipe spawnCapturing reads a sandboxed program's
    // output from.
    //
    // It imports chock-policy for two things, and neither is the table. The
    // first is the subagent limits, which the loop measures a spawn request
    // against because the loop is what holds the session state those limits
    // count. The second is the policy ratchet: the loop decides whether a
    // promise an agent makes about itself narrows or widens the promises that
    // session already holds, which it reads from its own folded log. **It never
    // evaluates the policy table**, which stays the broker's job, and
    // chock-core still imports no chock-broker: see lib/chock-core/Loop.zig's
    // own top comment.
    const chock_core = b.addModule("chock-core", .{
        .root_source_file = b.path("lib/chock-core.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "chock-sandbox", .module = chock_sandbox },
            .{ .name = "chock-proto", .module = chock_proto },
            .{ .name = "chock-provider", .module = chock_provider },
            .{ .name = "chock-io", .module = chock_io },
            .{ .name = "chock-cost", .module = chock_cost },
            .{ .name = "chock-policy", .module = chock_policy },
            // For chock_core.plugin_module, which reads a plugin's metadata
            // out of a wasm module with the very same reader the guest wrote
            // it with. A second copy of the format on the host side is the
            // one thing that would let a plugin and a Chock disagree about
            // what a plugin said.
            .{ .name = "chock-plugin-core", .module = chock_plugin_core },
        },
    });

    // Only the two tests in lib/chock-core/tools.zig itself run inside this
    // test binary: dispatch checks a tool call's own name before it ever
    // builds a Sandbox.Config, so those two tests never call Sandbox.spawn.
    // Every test that names a real tool needs tools_probe below instead.
    const core_tests = b.addTest(.{ .root_module = chock_core });
    const run_core_tests = b.addRunArtifact(core_tests);
    run_core_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_core_tests.step);

    // Linux only, by `linux_only` above. Every one of the thirteen tests in
    // test/core/tools.zig goes through the probe below, and the probe calls
    // chock_core.tools.Registry.dispatch, which builds a real sandbox.Config
    // and calls Sandbox.spawn for every tool call, including the read_file
    // ones. Sandbox.spawn refuses on Darwin, with error.NoMountNamespace, so
    // not one of these tests has a mechanism to assert against there. The two
    // tests that only look like plain path checks, "read_file refuses a path
    // that climbs out with .." and "read_file refuses an absolute path", still
    // reach dispatch, so they are gated with the rest rather than left behind.
    if (linux_only) {
        // test/core/tools.zig's own probe: like chock-sandbox-probe,
        // chock-workspace-overlay-helper, and chock-workspace-escape-probe, this
        // needs a single threaded caller to call Sandbox.spawn (by way of
        // chock_core.tools.Registry.dispatch), so it cannot run inside the zig
        // test binary itself. See test/core/tools_probe.zig's own top comment.
        const tools_probe = b.addExecutable(.{
            .name = "chock-core-tools-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/core/tools_probe.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                    .{ .name = "chock-core", .module = chock_core },
                },
            }),
        });

        // Same reasoning as probe_path_options above: embed the helper's path as
        // a build time constant, since Zig 0.16's test runner cannot take it as
        // a CLI argument.
        const tools_probe_path_options = b.addOptions();
        tools_probe_path_options.addOptionPath("tools_probe_path", tools_probe.getEmittedBin());

        const tools_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/core/tools.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-workspace", .module = chock_workspace },
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                    // For the bounds the searching tools keep. This suite
                    // reads them from the library rather than writing the
                    // numbers out a second time, so a bound that changes
                    // changes the test with it.
                    .{ .name = "chock-core", .module = chock_core },
                    // For the one test that proves an instruction file in a
                    // project cannot widen what the agent may do: it asks
                    // the real policy table what it answers, beside asking
                    // the real sandbox what it refuses.
                    .{ .name = "chock-policy", .module = chock_policy },
                    .{ .name = "tools_probe_path", .module = tools_probe_path_options.createModule() },
                },
            }),
        });
        const run_tools_tests = b.addRunArtifact(tools_tests);
        run_tools_tests.skip_foreign_checks = true;
        // Same reasoning as run_workspace_tests above: each git test sets its
        // own GIT_CEILING_DIRECTORIES.
        test_step.dependOn(&run_tools_tests.step);

        // The language server, end to end, through a real sandbox. Linux only
        // for the same reason as the tools suite above: it starts a real
        // `Sandbox.spawn`, which refuses on Darwin. The probe is both halves of
        // the pipe, so this needs no language server installed on the machine:
        // see test/core/lsp_probe.zig's own top comment for what that leaves
        // out.
        const lsp_probe = b.addExecutable(.{
            .name = "chock-core-lsp-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/core/lsp_probe.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                    .{ .name = "chock-core", .module = chock_core },
                },
            }),
        });

        // The same chain again, with a **real `zls`** on the far side of the
        // pipe instead of a probe written to answer what the driver expects.
        // See test/core/lsp_zls_probe.zig for the class of fault only that can
        // reach, and for the one it found.
        const lsp_zls_probe = b.addExecutable(.{
            .name = "chock-core-lsp-zls-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/core/lsp_zls_probe.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                    .{ .name = "chock-core", .module = chock_core },
                },
            }),
        });

        const lsp_probe_path_options = b.addOptions();
        lsp_probe_path_options.addOptionPath("lsp_probe_path", lsp_probe.getEmittedBin());
        lsp_probe_path_options.addOptionPath("lsp_zls_probe_path", lsp_zls_probe.getEmittedBin());
        // **Found here and never at test time, and null is an ordinary
        // answer.** A test that provisioned a language server would fetch,
        // build and evaluate on every run, which is a build and not a test, so
        // the program is one the dev shell already put on this PATH:
        // pkgs/chock/default.nix names it. A machine without one skips the
        // test that needs it rather than failing it.
        lsp_probe_path_options.addOption(
            ?[]const u8,
            "zls_path",
            b.findProgram(&.{"zls"}, &.{}) catch null,
        );

        const lsp_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/core/lsp.zig"),
                .target = target,
                .optimize = optimize,
                // `chock-sandbox` for one question only: the exit status a
                // probe answers with when this machine will not give it a
                // sandbox at all. See that suite's `skipIfNothingMeasured`.
                .imports = &.{
                    .{ .name = "lsp_probe_path", .module = lsp_probe_path_options.createModule() },
                    .{ .name = "chock-sandbox", .module = chock_sandbox },
                },
            }),
        });
        const run_lsp_tests = b.addRunArtifact(lsp_tests);
        run_lsp_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_lsp_tests.step);
    }

    // A **real MCP server**, driven by the production protocol. See
    // test/core/mcp_real.zig for the class of fault only a real server can
    // reach, and for the one it found before the driver was written.
    //
    // **Not Linux only**, unlike the language server suite above: this needs
    // no sandbox at all, because an MCP server speaks over two ordinary pipes
    // and chock_core.helper.Channel is exactly that. So Darwin, where
    // Sandbox.spawn refuses, still carries the protocol half of the check.
    const mcp_real_path_options = b.addOptions();
    // **Found here and never at test time, and null is an ordinary answer.**
    // The same rule the zls option above follows: a test that provisioned a
    // server would be a build, so the program is one the dev shell already put
    // on this PATH. pkgs/chock/default.nix names it.
    mcp_real_path_options.addOption(
        ?[]const u8,
        "mcp_server_time_path",
        b.findProgram(&.{"mcp-server-time"}, &.{}) catch null,
    );

    const mcp_real_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/mcp_real.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-policy", .module = chock_policy },
                .{ .name = "mcp_real_path", .module = mcp_real_path_options.createModule() },
            },
        }),
    });
    const run_mcp_real_tests = b.addRunArtifact(mcp_real_tests);
    run_mcp_real_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_mcp_real_tests.step);

    // One subagent, as a real second process with a log of its own. A
    // subagent that is not a process is not a subagent: `Sandbox.spawn` calls
    // `fork`, and `fork` carries only the calling thread, so an agent tree
    // built from threads deadlocks the moment a child runs a tool. **Not
    // Linux only**: nothing here needs a sandbox, a namespace or a mount, so
    // the boundary between a parent and a child is proven on both platforms.
    //
    // The child is `test/core/subagent_child.zig` and not `chock run` itself:
    // see that file's own top comment for what that leaves out and what it
    // keeps real.
    const subagent_child = b.addExecutable(.{
        .name = "chock-core-subagent-child",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/subagent_child.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-policy", .module = chock_policy },
                .{ .name = "chock-proto", .module = chock_proto },
            },
        }),
    });

    // Same reasoning as probe_path_options above: embed the helper's path as a
    // build time constant, since Zig 0.16's test runner cannot take it as a
    // CLI argument.
    const subagent_child_path_options = b.addOptions();
    subagent_child_path_options.addOptionPath("subagent_child_path", subagent_child.getEmittedBin());

    const subagent_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/subagent.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-proto", .module = chock_proto },
                .{ .name = "subagent_child_path", .module = subagent_child_path_options.createModule() },
            },
        }),
    });
    const run_subagent_tests = b.addRunArtifact(subagent_tests);
    run_subagent_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_subagent_tests.step);

    // The one Loop.run test that needs a real HTTP round trip, so it needs
    // test/core/fake_provider.zig the same way test/core/client.zig does:
    // Zig 0.16 refuses a relative @import that reaches outside a module's
    // own root, so lib/chock-core/Loop.zig cannot import fake_provider.zig
    // directly, and every other Loop.run test lives inside Loop.zig itself
    // instead, against in memory test doubles that need no socket.
    const loop_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/loop.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-provider", .module = chock_provider },
                .{ .name = "chock-proto", .module = chock_proto },
                .{ .name = "chock-core", .module = chock_core },
            },
        }),
    });
    const run_loop_tests = b.addRunArtifact(loop_tests);
    run_loop_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_loop_tests.step);

    // A tree of real agents, each one a process that is a child of the level
    // above it and a parent of the level below it. `chock-core-subagent-child`
    // above is one child and stops there; **everything above one child was
    // claimed and never run**: two children at once, a grandchild, a slice of a
    // slice, and a parent that resumed. See `test/core/tree_child.zig`.
    //
    // **Not Linux only**, for the same reason the one child suite is not:
    // nothing here needs a sandbox, a namespace or a mount.
    const tree_child = b.addExecutable(.{
        .name = "chock-core-tree-child",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/tree_child.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-cost", .module = chock_cost },
                .{ .name = "chock-policy", .module = chock_policy },
                .{ .name = "chock-proto", .module = chock_proto },
            },
        }),
    });

    // Same reasoning as subagent_child_path_options above: the path is a build
    // time constant, since Zig 0.16's test runner cannot take it as a CLI
    // argument. Two test binaries read it, so it is made once here.
    const tree_child_path_options = b.addOptions();
    tree_child_path_options.addOptionPath("tree_child_path", tree_child.getEmittedBin());
    const tree_child_path = tree_child_path_options.createModule();

    const tree_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/tree.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                // For `review.default_kind` alone: a reviewer is a child the
                // width bound has to count, and the kind is read from the one
                // place it is written.
                .{ .name = "chock-broker", .module = chock_broker },
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-cost", .module = chock_cost },
                .{ .name = "chock-policy", .module = chock_policy },
                .{ .name = "chock-proto", .module = chock_proto },
                .{ .name = "tree_child_path", .module = tree_child_path },
            },
        }),
    });
    const run_tree_tests = b.addRunArtifact(tree_tests);
    run_tree_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_tree_tests.step);

    const phantom = b.dependency("phantom", .{
        .target = target,
        .optimize = optimize,
        .@"gpu-drivers" = gpu_drivers,
    });

    // The wasm engine, for `src/plugin-host.zig` and for nothing else.
    //
    // **It is here, in the one binary, because there is only one binary.**
    // `chock-plugin-host` used to be a second installed program, and
    // `src/run.zig` found it by looking in the directory `chock` itself is in,
    // so an install that moved one file and not the other lost every plugin.
    // Chock links no libc and Zig cross compiles it, which makes a single file
    // install the whole point, so the second artifact is gone and `chock`
    // re-execs itself under a hidden word instead: see
    // `chock_core.plugin_host.verb`. It is the same thing this project already
    // does for a subagent, and the plugin still gets a process of its own.
    //
    // **What that must not cost, and does not:**
    //
    // * `src/plugin-host.zig` is still the one and only file in this project
    //   that names an engine. Nothing else imports `vulcan-wasm`, and the
    //   `chock` binary reaches it through that file alone.
    // * `chock-core` still compiles with no engine at all, on every target.
    //   It holds every rule a plugin is held to, over the `plugin_engine.Engine`
    //   seam, and it does not import this.
    // * No library test binary links an engine, and neither does any of the
    //   test binaries below. The exception is `chock`'s own test binary, which
    //   is built from `src/main.zig`, the very root the shipped binary is built
    //   from. That is not a leak: it is the test of the artifact that holds the
    //   engine, and it could only be avoided by testing a different program
    //   than the one that ships.
    const vulcan = b.dependency("vulcan", .{ .target = target, .optimize = optimize });

    const exe_imports = [_]std.Build.Module.Import{
        .{ .name = "phantom", .module = phantom.module("phantom") },
        // What `chock --version` prints. See the block above.
        .{ .name = "chock-version", .module = chock_version_module },
        .{ .name = "vulcan-wasm", .module = vulcan.module("vulcan-wasm") },
        .{ .name = "chock-sandbox", .module = chock_sandbox },
        .{ .name = "chock-io", .module = chock_io },
        .{ .name = "chock-proto", .module = chock_proto },
        .{ .name = "chock-provider", .module = chock_provider },
        .{ .name = "chock-policy", .module = chock_policy },
        // `chock sessions seal` writes a seal beside a log and `chock sessions
        // verify` reads it. The binary is where the two halves meet: the key
        // comes from chock-auth and the log's digests come from chock-proto,
        // and chock-pcsc must import neither.
        .{ .name = "chock-pcsc", .module = chock_pcsc },
        .{ .name = "chock-broker", .module = chock_broker },
        .{ .name = "chock-workspace", .module = chock_workspace },
        .{ .name = "chock-core", .module = chock_core },
        .{ .name = "chock-auth", .module = chock_auth },
        .{ .name = "chock-cost", .module = chock_cost },
        // The caller is what evaluates a dev shell, for the same reason
        // it is what builds a Workspace: chock-core must do neither.
        .{ .name = "chock-nix", .module = chock_nix },
        // And the caller is what reads a container image, for the same reason
        // again. It is the other answer to where a tool call's files come from,
        // for a machine with no Nix: see lib/chock-container.zig.
        .{ .name = "chock-container", .module = chock_container },
    };

    const chock_exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &exe_imports,
    });

    const exe = b.addExecutable(.{ .name = "chock", .root_module = chock_exe_module });
    b.installArtifact(exe);

    // **Its own step, and never on `test_step`.** This is not a test that
    // passes or fails a build. It is an exercise that is run deliberately. A
    // build gate that starts a model session would spend money on every `zig
    // build test`, and a step that a person runs on purpose is what is wanted.
    //
    // `zig build redteam` builds the program and prints how to fire it.
    // `zig build redteam-oracle` proves the oracle by forging each escape and
    // checking the verdict, which needs no model and no credential, and is
    // the only part of this that could ever be automated.
    //
    // Linux only, by `linux_only` above. Every canary here reads `/proc`,
    // which macOS has not got, and the sandbox a run measures is the Linux
    // driver. This is NOT because macOS runs no tool calls. It runs real
    // sessions with four layers on: see `docs/sandbox.md`. Measuring the
    // Darwin boundary needs canaries of its own.
    if (linux_only) {
        // The harness starts `chock`, so it needs the path of the very binary
        // this build produced. Same reasoning as every probe path above: Zig
        // 0.16's test runner and this program alike take it as a build time
        // constant rather than hunting a `zig-out` that may hold an older
        // build. A run therefore measures the tree it was built from.
        const redteam_paths = b.addOptions();
        redteam_paths.addOptionPath("chock_path", exe.getEmittedBin());
        // The realistic configuration's dev shell is Chock's own, taken from
        // this repository's flake by reference rather than described a second
        // time. So the harness needs to know where the repository is, and a
        // build time constant is the one answer that cannot be a stale copy.
        redteam_paths.addOptionPath("repo_root", b.path("."));

        const redteam_module = b.createModule(.{
            .root_source_file = b.path("test/redteam/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-auth", .module = chock_auth },
                .{ .name = "chock-broker", .module = chock_broker },
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-nix", .module = chock_nix },
                .{ .name = "chock-policy", .module = chock_policy },
                .{ .name = "chock-proto", .module = chock_proto },
                .{ .name = "redteam-paths", .module = redteam_paths.createModule() },
            },
        });

        const redteam_exe = b.addExecutable(.{
            .name = "chock-redteam",
            .root_module = redteam_module,
        });
        // **Never installed.** `test/plugin/one_binary.zig` measures the
        // install list and fails on a second artifact, and it is right to:
        // `zig-out/bin` holds `chock` and nothing else, because an install is
        // one static file and a helper found by a path is what that cannot
        // survive. So the harness is run through its own step instead, and
        // `zig build redteam -- <args>` passes everything after the `--`
        // through to it. That was measured, not assumed: the first version
        // here installed it and failed that test by name.
        const run_harness = b.addRunArtifact(redteam_exe);
        if (b.args) |args| run_harness.addArgs(args);
        const redteam_step = b.step(
            "redteam",
            "The red team exercise. Pass arguments after --.",
        );
        redteam_step.dependOn(&run_harness.step);

        // Forge each escape and check that the oracle catches it, then check
        // that a clean session reports clean. No model, no credential, no
        // network: the escapes are made by this program itself, which is a
        // better test of the oracle than a model session, because the right
        // answer is known before the check runs.
        const run_oracle = b.addRunArtifact(redteam_exe);
        run_oracle.addArg("self-test");
        // **No `expectExitCode`.** Setting one puts the run into checking
        // mode, which captures the output, and this step's whole value is the
        // table of one row per forge it prints. A non-zero exit already fails the
        // step, so nothing is lost by leaving the expectation off.
        run_oracle.stdio = .inherit;
        const oracle_step = b.step(
            "redteam-oracle",
            "Forge every escape in the scope list and prove the oracle catches each one.",
        );
        oracle_step.dependOn(&run_oracle.step);

        // The harness's own unit tests: the manifest arithmetic, the scope
        // list, and the log reader. Separate from the oracle proof above,
        // and on `test_step`, because none of these starts a session.
        const redteam_tests = b.addTest(.{ .root_module = redteam_module });
        const run_redteam_tests = b.addRunArtifact(redteam_tests);
        run_redteam_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_redteam_tests.step);
    }

    // The program's own tests: the command line parsers, the exit code map,
    // where a session lives on disk, and the two decisions that read a real
    // tree of agents off it. Not one of them starts a session: that proof is
    // `zig build test`'s job for the libraries below it, and a real end to end
    // run's job for the wiring, which is what a unit test cannot give.
    //
    // **A module of its own, and not the one the binary is built from.** The
    // tree tests start `chock-core-tree-child`, so they need its path, and
    // putting that in the shipped binary's module would make every release
    // build of `chock` build a test helper. The extra import is read from a
    // test and from nowhere else, so `src/run.zig` still compiles in the
    // binary, where the module does not exist.
    const chock_exe_test_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &exe_imports,
    });
    chock_exe_test_module.addImport("tree_child_path", tree_child_path);

    // **Where `build.zig.zon` is, so a test can read the manifest itself.**
    // `src/main.zig` gets the version as a build option, and a test that
    // compared that option against itself would prove nothing. So the test
    // opens the manifest and reads the number out of it, and it fails the day
    // the option stops carrying what the manifest says.
    //
    // Same reasoning as `chock_path_options` below for the shape: the path is
    // a build time constant, since Zig 0.16's test runner cannot take it as an
    // argument. On the test module alone, so the shipped binary holds no
    // absolute path from the machine that built it.
    const manifest_path_options = b.addOptions();
    manifest_path_options.addOptionPath("manifest_path", b.path("build.zig.zon"));
    chock_exe_test_module.addImport("manifest_path", manifest_path_options.createModule());

    const exe_tests = b.addTest(.{ .root_module = chock_exe_test_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    // Same reasoning as run_sandbox_tests above.
    run_exe_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_exe_tests.step);

    // The two streams of the **built binary**, read apart. Every test in
    // `src/tty.zig` sets the streams itself, so a `main` that never wired them
    // would pass all of them: only a real process has a real fd 1 and a real
    // fd 2. See `test/cli/streams.zig`, which says what it can see that a unit
    // test cannot.
    //
    // Same reasoning as probe_path_options below: the path is a build time
    // constant, since Zig 0.16's test runner cannot take it as an argument.
    const chock_path_options = b.addOptions();
    chock_path_options.addOptionPath("chock_path", exe.getEmittedBin());
    // **Where `git` is, found here and not in the test.** One of those tests
    // starts a real session, which builds a workspace, which spawns `git`. A
    // test binary has no environment of its own to search: `std.Io.Threaded`
    // resolves a bare `argv[0]` against the `environ` it was built with, which
    // is nothing in a test, and it then falls back to a compiled in
    // `/usr/local/bin:/bin:/usr/bin` where a Nix machine has no `git` at all.
    // The build script does have the environment, so it answers once.
    //
    // An empty string when this machine has none, which the test reads as a
    // reason to skip rather than as a path to try.
    chock_path_options.addOption(
        []const u8,
        "git_path",
        b.findProgram(&.{"git"}, &.{}) catch "",
    );

    const cli_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/cli/streams.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock_path", .module = chock_path_options.createModule() },
                .{ .name = "chock_main", .module = chock_exe_module },
            },
        }),
    });
    const run_cli_tests = b.addRunArtifact(cli_tests);
    // These spawn the binary that was just built, so a build for another
    // machine has nothing it can run.
    run_cli_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_cli_tests.step);

    // test/broker/askpass.zig drives the askpass helper with the git on this
    // machine: GIT_ASKPASS points at the binary that was just built, and `git
    // credential fill` really asks it for a password. The unit tests beside
    // lib/chock-broker/askpass.zig drive a real socket and no git at all, so
    // none of them can say whether git ever reaches that socket, or whether
    // what comes back is a password as far as git is concerned.
    //
    // It sits here rather than beside the other three broker suites above
    // because it needs `chock_path_options`, which cannot exist until the
    // binary does. Linux only: one test reads `/proc/<pid>/environ` to show
    // what `ps` would have seen while the helper ran.
    if (linux_only) {
        const broker_askpass_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/broker/askpass.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-broker", .module = chock_broker },
                    .{ .name = "chock-policy", .module = chock_policy },
                    .{ .name = "chock-proto", .module = chock_proto },
                    .{ .name = "chock_path", .module = chock_path_options.createModule() },
                },
            }),
        });
        const run_broker_askpass_tests = b.addRunArtifact(broker_askpass_tests);
        // These spawn the binary that was just built, so a build for another
        // machine has nothing it can run.
        run_broker_askpass_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_broker_askpass_tests.step);
    }

    // The guest half: what a plugin author imports. It reads the author's own
    // `chock_plugin_metadata` while the plugin compiles and emits the guest
    // symbols, so it is a compiler and not a header.
    const chock_plugin_sdk = b.addModule("chock-plugin-sdk", .{
        .root_source_file = b.path("lib/chock-plugin-sdk.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "chock-plugin-core", .module = chock_plugin_core },
            .{ .name = "chock-version", .module = chock_version_module },
        },
    });

    // `@import("root")` is this test binary itself, and this binary's root
    // declares no plugin, so the export block emits nothing here. The plugin
    // it does emit for is `test/plugin/guest.zig` below.
    const plugin_sdk_tests = b.addTest(.{ .root_module = chock_plugin_sdk });
    const run_plugin_sdk_tests = b.addRunArtifact(plugin_sdk_tests);
    run_plugin_sdk_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_plugin_sdk_tests.step);

    // The plugin the project ships, as a module an author would get. Two test
    // targets and one wasm build all use this same file, so no copy of it can
    // drift from the one an author reads.
    const hello_plugin_module = b.createModule(.{
        .root_source_file = b.path("plugins/hello.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "chock-plugin-sdk", .module = chock_plugin_sdk }},
    });

    // The guest half against the real plugin. This test binary's own root
    // declares `chock_plugin_metadata`, which is what makes the SDK emit the
    // three guest symbols into it, so the tests read the bytes a plugin
    // really carries instead of a copy built for the test.
    const plugin_guest_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/plugin/guest.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-plugin-core", .module = chock_plugin_core },
                .{ .name = "chock-plugin-sdk", .module = chock_plugin_sdk },
                .{ .name = "chock-plugin", .module = hello_plugin_module },
            },
        }),
    });
    const run_plugin_guest_tests = b.addRunArtifact(plugin_guest_tests);
    run_plugin_guest_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_plugin_guest_tests.step);

    // The same plugin for the target it will really run on. **Not gated on
    // the host target**: a plugin is wasm wherever Chock runs, so this builds
    // on Linux and on Darwin alike, and it is what proves chock-plugin-core
    // and chock-plugin-sdk compile with no host, no libc, and no allocator.
    //
    // The root source file is the SDK's `start.zig` and not the author's own
    // file. Zig analyses a declaration when something reaches it, and an
    // author's file reaches nothing, so a plugin rooted at the author's file
    // compiles and exports nothing at all. See that file's own top comment.
    const plugin_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });

    const plugin_core_wasm = b.createModule(.{
        .root_source_file = b.path("lib/chock-plugin-core.zig"),
        .target = plugin_target,
        .optimize = optimize,
    });

    const plugin_sdk_wasm = b.createModule(.{
        .root_source_file = b.path("lib/chock-plugin-sdk.zig"),
        .target = plugin_target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "chock-plugin-core", .module = plugin_core_wasm },
            .{ .name = "chock-version", .module = chock_version_module },
        },
    });

    const hello_plugin_wasm = b.createModule(.{
        .root_source_file = b.path("plugins/hello.zig"),
        .target = plugin_target,
        .optimize = optimize,
        .imports = &.{.{ .name = "chock-plugin-sdk", .module = plugin_sdk_wasm }},
    });

    const hello_wasm = b.addExecutable(.{
        .name = "chock-plugin-hello",
        .root_module = b.createModule(.{
            .root_source_file = b.path("lib/chock-plugin-sdk/start.zig"),
            .target = plugin_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-plugin-sdk", .module = plugin_sdk_wasm },
                .{ .name = "chock-plugin", .module = hello_plugin_wasm },
            },
        }),
    });
    // A plugin has no entry point. The host reads its metadata and then calls
    // `chock_plugin_init`, and `rdynamic` is what keeps the three symbols in
    // the module for it to find.
    hello_wasm.entry = .disabled;
    hello_wasm.rdynamic = true;
    test_step.dependOn(&hello_wasm.step);

    b.getInstallStep().dependOn(&b.addInstallLibFile(hello_wasm.getEmittedBin(), b.pathJoin(&.{
        "chock",
        b.fmt("{}.{}", .{ chock_version.major, chock_version.minor }),
        "plugins",
        hello_wasm.out_filename,
    })).step);

    // The built module, read back. This is the only test of the SDK's
    // automatic path, where the export block reads
    // `@import("root").chock_plugin_metadata` with nobody calling it: a
    // plugin built the wrong way compiles and exports nothing, and only a
    // look at the module says so. See `test/plugin/wasm.zig`.
    //
    // Same reasoning as probe_path_options above: embed the module's path as
    // a build time constant, since Zig 0.16's test runner cannot take it as a
    // CLI argument.
    const plugin_wasm_path_options = b.addOptions();
    plugin_wasm_path_options.addOptionPath("plugin_wasm_path", hello_wasm.getEmittedBin());

    const plugin_wasm_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/plugin/wasm.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-plugin-core", .module = chock_plugin_core },
                // The host side reader and the decisions on top of it, which
                // are what this test drives against the real module.
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-policy", .module = chock_policy },
                // The author's file for the native target, so the test can
                // lower the same declaration and compare it against what the
                // module carries.
                .{ .name = "chock-plugin", .module = hello_plugin_module },
                .{ .name = "plugin_wasm_path", .module = plugin_wasm_path_options.createModule() },
            },
        }),
    });
    const run_plugin_wasm_tests = b.addRunArtifact(plugin_wasm_tests);
    run_plugin_wasm_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_plugin_wasm_tests.step);

    // The acceptance test, and the only one in this project that runs guest
    // code.
    //
    // It drives the real host process, over a real pipe, with the real module
    // built above and the real engine, so the framing, the call ABI and the
    // bounded reads of guest memory are all the production ones. Every other
    // test of this feature drives a peer written by the same hand: see
    // `lib/chock-core/plugin_host.zig`'s own note.
    //
    // **The host process is `chock` itself**, started under
    // `chock_core.plugin_host.verb`. So the program this test drives is the
    // very program a person installs, and not a helper built beside it: see
    // the `vulcan` dependency above.
    //
    // Both paths are build time constants, for the reason
    // `plugin_wasm_path_options` above gives.
    const engine_paths = b.addOptions();
    engine_paths.addOptionPath("plugin_wasm_path", hello_wasm.getEmittedBin());
    engine_paths.addOptionPath("chock_path", exe.getEmittedBin());

    const plugin_engine_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/plugin/engine.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-plugin-core", .module = chock_plugin_core },
                .{ .name = "chock-policy", .module = chock_policy },
                // For the one test that starts a plugin host the way a session
                // starts it: the mount tree, the Landlock rules and the
                // lockdown are all sandbox values.
                .{ .name = "chock-sandbox", .module = chock_sandbox },
                .{ .name = "engine_paths", .module = engine_paths.createModule() },
            },
        }),
    });
    // The test spawns the host process and reads the module, so both have to
    // exist before it runs. `addOptionPath` records where they will be and
    // does not itself order the steps.
    plugin_engine_tests.step.dependOn(&exe.step);
    plugin_engine_tests.step.dependOn(&hello_wasm.step);
    const run_plugin_engine_tests = b.addRunArtifact(plugin_engine_tests);
    run_plugin_engine_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_plugin_engine_tests.step);

    // **The install list, read out of the install step itself and handed to a
    // test.** `chock` is a static binary that links no libc and Zig cross
    // compiles it, so a person installs one file, and a second artifact found
    // by a path is what a one file install cannot survive. That is not a rule a
    // reader can keep on their own: `b.installArtifact` is one line, and the
    // program it installs would be found or not found at run time, on somebody
    // else's machine.
    //
    // **Last in this file, and it has to be.** It reads what every call above
    // it added, so a `b.installArtifact` after this point would not be counted.
    //
    // Read here rather than by listing `zig-out/bin`: `zig build test` installs
    // nothing, and a directory left over from an older build would answer for a
    // program this build does not produce, which is the wrong answer in both
    // directions.
    var installed: std.ArrayList([]const u8) = .empty;
    for (b.install_tls.step.dependencies.items) |step| {
        const install = step.cast(std.Build.Step.InstallArtifact) orelse continue;
        installed.append(b.allocator, install.artifact.name) catch @panic("OOM");
    }

    const install_names = b.addOptions();
    install_names.addOption([]const []const u8, "installed", installed.items);

    const one_binary_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/plugin/one_binary.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "install_names", .module = install_names.createModule() },
            },
        }),
    });
    const run_one_binary_tests = b.addRunArtifact(one_binary_tests);
    run_one_binary_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_one_binary_tests.step);

    // **No test binary may write a byte to standard error.** `zig build` puts a
    // `failed command:` line in the log for any run step that wrote there,
    // whatever the step's exit status, so a note from a passing test reads like
    // a failure. That has already cost this project one wrong diagnosis, where
    // a whole suite was called broken because of a single chatty test.
    //
    // **Measured and not read.** `test/proto/lock.zig` greps the sources for
    // two spellings, which is a check of what a line says. This one reads
    // `result_stderr`, the very field `zig build` reacts to, so it sees the
    // bytes however they were written: `tty.print` with no stream set,
    // `std.debug`, a raw `write`, or a child that inherited the descriptor.
    // The `failed command:` line stops being cosmetic and fails the build.
    //
    // **Last in this file, and it has to be**, because it reads the run steps
    // every call above it hung on `test_step`. Only `.zig_test` steps are
    // taken: a helper program a test starts is not a test binary, and the
    // choice of what its output does belongs to the spawn that starts it.
    const quiet_tests = b.allocator.create(std.Build.Step) catch @panic("OOM");
    quiet_tests.* = .init(.{
        .id = .custom,
        .name = "quiet test binaries",
        .owner = b,
        .makeFn = failOnTestStderr,
    });
    for (test_step.dependencies.items) |step| {
        const run = step.cast(std.Build.Step.Run) orelse continue;
        if (run.stdio != .zig_test) continue;
        quiet_tests.dependOn(step);
    }
    test_step.dependOn(quiet_tests);
}

/// Fail the build when a test binary this step waited on wrote to standard
/// error. A dependency that failed on its own never reaches here: the build
/// runner marks a step with a failed dependency `dependency_failure` and does
/// not run it, so a real test failure is reported once and not twice.
///
/// **What this cannot see is a run step `zig build` did not run.** A cache hit
/// leaves `result_stderr` empty, exactly as it leaves the `failed command:`
/// line out of the log, so this answers for the runs of this build alone.
fn failOnTestStderr(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
    _ = options;
    const gpa = step.owner.allocator;

    var noisy: std.ArrayList(u8) = .empty;
    for (step.dependencies.items) |dep| {
        if (dep.result_stderr.len == 0) continue;
        const run = dep.cast(std.Build.Step.Run) orelse continue;
        const named = named: {
            const producer = run.producer orelse break :named dep.name;
            const source = producer.root_module.root_source_file orelse break :named producer.name;
            break :named source.getDisplayName();
        };
        try noisy.print(gpa, "\n{s} wrote to standard error:\n{s}", .{ named, dep.result_stderr });
    }
    if (noisy.items.len == 0) return;

    return step.fail(
        "a passing test binary wrote to standard error, which reads in the build log " ++
            "like a failure. Give the code under test a writer the test owns, as " ++
            "`src/tty.zig`'s `Capture` does.\n{s}",
        .{noisy.items},
    );
}
