const std = @import("std");
const phantom_build = @import("phantom");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const gpu_drivers = b.option([]const u8, "gpu-drivers", "Specific GPU drivers to enable, defaults to Prism's choice.");

    // A mobile target is the remote interface, not the Chock daemon. Its root
    // receives only the protocol, UI, and remote-client imports; host-only
    // imports such as the sandbox, providers, VMM, and CLI are never attached
    // to the artifact. Keep this at the import boundary so another mobile
    // packager (notably iOS) can use the same graph when Phantom gains one.
    if (target.result.abi.isAndroid()) {
        const phantom = b.dependency("phantom", .{
            .target = target,
            .optimize = optimize,
            .@"gpu-drivers" = gpu_drivers,
        });
        const chock_proto = b.createModule(.{
            .root_source_file = b.path("lib/chock-proto.zig"),
            .target = target,
            .optimize = optimize,
        });
        const chock_core = b.createModule(.{
            .root_source_file = b.path("lib/chock-core.zig"),
            .target = target,
            .optimize = optimize,
        });
        chock_core.addImport("chock-proto", chock_proto);
        const chock_ui = b.createModule(.{
            .root_source_file = b.path("lib/chock-ui.zig"),
            .target = target,
            .optimize = optimize,
        });
        chock_ui.addImport("chock-proto", chock_proto);
        chock_ui.addImport("chock-core", chock_core);
        const remote_app = b.createModule(.{
            .root_source_file = b.path("src/web/app.zig"),
            .target = target,
            .optimize = optimize,
        });
        remote_app.addImport("phantom", phantom.module("phantom"));
        remote_app.addImport("chock-ui", chock_ui);
        remote_app.addImport("chock-proto", chock_proto);

        const app_options = phantom_build.AppOptions{
            .id = "ws.chock.android",
            .exec_name = "chock-android",
            .name = .{ .default = "Chock" },
            .summary = .{ .default = "The Chock interface for Android" },
            .android = .{
                .permissions = &.{.internet},
                .uses_cleartext_traffic = true,
            },
            .root = b.path("src/android/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-ui", .module = chock_ui },
                .{ .name = "chock-proto", .module = chock_proto },
                .{ .name = "chock-remote-app", .module = remote_app },
            },
        };
        const app = phantom_build.addApp(b, phantom, app_options);
        b.getInstallStep().dependOn(app);
        return;
    }

    const test_step = b.step("test", "Run all tests");

    // **One step a module, beside the one that runs them all.** The whole suite
    // does not finish on every machine, and a `--test-filter` is worse than it
    // looks: a filter drops every non-matching test from **analysis**, so a call
    // site a change made stale compiles only on the machine that did not run it.
    // A module's own step analyses and runs all of that module's tests.
    const module_test_steps = struct {
        fn add(owner: *std.Build, name: []const u8, what: []const u8, run: *std.Build.Step) void {
            owner.step(name, what).dependOn(run);
        }
    };

    const linux_only = target.result.os.tag == .linux;

    // Where this repository is, as an absolute path, because `zig build` can
    // start from any directory. `addOptionPath` is wrong for it: that one reads
    // the path to hash its contents and refuses a directory. The tests want the
    // string and no dependency on what is in the tree.
    const repo_root = b.pathResolve(&.{ b.root.root_dir.path orelse ".", b.root.sub_path });

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

    // A workaround module for Zig 0.17.0: see its own comment. Delete it once
    // `std.zon.parse.fromZoir` honours the node it is given. Declared first,
    // before anything that reads a block out of `chock.zon` needs it.
    const chock_zon = b.addModule("chock-zon", .{
        .root_source_file = b.path("lib/chock-zon.zig"),
        .target = target,
        .optimize = optimize,
    });
    const chock_zon_tests = b.addTest(.{ .root_module = chock_zon });
    test_step.dependOn(&b.addRunArtifact(chock_zon_tests).step);

    // Process confinement: seccomp, Landlock, namespaces, cgroups, rlimits,
    // capabilities and Seatbelt. It was Chock's own code until it became its
    // own library for other projects to use. Every module that confines a
    // process imports it directly.
    const palisade = b.dependency("palisade", .{ .target = target, .optimize = optimize }).module("palisade");

    // The links a confined call reaches the host through: the network broker,
    // the network router, the device link and the guest wire. It imports no
    // other chock library. It has no build.zig of its own, though: this root
    // build script is the only thing that builds and tests it.
    const chock_net = b.addModule("chock-net", .{
        .root_source_file = b.path("lib/chock-net.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "palisade", .module = palisade }},
    });

    const net_tests = b.addTest(.{ .root_module = chock_net });
    const run_net_tests = b.addRunArtifact(net_tests);
    // Building a test binary for a foreign target already analyses every
    // declaration `std.testing.refAllDecls` reaches, which is how this
    // project checks a Darwin build: `zig build test -Dtarget=aarch64-macos`
    // compiles every module below for that target and skips only the run,
    // because a foreign binary cannot execute on this host. Without this
    // flag the same command would fail the whole build on the first module,
    // rather than compiling every one of them and reporting every error.
    // See `std.Build.Step.Run.skip_foreign_checks`'s own doc comment.
    run_net_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_net_tests.step);
    // Kept as a local, and not folded into `module_test_steps.add`, because
    // `test/sandbox/confine.zig` further down adds to this same step: a
    // top-level step can only be created once, and the helper's own call
    // would be the second.
    const test_net_step = b.step("test-net", "Run the chock-net tests only");
    test_net_step.dependOn(&run_net_tests.step);

    // The layer for the small number of primitives std.Io does not have. Like
    // chock-net, it imports no other chock library and has no build.zig of
    // its own.
    const chock_io = b.addModule("chock-io", .{
        .root_source_file = b.path("lib/chock-io.zig"),
        .target = target,
        .optimize = optimize,
    });

    const io_tests = b.addTest(.{ .root_module = chock_io });
    const run_io_tests = b.addRunArtifact(io_tests);
    // Same reasoning as run_net_tests above: a Darwin cross build compiles
    // chock-io/darwin/driver.zig for real, including its std.c calls, and only
    // skips running the resulting binary, which this host cannot execute.
    run_io_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_io_tests.step);

    // The event types and the session log. It imports chock-io, for the one pipe
    // lib/chock-proto/log.zig's own short write test needs; besides that it imports
    // no other chock library, the same rule chock-net follows.
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
    // Run every time, for the reason the docs suite does: one of these tests
    // reads every source file in the tree when it runs, so a file this binary
    // does not import keeps the last answer it was given. A line that names
    // standard error then passes here and fails in CI.
    run_lock_tests.has_side_effects = true;
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

    // The policy table the broker evaluates. Like chock-net and chock-io,
    // it imports no other chock library and has no build.zig of its own: it
    // reads chock.zon and answers a question about one key, and nothing else in
    // Chock has to be present for that.
    const chock_policy = b.addModule("chock-policy", .{
        .root_source_file = b.path("lib/chock-policy.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "chock-zon", .module = chock_zon }},
    });

    // The directory the sandbox mounts, and the git and overlay layers that
    // build it. Only chock-net is forbidden from importing a library above
    // it. Nothing forbids chock-workspace from importing chock-net, so this
    // imports chock-net for the one Mount type a worktree's own mount list,
    // an overlay's own mount list, and Sandbox.spawn all need to agree on,
    // field for field. chock-policy comes in for the `workspace` block, whose
    // binds this builds the mount list from.
    const chock_workspace = b.addModule("chock-workspace", .{
        .root_source_file = b.path("lib/chock-workspace.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "chock-net", .module = chock_net },
            .{ .name = "palisade", .module = palisade },
            .{ .name = "chock-policy", .module = chock_policy },
            .{ .name = "chock-zon", .module = chock_zon },
        },
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
                .{ .name = "chock-net", .module = chock_net },
                .{ .name = "palisade", .module = palisade },
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
                .{ .name = "chock-net", .module = chock_net },
                .{ .name = "palisade", .module = palisade },
                .{ .name = "chock-policy", .module = chock_policy },
                .{ .name = "chock-zon", .module = chock_zon },
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
        // Like chock-net-probe and chock-workspace-overlay-helper, this
        // needs a single threaded caller to call Sandbox.spawn, so it cannot
        // run inside the zig test binary itself. See
        // test/workspace/escape_probe.zig's own top comment.
        const workspace_escape_probe = b.addExecutable(.{
            .name = "chock-workspace-escape-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/workspace/escape_probe.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
                },
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
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
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
    // The Agent Client Protocol is package-owned; Chock only maps session
    // events onto its public wire types.
    const acp_dependency = b.dependency("acp", .{ .target = target, .optimize = optimize });
    const acp = acp_dependency.module("acp");

    const chock_cost = b.addModule("chock-cost", .{
        .root_source_file = b.path("lib/chock-cost.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "chock-zon", .module = chock_zon },
            .{ .name = "chock-proto", .module = chock_proto },
        },
    });

    const cost_tests = b.addTest(.{ .root_module = chock_cost });
    const run_cost_tests = b.addRunArtifact(cost_tests);
    // Same reasoning as run_net_tests above.
    run_cost_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_cost_tests.step);

    // The provider package owns model wire formats, streaming, and its neutral
    // message types. This small Chock module converts those neutral records to
    // and from the durable session-log types.
    const llm_provider_dependency = b.dependency("llm_provider", .{ .target = target, .optimize = optimize });
    const llm_provider = llm_provider_dependency.module("llm-provider");
    const chock_provider = b.addModule("chock-provider", .{
        .root_source_file = b.path("lib/chock-provider.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "chock-proto", .module = chock_proto },
            .{ .name = "llm-provider", .module = llm_provider },
        },
    });

    const provider_tests = b.addTest(.{ .root_module = chock_provider });
    const run_provider_tests = b.addRunArtifact(provider_tests);
    run_provider_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_provider_tests.step);

    // A consumer-boundary test drives the package's real HTTP client against
    // Chock's deterministic local server.
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
    // the key. pcsc.zig owns its protocol, transport, crypto, and hardware-facing
    // tests; Chock's session tests cover the integration with its hash chain.
    const pcsc_dependency = b.dependency("pcsc", .{ .target = target, .optimize = optimize });
    const pcsc = pcsc_dependency.module("pcsc");

    const policy_tests = b.addTest(.{ .root_module = chock_policy });
    const run_policy_tests = b.addRunArtifact(policy_tests);
    // Same reasoning as run_net_tests above.
    run_policy_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_policy_tests.step);

    // The udev client, for the device identity and hotplug events a later
    // milestone wires into `lib/chock-policy/devices.zig`. That file is pure
    // and reads no udev of its own, on purpose: this dependency is what will
    // hand it a bus, a vendor id, and a product id, and nothing here builds
    // that wiring yet.
    //
    // Chock uses only the client half the package exports: linux.zig,
    // uevent.zig, context.zig, device.zig, enumerate.zig, and monitor.zig.
    // There is no rules engine, no hwdb, no udev_db, no udevadm, and no
    // daemon here, and this build links none of those in.
    //
    // **The package also pulls `blkid`, which only its rule builtins call.**
    // Nothing in Chock reaches a rule builtin. That is a published fact about
    // a package built to be depended on whole, not a shape Chock chose, and
    // the owner's call is to let the unused half sit unused rather than
    // vendor six files out of it or ask upstream for a client-only module.
    //
    // Not gated behind `linux_only`: `test/devices/udev.zig` carries its own
    // runtime check and skips itself on a target with no kernel netlink to
    // open.
    const udev = b.dependency("udev", .{ .target = target, .optimize = optimize });

    // The proof and not a library test: it opens a real netlink monitor and
    // enumerates real devices, because a fake here would prove nothing about
    // a kernel this build has not yet touched. See that file's own top
    // comment.
    const udev_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/devices/udev.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "udev", .module = udev.module("udev") }},
        }),
    });
    const run_udev_tests = b.addRunArtifact(udev_tests);
    // Same reasoning as run_net_tests above.
    run_udev_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_udev_tests.step);

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
    // It imports chock-net for one type, `Sandbox.NetBroker`: the seam a
    // filtered sandbox asks for a connection through. The decision belongs
    // here, beside the policy table, and the mechanism belongs there, beside
    // the namespaces, so one of the two has to name the other.
    // chock-workspace already imports chock-net for the same shape of
    // reason, and chock-net imports no chock library at all, so this makes
    // no cycle. See lib/chock-broker/network.zig's own top comment.
    const chock_broker = b.addModule("chock-broker", .{
        .root_source_file = b.path("lib/chock-broker.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "chock-proto", .module = chock_proto },
            .{ .name = "chock-policy", .module = chock_policy },
            .{ .name = "chock-workspace", .module = chock_workspace },
            .{ .name = "chock-net", .module = chock_net },
            .{ .name = "palisade", .module = palisade },
            .{ .name = "chock-version", .module = chock_version_module },
        },
    });

    const broker_tests = b.addTest(.{ .root_module = chock_broker });
    const run_broker_tests = b.addRunArtifact(broker_tests);
    // Same reasoning as run_net_tests above.
    run_broker_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_broker_tests.step);

    // Linux only, by `linux_only` above: every test in test/sandbox/escape.zig
    // asserts on a Landlock rule, a seccomp filter, a namespace, or a mount.
    // None of those exist on another target.
    //
    // **This block sits below chock-broker and not beside chock-net, and
    // that is on purpose.** The filtered network tests need the real
    // `chock_broker.network.Network` over a real `chock_policy` table on the
    // parent side of a real `Sandbox.spawn`. A stand-in broker written inside
    // the probe would be a protocol tested only against something more
    // permissive than the thing that ships, which is one of the two shapes of
    // vacuous test this project has been caught by. The probe is a test
    // program and not a library, so it is free to import whatever a test
    // needs: test/broker/actions.zig already imports chock-net for the
    // same reason in the other direction.
    if (linux_only) {
        const probe = b.addExecutable(.{
            .name = "chock-net-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/probe.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
                    .{ .name = "chock-broker", .module = chock_broker },
                    .{ .name = "chock-policy", .module = chock_policy },
                    // For a real chock_proto.storage.Memory and a real
                    // Broker.request, driven from inside this probe's own
                    // Sandbox.spawn: see test/sandbox/probe.zig's own
                    // AskArbiter and askingEscape.
                    .{ .name = "chock-proto", .module = chock_proto },
                },
            }),
        });

        // **A second, dynamically linked program, for the path record.** The
        // probe above is statically linked, so it never runs a dynamic loader,
        // and a path audit tested only against it is tested against a program
        // that opens nothing it did not ask for. Linking libc is what makes
        // this one dynamic: the interpreter and every library it opens live
        // under the toolchain tree, which is a mount every "spawn-" operation
        // declares. See test/sandbox/dynamic_probe.zig.
        const dynamic_probe = b.addExecutable(.{
            .name = "chock-net-dynamic-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/dynamic_probe.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });

        // The test needs the path of the probe program. Zig 0.16 removed the argv access
        // that would let addArtifactArg hand the path to a test at run time, and the
        // default test runner panics on any argv it does not recognize. Embed the path
        // as a build time constant instead.
        const probe_path_options = b.addOptions();
        probe_path_options.addOptionPath("probe_path", probe.getEmittedBin());

        // The same trick again, for the probe that runs the dynamic program:
        // the path is a build time constant inside the probe rather than an
        // argument, because the probe is what binds the program into a sandbox
        // root of its own.
        const dynamic_probe_path_options = b.addOptions();
        dynamic_probe_path_options.addOptionPath(
            "dynamic_probe_path",
            dynamic_probe.getEmittedBin(),
        );
        probe.root_module.addImport(
            "dynamic_probe_path",
            dynamic_probe_path_options.createModule(),
        );

        const escape_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/escape.zig"),
                .target = target,
                .optimize = optimize,
                // `chock-net` for one question only: the exit status a
                // probe answers with when this machine will not give it a
                // sandbox at all. See that suite's own `skipIfNothingMeasured`,
                // and `test/sandbox/darwin_escape.zig`, which takes the same
                // narrow import for `confinedAlready`.
                .imports = &.{
                    .{ .name = "probe_path", .module = probe_path_options.createModule() },
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
                },
            }),
        });
        const run_escape_tests = b.addRunArtifact(escape_tests);
        run_escape_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_escape_tests.step);
    }

    // Linux and macOS, and nothing else: every test in test/sandbox/confine.zig
    // forks, installs the guest's own outer boundary on the child, and asserts
    // on what the platform refused. On Linux that is a Landlock domain and a
    // seccomp filter, on macOS a Seatbelt profile, and no other target has
    // either. It needs no probe binary of its own: the child it forks never
    // execs successfully, so the test and the boundary it proves live in the
    // same source file.
    //
    // **`skip_foreign_checks` is left off on macOS, and that is deliberate.**
    // It is the same rule the two Darwin suites below follow: a boundary proved
    // only by a skipped run step is worth nothing, and a Darwin claim on this
    // project has been wrong three times because it was cross compiled and
    // never run. The Linux arm keeps the flag, so a Linux build for a foreign
    // Linux still compiles the suite.
    if (linux_only or target.result.os.tag == .macos) {
        const confine_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/confine.zig"),
                .target = target,
                .optimize = optimize,
                // libSystem for the Darwin arm, which reaches `fork`,
                // `sandbox_init` and `pthread_create` through it. `std.Thread`
                // has no other way to start a thread on macOS.
                .link_libc = target.result.os.tag == .macos,
                .imports = &.{
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
                },
            }),
        });
        const run_confine_tests = b.addRunArtifact(confine_tests);
        run_confine_tests.skip_foreign_checks = target.result.os.tag != .macos;
        test_step.dependOn(&run_confine_tests.step);
        test_net_step.dependOn(&run_confine_tests.step);
    }

    // macOS only, and for the same reason the block above is Linux only: every
    // test in test/sandbox/darwin_escape.zig asserts on a Seatbelt profile that
    // was really applied by `sandbox_init`, and no other target has one.
    //
    // **It has to run on a real Mac, and a cross build must not look like it
    // did.** `run_net_tests` and every other test target here set
    // `skip_foreign_checks`, so a binary the host cannot run is skipped and the
    // step still reports success. That is how a Darwin cross build from Linux
    // once passed while every Linux only suite inside it had been skipped. A
    // sandbox proved only by a skipped run step is worth nothing, so this one
    // leaves the flag off: on a host that cannot run the binary the step fails
    // rather than passing quietly.
    if (target.result.os.tag == .macos) {
        const darwin_probe = b.addExecutable(.{
            .name = "chock-net-darwin-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/darwin_probe.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
                },
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
                // `chock-net` for one question only: whether this process
                // is inside a profile already, which is the one state in which
                // none of these tests can be answered. See that suite's own
                // `requireOwnProfile`.
                .imports = &.{
                    .{ .name = "probe_path", .module = darwin_probe_path.createModule() },
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
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
                .imports = &.{
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
                },
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
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
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
        // A real HTTP server on 127.0.0.1, shared with Chock's provider
        // consumer-boundary tests. Named as a module rather than reached by a
        // relative path, because Zig refuses a relative @import that leaves a
        // module's own root and test/broker/actions.zig is its own root.
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
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
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
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
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
    // of them is found. Like chock-net, chock-io and chock-policy, it
    // imports no other chock library and has no build.zig of its own: `chock
    // login` runs before a session, a workspace, or a sandbox exists, so it
    // must not need any of them.
    const chock_auth = b.addModule("chock-auth", .{
        .root_source_file = b.path("lib/chock-auth.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "chock-zon", .module = chock_zon }},
    });

    // The Darwin credential driver calls the Keychain through the Security
    // framework, and CoreFoundation releases what a lookup hands back. Declared
    // on the module, so every artifact that imports it links them and none has
    // to remember. Nothing is linked for any other target.
    if (target.result.os.tag == .macos) {
        chock_auth.linkFramework("Security", .{});
        chock_auth.linkFramework("CoreFoundation", .{});

        // **Zig is told where the frameworks are, because it will not look.**
        // It reads `NIX_CFLAGS_COMPILE` and `NIX_LDFLAGS`, and finding either
        // one set it stops before its own SDK search. Both are always set
        // inside a nix shell, and neither names a framework directory, so a
        // build there reports "searched paths: none".
        //
        // `SDKROOT` names the SDK and is exported by the SDK's own setup, in a
        // nix build and in a nix dev shell alike. It is absent on a Mac with
        // Xcode and no nix, and there the search zig makes for itself works,
        // so this only adds a path when one was given.
        if (b.graph.environ_map.get("SDKROOT")) |sdkroot| {
            chock_auth.addSystemFrameworkPath(.{
                .cwd_relative = b.pathJoin(&.{ sdkroot, "System/Library/Frameworks" }),
            });
            // A framework names dylibs of its own: CoreFoundation wants
            // `libobjc.A.dylib`, which lives beside the frameworks and not
            // among them. Without this the frameworks are found and what they
            // depend on is not.
            chock_auth.addLibraryPath(.{
                .cwd_relative = b.pathJoin(&.{ sdkroot, "usr/lib" }),
            });
        }
    }

    // The Linux credential driver can keep a value in the freedesktop secret
    // service, which is reached over the session bus. Imported for Linux alone,
    // because the driver that names it is compiled for Linux alone.
    if (target.result.os.tag == .linux) {
        const dbus = b.dependency("dbus", .{ .target = target, .optimize = optimize });
        chock_auth.addImport("dbus", dbus.module("dbus"));
    }

    const auth_tests = b.addTest(.{ .root_module = chock_auth });
    const run_auth_tests = b.addRunArtifact(auth_tests);
    // Same reasoning as run_net_tests above.
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
    // with, and the store paths the sandbox mounts for it. Like chock-net,
    // chock-io, chock-policy and chock-auth, it imports no other chock library:
    // a dev shell is evaluated before a session, a workspace, or a sandbox
    // exists, so it must not need any of them.
    //
    // fix, the Nix evaluator in Zig, is the one dependency it takes: an
    // evaluation then needs no `nix` process, and no store, because store
    // writes stay off until a caller asks for them. See
    // `lib/chock-nix/eval.zig`.
    const fix = b.dependency("fix", .{ .target = target, .optimize = optimize });
    const chock_nix = b.addModule("chock-nix", .{
        .root_source_file = b.path("lib/chock-nix.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "expr", .module = fix.module("expr") },
            .{ .name = "store", .module = fix.module("store") },
        },
    });

    // fix's evaluator dispatches one opcode to the next with
    // `@call(.always_tail)`, and the self-hosted x86_64 backend cannot emit a
    // tail call, so every artifact holding the evaluator asks for LLVM on that
    // one target. fix's own build asks for it everywhere; this asks only where
    // the backend cannot do the work, so an aarch64 build keeps the faster
    // path. Null means "whatever this target's default is".
    const evaluator_llvm: ?bool = if (target.result.cpu.arch == .x86_64) true else null;

    const nix_tests = b.addTest(.{ .root_module = chock_nix, .use_llvm = evaluator_llvm });
    const run_nix_tests = b.addRunArtifact(nix_tests);
    // Same reasoning as run_net_tests above.
    run_nix_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_nix_tests.step);

    // A **real `nix`**, driven by the production argument vector. Every other
    // test of a build answers `nix` from a table, which is what
    // `lib/chock-nix/provision.zig` argues for, and a table still only says
    // what somebody thought `nix` does. See `test/nix/real.zig`.
    //
    // An empty string on a machine with no `nix`, which that suite reads as a
    // reason to skip. The same shape `chock_path_options.git_path` has, and
    // for the same reason: the build script has an environment to search and
    // a test binary has none.
    const nix_path_options = b.addOptions();
    nix_path_options.addOption(
        []const u8,
        "nix_path",
        b.findProgram(.{ .names = &.{"nix"} }) orelse "",
    );

    const nix_real_tests = b.addTest(.{
        .use_llvm = evaluator_llvm,
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/nix/real.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-nix", .module = chock_nix },
                .{ .name = "nix_path", .module = nix_path_options.createModule() },
            },
        }),
    });
    const run_nix_real_tests = b.addRunArtifact(nix_real_tests);
    // These spawn a program of this machine's own, so a build for another
    // machine has nothing it can run.
    run_nix_real_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_nix_real_tests.step);

    // OCI image loading is package-owned. Chock keeps only the adapter that
    // reads the container block from chock.zon.
    //
    // **A tool call never runs inside a container.** The image is a source of
    // files, exactly as a Nix closure is, and Chock's own sandbox is still the
    // whole boundary.
    const oci_dependency = b.dependency("oci", .{ .target = target, .optimize = optimize });
    const oci = oci_dependency.module("oci");
    const chock_container = b.addModule("chock-container", .{
        .root_source_file = b.path("lib/chock-container.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "chock-zon", .module = chock_zon },
            .{ .name = "oci", .module = oci },
        },
    });

    const container_tests = b.addTest(.{ .root_module = chock_container });
    const run_container_tests = b.addRunArtifact(container_tests);
    // Same reasoning as run_net_tests above.
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
    // lib/chock-net/darwin/driver.zig refuses by design.
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
                .imports = &.{
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
                },
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
                // `chock-net` for one question only: the exit status the
                // probe answers with when this machine will not give it a
                // sandbox at all. See that suite's own `runInside`.
                .imports = &.{
                    .{ .name = "chock-container", .module = chock_container },
                    .{ .name = "rootfs_probe_path", .module = rootfs_probe_path_options.createModule() },
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
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
    // chock-net and chock-policy, it imports no other chock library, and
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
    // Same reasoning as run_net_tests above.
    run_plugin_core_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_plugin_core_tests.step);

    // The tool definitions, the dispatch, and the two tools. See the design
    // spec sections 5, part of 10, and 13. This is the first library whose
    // output can change something on the machine, so it imports
    // chock-net directly, the same way chock-workspace already does,
    // for the one Sandbox.Config and Sandbox.spawn every tool call goes
    // through. It also imports chock-proto directly, for the tool.call and
    // tool.result event types dispatch reads and builds, chock-provider,
    // for the tool definition shape a caller offers the model, and chock-io,
    // for the close-on-exec pipe spawnCapturing reads a sandboxed program's
    // output from.
    //
    // It imports chock-policy for three things, and none of them is the
    // table. The first is the subagent limits, which the loop measures a
    // spawn request against because the loop is what holds the session state
    // those limits count. The second is the policy ratchet: the loop decides
    // whether a promise an agent makes about itself narrows or widens the
    // promises that session already holds, which it reads from its own
    // folded log. The third is chock_policy.devices, for the Identity and
    // actionInto a udev event turns into: chock_core.devices asks whether an
    // action may reach the sandbox through its own PolicySeam, never through
    // chock_policy.table.Table directly. **It never evaluates the policy
    // table**, which stays the broker's job, and chock-core still imports no
    // chock-broker: see lib/chock-core/Loop.zig's own top comment.
    //
    // It also imports the udev client, for chock_core.devices alone: the
    // library that resolves a plugged-in device's identity off sysfs and a
    // netlink monitor. See that file's own top comment for the three
    // measurements it is built against.
    const chock_core = b.addModule("chock-core", .{
        .root_source_file = b.path("lib/chock-core.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "chock-net", .module = chock_net },
            .{ .name = "palisade", .module = palisade },
            .{ .name = "chock-proto", .module = chock_proto },
            .{ .name = "chock-provider", .module = chock_provider },
            .{ .name = "chock-io", .module = chock_io },
            .{ .name = "chock-cost", .module = chock_cost },
            .{ .name = "chock-policy", .module = chock_policy },
            .{ .name = "chock-zon", .module = chock_zon },
            // For chock_core.plugin_module, which reads a plugin's metadata
            // out of a wasm module with the very same reader the guest wrote
            // it with. A second copy of the format on the host side is the
            // one thing that would let a plugin and a Chock disagree about
            // what a plugin said.
            .{ .name = "chock-plugin-core", .module = chock_plugin_core },
            .{ .name = "udev", .module = udev.module("udev") },
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

    // The proof and not a library test: `chock_core.devices.drainInto`
    // against a real `udev.Monitor`, because a fake here would prove nothing
    // about whether the generic seam in `lib/chock-core/devices.zig`
    // actually compiles and behaves against the production type it was
    // written for. See that file's own top comment. Not gated behind
    // `linux_only`, the same as `udev_tests` above: the test carries its own
    // runtime skip.
    const core_devices_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/devices.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "udev", .module = udev.module("udev") },
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-net", .module = chock_net },
                .{ .name = "palisade", .module = palisade },
            },
        }),
    });
    const run_core_devices_tests = b.addRunArtifact(core_devices_tests);
    run_core_devices_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_core_devices_tests.step);

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
        // test/core/tools.zig's own probe: like chock-net-probe,
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
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
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
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
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
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
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
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
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
            b.findProgram(.{ .names = &.{"zls"} }),
        );

        const lsp_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/core/lsp.zig"),
                .target = target,
                .optimize = optimize,
                // `chock-net` for one question only: the exit status a
                // probe answers with when this machine will not give it a
                // sandbox at all. See that suite's `skipIfNothingMeasured`.
                .imports = &.{
                    .{ .name = "lsp_probe_path", .module = lsp_probe_path_options.createModule() },
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
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
        b.findProgram(.{ .names = &.{"mcp-server-time"} }),
    );

    const mcp_real_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/mcp_real.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-policy", .module = chock_policy },
                // A tool call is decided by an arbiter now, and an arbiter
                // writes its question through the session log's own locked
                // handle: see `chock_core.mcp.Session.asker`. The test needs
                // real storage to build one.
                .{ .name = "chock-proto", .module = chock_proto },
                .{ .name = "mcp_real_path", .module = mcp_real_path_options.createModule() },
            },
        }),
    });
    const run_mcp_real_tests = b.addRunArtifact(mcp_real_tests);
    run_mcp_real_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_mcp_real_tests.step);

    // The **real streamable HTTP transport** against a real server. See
    // test/core/mcp_remote_real.zig for what it covers and what it does not:
    // the server runs on loopback over plain http, so TLS is not here, and the
    // address check has its own test where the real one refuses a loopback
    // answer.
    //
    // **Not Linux only**, like the stdio suite above: a remote server needs no
    // sandbox at all.
    const mcp_probe_path_options = b.addOptions();
    // Found here and never at test time, and null is an ordinary answer. The
    // dev shell puts it on this PATH; pkgs/chock/default.nix names it.
    mcp_probe_path_options.addOption(
        ?[]const u8,
        "mcp_probe_http_path",
        b.findProgram(.{ .names = &.{"mcp-probe-http"} }),
    );

    const mcp_remote_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/mcp_remote_real.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-broker", .module = chock_broker },
                .{ .name = "mcp_probe_path", .module = mcp_probe_path_options.createModule() },
            },
        }),
    });
    const run_mcp_remote_tests = b.addRunArtifact(mcp_remote_tests);
    run_mcp_remote_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_mcp_remote_tests.step);

    // The **real tree-sitter command** against a real grammar, driven by the
    // production argument list and the production reader. See
    // test/core/ast_real.zig for the half a captured output sample cannot keep
    // honest.
    //
    // **Not Linux only**: the test runs the program plainly, because a sandbox
    // cannot nest inside CI, and the command needs none to parse a file.
    //
    // All three are found here and never at test time, and null is an
    // ordinary answer: the dev shell puts the command on this PATH and both
    // directories in this environment, and the package build has none of
    // them. pkgs/chock/default.nix names them.
    const tree_sitter_path = b.findProgram(.{ .names = &.{"tree-sitter"} });
    const parsers_dir = b.graph.environ_map.get("TREE_SITTER_PARSERS");
    const ast_module_dir = b.graph.environ_map.get("CHOCK_PARSER_MODULES");

    const ast_real_path_options = b.addOptions();
    ast_real_path_options.addOption(?[]const u8, "tree_sitter_path", tree_sitter_path);
    ast_real_path_options.addOption(?[]const u8, "parsers_dir", parsers_dir);

    const ast_real_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/core/ast_real.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "ast_real_path", .module = ast_real_path_options.createModule() },
            },
        }),
    });
    const run_ast_real_tests = b.addRunArtifact(ast_real_tests);
    run_ast_real_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_ast_real_tests.step);

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
    // `chock-plugin-host` used to be a second installed program, then `chock`
    // re-executed itself under a hidden word. A plugin now enters this runtime
    // directly in a forked sandbox child. The installed artifact remains one
    // static binary, and starting a plugin loads neither it nor its module from
    // the sandbox filesystem.
    //
    // **What that must not cost, and does not:**
    //
    // * `src/plugin-host.zig` and `src/ast_engine.zig` are the only files in
    //   this project that name an engine: a plugin gets a process of its own
    //   and a style rule's parser runs in this one. Nothing else imports
    //   `vulcan-wasm`.
    // * `chock-core` still compiles with no engine at all, on every target.
    //   It holds every rule a plugin is held to, over the `plugin_engine.Engine`
    //   seam, and it does not import this.
    // * No ordinary library test binary links an engine. The exceptions are
    //   `chock`'s own test binary and the dedicated engine acceptance suite
    //   below, including its test-only protocol host. Both import this same
    //   file, so the tests cannot drift into a second runtime implementation.
    const vulcan = b.dependency("vulcan", .{ .target = target, .optimize = optimize });

    // **Running a guest is every target Mirage has both a machine and an
    // architecture for.** That is Linux on aarch64 and x86_64, where the setup is
    // KVM, and macOS on aarch64, where it is Hypervisor.framework. The devices
    // placed are the architecture's own: arm64 states them in a device tree,
    // x86_64 in ACPI tables.
    //
    // **Compiling is not booting, and this flag only claims the first.** A guest
    // has been booted by hand on aarch64 Linux and on an Apple Silicon Mac. On
    // x86_64 nothing in this repository has run one, because the development host
    // is aarch64 and a hosted CI runner exposes no `/dev/kvm`. `src/vmm.zig`
    // refuses an architecture it has no layout for rather than guessing one, so
    // widening this cannot quietly place a guest wrongly.
    //
    // **A Mac needs the hypervisor entitlement**, which an ad hoc signature
    // carries: see `docs/security/microvm.md` for the one command, and for why
    // an unsigned binary gets `HV_DENIED` rather than a diagnosable fault.
    //
    // Two files behind one module name, so every build compiles: the one that cannot
    // run a guest answers `available = false`, which the daemon reads before it
    // offers a session one. See `src/vmm_absent.zig`.
    const can_run_a_guest = switch (target.result.os.tag) {
        .linux => target.result.cpu.arch == .aarch64 or target.result.cpu.arch == .x86_64,
        .macos => target.result.cpu.arch == .aarch64,
        else => false,
    };
    const mirage = if (can_run_a_guest)
        b.dependency("mirage", .{ .target = target, .optimize = optimize })
    else
        null;

    // One architecture under one name, the way Mirage's own build does it: `src/vmm.zig`
    // names `mirage-arch` and never an architecture, so where the devices sit is chosen
    // here. A target Mirage has no architecture module for cannot run a guest, so it
    // never reaches this.
    const mirage_arch = if (mirage) |dep| dep.module(switch (target.result.cpu.arch) {
        .x86_64 => "mirage-x86_64",
        else => "mirage-arm64",
    }) else null;

    const vmm_module = b.createModule(.{
        .root_source_file = b.path(if (can_run_a_guest) "src/vmm.zig" else "src/vmm_absent.zig"),
        .target = target,
        .optimize = optimize,
        .imports = if (mirage) |dep| &.{
            .{ .name = "chock-net", .module = chock_net },
            .{ .name = "palisade", .module = palisade },
            .{ .name = "mirage-backend", .module = dep.module("mirage-backend") },
            .{ .name = "mirage-core", .module = dep.module("mirage-core") },
            .{ .name = "mirage-arch", .module = mirage_arch.? },
            .{ .name = "mirage-device", .module = dep.module("mirage-device") },
            .{ .name = "mirage-memory", .module = dep.module("mirage-memory") },
            .{ .name = "mirage-attest", .module = dep.module("mirage-attest") },
            .{ .name = "mirage-session", .module = dep.module("mirage-session") },
            .{ .name = "mirage-fs", .module = dep.module("mirage-fs") },
        } else &.{},
    });

    // The widget tree and the words on it. Imports phantom and nothing of the
    // host, so the same tree builds for the terminal, a window, and wasm in a
    // browser. See `lib/chock-ui.zig`.
    const chock_ui = b.addModule("chock-ui", .{
        .root_source_file = b.path("lib/chock-ui.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "phantom", .module = phantom.module("phantom") },
            .{ .name = "chock-proto", .module = chock_proto },
            .{ .name = "chock-core", .module = chock_core },
        },
    });

    // The widget tree's own tests. Without this the module compiles into the
    // binary and every test in it is skipped, which is how a broken assertion
    // sat green: a module is not a test root until something makes one.
    const chock_ui_tests = b.addTest(.{ .root_module = chock_ui });
    const run_chock_ui_tests = b.addRunArtifact(chock_ui_tests);
    test_step.dependOn(&run_chock_ui_tests.step);

    // The browser's own wiring, built for the host so its pure parts run here.
    // The page itself is wasm and cannot run on this machine; these are the
    // functions that decide what a line says, which need no browser.
    const web_test_module = b.createModule(.{
        .root_source_file = b.path("src/web/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "phantom", .module = phantom.module("phantom") },
            .{ .name = "chock-ui", .module = chock_ui },
            .{ .name = "chock-proto", .module = chock_proto },
        },
    });
    const web_tests = b.addTest(.{ .root_module = web_test_module });
    const run_web_tests = b.addRunArtifact(web_tests);
    test_step.dependOn(&run_web_tests.step);

    // The browser build. `addApp` makes its own wasm phantom and injects it into
    // every module passed here, so these instances must not import phantom
    // themselves: a second instance would give types that do not match. One
    // module instance per target, because `addApp` writes into the import table.
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });

    const chock_proto_wasm = b.createModule(.{
        .root_source_file = b.path("lib/chock-proto.zig"),
        .target = wasm_target,
        .optimize = optimize,
    });

    // Only the handful of declarations the interface reaches are compiled, so
    // this needs the module graph and not every one of chock-core's own
    // dependencies.
    const chock_core_wasm = b.createModule(.{
        .root_source_file = b.path("lib/chock-core.zig"),
        .target = wasm_target,
        .optimize = optimize,
    });
    chock_core_wasm.addImport("chock-proto", chock_proto_wasm);

    const chock_ui_wasm = b.createModule(.{
        .root_source_file = b.path("lib/chock-ui.zig"),
        .target = wasm_target,
        .optimize = optimize,
    });
    // A nested import is the caller's own: `imports` below reaches the app root
    // and no further.
    chock_ui_wasm.addImport("chock-proto", chock_proto_wasm);
    chock_ui_wasm.addImport("chock-core", chock_core_wasm);

    // The page, as build outputs. `addWebDist` always builds for
    // wasm32-freestanding and installs nothing, so the wasm is compiled once and
    // the file list comes from phantom rather than from a guess here.
    const web_dist = phantom_build.addWebDist(b, phantom, .{
        .id = "ws.chock.web",
        .exec_name = "chock-web",
        .name = .{ .default = "Chock" },
        .summary = .{ .default = "The Chock interface in a browser" },
        .root = b.path("src/web/main.zig"),
        .target = wasm_target,
        .optimize = optimize,
        // A real path and not a fragment, so a session can be linked and a
        // reload lands back in it. `base_path` keeps the assets rooted at `/`
        // when Chock's server answers `/s/<id>` with Phantom's plain shell.
        .url_strategy = .path,
        .base_path = "/",
        .imports = &.{
            .{ .name = "chock-ui", .module = chock_ui_wasm },
            .{ .name = "chock-proto", .module = chock_proto_wasm },
        },
    });

    // One file the binary carries, so `chock serve` needs nothing on disk.
    //
    // A program the build runs, the way the protocol generators are run. Zig
    // 0.17 closed `Step.Tag`, so a build carries no code of its own.
    const web_bundle_tool = b.addExecutable(.{
        .name = "web-bundle",
        .root_module = b.createModule(.{
            .root_source_file = b.path("build/web_bundle.zig"),
            .target = b.graph.host,
            .optimize = .debug,
        }),
    });
    const run_web_bundle = b.addRunArtifact(web_bundle_tool);
    const web_bundle = run_web_bundle.addOutputFileArg2("web.tar", .{});
    // The name a browser asks for, then where that file is now. The list is
    // phantom's, so a file it adds or renames arrives here on its own.
    for (web_dist.files) |name| {
        run_web_bundle.addArg(name);
        run_web_bundle.addFileArg2(web_dist.dir.path(b, name), .{});
    }

    // Structured Git diffs for workspace review and selective application.
    // Keeping this as a direct dependency makes that API explicit instead of
    // reaching through fix's private dependency graph.
    const ziggit = b.dependency("ziggit", .{ .target = target, .optimize = optimize });

    const exe_imports = [_]std.Build.Module.Import{
        .{ .name = "chock-vmm", .module = vmm_module },
        .{ .name = "phantom", .module = phantom.module("phantom") },
        .{ .name = "chock-ui", .module = chock_ui },
        // What `chock --version` prints. See the block above.
        .{ .name = "chock-version", .module = chock_version_module },
        .{ .name = "vulcan-wasm", .module = vulcan.module("vulcan-wasm") },
        .{ .name = "chock-net", .module = chock_net },
        .{ .name = "palisade", .module = palisade },
        .{ .name = "chock-io", .module = chock_io },
        .{ .name = "chock-proto", .module = chock_proto },
        // `chock acp` is the one caller. It is the wire and holds no session, so
        // the binary is where it meets one.
        .{ .name = "acp", .module = acp },
        .{ .name = "chock-provider", .module = chock_provider },
        .{ .name = "chock-policy", .module = chock_policy },
        // `chock sessions seal` writes a seal beside a log and `chock sessions
        // verify` reads it. The binary is where the two halves meet: the key
        // comes from chock-auth and the log's digests come from chock-proto,
        // and pcsc.zig must import neither.
        .{ .name = "pcsc", .module = pcsc },
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
        .{ .name = "ziggit", .module = ziggit.module("ziggit") },
    };

    const chock_exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &exe_imports,
    });

    // The page rides in the binary. `chock serve` has no files on disk to find,
    // and the page cannot run without the daemon behind it anyway, so it is
    // built by an ordinary `zig build` rather than by a step somebody has to
    // remember.
    chock_exe_module.addAnonymousImport("web-bundle", .{
        .root_source_file = web_bundle,
    });

    const exe = std.Build.Step.Compile.create(b, .{
        .name = "chock",
        .root_module = chock_exe_module,
        .kind = .exe,
        .use_llvm = evaluator_llvm,
        .entitlements = if (target.result.os.tag == .macos)
            b.path("build/hypervisor.plist")
        else
            null,
    });
    b.installArtifact(exe);

    // Both parsers over one file, which needs the module the dev shell builds.
    // The module directory is the gate, the way the kernel path gates the
    // guest: a shell without it does not build this test, because the engine
    // compiles every function in the module before the first answer, and that
    // is minutes for a debug build.
    if (ast_module_dir) |module_dir| {
        const ast_agree_path_options = b.addOptions();
        ast_agree_path_options.addOption(?[]const u8, "tree_sitter_path", tree_sitter_path);
        ast_agree_path_options.addOption(?[]const u8, "parsers_dir", parsers_dir);
        ast_agree_path_options.addOption([]const u8, "module_dir", module_dir);
        // The engine, in the one test that puts it beside the command. This is
        // the same file `chock` builds, so the two parsers under test are the
        // shipped ones.
        const ast_engine_module = b.createModule(.{
            .root_source_file = b.path("src/ast_engine.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "vulcan-wasm", .module = vulcan.module("vulcan-wasm") },
            },
        });
        const ast_agree_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/core/ast_agree.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-core", .module = chock_core },
                    .{ .name = "chock-policy", .module = chock_policy },
                    .{ .name = "ast_engine", .module = ast_engine_module },
                    .{ .name = "ast_real_path", .module = ast_agree_path_options.createModule() },
                },
            }),
        });
        const run_ast_agree_tests = b.addRunArtifact(ast_agree_tests);
        run_ast_agree_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_ast_agree_tests.step);
    }

    // The tests of `src/vmm.zig` are the drift guard: they name every Mirage
    // declaration this file's copy of the setup reaches, so an upgrade that moves
    // one fails a build instead of leaving two versions of the same loop.
    if (can_run_a_guest) {
        const vmm_tests = b.addTest(.{ .root_module = vmm_module });
        const run_vmm_tests = b.addRunArtifact(vmm_tests);
        run_vmm_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_vmm_tests.step);
        // The same drift guard, for the one Mirage declaration whose **body** the
        // VMM's syscall allow list depends on. `test/sandbox/vmm_allowlist.zig`
        // reads `mirage-fs`'s own `Export.zig` and fails on a `std.Io` call the
        // allow list has no row for, which is what a version bump that touches the
        // filesystem would otherwise leave as a guest that dies with an empty
        // console.
        //
        // The file arrives as an import so it can be embedded, and the embed is
        // why this cannot live in `chock-net` itself: that module is built for
        // every target, including the ones Mirage is not built for at all.
        const fs_export = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/vmm_allowlist.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "chock-net", .module = chock_net },
                    .{ .name = "palisade", .module = palisade },
                },
            }),
        });
        fs_export.root_module.addAnonymousImport("mirage-fs-export", .{
            .root_source_file = mirage.?.path("lib/mirage-fs/Export.zig"),
        });
        const run_fs_export = b.addRunArtifact(fs_export);
        run_fs_export.skip_foreign_checks = true;
        test_step.dependOn(&run_fs_export.step);
        test_net_step.dependOn(&run_fs_export.step);

        // Written out rather than through `module_test_steps.add`, for the reason
        // `test_net_step` is: two runs share this step, and the helper would be
        // the second call to create it.
        const test_vmm_step = b.step("test-vmm", "Run the src/vmm.zig tests only");
        test_vmm_step.dependOn(&run_vmm_tests.step);
        test_vmm_step.dependOn(&run_fs_export.step);
    }

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
    // sessions with four layers on: see `docs/security/sandbox.md`. Measuring the
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
        redteam_paths.addOption([]const u8, "repo_root", repo_root);

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
            .use_llvm = evaluator_llvm,
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
        run_harness.addPassthruArgs();
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
        const redteam_tests = b.addTest(.{
            .root_module = redteam_module,
            .use_llvm = evaluator_llvm,
        });
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
    chock_exe_test_module.addAnonymousImport("web-bundle", .{
        .root_source_file = web_bundle,
    });

    const exe_tests = b.addTest(.{
        .root_module = chock_exe_test_module,
        .use_llvm = evaluator_llvm,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    // Same reasoning as run_net_tests above.
    run_exe_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_exe_tests.step);
    module_test_steps.add(b, "test-exe", "Run the src/ program tests only", &run_exe_tests.step);

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
        b.findProgram(.{ .names = &.{"git"} }) orelse "",
    );
    const cli_fake_provider = b.createModule(.{
        .root_source_file = b.path("test/core/fake_provider.zig"),
        .target = target,
        .optimize = optimize,
    });

    const cli_tests = b.addTest(.{
        .use_llvm = evaluator_llvm,
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/cli/streams.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock_path", .module = chock_path_options.createModule() },
                .{ .name = "chock_main", .module = chock_exe_module },
                .{ .name = "fake_provider", .module = cli_fake_provider },
            },
        }),
    });
    const run_cli_tests = b.addRunArtifact(cli_tests);
    // These spawn the binary that was just built, so a build for another
    // machine has nothing it can run.
    run_cli_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_cli_tests.step);

    // **The one test that boots a guest.** Everything else on the microVM path
    // drives a piece of it: the allow list against Mirage's own exports, the
    // grant set against the offer set, the fault text. Only this starts the
    // binary that was just built, speaks the control protocol to it, and reads a
    // tool result back out of a real guest. Several syscall allow list faults
    // there were found by running a session by hand, which is exactly the class
    // of fault a build cannot see.
    //
    // **Its own step, and on `test_step` as well.** `test-guest` is for a person
    // who wants this and not the hour the whole suite takes; being on `test_step`
    // too is what puts it in front of `nix build`, where it skips, because that
    // sandbox has no `/dev/kvm` and nobody passes it images. A skip there is the
    // honest answer and a failure would be a false one: see `whyNoGuest` in
    // `test/cli/guest.zig`, which names the fact that stopped it.
    //
    // **The images are given, never hunted for.** They come out of
    // `nix build .#guest-kernel .#guest-initrd`, which needs a Linux builder of
    // the guest's own architecture, so there is no default a build script could
    // honestly guess. Empty strings when nobody passed them, which the test
    // reads as a reason to skip.
    const guest_gate_options = b.addOptions();
    guest_gate_options.addOptionPath("chock_path", exe.getEmittedBin());
    guest_gate_options.addOption(
        []const u8,
        "git_path",
        b.findProgram(.{ .names = &.{"git"} }) orelse "",
    );
    // The program the one tool call runs. Named here for the reason `git_path`
    // is: a test binary resolves a bare `argv[0]` against an `environ` it has
    // not got, and a Nix machine has no `wc` where the fallback looks.
    guest_gate_options.addOption(
        []const u8,
        "wc_path",
        b.findProgram(.{ .names = &.{"wc"} }) orelse "",
    );
    guest_gate_options.addOption(
        []const u8,
        "guest_kernel",
        b.option([]const u8, "guest-kernel", "The kernel test-guest boots. From nix build .#guest-kernel.") orelse "",
    );
    guest_gate_options.addOption(
        []const u8,
        "guest_initrd",
        b.option([]const u8, "guest-initrd", "The initrd test-guest boots. From nix build .#guest-initrd.") orelse "",
    );

    const guest_gate_tests = b.addTest(.{
        .use_llvm = evaluator_llvm,
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/cli/guest.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-proto", .module = chock_proto },
                .{ .name = "guest_gate", .module = guest_gate_options.createModule() },
            },
        }),
    });
    const run_guest_gate_tests = b.addRunArtifact(guest_gate_tests);
    // It spawns the binary that was just built, so a build for another machine
    // has nothing it can run.
    run_guest_gate_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_guest_gate_tests.step);
    module_test_steps.add(
        b,
        "test-guest",
        "Boot a guest through chock daemon and run one tool call in it. " ++
            "Skips unless -Dguest-kernel= and -Dguest-initrd= name readable images " ++
            "and this user can open /dev/kvm.",
        &run_guest_gate_tests.step,
    );

    // Every claim in the documentation that a machine can check: see
    // `test/docs/claims.zig`. It reads the pages off the disk and compares
    // them against the command table, the exit codes, the tool list, the
    // policy types and the source itself.
    //
    // **Where this repository is, because a test binary cannot know.** The
    // tests read files that are not compiled into them, and `zig build` can be
    // started from any directory, so the root is a build time constant. Same
    // shape as `chock_path_options` below.
    const repo_root_options = b.addOptions();
    repo_root_options.addOption([]const u8, "repo_root", repo_root);

    const docs_tests = b.addTest(.{
        .use_llvm = evaluator_llvm,
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/docs/claims.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock_main", .module = chock_exe_module },
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-policy", .module = chock_policy },
                .{ .name = "chock-net", .module = chock_net },
                .{ .name = "palisade", .module = palisade },
                .{ .name = "repo_root", .module = repo_root_options.createModule() },
            },
        }),
    });
    const run_docs_tests = b.addRunArtifact(docs_tests);
    // They read this machine's own checkout, so a build for another machine
    // has nothing to read.
    run_docs_tests.skip_foreign_checks = true;
    // **Run every time, because the pages are not inputs the build can see.**
    // They are read when this runs and not when it is built, so a doc edit
    // leaves this binary alone: without this, the build has nothing to
    // re-run and an edited page keeps the last answer it was given. The
    // suite reads a few files and takes no time worth saving.
    run_docs_tests.has_side_effects = true;
    test_step.dependOn(&run_docs_tests.step);

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

        // test/broker/git_push.zig drives a real `git push` against a server of
        // its own that demands Basic auth, and reads the credential back out of
        // the `Authorization` header. The suite above proves that git reaches
        // the socket; this one proves that a push asks at all and that what
        // comes back is what goes out on the wire. It also holds the test that
        // matters most in this whole path: the password is in neither the
        // session log nor anything git printed.
        const broker_push_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/broker/git_push.zig"),
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
        const run_broker_push_tests = b.addRunArtifact(broker_push_tests);
        run_broker_push_tests.skip_foreign_checks = true;
        test_step.dependOn(&run_broker_push_tests.step);
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
    // It drives the real host runtime, over a real pipe, with the real module
    // built above and the real engine, so the framing, the call ABI and the
    // bounded reads of guest memory are all the production ones. Every other
    // test of this feature drives a peer written by the same hand: see
    // `lib/chock-core/plugin_host.zig`'s own note.
    //
    // Most protocol cases use a test-only executable around that runtime. The
    // final case uses the production callback entry in a real sandbox and is
    // the guard that no executable or module mount came back.
    const plugin_runtime = b.createModule(.{
        .root_source_file = b.path("src/plugin-host.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "chock-core", .module = chock_core },
            .{ .name = "palisade", .module = palisade },
            .{ .name = "vulcan-wasm", .module = vulcan.module("vulcan-wasm") },
        },
    });

    const plugin_engine_host = b.addExecutable(.{
        .name = "chock-plugin-engine-test-host",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/plugin/engine_host.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "plugin-runtime", .module = plugin_runtime },
                .{ .name = "chock-core", .module = chock_core },
            },
        }),
    });

    const engine_paths = b.addOptions();
    engine_paths.addOptionPath("plugin_wasm_path", hello_wasm.getEmittedBin());
    engine_paths.addOptionPath("engine_host_path", plugin_engine_host.getEmittedBin());

    const plugin_engine_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/plugin/engine.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "chock-core", .module = chock_core },
                .{ .name = "chock-plugin-core", .module = chock_plugin_core },
                .{ .name = "chock-policy", .module = chock_policy },
                // A tool call is decided by an arbiter now, and an arbiter
                // writes its question through the session log's own locked
                // handle: see `chock_core.plugin.Session.asker`. The test needs
                // real storage to build one.
                .{ .name = "chock-proto", .module = chock_proto },
                // For the one test that starts a plugin host the way a session
                // starts it: the mount tree, the Landlock rules and the
                // lockdown are all sandbox values.
                .{ .name = "chock-net", .module = chock_net },
                .{ .name = "palisade", .module = palisade },
                .{ .name = "plugin-runtime", .module = plugin_runtime },
                .{ .name = "engine_paths", .module = engine_paths.createModule() },
            },
        }),
    });
    // The test spawns its host process and reads the module, so both have to
    // exist before it runs. `addOptionPath` records where they will be and
    // does not itself order the steps.
    plugin_engine_tests.step.dependOn(&plugin_engine_host.step);
    plugin_engine_tests.step.dependOn(&hello_wasm.step);
    const run_plugin_engine_tests = b.addRunArtifact(plugin_engine_tests);
    run_plugin_engine_tests.skip_foreign_checks = true;
    test_step.dependOn(&run_plugin_engine_tests.step);
    module_test_steps.add(
        b,
        "test-plugin-engine",
        "Run the real WebAssembly plugin engine tests only",
        &run_plugin_engine_tests.step,
    );

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
}
