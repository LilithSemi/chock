//! `chock daemon`: the process that owns sessions and is the only thing a
//! frontend talks to. Agent turns run on owned worker threads; tools and sandbox
//! supervisors remain separate processes where their isolation belongs.

const std = @import("std");
const builtin = @import("builtin");
const chock_auth = @import("chock-auth");
const chock_broker = @import("chock-broker");
const chock_container = @import("chock-container");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const vmm = @import("chock-vmm");
const chock_proto = @import("chock-proto");
const ziggit = @import("ziggit");

const run_cmd = @import("run.zig");
const session_paths = @import("session.zig");
const sessions_cmd = @import("sessions.zig");
const workspace_cmd = @import("workspace.zig");
const interrupt = @import("interrupt.zig");
const Exit = @import("exit.zig").Exit;
const directory_help = @import("directory_help.zig");
const tty = @import("tty.zig");
const guest_limits = @import("guest_limits.zig");
const daemon_state = @import("chock-daemon");
const oidc_transport = @import("oidc_transport.zig");
const service_oidc_config = @import("service_oidc_config.zig");
const oauth = @import("oauth-core");
const telemetry = @import("chock-telemetry");

const control = chock_proto.control;

// Keep the daemon-owned platform state in the daemon's compilation and test
// boundary. It is not a public Chock library.
comptime {
    _ = daemon_state;
}

const max_request_bytes: usize = control.max_request_bytes;

const max_events_per_read: usize = 100_000;
const max_worker_events_per_read: usize = 64;

const max_listeners: usize = 2;

const max_connections: usize = 64;

const max_pending_oidc_attempts: usize = 128;

test "service OIDC configuration persistence module is linked" {
    _ = service_oidc_config.Config;
}
const max_oidc_callback_url: usize = 2048;

const PendingOidcAttempt = struct {
    attempt: oauth.Attempt,
    expires: i64,
    callback_url: [max_oidc_callback_url]u8,
    callback_url_len: usize,

    fn wipe(self: *PendingOidcAttempt) void {
        self.attempt.wipe();
        std.crypto.secureZero(u8, &self.callback_url);
        self.* = undefined;
    }
};

const watch_idle_ms: u64 = 250;

const usage_text =
    \\Usage: chock daemon [options]
    \\
    \\Owns sessions and answers `chock serve`, `chock detach`, and any other
    \\client. Listens on a unix socket in the state directory, and on nothing
    \\else until --host names an address.
    \\
    \\The unix socket serves the user that started this daemon. --socket-group
    \\can grant access to one dedicated local group; all other peers are refused
    \\using credentials the kernel puts on the connection.
    \\
    \\Options:
    \\  --socket <path>  The unix socket. Default is daemon.sock in the state directory.
    \\  --socket-group <group> Give this local primary group access to the socket.
    \\  --host <addr>    Also listen on this address, over TCP. Off by default.
    \\  --port <n>       The TCP port, with --host. 0 asks the system for one and
    \\                   prints it. Default 7373.
    \\  --database <url> Quarry database URL. Defaults to daemon.sqlite in the
    \\                   state directory. CHOCK_DATABASE_URL is the environment default.
    \\  --oidc-provider <name> kanidm, authentik, or authelia. Also CHOCK_OIDC_PROVIDER.
    \\  --oidc-issuer <url>   Exact issuer URL. Also CHOCK_OIDC_ISSUER.
    \\  --oidc-client-id <id> Public OIDC client ID. Also CHOCK_OIDC_CLIENT_ID.
    \\  --oidc-discovery-url <url> Override discovery metadata URL when needed.
    \\  --oidc-admin-subject <sub> Explicit OIDC subject to grant instance admin. Also CHOCK_OIDC_ADMIN_SUBJECT.
    \\  CHOCK_GIT_ALLOWED_HOSTS Comma-separated exact HTTPS Git host allowlist for project provisioning.
    \\
    \\Chock does no authentication over a network, and a TCP connection carries
    \\no credential to check. Anything that can route to a --host address can
    \\drive this daemon, so put a reverse proxy such as Authelia in front of it.
    \\
++ tty.options_text;

const Session = struct {
    id: [session_paths.id_length]u8,
    log_path: [:0]u8,
    snapshot_path: [:0]u8,
    project: []u8,
    turn: ?*Turn = null,
    guest: ?Guest = null,
    has_snapshot: bool = false,
    snapshotting: bool = false,
};

const Turn = struct {
    stop: std.atomic.Value(bool) = .init(false),
};

const Guest = struct {
    running: *Running,
    socket: [:0]u8,
    turns: u64 = 0,
};

const ForkSnapshot = union(enum) {
    none,
    wait,
    file,
    guest: Guest,
};

// PR_SET_PDEATHSIG fires when the thread that forked the guest ends, not when its process does, so the thread lives as long as the guest.
const Running = struct {
    thread: std.Thread,
    ready: std.atomic.Value(bool) = .init(false),
    stopping: std.atomic.Value(bool) = .init(false),
    snapshotting: std.atomic.Value(bool) = .init(false),
    snapshot_saved: std.atomic.Value(bool) = .init(false),
    snapshot_allowed: std.atomic.Value(bool) = .init(false),
    ended: std.atomic.Value(bool) = .init(false),
};

const guest_idle_ms: u64 = 5 * std.time.ms_per_min;

const guest_boot_ms: u64 = 30 * std.time.ms_per_s;

const guest_look_ms: u64 = 100;

const max_guests: usize = 4;

const Daemon = struct {
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator = std.heap.page_allocator,
    io: std.Io,
    exe_path: []const u8,
    environ: std.process.Environ = .empty,
    env: *const std.process.Environ.Map,
    owner_uid: std.posix.uid_t = 0,
    socket_group_gid: ?std.posix.gid_t = null,
    mutex: std.Io.Mutex = .init,
    oidc_mutex: std.Io.Mutex = .init,
    pending_oidc: [max_pending_oidc_attempts]?PendingOidcAttempt = @splat(null),
    sessions: std.ArrayList(Session) = .empty,
    live: std.atomic.Value(usize) = .init(0),
    sandbox: chock_policy.sandbox.Block = .{},
    socket_dir: []const u8 = "",
    project_store_dir: []const u8 = "",
    snapshot_dir: []const u8 = "",
    oidc_config_path: []const u8 = "",
    persisted_oidc_config: ?service_oidc_config.Config = null,
    oidc_admin_subject: ?[]const u8 = null,
    database: ?daemon_state.Database = null,
    oidc: ?daemon_state.Oidc = null,
    oidc_metadata: ?oauth.oidc.Metadata = null,

    fn deinit(self: *Daemon) void {
        for (&self.pending_oidc) |*entry| if (entry.*) |*pending| {
            pending.wipe();
            entry.* = null;
        };
        for (self.sessions.items) |entry| {
            var keep_snapshot = entry.has_snapshot;
            if (entry.guest) |one| {
                if (one.running.snapshot_allowed.load(.acquire)) {
                    one.running.snapshotting.store(true, .release);
                } else {
                    one.running.stopping.store(true, .release);
                }
                one.running.thread.join();
                keep_snapshot = one.running.snapshot_saved.load(.acquire);
                self.gpa.destroy(one.running);
                self.gpa.free(one.socket);
            }
            self.gpa.free(entry.log_path);
            if (!keep_snapshot) std.Io.Dir.deleteFileAbsolute(self.io, entry.snapshot_path) catch {};
            self.gpa.free(entry.snapshot_path);
            self.gpa.free(entry.project);
        }
        if (self.persisted_oidc_config) |*config| config.deinit(self.gpa);
        self.sessions.deinit(self.gpa);
        self.sandbox.deinit(self.gpa);
        if (self.database) |*database| database.close();
    }

    fn guestFor(self: *Daemon, id: []const u8) ?Guest {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |entry| {
            if (std.mem.eql(u8, &entry.id, id)) return entry.guest;
        }
        return null;
    }

    const GuestState = union(enum) {
        none,
        snapshotting,
        ready: Guest,
    };

    fn guestState(self: *Daemon, id: []const u8) GuestState {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            if (entry.guest) |one| return .{ .ready = one };
            if (entry.snapshotting) return .snapshotting;
            return .none;
        }
        return .none;
    }

    fn rememberGuest(self: *Daemon, id: []const u8, one: Guest) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            if (entry.guest != null) return false;
            entry.guest = one;
            return true;
        }
        return false;
    }

    fn takeSnapshot(self: *Daemon, id: []const u8) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            const had = entry.has_snapshot;
            entry.has_snapshot = false;
            return had;
        }
        return false;
    }

    fn noteSnapshot(self: *Daemon, id: []const u8, saved: bool) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            entry.has_snapshot = saved;
            entry.snapshotting = false;
            return;
        }
    }

    fn claimForkSnapshot(self: *Daemon, id: []const u8) ForkSnapshot {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            if (entry.snapshotting) return .wait;
            if (entry.has_snapshot) {
                entry.has_snapshot = false;
                entry.snapshotting = true;
                return .file;
            }
            const guest = entry.guest orelse return .none;
            if (!guest.running.snapshot_allowed.load(.acquire)) return .none;
            entry.guest = null;
            entry.snapshotting = true;
            return .{ .guest = guest };
        }
        return .none;
    }

    fn finishForkSnapshot(self: *Daemon, id: []const u8, kept: bool) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            entry.has_snapshot = kept;
            entry.snapshotting = false;
            return;
        }
    }

    fn snapshotPathFor(self: *Daemon, id: []const u8) ?[]const u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |entry| {
            if (std.mem.eql(u8, &entry.id, id)) return entry.snapshot_path;
        }
        return null;
    }

    fn noteTurn(self: *Daemon, id: []const u8) ?u64 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            const one = &(entry.guest orelse return null);
            one.turns += 1;
            return one.turns;
        }
        return null;
    }

    fn takeGuest(self: *Daemon, id: []const u8, turns: u64) ?Guest {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            const one = entry.guest orelse return null;
            if (one.turns != turns) return null;
            entry.guest = null;
            entry.snapshotting = true;
            return one;
        }
        return null;
    }

    fn guestCount(self: *Daemon) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var count: usize = 0;
        for (self.sessions.items) |entry| {
            if (entry.guest != null) count += 1;
        }
        return count;
    }

    /// Register a session once. Requests for later turns reuse that entry
    /// instead of growing the daemon's table once per prompt.
    fn remember(self: *Daemon, entry: Session) !bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |known| {
            if (std.mem.eql(u8, &known.id, &entry.id)) return false;
        }
        try self.sessions.append(self.gpa, entry);
        return true;
    }

    /// Forget a just-created idle session after its registry transaction needs
    /// compensation. A live turn or guest always keeps its session entry.
    fn forgetIdleSession(self: *Daemon, id: []const u8) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items, 0..) |entry, index| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            if (entry.turn != null or entry.guest != null or entry.snapshotting) return false;
            const forgotten = self.sessions.orderedRemove(index);
            self.gpa.free(forgotten.log_path);
            self.gpa.free(forgotten.snapshot_path);
            self.gpa.free(forgotten.project);
            return true;
        }
        return false;
    }

    fn noteTurnWorker(self: *Daemon, id: []const u8, turn: ?*Turn) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            if (turn != null and entry.turn != null) return false;
            entry.turn = turn;
            return true;
        }
        return false;
    }

    fn cancelTurn(self: *Daemon, id: []const u8) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |*entry| {
            if (!std.mem.eql(u8, &entry.id, id)) continue;
            const turn = entry.turn orelse return false;
            turn.stop.store(true, .monotonic);
            return true;
        }
        return false;
    }

    fn logPathFor(self: *Daemon, id: []const u8) !?[:0]u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.sessions.items) |entry| {
            if (std.mem.eql(u8, &entry.id, id)) return try self.gpa.dupeSentinel(u8, entry.log_path, 0);
        }
        return null;
    }
};

pub fn main(
    init: std.process.Init,
    exe_path: []const u8,
    args: []const []const u8,
) !u8 {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const io = init.io;
    const environ = init.minimal.environ;
    const env = init.environ_map.*;

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        error.BadArguments => return Exit.usage.code(),
    };

    var daemon = Daemon{
        .gpa = gpa,
        .arena = arena,
        .io = io,
        .exe_path = exe_path,
        .environ = environ,
        .env = &env,
        .owner_uid = std.posix.system.getuid(),
    };
    if (options.socket_group) |name| {
        daemon.socket_group_gid = groupId(gpa, io, name) orelse {
            tty.print(.err, "chock daemon: --socket-group does not name a local group: {s}\n", .{name});
            return Exit.usage.code();
        };
    }
    defer daemon.deinit();

    daemon.sandbox = readSandbox(gpa, io, arena, &env) orelse return Exit.usage.code();
    if (daemon.sandbox.missing()) |key| {
        tty.print(
            .err,
            "chock daemon: config.zon chose the microvm sandbox driver and names no {s}. " ++
                "Add .sandbox = .{{ .{s} = \"...\" }} to it. The guest images are the flake's " ++
                "own guest-kernel and guest-initrd outputs.\n",
            .{ key, key },
        );
        return Exit.usage.code();
    }
    if (daemon.sandbox.chosen() == .microvm) {
        tty.print(.plain, "chock daemon: tool calls run in a microVM guest, one a session\n", .{});
    }

    const state_dir = chock_auth.paths.stateDir(arena, &env) catch |err| switch (err) {
        error.NoHomeDirectory => {
            directory_help.report("daemon", .state);
            return Exit.usage.code();
        },
        error.OutOfMemory => return error.OutOfMemory,
    };
    makeDirAll(io, state_dir) catch |err| {
        tty.print(.err, "chock daemon: {s} could not be made: {t}\n", .{ state_dir, err });
        return Exit.usage.code();
    };
    daemon.snapshot_dir = state_dir;
    daemon.oidc_config_path = std.fs.path.join(arena, &.{ state_dir, "service-oidc.json" }) catch return Exit.faulted.code();
    daemon.project_store_dir = std.fs.path.join(arena, &.{ state_dir, "projects" }) catch return Exit.faulted.code();
    makeDirAll(io, daemon.project_store_dir) catch |err| {
        tty.print(.err, "chock daemon: project storage {s} could not be made: {t}\n", .{ daemon.project_store_dir, err });
        return Exit.usage.code();
    };

    const database_url = options.database orelse env.get("CHOCK_DATABASE_URL") orelse
        (std.fmt.allocPrint(arena, "sqlite:{f}/daemon.sqlite", .{std.fmt.alt(
            @as(std.Uri.Component, .{ .raw = state_dir }),
            .formatEscaped,
        )}) catch return Exit.faulted.code());
    const now_ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
    daemon.database = daemon_state.Database.open(gpa, io, database_url, &env, now_ms) catch |err| {
        tty.print(.err, "chock daemon: database {s} could not be opened: {t}\n", .{ database_url, err });
        return Exit.usage.code();
    };

    var oidc = configuredOidc(options, &env) catch |err| switch (err) {
        error.IncompleteOidcConfiguration => {
            tty.print(.err, "chock daemon: OIDC needs a provider, issuer, and client ID.\n", .{});
            return Exit.usage.code();
        },
        error.InvalidOidcProvider => {
            tty.print(.err, "chock daemon: OIDC provider must be kanidm, authentik, or authelia.\n", .{});
            return Exit.usage.code();
        },
        error.InvalidOidcConfiguration => {
            tty.print(.err, "chock daemon: OIDC issuer and discovery URLs must use HTTPS (HTTP is allowed only for loopback development).\n", .{});
            return Exit.usage.code();
        },
    };
    if (oidc == null) {
        daemon.persisted_oidc_config = service_oidc_config.load(gpa, io, daemon.oidc_config_path) catch |err| switch (err) {
            error.FileNotFound => null,
            else => {
                tty.print(.err, "chock daemon: private OIDC configuration {s} could not be loaded: {t}\n", .{ daemon.oidc_config_path, err });
                return Exit.usage.code();
            },
        };
        if (daemon.persisted_oidc_config) |stored| {
            oidc = .{
                .provider = stored.provider,
                .issuer = stored.issuer,
                .client_id = stored.client_id,
                .client_secret = stored.client_secret,
                .discovery_url = stored.discovery_url,
            };
        }
    }
    daemon.oidc = oidc;
    daemon.oidc_admin_subject = options.oidc_admin_subject orelse env.get("CHOCK_OIDC_ADMIN_SUBJECT") orelse
        if (daemon.persisted_oidc_config) |stored| stored.admin_subject else null;
    if (oidc) |config| {
        var transport = oidc_transport.init(io, env.get("SSL_CERT_FILE"));
        daemon.oidc_metadata = config.discover(arena, transport.transport()) catch |err| {
            tty.print(.err, "chock daemon: OIDC discovery for {s} failed: {t}\n", .{ config.issuer, err });
            return Exit.usage.code();
        };
    }

    const socket_path = options.socket orelse
        (control.socketPathIn(arena, state_dir) catch return Exit.faulted.code());

    daemon.socket_dir = std.fs.path.dirname(socket_path) orelse ".";

    var wanted_buffer: [max_listeners]control.Address = undefined;
    const wanted = listenSet(&wanted_buffer, socket_path, options);

    var listeners: [max_listeners]control.Listener = undefined;
    var opened: usize = 0;
    defer for (listeners[0..opened]) |*one| one.close(io);

    for (wanted) |address| {
        listeners[opened] = address.listen(io) catch |err| {
            tty.print(
                .err,
                "chock daemon: {f} could not be listened on: {t}\n",
                .{ address, err },
            );
            if (err == error.PathTooLong) tty.print(
                .err,
                "chock daemon: a unix socket path is at most {d} bytes on this platform. " ++
                    "Name a shorter one with --socket.\n",
                .{control.max_socket_path},
            );
            return Exit.usage.code();
        };
        opened += 1;
        if (address == .unix and daemon.socket_group_gid != null) {
            const path = address.unix;
            const path_z = try arena.dupeSentinel(u8, path, 0);
            const group_set = switch (builtin.os.tag) {
                .linux => std.posix.errno(std.os.linux.fchownat(
                    std.posix.AT.FDCWD,
                    path_z.ptr,
                    std.math.maxInt(std.posix.uid_t),
                    daemon.socket_group_gid.?,
                    std.posix.AT.SYMLINK_NOFOLLOW,
                )) == .SUCCESS,
                .macos => std.c.fchownat(
                    std.posix.AT.FDCWD,
                    path_z.ptr,
                    std.math.maxInt(std.c.uid_t),
                    daemon.socket_group_gid.?,
                    std.posix.AT.SYMLINK_NOFOLLOW,
                ) == 0,
                else => false,
            };
            if (!group_set) {
                tty.print(.err, "chock daemon: could not assign the control socket group.\n", .{});
                return Exit.usage.code();
            }
            std.Io.Dir.cwd().setFilePermissions(io, path, @fromBackingInt(@intCast(0o770)), .{ .follow_symlinks = false }) catch |err| {
                tty.print(.err, "chock daemon: could not make the control socket group-accessible: {t}\n", .{err});
                return Exit.usage.code();
            };
        }
        tty.print(.plain, "chock daemon: listening on {f}\n", .{reportable(address, listeners[opened - 1])});
    }

    accept(&daemon, listeners[0..opened]);
    return Exit.finished.code();
}

fn readSandbox(
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.mem.Allocator,
    env: *const std.process.Environ.Map,
) ?chock_policy.sandbox.Block {
    const dir = chock_auth.paths.configDir(arena, env) catch return .{};
    const path = std.fs.path.joinZ(arena, &.{ dir, chock_auth.config.file_name }) catch return .{};

    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        arena,
        .limited(chock_auth.config.max_file_bytes),
        .of(u8),
        0,
    ) catch return .{};

    var diag: ?chock_policy.sandbox.Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    defer std.crypto.secureZero(u8, source);
    return chock_policy.sandbox.parse(gpa, source, &diag) catch {
        if (diag) |*one| {
            tty.print(.err, "chock daemon: {s}: {f}\n", .{ path, one });
        } else {
            tty.print(.err, "chock daemon: {s} could not be read\n", .{path});
        }
        return null;
    };
}

fn makeDirAll(io: std.Io, path: []const u8) !void {
    if (path.len == 0) return;
    std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return err;
            try makeDirAll(io, parent);
            std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |second| switch (second) {
                error.PathAlreadyExists => return,
                else => return second,
            };
        },
        else => return err,
    };
}

fn groupId(gpa: std.mem.Allocator, io: std.Io, name: []const u8) ?std.posix.gid_t {
    if (std.fmt.parseInt(std.posix.gid_t, name, 10)) |gid| return gid else |_| {}
    const text = std.Io.Dir.readFileAlloc(.cwd(), io, "/etc/group", gpa, .limited(1 << 20)) catch return null;
    defer gpa.free(text);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        const group_name = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const gid_text = fields.next() orelse continue;
        if (std.mem.eql(u8, group_name, name)) return std.fmt.parseInt(std.posix.gid_t, gid_text, 10) catch null;
    }
    return null;
}

fn listenSet(
    buffer: *[max_listeners]control.Address,
    socket_path: []const u8,
    options: Options,
) []const control.Address {
    buffer[0] = .{ .unix = socket_path };
    const host = options.host orelse return buffer[0..1];
    buffer[1] = .{ .ip = .{ .host = host, .port = options.port } };
    return buffer[0..2];
}

const peerAllowed = control.peerAllowed;

fn daemonPeerAllowed(daemon: *const Daemon, handle: std.posix.fd_t) bool {
    return control.peerAllowed(control.peerUid(handle), daemon.owner_uid) or
        control.peerGroupAllowed(control.peerGid(handle), daemon.socket_group_gid);
}

fn reportable(address: control.Address, listener: control.Listener) control.Address {
    return switch (address) {
        .unix => address,
        .ip => |ip| .{ .ip = .{ .host = ip.host, .port = listener.server.socket.address.getPort() } },
    };
}

fn accept(daemon: *Daemon, listeners: []control.Listener) void {
    var fds: [4]std.posix.pollfd = undefined;
    std.debug.assert(listeners.len <= fds.len);

    while (true) {
        for (listeners, 0..) |*one, index| {
            fds[index] = .{ .fd = one.server.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
        }
        const ready = std.posix.poll(fds[0..listeners.len], 1000) catch continue;
        if (ready == 0) continue;

        for (fds[0..listeners.len], listeners) |entry, *one| {
            if (entry.revents == 0) continue;
            var stream = one.server.accept(daemon.io) catch |err| {
                tty.print(.warn, "chock daemon: an incoming connection failed: {t}\n", .{err});
                continue;
            };

            if (one.unix_path != null and !daemonPeerAllowed(daemon, stream.socket.handle)) {
                var buffer: [256]u8 = undefined;
                var writer = stream.writer(daemon.io, &buffer);
                fail(&writer.interface, "this daemon serves the user that started it, and you are not that user");
                tty.print(.warn, "chock daemon: a client of another user was refused.\n", .{});
                stream.close(daemon.io);
                continue;
            }

            if (daemon.live.load(.monotonic) >= max_connections) {
                var buffer: [256]u8 = undefined;
                var writer = stream.writer(daemon.io, &buffer);
                fail(&writer.interface, "this daemon is serving as many clients as it can");
                stream.close(daemon.io);
                continue;
            }

            _ = daemon.live.fetchAdd(1, .monotonic);
            const thread = std.Thread.spawn(.{}, runConnection, .{Connection{
                .daemon = daemon,
                .stream = stream,
            }}) catch {
                _ = daemon.live.fetchSub(1, .monotonic);
                stream.close(daemon.io);
                continue;
            };
            thread.detach();
        }
    }
}

const Connection = struct {
    daemon: *Daemon,
    stream: std.Io.net.Stream,
};

fn runConnection(conn: Connection) void {
    const daemon = conn.daemon;
    var stream = conn.stream;
    defer {
        stream.close(daemon.io);
        _ = daemon.live.fetchSub(1, .monotonic);
    }

    var arena = std.heap.ArenaAllocator.init(daemon.gpa);
    defer arena.deinit();

    serve(daemon, arena.allocator(), &stream);
}

fn serve(daemon: *Daemon, arena: std.mem.Allocator, stream: *std.Io.net.Stream) void {
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(daemon.io, &read_buffer);
    const reader = &stream_reader.interface;

    var write_buffer: [64 * 1024]u8 = undefined;
    var stream_writer = stream.writer(daemon.io, &write_buffer);
    const writer = &stream_writer.interface;
    // The buffer is local, so a handler that returns without flushing leaves its answer here and the client gets nothing back.
    defer writer.flush() catch {};

    if (!greet(reader, writer)) return;

    // takeDelimiterExclusive stops before the line break, so a second read on one connection would see an empty line forever.
    const line = (reader.takeDelimiter('\n') catch null) orelse {
        fail(writer, "the request had no line to read");
        return;
    };
    if (line.len > max_request_bytes) {
        fail(writer, "the request is too long");
        return;
    }

    const request = control.Request.parse(std.mem.trimEnd(u8, line, "\r")) catch |err| switch (err) {
        error.NoVerb => {
            fail(writer, control.no_verb_text);
            return;
        },
        error.BadArguments => {
            fail(writer, "that verb does not take those arguments");
            return;
        },
    };

    if (!enforceWorkerCredentialScope(daemon, arena, writer, request)) return;

    // The current platform gateway and browser authorization path run beside
    // the daemon and use its private Unix socket. Legacy v1 worker commands do
    // not carry an identity, so never accept them from a network peer while
    // OIDC is enabled; client-hosted workers need an authenticated extension.
    if (daemon.oidc != null and !daemonPeerAllowed(daemon, stream.socket.handle)) {
        fail(writer, "OIDC-enabled daemon control currently accepts requests only from its owner's local socket");
        return;
    }

    if (request == .auth_status or request == .auth_local_setup or request == .auth_local_login or request == .auth_oidc_setup or request == .auth_oidc_begin or request == .auth_oidc_exchange or request == .auth_session or request == .auth_logout or request == .auth_authorize or request == .auth_project_create or request == .auth_project_list or request == .auth_session_create or request == .auth_session_register or request == .auth_session_register_placed or request == .auth_session_member or request == .auth_session_people or request == .auth_session_presence or request == .auth_session_host or request == .auth_worker_event or request == .auth_worker_read or request == .auth_worker_token or request == .auth_people or request == .auth_team or request == .auth_acl or request == .auth_provider or request == .auth_prompt or request == .auth_cancel or request == .auth_answer or request == .auth_agent_answer) {
        if (!daemonPeerAllowed(daemon, stream.socket.handle)) {
            fail(writer, "authentication handoff is accepted only from the daemon owner's local socket");
            return;
        }
    }

    switch (request) {
        .auth_status => handleAuthStatus(daemon, writer),
        .auth_local_setup => |one| handleAuthLocal(daemon, arena, writer, one, true),
        .auth_local_login => |one| handleAuthLocal(daemon, arena, writer, one, false),
        .auth_oidc_setup => |one| handleAuthOidcSetup(daemon, arena, writer, one),
        .start => |one| handleStart(daemon, writer, one),
        .adopt => |one| handleAdopt(daemon, writer, one),
        .create => |one| handleCreate(daemon, writer, one),
        .fork => |one| handleFork(daemon, writer, one),
        .review => |one| handleReview(daemon, arena, writer, one),
        .select => |one| handleSelect(daemon, arena, writer, one),
        .undo_selection => |one| handleUndoSelection(daemon, arena, writer, one),
        .prompt => |one| handlePrompt(daemon, writer, one),
        .cancel => |one| handleCancel(daemon, writer, one),
        .read => |one| handleRead(daemon, arena, writer, one, false, max_events_per_read),
        .list => |one| handleList(daemon, arena, writer, one),
        .projects => handleProjects(daemon, arena, writer),
        .watch => |one| handleWatch(daemon, arena, writer, stream.socket.handle, one),
        .answer => |one| handleAnswer(daemon, arena, writer, one),
        .auth_oidc_begin => |one| handleAuthOidcBegin(daemon, arena, writer, one),
        .auth_oidc_exchange => |one| handleAuthOidcExchange(daemon, arena, writer, one),
        .auth_session => |one| handleAuthSession(daemon, arena, writer, one),
        .auth_logout => |one| handleAuthLogout(daemon, writer, one),
        .auth_authorize => |one| handleAuthAuthorize(daemon, arena, writer, one),
        .auth_project_create => |one| handleAuthProjectCreate(daemon, arena, writer, one),
        .auth_project_list => |one| handleAuthProjectList(daemon, arena, writer, one),
        .auth_session_create => |one| handleAuthSessionCreate(daemon, arena, writer, one),
        .auth_session_register => |one| handleAuthSessionRegister(daemon, arena, writer, .{
            .token = one.token,
            .session = one.session,
            .project = one.project,
            .placement = "daemon",
        }),
        .auth_session_register_placed => |one| handleAuthSessionRegister(daemon, arena, writer, one),
        .auth_session_member => |one| handleAuthSessionMember(daemon, arena, writer, one),
        .auth_session_people => |one| handleAuthSessionPeople(daemon, arena, writer, one),
        .auth_session_presence => |one| handleAuthSessionPresence(daemon, arena, writer, one),
        .auth_session_host => |one| handleAuthSessionHost(daemon, arena, writer, one),
        .auth_worker_event => |one| handleAuthWorkerEvent(daemon, arena, writer, one),
        .auth_worker_read => |one| handleAuthWorkerRead(daemon, arena, writer, one),
        .auth_worker_token => |one| handleAuthWorkerToken(daemon, arena, writer, one),
        .auth_people => |one| handleAuthPeople(daemon, arena, writer, one),
        .auth_team => |one| handleAuthTeam(daemon, arena, writer, one),
        .auth_acl => |one| handleAuthAcl(daemon, arena, writer, one),
        .auth_provider => |one| handleAuthProvider(daemon, arena, writer, one),
        .auth_prompt => |one| handleAuthPrompt(daemon, arena, writer, one),
        .auth_cancel => |one| handleAuthCancel(daemon, arena, writer, one),
        .auth_answer => |one| handleAuthAnswer(daemon, arena, writer, one),
        .auth_agent_answer => |one| handleAuthAgentAnswer(daemon, arena, writer, one),
    }
}

/// A worker bearer is a capability for one client-hosted session, not a
/// shorter-lived copy of a user's browser login. Enforce that restriction at
/// the control boundary, including requests that would otherwise accept any
/// authenticated identity.
fn enforceWorkerCredentialScope(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    request: control.Request,
) bool {
    const token = authRequestToken(request) orelse return true;
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return false;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return false;
    } orelse return true;
    defer arena.free(principal.instance_role);
    const scope = principal.workerScope() orelse return true;
    if (!workerScopeAllows(scope, request)) {
        fail(writer, "this worker credential is restricted to its assigned client-hosted session");
        return false;
    }
    return true;
}

fn workerScopeAllows(scope: []const u8, request: control.Request) bool {
    return switch (request) {
        .auth_logout => true,
        .auth_session_host => |one| (std.mem.eql(u8, one.action, "claim") or std.mem.eql(u8, one.action, "release")) and
            std.mem.eql(u8, one.placement, "client") and std.mem.eql(u8, scope, one.session),
        .auth_worker_read => |one| std.mem.eql(u8, scope, one.session),
        .auth_worker_event => |one| std.mem.eql(u8, scope, one.session),
        else => false,
    };
}

fn authRequestToken(request: control.Request) ?[]const u8 {
    return switch (request) {
        .auth_session => |one| one.token,
        .auth_logout => |one| one.token,
        .auth_authorize => |one| one.token,
        .auth_project_create => |one| one.token,
        .auth_project_list => |one| one.token,
        .auth_session_create => |one| one.token,
        .auth_session_register => |one| one.token,
        .auth_session_register_placed => |one| one.token,
        .auth_session_member => |one| one.token,
        .auth_session_people => |one| one.token,
        .auth_session_presence => |one| one.token,
        .auth_session_host => |one| one.token,
        .auth_worker_event => |one| one.token,
        .auth_worker_read => |one| one.token,
        .auth_worker_token => |one| one.token,
        .auth_people => |one| one.token,
        .auth_team => |one| one.token,
        .auth_acl => |one| one.token,
        .auth_provider => |one| one.token,
        .auth_prompt => |one| one.token,
        .auth_cancel => |one| one.token,
        .auth_answer => |one| one.token,
        .auth_agent_answer => |one| one.token,
        else => null,
    };
}

test "worker credentials stay inside their one client-hosted session" {
    const credential = "01JQ0000000000000000000000";
    try std.testing.expect(workerScopeAllows(credential, .{ .auth_worker_read = .{
        .token = "bearer",
        .session = credential,
        .host_id = "00000000-0000-4000-8000-000000000099",
        .generation = 1,
        .after = 0,
    } }));
    try std.testing.expect(!workerScopeAllows(credential, .{ .auth_worker_read = .{
        .token = "bearer",
        .session = "01JQ0000000000000000000001",
        .host_id = "00000000-0000-4000-8000-000000000099",
        .generation = 1,
        .after = 0,
    } }));
    try std.testing.expect(!workerScopeAllows(credential, .{ .auth_prompt = .{
        .token = "bearer",
        .project = "/work",
        .session = credential,
        .message = "dGVzdA",
    } }));
    try std.testing.expect(!workerScopeAllows(credential, .{ .auth_cancel = .{
        .token = "bearer",
        .project = "/work",
        .session = credential,
    } }));
    try std.testing.expect(!workerScopeAllows(credential, .{ .auth_agent_answer = .{
        .token = "bearer",
        .project = "/work",
        .session = credential,
        .request_id = 128,
        .answer = "dGVzdA",
    } }));
    try std.testing.expect(workerScopeAllows(credential, .{ .auth_logout = .{ .token = "bearer" } }));
}

const AuthAssertion = struct {
    issuer: []const u8,
    subject: []const u8,
    email: ?[]const u8 = null,
    display_name: ?[]const u8 = null,
};

const LocalCredentials = struct { username: []const u8, password: []const u8 };
const OidcSetupInput = service_oidc_config.Config;

fn cloneOidcConfig(gpa: std.mem.Allocator, input: service_oidc_config.Config) !service_oidc_config.Config {
    var owned: service_oidc_config.Config = .{
        .provider = input.provider,
        .issuer = try gpa.dupe(u8, input.issuer),
        .discovery_url = null,
        .client_id = "",
        .client_secret = null,
        .admin_subject = "",
    };
    errdefer owned.deinit(gpa);
    owned.discovery_url = if (input.discovery_url) |url| try gpa.dupe(u8, url) else null;
    owned.client_id = try gpa.dupe(u8, input.client_id);
    owned.client_secret = if (input.client_secret) |secret| try gpa.dupe(u8, secret) else null;
    owned.admin_subject = try gpa.dupe(u8, input.admin_subject);
    return owned;
}

fn handleAuthStatus(daemon: *Daemon, writer: *std.Io.Writer) void {
    if (daemon.oidc != null) {
        writer.writeAll(control.ok_prefix ++ "oidc\n") catch {};
        return;
    }
    const database = if (daemon.database) |*value| value else {
        writer.writeAll(control.ok_prefix ++ "single-user\n") catch {};
        return;
    };
    const state = database.localSetupState() catch {
        fail(writer, "the authentication state could not be read");
        return;
    };
    if (state == .available) {
        writer.writeAll(control.ok_prefix ++ "setup-required\n") catch {};
    } else if (state == .local) {
        writer.writeAll(control.ok_prefix ++ "local\n") catch {};
    } else {
        writer.writeAll(control.ok_prefix ++ "configured\n") catch {};
    }
}

fn handleAuthOidcSetup(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.AuthOidcSetup,
) void {
    daemon.oidc_mutex.lockUncancelable(daemon.io);
    defer daemon.oidc_mutex.unlock(daemon.io);
    if (daemon.oidc != null or daemon.oidc_config_path.len == 0) {
        fail(writer, "OIDC setup is already configured or unavailable");
        return;
    }
    const database = if (daemon.database) |*value| value else {
        fail(writer, "service authentication requires a database");
        return;
    };
    const setup_state = database.localSetupState() catch {
        fail(writer, "the service setup state could not be read");
        return;
    };
    if (setup_state != .available) {
        fail(writer, "initial service setup has already been completed");
        return;
    }

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(one.configuration) catch {
        fail(writer, "the OIDC configuration was malformed");
        return;
    };
    if (decoded_len > service_oidc_config.max_config_bytes) {
        fail(writer, "the OIDC configuration is too large");
        return;
    }
    const decoded = arena.alloc(u8, decoded_len) catch {
        fail(writer, "the OIDC configuration could not be read");
        return;
    };
    decoder.decode(decoded, one.configuration) catch {
        fail(writer, "the OIDC configuration was malformed");
        return;
    };
    const input = std.json.parseFromSliceLeaky(OidcSetupInput, arena, decoded, .{}) catch {
        fail(writer, "the OIDC configuration was malformed");
        return;
    };
    input.validate() catch {
        fail(writer, "the OIDC configuration was invalid");
        return;
    };
    const config: daemon_state.Oidc = .{
        .provider = input.provider,
        .issuer = input.issuer,
        .client_id = input.client_id,
        .client_secret = input.client_secret,
        .discovery_url = input.discovery_url,
    };
    var transport = oidc_transport.init(daemon.io, daemon.env.get("SSL_CERT_FILE"));
    const metadata = config.discover(daemon.arena, transport.transport()) catch {
        fail(writer, "OIDC discovery failed or returned a different issuer");
        return;
    };
    const owned = cloneOidcConfig(daemon.gpa, input) catch {
        fail(writer, "the OIDC configuration could not be retained");
        return;
    };
    service_oidc_config.save(daemon.gpa, daemon.io, daemon.oidc_config_path, input) catch {
        var uncommitted = owned;
        uncommitted.deinit(daemon.gpa);
        fail(writer, "the private OIDC configuration could not be saved");
        return;
    };
    daemon.persisted_oidc_config = owned;
    daemon.oidc = .{
        .provider = owned.provider,
        .issuer = owned.issuer,
        .client_id = owned.client_id,
        .client_secret = owned.client_secret,
        .discovery_url = owned.discovery_url,
    };
    daemon.oidc_admin_subject = owned.admin_subject;
    daemon.oidc_metadata = metadata;
    writer.writeAll(control.ok_prefix ++ "configured\n") catch {};
}

fn handleAuthLocal(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.AuthLocalCredentials,
    setup: bool,
) void {
    if (setup) daemon.oidc_mutex.lockUncancelable(daemon.io);
    defer if (setup) daemon.oidc_mutex.unlock(daemon.io);
    if (daemon.oidc != null) {
        fail(writer, "local authentication is disabled when OIDC is configured");
        return;
    }
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the service database is not available");
        return;
    };
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(one.credentials) catch {
        fail(writer, "the local credentials were malformed");
        return;
    };
    const decoded = arena.alloc(u8, decoded_len) catch {
        fail(writer, "the local credentials could not be read");
        return;
    };
    decoder.decode(decoded, one.credentials) catch {
        fail(writer, "the local credentials were malformed");
        return;
    };
    const credentials = std.json.parseFromSliceLeaky(LocalCredentials, arena, decoded, .{}) catch {
        fail(writer, "the local credentials were malformed");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const identity = if (setup)
        database.createInitialLocalAdmin(daemon.gpa, daemon.io, credentials.username, credentials.password, now_ms) catch {
            fail(writer, "initial account setup was refused");
            return;
        }
    else
        (database.authenticateLocalAccount(daemon.gpa, daemon.io, credentials.username, credentials.password) catch {
            fail(writer, "account authentication failed");
            return;
        }) orelse {
            fail(writer, "account authentication failed");
            return;
        };
    defer daemon.gpa.free(identity.instance_role);
    const expires_ms = std.math.add(i64, now_ms, login_session_ms) catch {
        fail(writer, "the login session expiry overflowed");
        return;
    };
    const session = database.createLoginSession(daemon.io, &identity.id, now_ms, expires_ms) catch {
        fail(writer, "the login session could not be created");
        return;
    };
    telemetry.event("chock.auth.login.succeeded", .info, &.{.{
        .key = "auth.mode",
        .value = .{ .string = "local" },
    }});
    writer.print(control.ok_prefix ++ "{s}\t{s}\t{s}\t{d}\n", .{
        &identity.id, identity.instance_role, &session.token, session.expires_ms,
    }) catch {};
}

const login_session_ms: i64 = 30 * std.time.ms_per_day;

const OidcBeginInput = struct {
    redirect_uri: []const u8,
    allow_http: bool = false,
};
const OidcExchangeInput = struct { target: []const u8, cookie_state: []const u8 };

fn handleAuthOidcBegin(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.AuthOidcBegin,
) void {
    const oidc = daemon.oidc orelse {
        fail(writer, "the daemon has no OIDC provider configured");
        return;
    };
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(one.input) catch {
        fail(writer, "the OIDC setup was malformed");
        return;
    };
    const decoded = arena.alloc(u8, decoded_len) catch {
        fail(writer, "the OIDC setup could not be read");
        return;
    };
    decoder.decode(decoded, one.input) catch {
        fail(writer, "the OIDC setup was malformed");
        return;
    };
    const input = std.json.parseFromSliceLeaky(OidcBeginInput, arena, decoded, .{}) catch {
        fail(writer, "the OIDC setup was malformed");
        return;
    };
    if (input.redirect_uri.len == 0 or input.redirect_uri.len > max_oidc_callback_url or
        !daemon_state.isWebBaseUrl(input.redirect_uri, input.allow_http) or
        std.mem.indexOfAny(u8, input.redirect_uri, "\t\r\n\x00") != null)
    {
        fail(writer, "the OIDC redirect URI was invalid");
        return;
    }

    var attempt = oauth.Attempt.init(daemon.io);
    defer attempt.wipe();
    const metadata = daemon.oidc_metadata orelse {
        fail(writer, "OIDC metadata is not available");
        return;
    };
    const url = daemon_state.oidcAuthorizationUrl(oidc, arena, metadata, &attempt, input.redirect_uri) catch {
        fail(writer, "the OIDC authorization URL could not be created");
        return;
    };

    const now = std.Io.Clock.real.now(daemon.io).toSeconds();
    daemon.oidc_mutex.lockUncancelable(daemon.io);
    defer daemon.oidc_mutex.unlock(daemon.io);
    var available: ?usize = null;
    for (&daemon.pending_oidc, 0..) |*entry, index| {
        if (entry.* == null or entry.*.?.expires <= now) {
            if (entry.*) |*expired| expired.wipe();
            available = index;
            break;
        }
    }
    const index = available orelse {
        fail(writer, "too many sign-in attempts are pending");
        return;
    };
    var pending: PendingOidcAttempt = .{
        .attempt = attempt,
        .expires = now + 600,
        .callback_url = @splat(0),
        .callback_url_len = input.redirect_uri.len,
    };
    @memcpy(pending.callback_url[0..input.redirect_uri.len], input.redirect_uri);
    daemon.pending_oidc[index] = pending;
    writer.print(control.ok_prefix ++ "{s}\t{s}\n", .{ url, &attempt.state }) catch {};
}

/// Provider credentials, OAuth attempts, and tokens stay inside the daemon.
/// The gateway forwards only the callback request target and its state cookie.
fn handleAuthOidcExchange(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.AuthOidcExchange,
) void {
    const oidc = daemon.oidc orelse {
        fail(writer, "the daemon has no OIDC provider configured");
        return;
    };
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(one.exchange) catch {
        fail(writer, "the OIDC callback was malformed");
        return;
    };
    const decoded = arena.alloc(u8, decoded_len) catch {
        fail(writer, "the OIDC callback could not be read");
        return;
    };
    decoder.decode(decoded, one.exchange) catch {
        fail(writer, "the OIDC callback was malformed");
        return;
    };
    const input = std.json.parseFromSliceLeaky(OidcExchangeInput, arena, decoded, .{}) catch {
        fail(writer, "the OIDC callback was malformed");
        return;
    };
    if (input.target.len == 0 or input.target.len > 8192 or input.cookie_state.len != oauth.pkce.state_len or
        std.mem.indexOfAny(u8, input.target, "\r\n\x00") != null)
    {
        fail(writer, "the OIDC callback was invalid");
        return;
    }

    const now = std.Io.Clock.real.now(daemon.io).toSeconds();
    var pending_attempt: ?PendingOidcAttempt = null;
    daemon.oidc_mutex.lockUncancelable(daemon.io);
    for (&daemon.pending_oidc) |*entry| {
        if (entry.*) |*pending| {
            if (pending.expires > now and std.crypto.timing_safe.eql(
                [oauth.pkce.state_len]u8,
                pending.attempt.state,
                input.cookie_state[0..oauth.pkce.state_len].*,
            )) {
                pending_attempt = pending.*;
                pending.wipe();
                entry.* = null;
                break;
            }
        }
    }
    daemon.oidc_mutex.unlock(daemon.io);
    var pending = pending_attempt orelse {
        fail(writer, "the OIDC sign-in attempt is invalid or expired");
        return;
    };
    defer pending.wipe();

    const callback = oauth.parseCallback(arena, input.target, "/auth/callback", &pending.attempt) catch {
        fail(writer, "the OIDC callback state or code was invalid");
        return;
    };

    var transport = oidc_transport.init(daemon.io, daemon.env.get("SSL_CERT_FILE"));
    const metadata = daemon.oidc_metadata orelse {
        fail(writer, "OIDC metadata is not available");
        return;
    };
    var tokens = daemon_state.oidcExchangeCode(
        oidc,
        daemon.gpa,
        transport.transport(),
        metadata,
        callback.code(),
        &pending.attempt,
        pending.callback_url[0..pending.callback_url_len],
    ) catch {
        fail(writer, "the OIDC token exchange failed");
        return;
    };
    defer tokens.deinit();
    const id_token = tokens.value().id_token orelse {
        fail(writer, "the identity provider returned no ID token");
        return;
    };
    const now_seconds = std.Io.Clock.real.now(daemon.io).toSeconds();
    const verified = daemon_state.verifyOidcIdToken(
        oidc,
        arena,
        transport.transport(),
        metadata,
        id_token,
        &pending.attempt,
        now_seconds,
    ) catch {
        fail(writer, "the OIDC ID token could not be verified");
        return;
    };
    const Profile = struct { name: ?[]const u8 = null };
    const profile = std.json.parseFromSliceLeaky(Profile, arena, verified.payload, .{ .ignore_unknown_fields = true }) catch Profile{};
    const assertion = std.json.Stringify.valueAlloc(arena, .{
        .issuer = oidc.issuer,
        .subject = verified.subject,
        .email = verified.email,
        .display_name = profile.name,
    }, .{ .emit_null_optional_fields = false }) catch {
        fail(writer, "the verified identity could not be encoded");
        return;
    };
    const encoded = arena.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(assertion.len)) catch {
        fail(writer, "the verified identity could not be encoded");
        return;
    };
    const body = std.base64.url_safe_no_pad.Encoder.encode(encoded, assertion);
    handleAuthLogin(daemon, arena, writer, body);
}

fn handleAuthLogin(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, encoded_assertion: []const u8) void {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(encoded_assertion) catch {
        fail(writer, "the OIDC assertion was malformed");
        return;
    };
    const decoded = arena.alloc(u8, decoded_len) catch {
        fail(writer, "the OIDC assertion could not be read");
        return;
    };
    decoder.decode(decoded, encoded_assertion) catch {
        fail(writer, "the OIDC assertion was malformed");
        return;
    };
    const assertion = std.json.parseFromSliceLeaky(AuthAssertion, arena, decoded, .{
        .ignore_unknown_fields = true,
    }) catch {
        fail(writer, "the OIDC assertion was malformed");
        return;
    };
    const oidc = daemon.oidc orelse {
        fail(writer, "the daemon has no OIDC provider configured");
        return;
    };
    if (!std.mem.eql(u8, assertion.issuer, oidc.issuer)) {
        fail(writer, "the OIDC assertion issuer does not match daemon configuration");
        return;
    }
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const identity = database.resolveIdentity(daemon.gpa, daemon.io, assertion.issuer, .{
        .subject = assertion.subject,
        .email = assertion.email,
        .payload = decoded,
    }, assertion.display_name, if (daemon.oidc_admin_subject) |subject| std.mem.eql(u8, subject, assertion.subject) else false, now_ms) catch {
        fail(writer, "the verified identity could not be recorded");
        return;
    };
    defer daemon.gpa.free(identity.instance_role);
    const expires_ms = std.math.add(i64, now_ms, login_session_ms) catch {
        fail(writer, "the login session expiry overflowed");
        return;
    };
    const session = database.createLoginSession(daemon.io, &identity.id, now_ms, expires_ms) catch {
        fail(writer, "the login session could not be created");
        return;
    };
    telemetry.event("chock.auth.login.succeeded", .info, &.{.{
        .key = "auth.mode",
        .value = .{ .string = "oidc" },
    }});
    writer.print(control.ok_prefix ++ "{s}\t{s}\t{s}\t{d}\n", .{
        &identity.id,
        identity.instance_role,
        &session.token,
        session.expires_ms,
    }) catch return;
}

fn handleAuthSession(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthSession) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const session = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    defer arena.free(session.instance_role);
    writer.print(control.ok_prefix ++ "{s}\t{s}\n", .{ &session.id, session.instance_role }) catch return;
}

fn handleAuthPeople(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthPeople) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    defer arena.free(principal.instance_role);
    if (std.mem.eql(u8, one.action, "promote") or std.mem.eql(u8, one.action, "demote")) {
        const make_admin = std.mem.eql(u8, one.action, "promote");
        database.setInstanceAdmin(&principal.id, one.identity, make_admin) catch |err| {
            fail(writer, if (err == error.NotInstanceAdmin)
                "only an instance administrator may change instance roles"
            else if (err == error.LastInstanceAdministrator)
                "the last instance administrator cannot be demoted"
            else
                "the instance role could not be changed");
            return;
        };
        writer.writeAll(if (make_admin) control.ok_prefix ++ "instance_admin\n" else control.ok_prefix ++ "member\n") catch {};
        return;
    }
    if (std.mem.eql(u8, one.action, "change-local-password")) {
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const decoded_len = decoder.calcSizeForSlice(one.identity) catch {
            fail(writer, "the password change was malformed");
            return;
        };
        const decoded = arena.alloc(u8, decoded_len) catch {
            fail(writer, "the password change could not be read");
            return;
        };
        decoder.decode(decoded, one.identity) catch {
            fail(writer, "the password change was malformed");
            return;
        };
        const change = std.json.parseFromSliceLeaky(struct {
            current_password: []const u8,
            new_password: []const u8,
        }, arena, decoded, .{}) catch {
            fail(writer, "current_password and new_password are required");
            return;
        };
        database.changeLocalAccountPassword(
            daemon.gpa,
            daemon.io,
            &principal.id,
            one.token,
            change.current_password,
            change.new_password,
            now_ms,
        ) catch |err| {
            fail(writer, if (err == error.InvalidCurrentPassword)
                "the current password is incorrect"
            else if (err == error.LocalAuthDisabled)
                "password changes are only available for Chock-managed accounts"
            else if (err == error.InvalidSessionToken)
                "the browser login session is invalid or expired"
            else if (err == error.InvalidLocalAccount)
                "the new password must be 12–1024 characters"
            else
                "the local password could not be changed");
            return;
        };
        writer.writeAll(control.ok_prefix ++ "password-changed\n") catch {};
        return;
    }
    if (std.mem.eql(u8, one.action, "create-local")) {
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const decoded_len = decoder.calcSizeForSlice(one.identity) catch {
            fail(writer, "the local account details were malformed");
            return;
        };
        const decoded = arena.alloc(u8, decoded_len) catch {
            fail(writer, "the local account details could not be read");
            return;
        };
        decoder.decode(decoded, one.identity) catch {
            fail(writer, "the local account details were malformed");
            return;
        };
        const account = std.json.parseFromSliceLeaky(daemon_state.LocalAccount, arena, decoded, .{}) catch {
            fail(writer, "username and password are required");
            return;
        };
        const created = database.createLocalAccount(
            daemon.gpa,
            daemon.io,
            &principal.id,
            account.username,
            account.password,
            now_ms,
        ) catch |err| {
            fail(writer, if (err == error.NotInstanceAdmin)
                "only an instance administrator may create local accounts"
            else if (err == error.LocalAuthDisabled)
                "service-managed accounts are not enabled"
            else if (err == error.AccountAlreadyExists)
                "that username is already in use"
            else
                "the local account could not be created");
            return;
        };
        writer.print(control.ok_prefix ++ "{s}\n", .{&created}) catch {};
        return;
    }
    if (std.mem.eql(u8, one.action, "reset-local-password")) {
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const decoded_len = decoder.calcSizeForSlice(one.identity) catch {
            fail(writer, "the local account reset was malformed");
            return;
        };
        const decoded = arena.alloc(u8, decoded_len) catch {
            fail(writer, "the local account reset could not be read");
            return;
        };
        decoder.decode(decoded, one.identity) catch {
            fail(writer, "the local account reset was malformed");
            return;
        };
        const reset = std.json.parseFromSliceLeaky(struct {
            identity_id: []const u8,
            password: []const u8,
        }, arena, decoded, .{}) catch {
            fail(writer, "identity_id and password are required");
            return;
        };
        database.resetLocalAccountPassword(
            daemon.gpa,
            daemon.io,
            &principal.id,
            reset.identity_id,
            reset.password,
        ) catch |err| {
            fail(writer, if (err == error.NotInstanceAdmin)
                "only an instance administrator may reset local passwords"
            else if (err == error.LocalAuthDisabled)
                "service-managed accounts are not enabled"
            else
                "the local password could not be reset");
            return;
        };
        writer.writeAll(control.ok_prefix ++ "reset\n") catch {};
        return;
    }
    if (std.mem.eql(u8, one.action, "disable-local") or std.mem.eql(u8, one.action, "enable-local")) {
        const disabled = std.mem.eql(u8, one.action, "disable-local");
        database.setLocalAccountDisabled(&principal.id, one.identity, disabled, now_ms) catch |err| {
            fail(writer, if (err == error.NotInstanceAdmin)
                "only an instance administrator may change local account status"
            else if (err == error.LocalAuthDisabled)
                "service-managed accounts are not enabled"
            else if (err == error.LastLocalAdministrator)
                "the last enabled local administrator cannot be disabled"
            else
                "the local account status could not be changed");
            return;
        };
        writer.writeAll(if (disabled) control.ok_prefix ++ "disabled\n" else control.ok_prefix ++ "enabled\n") catch {};
        return;
    }
    if (std.mem.eql(u8, one.action, "revoke-sessions")) {
        const revoked = database.revokeIdentitySessions(&principal.id, one.identity, now_ms) catch |err| {
            fail(writer, if (err == error.NotInstanceAdmin)
                "only an instance administrator may revoke credentials"
            else
                "the person's credentials could not be revoked");
            return;
        };
        writer.print(control.ok_prefix ++ "{d}\n", .{revoked}) catch {};
        return;
    }
    if (!std.mem.eql(u8, one.action, "list")) {
        fail(writer, "unknown people action");
        return;
    }
    const people = database.listPeople(arena, &principal.id) catch |err| {
        fail(writer, if (err == error.NotInstanceAdmin)
            "only an instance administrator may view the people directory"
        else
            "the people directory could not be read");
        return;
    };
    const rows = arena.alloc(control.PersonRow, people.len) catch {
        fail(writer, "the people directory could not be encoded");
        return;
    };
    for (people, rows) |person, *row| row.* = .{
        .identity_id = person.identity_id,
        .display_name = person.display_name,
        .email = person.email,
        .instance_role = person.instance_role,
        .local_account = person.local_account,
        .local_account_disabled = person.local_account_disabled,
    };
    const payload = std.json.Stringify.valueAlloc(arena, rows, .{}) catch {
        fail(writer, "the people directory could not be encoded");
        return;
    };
    say(writer, .{ .record = .{ .id = 0, .payload = payload } });
}

fn handleAuthLogout(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.AuthLogout) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    database.revokeLoginSession(one.token, now_ms) catch {
        fail(writer, "the login session could not be revoked");
        return;
    };
    say(writer, .{ .ok = "logged out" });
}

fn handleAuthAuthorize(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthAuthorize) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const capability = std.meta.stringToEnum(daemon_state.Capability, one.capability) orelse {
        fail(writer, "the requested capability is unknown");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const decision = database.authorizeLoginSession(
        arena,
        one.token,
        now_ms,
        one.resource_kind,
        one.resource_id,
        capability,
    ) catch {
        fail(writer, "the authorization decision could not be read");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    say(writer, .{ .ok = if (decision) "allow" else "deny" });
}

const ProjectRequest = struct {
    action: []const u8 = "create",
    project_id: ?[]const u8 = null,
    status: ?[]const u8 = null,
    name: ?[]const u8 = null,
    root: ?[]const u8 = null,
    repository_url: ?[]const u8 = null,
};

fn validGitRepositoryUrl(url: []const u8) bool {
    if (url.len < 13 or url.len > 2048 or !std.mem.startsWith(u8, url, "https://")) return false;
    if (std.mem.indexOfAny(u8, url, "\t\r\n\x00 \\?#") != null) return false;
    const authority_end = std.mem.indexOfScalarPos(u8, url, 8, '/') orelse url.len;
    const authority = url[8..authority_end];
    return authority.len != 0 and std.mem.indexOfScalar(u8, authority, '@') == null;
}

fn gitRepositoryHost(url: []const u8) []const u8 {
    const authority_end = std.mem.indexOfScalarPos(u8, url, 8, '/') orelse url.len;
    return url[8..authority_end];
}

fn gitHostAllowed(url: []const u8, configured_hosts: ?[]const u8) bool {
    const allowlist = configured_hosts orelse return false;
    var entries = std.mem.splitScalar(u8, allowlist, ',');
    while (entries.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len != 0 and std.ascii.eqlIgnoreCase(entry, gitRepositoryHost(url))) return true;
    }
    return false;
}

test "project cloning accepts credential-free HTTPS repositories only" {
    try std.testing.expect(validGitRepositoryUrl("https://code.example/team/chock.git"));
    try std.testing.expect(!validGitRepositoryUrl("http://code.example/team/chock.git"));
    try std.testing.expect(!validGitRepositoryUrl("https://user:password@code.example/chock.git"));
    try std.testing.expect(!validGitRepositoryUrl("https://code.example/chock.git?token=secret"));
    try std.testing.expect(!validGitRepositoryUrl("https://code.example/chock.git#branch"));
    try std.testing.expect(!validGitRepositoryUrl("https:///chock.git"));
    try std.testing.expect(gitHostAllowed("https://code.example/team/chock.git", "forge.example, code.example"));
    try std.testing.expect(!gitHostAllowed("https://code.example.evil/team/chock.git", "code.example"));
    try std.testing.expect(!gitHostAllowed("https://code.example/team/chock.git", null));
}

fn cloneGitProject(daemon: *Daemon, arena: std.mem.Allocator, repository_url: []const u8) ![]const u8 {
    if (!validGitRepositoryUrl(repository_url)) return error.InvalidRepositoryUrl;
    if (!gitHostAllowed(repository_url, daemon.env.get("CHOCK_GIT_ALLOWED_HOSTS")))
        return error.RepositoryHostNotAllowed;
    const directory_id = session_paths.newId(daemon.io);
    const destination = try std.fs.path.join(arena, &.{ daemon.project_store_dir, &directory_id });
    errdefer std.Io.Dir.cwd().deleteTree(daemon.io, destination) catch {};
    // ziggit reads no environment of its own, and the git this replaced took
    // its proxy from one, so a daemon behind a proxy keeps working.
    const proxy = daemon.env.get("HTTPS_PROXY") orelse daemon.env.get("https_proxy");
    cloneRepository(
        daemon.gpa,
        daemon.io,
        repository_url,
        destination,
        daemon.env.get("SSL_CERT_FILE"),
        proxy,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            // The reply to the caller says a clone failed and may not say more, so this is
            // the only account of which leg of it did.
            tty.print(.err, "chock daemon: cloning {s} failed: {t}\n", .{ repository_url, err });
            return error.GitCloneFailed;
        },
    };
    return destination;
}

/// Clones every branch of `url` into `destination` the way `git clone` leaves
/// it: the default branch checked out with an index, and its upstream set.
/// The caller has already checked the URL. Reads no gitconfig and no credential.
fn cloneRepository(
    gpa: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    destination: []const u8,
    ca_cert_file: ?[]const u8,
    proxy_url: ?[]const u8,
) !void {
    const branch_prefix = "refs/heads/";
    const fetch_spec = "+refs/heads/*:refs/remotes/origin/*";
    try std.Io.Dir.cwd().createDirPath(io, destination);
    var dir = try std.Io.Dir.cwd().openDir(io, destination, .{});
    defer dir.close(io);

    try ziggit.Repository.init(gpa, io, dir, .{});
    const layout = try ziggit.discover(gpa, io, dir, .{}, null);
    var repo = try ziggit.Repository.open(gpa, io, layout, .{}, null);
    defer repo.deinit();
    try repo.createRemote("origin", url, fetch_spec);

    var refspec = try ziggit.Refspec.parse(gpa, fetch_spec);
    defer refspec.deinit(gpa);
    const refspecs = [_]ziggit.Refspec{refspec};
    // ziggit says which step of the exchange failed, and the error name alone does not.
    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*it| it.deinit(gpa);
    var fetched = ziggit.fetch(gpa, io, &repo, url, .{
        .refspecs = &refspecs,
        .remote_url = url,
        .transport = .{ .ca_cert_file = ca_cert_file, .proxy_url = proxy_url },
    }, &fault) catch |err| {
        if (fault) |it| tty.print(.err, "chock daemon: fetching {s}: {t} {s}\n", .{
            url,
            it.kind,
            it.detail orelse "",
        });
        return err;
    };
    defer fetched.deinit(gpa);
    if (fetched.firstFailure() != null) return error.FetchRefFailed;

    const head_ref = fetched.head_symref orelse return error.NoDefaultBranch;
    if (!std.mem.startsWith(u8, head_ref, branch_prefix)) return error.NoDefaultBranch;
    const branch = head_ref[branch_prefix.len..];

    const remote_ref = try std.fmt.allocPrint(gpa, "refs/remotes/origin/{s}", .{branch});
    defer gpa.free(remote_ref);
    const tip = try repo.refs.resolve(remote_ref, null);
    try repo.refs.update(head_ref, tip, null, null, null);

    const commit_oid = try ziggit.peel(gpa, &repo, tip, .commit);
    const bytes = try repo.odb.readAlloc(gpa, commit_oid, 1 << 24, null);
    defer gpa.free(bytes);
    var commit = try ziggit.Commit.parse(gpa, repo.format, bytes);
    defer commit.deinit(gpa);
    try ziggit.checkoutTree(gpa, io, &repo.odb, dir, commit.tree, .{ .write_index_to = repo.layout.git_dir }, null);
    try repo.refs.setHead(head_ref, null, null);

    // ziggit has no config setter, so the upstream section is appended by hand.
    const config = try repo.layout.common_dir.readFileAlloc(io, "config", gpa, .limited(1 << 20));
    defer gpa.free(config);
    const updated = try std.fmt.allocPrint(gpa, "{s}[branch \"{s}\"]\n\tremote = origin\n\tmerge = {s}\n", .{ config, branch, head_ref });
    defer gpa.free(updated);
    try repo.layout.common_dir.writeFile(io, .{ .sub_path = "config", .data = updated });
}

test "a cloned repository is one real git accepts" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try tmp.dir.realPath(io, &root_buffer)];
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const source = try std.fs.path.join(arena, &.{ root, "source" });
    const clone = try std.fs.path.join(arena, &.{ root, "clone" });
    const worktree = try std.fs.path.join(arena, &.{ root, "worktree" });

    try std.Io.Dir.cwd().createDirPath(io, source);
    _ = try testGit(arena, io, source, &.{ "init", "--quiet", "--initial-branch=trunk" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/hello.txt", .data = "hello from the source\n" });
    _ = try testGit(arena, io, source, &.{ "add", "hello.txt" });
    _ = try testGit(arena, io, source, &.{ "-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "--quiet", "-m", "first" });

    try cloneRepository(gpa, io, source, clone, null, null);

    try std.testing.expectEqualStrings("", try testGit(arena, io, clone, &.{ "status", "--porcelain" }));
    try std.testing.expectEqualStrings("trunk\n", try testGit(arena, io, clone, &.{ "rev-parse", "--abbrev-ref", "HEAD" }));
    try std.testing.expectEqualStrings("origin/trunk\n", try testGit(arena, io, clone, &.{ "rev-parse", "--abbrev-ref", "@{upstream}" }));
    try std.testing.expectEqualStrings("hello from the source\n", try tmp.dir.readFileAlloc(io, "clone/hello.txt", arena, .limited(1024)));
    _ = try testGit(arena, io, clone, &.{ "fsck", "--strict" });
    _ = try testGit(arena, io, clone, &.{ "worktree", "add", "--detach", worktree });
}

fn testGit(arena: std.mem.Allocator, io: std.Io, cwd: []const u8, args: []const []const u8) ![]const u8 {
    const argv = try std.mem.concat(arena, []const u8, &.{ &.{ "git", "-C", cwd }, args });
    const result = try std.process.run(arena, io, .{ .argv = argv });
    // The fixture's own git must succeed, and what it wrote is the reason when
    // it does not, so the assertion carries it.
    if (result.term != .exited or result.term.exited != 0) {
        try std.testing.expectEqualStrings("", try std.mem.concat(arena, u8, &.{ result.stdout, result.stderr }));
        return error.GitFailed;
    }
    return result.stdout;
}

fn handleAuthProjectCreate(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthProjectCreate) void {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(one.project_json) catch {
        fail(writer, "project details were malformed");
        return;
    };
    const decoded = arena.alloc(u8, decoded_len) catch {
        fail(writer, "project details could not be read");
        return;
    };
    decoder.decode(decoded, one.project_json) catch {
        fail(writer, "project details were malformed");
        return;
    };
    const asked = std.json.parseFromSliceLeaky(ProjectRequest, arena, decoded, .{ .ignore_unknown_fields = true }) catch {
        fail(writer, "project details were malformed");
        return;
    };
    if (std.mem.eql(u8, asked.action, "set_status")) {
        const project_id = asked.project_id orelse {
            fail(writer, "project status changes need a project UUID");
            return;
        };
        const status = asked.status orelse {
            fail(writer, "project status is required");
            return;
        };
        if (!std.mem.eql(u8, status, "ready") and !std.mem.eql(u8, status, "archived")) {
            fail(writer, "project status must be ready or archived");
            return;
        }
        const database = if (daemon.database) |*value| value else {
            fail(writer, "the daemon database is not available");
            return;
        };
        const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
        const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
            fail(writer, "the login session could not be checked");
            return;
        } orelse {
            fail(writer, "the login session is invalid or expired");
            return;
        };
        database.setProjectArchived(&principal.id, project_id, std.mem.eql(u8, status, "archived")) catch |err| {
            fail(writer, switch (err) {
                error.NotProjectManager => "only a project manager may change project status",
                error.InvalidProject => "the project or status is invalid",
                else => "the project status could not be changed",
            });
            return;
        };
        const attributes = [_]telemetry.Attribute{
            .{ .key = "project.status", .value = .{ .string = status } },
        };
        telemetry.event("chock.project.status.changed", .info, &attributes);
        say(writer, .{ .ok = "project status changed" });
        return;
    }
    if (!std.mem.eql(u8, asked.action, "create")) {
        fail(writer, "the project action is unknown");
        return;
    }
    const name = std.mem.trim(u8, asked.name orelse "", " \t\r\n");
    if (name.len == 0 or name.len > 128 or (asked.root == null) == (asked.repository_url == null)) {
        fail(writer, "project needs a name and exactly one local directory or HTTPS repository URL");
        return;
    }
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    if (asked.root != null and !std.mem.eql(u8, principal.instance_role, "instance_admin")) {
        fail(writer, "registering an existing daemon path is reserved for instance administrators; provision a project from an HTTPS repository instead");
        return;
    }

    var cloned_root: ?[]const u8 = null;
    var project_registered = false;
    defer if (!project_registered) {
        if (cloned_root) |root| std.Io.Dir.cwd().deleteTree(daemon.io, root) catch {};
    };
    const requested_root = if (asked.root) |root|
        root
    else blk: {
        const repository_url = asked.repository_url.?;
        const clone = cloneGitProject(daemon, arena, repository_url) catch |err| {
            fail(writer, if (err == error.InvalidRepositoryUrl)
                "project clone requires an HTTPS repository URL without credentials or a query"
            else if (err == error.RepositoryHostNotAllowed)
                "repository host is not allowed; add its exact hostname to CHOCK_GIT_ALLOWED_HOSTS"
            else if (err == error.GitCloneFailed)
                "Git could not clone the repository on the daemon; check repository access and daemon network access"
            else
                "the repository could not be cloned on the daemon");
            return;
        };
        cloned_root = clone;
        break :blk clone;
    };
    if (!std.fs.path.isAbsolute(requested_root)) {
        fail(writer, "project directories must be absolute paths");
        return;
    }
    var dir = std.Io.Dir.openDirAbsolute(daemon.io, requested_root, .{ .iterate = true }) catch {
        fail(writer, "the daemon could not open the project directory; verify it exists and is accessible to the daemon account");
        return;
    };
    defer dir.close(daemon.io);
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0 .. dir.realPath(daemon.io, &root_buffer) catch {
        fail(writer, "the project directory could not be resolved");
        return;
    }];
    const id = (if (asked.repository_url) |repository_url|
        database.registerGitProject(daemon.io, &principal.id, name, repository_url, root, now_ms)
    else
        database.registerLocalProject(daemon.io, &principal.id, name, root, now_ms)) catch {
        fail(writer, "the project could not be registered");
        return;
    };
    project_registered = true;
    const project_attributes = [_]telemetry.Attribute{
        .{ .key = "project.source_kind", .value = .{ .string = if (asked.repository_url != null) "git" else "local" } },
    };
    telemetry.event("chock.project.created", .info, &project_attributes);
    const row: control.ProjectRow = .{
        .id = &id,
        .name = name,
        .root = root,
        .source_kind = if (asked.repository_url != null) "git" else "local",
        .source_locator = asked.repository_url orelse root,
        .status = "ready",
        .can_manage = true,
    };
    const json = row.toJson(arena) catch {
        fail(writer, "the project record could not be encoded");
        return;
    };
    say(writer, .{ .record = .{ .id = 0, .payload = json } });
}

fn handleAuthProjectList(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthProjectList) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const projects = database.listProjects(arena) catch {
        fail(writer, "the registered projects could not be read");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    for (projects) |project| {
        const allowed = database.authorizeLoginSession(
            arena,
            one.token,
            now_ms,
            "project",
            &project.id,
            .project_view,
        ) catch {
            fail(writer, "the project access list could not be checked");
            return;
        } orelse {
            fail(writer, "the login session is invalid or expired");
            return;
        };
        if (!allowed) continue;
        const can_manage = database.authorizeLoginSession(
            arena,
            one.token,
            now_ms,
            "project",
            &project.id,
            .project_manage,
        ) catch {
            fail(writer, "the project management permissions could not be checked");
            return;
        } orelse {
            fail(writer, "the login session is invalid or expired");
            return;
        };
        const row: control.ProjectRow = .{
            .id = &project.id,
            .root = project.root,
            .source_kind = project.source_kind,
            .source_locator = project.source_locator,
            .name = project.name,
            .status = project.status,
            .can_manage = can_manage,
        };
        const json = row.toJson(arena) catch {
            fail(writer, "a project could not be written out");
            return;
        };
        say(writer, .{ .record = .{ .id = 0, .payload = json } });
    }
    writer.flush() catch return;
}

fn handleAuthSessionCreate(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthSessionCreate) void {
    if (one.token.len != 43 or !std.fs.path.isAbsolute(one.project)) {
        fail(writer, "session creation needs a login token and absolute registered project directory");
        return;
    }
    const placement = std.meta.stringToEnum(daemon_state.SessionPlacement, one.placement) orelse {
        fail(writer, "the requested session placement is invalid");
        return;
    };
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const allowed = database.authorizeLoginSession(
        arena,
        one.token,
        now_ms,
        "project",
        one.project,
        .project_manage,
    ) catch {
        fail(writer, "project authorization could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    if (!allowed) {
        fail(writer, "project access does not allow creating a session");
        return;
    }
    const accepts_sessions = database.projectAcceptsNewSessions(one.project) catch {
        fail(writer, "the project status could not be checked");
        return;
    };
    if (!accepts_sessions) {
        fail(writer, "the project is archived or unavailable for new sessions");
        return;
    }
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    defer arena.free(principal.instance_role);

    const id = session_paths.newId(daemon.io);
    database.registerSession(&principal.id, one.project, &id, placement, now_ms) catch {
        fail(writer, "the session owner and project could not be recorded");
        return;
    };

    var response: std.Io.Writer.Allocating = .init(arena);
    beginSession(daemon, &response.writer, one.project, id, .nothing);
    const result = response.written();
    if (!std.mem.startsWith(u8, result, control.ok_prefix)) {
        _ = daemon.forgetIdleSession(&id);
        _ = database.unregisterSession(&principal.id, &id) catch false;
    } else {
        const attributes = [_]telemetry.Attribute{
            .{ .key = "session.placement", .value = .{ .string = @tagName(placement) } },
        };
        telemetry.event("chock.session.created", .info, &attributes);
    }
    writer.writeAll(result) catch return;
    writer.flush() catch return;
}

fn handleAuthSessionRegister(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthSessionRegisterPlaced) void {
    if (!session_paths.isValidId(one.session) or !std.fs.path.isAbsolute(one.project)) {
        fail(writer, "session registration needs a session identifier and absolute project directory");
        return;
    }
    const placement = std.meta.stringToEnum(daemon_state.SessionPlacement, one.placement) orelse {
        fail(writer, "the requested session placement is invalid");
        return;
    };
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const allowed = database.authorizeLoginSession(
        arena,
        one.token,
        now_ms,
        "project",
        one.project,
        .project_manage,
    ) catch {
        fail(writer, "project authorization could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    if (!allowed) {
        fail(writer, "project access does not allow creating a session");
        return;
    }
    if (!importableLocalSession(daemon.io, arena, daemon.env, one.project, one.session)) {
        fail(writer, "there is no readable, complete session log with that identifier in this project");
        return;
    }
    const accepts_sessions = database.projectAcceptsNewSessions(one.project) catch {
        fail(writer, "the project status could not be checked");
        return;
    };
    if (!accepts_sessions) {
        fail(writer, "the project is archived or unavailable for new sessions");
        return;
    }
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    database.registerSession(&principal.id, one.project, one.session, placement, now_ms) catch |err| {
        std.log.err("could not register imported session {s}: {s}", .{ one.session, @errorName(err) });
        fail(writer, "the session owner could not be recorded");
        return;
    };
    say(writer, .{ .ok = "registered" });
}

fn importableLocalSession(
    io: std.Io,
    arena: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    project: []const u8,
    session: []const u8,
) bool {
    if (!session_paths.isValidId(session) or !std.fs.path.isAbsolute(project)) return false;
    const directory = session_paths.projectDir(arena, env, project) catch return false;
    const existing = sessions_cmd.fold(arena, io, directory, session) catch return false;
    const found = existing orelse return false;
    return found.readable and found.complete;
}

test "a local session can be imported only from its complete project log" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var home_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const home_len = try tmp.dir.realPath(io, &home_buffer);
    const home = home_buffer[0..home_len];

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", home);

    const project = "/registered/project";
    const complete_id = "01JQ" ++ @as([22]u8, @splat('A'));
    const incomplete_id = "01JQ" ++ @as([22]u8, @splat('B'));
    var complete_paths = try session_paths.pathsFor(gpa, &env, project, complete_id);
    defer complete_paths.deinit();
    try session_paths.create(io, complete_paths);
    {
        const log = try chock_proto.log.Log.open(io, complete_paths.log, complete_id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "completed" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 2);
        try locked.unlock(io);
    }

    var incomplete_paths = try session_paths.pathsFor(gpa, &env, project, incomplete_id);
    defer incomplete_paths.deinit();
    try session_paths.create(io, incomplete_paths);
    {
        const log = try chock_proto.log.Log.open(io, incomplete_paths.log, incomplete_id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "unfinished" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        try locked.unlock(io);
        const original = try std.Io.Dir.cwd().readFileAlloc(io, incomplete_paths.log, gpa, .limited(1 << 20));
        defer gpa.free(original);
        const torn = try std.fmt.allocPrint(arena, "{s}{{\"id\":0,\"sessi", .{original});
        var damaged = try std.Io.Dir.createFileAbsolute(io, incomplete_paths.log, .{ .truncate = true });
        defer damaged.close(io);
        try damaged.writeStreamingAll(io, torn);
    }

    try testing.expect(importableLocalSession(io, arena, &env, project, complete_id));
    try testing.expect(!importableLocalSession(io, arena, &env, "/another/project", complete_id));
    try testing.expect(!importableLocalSession(io, arena, &env, project, incomplete_id));
    try testing.expect(!importableLocalSession(io, arena, &env, project, "../../outside"));
}

fn handleAuthSessionMember(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthSessionMember) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    const removing = std.mem.eql(u8, one.role, "remove");
    const update_result = if (removing) blk: {
        database.removeSessionMember(one.session, &principal.id, one.identity) catch |err| {
            fail(writer, switch (err) {
                error.NotSessionOwner => "only a session owner may change members",
                error.InvalidSession => "the session member details are invalid",
                else => "the session membership could not be updated",
            });
            return;
        };
        break :blk true;
    } else blk: {
        const role = std.meta.stringToEnum(daemon_state.MemberRole, one.role) orelse {
            fail(writer, "the session member role is unknown");
            return;
        };
        database.setSessionMember(one.session, &principal.id, one.identity, role, now_ms) catch |err| {
            fail(writer, switch (err) {
                error.NotSessionOwner => "only a session owner may change members",
                error.InvalidSession => "the session member details are invalid",
                else => "the session membership could not be updated",
            });
            return;
        };
        break :blk false;
    };
    const attributes = [_]telemetry.Attribute{
        .{ .key = "membership.resource", .value = .{ .string = "session" } },
        .{ .key = "membership.action", .value = .{ .string = if (removing) "removed" else "updated" } },
        .{ .key = "membership.role", .value = .{ .string = if (removing) "none" else one.role } },
    };
    telemetry.event("chock.membership.changed", .info, &attributes);
    if (update_result) {
        say(writer, .{ .ok = "member removed" });
    } else {
        say(writer, .{ .ok = "member updated" });
    }
}

fn handleAuthSessionPeople(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthSessionPeople) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    const people = database.listSessionPeople(arena, one.session, &principal.id) catch |err| {
        fail(writer, if (err == error.NotSessionOwner)
            "only a session owner may view its available people"
        else
            "the session people could not be read");
        return;
    };
    const json = std.json.Stringify.valueAlloc(arena, people, .{}) catch {
        fail(writer, "the session people response could not be encoded");
        return;
    };
    say(writer, .{ .record = .{ .id = 0, .payload = json } });
}

fn handleAuthSessionPresence(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthSessionPresence) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    if (std.mem.eql(u8, one.action, "touch")) {
        database.touchSessionPresence(one.session, &principal.id, now_ms) catch |err| {
            fail(writer, if (err == error.NotSessionViewer)
                "session access does not allow presence"
            else
                "the session presence could not be refreshed");
            return;
        };
        say(writer, .{ .ok = "present" });
        return;
    }
    if (!std.mem.eql(u8, one.action, "list")) {
        fail(writer, "unknown session presence action");
        return;
    }
    const people = database.listSessionPresence(arena, one.session, &principal.id, now_ms) catch |err| {
        fail(writer, if (err == error.NotSessionViewer)
            "session access does not allow presence"
        else
            "the session presence could not be read");
        return;
    };
    const json = std.json.Stringify.valueAlloc(arena, people, .{}) catch {
        fail(writer, "the session presence response could not be encoded");
        return;
    };
    say(writer, .{ .record = .{ .id = 0, .payload = json } });
}

const SessionHostLeaseReply = struct { generation: u64, expires_ms: i64 };
const WorkerTokenReply = struct { token: []const u8, expires_ms: i64 };
const worker_login_session_ms: i64 = 24 * std.time.ms_per_hour;

fn handleAuthWorkerToken(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthWorkerToken) void {
    if (!session_paths.isValidId(one.session)) {
        fail(writer, "the worker session id is invalid");
        return;
    }
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    defer arena.free(principal.instance_role);
    const owns_session = database.isClientSessionOwner(one.session, &principal.id) catch {
        fail(writer, "the worker session ownership could not be checked");
        return;
    };
    if (!owns_session) {
        fail(writer, "only the owner of a client-placed session may provision its worker");
        return;
    }
    const expires_ms = std.math.add(i64, now_ms, worker_login_session_ms) catch {
        fail(writer, "the worker credential expiry is invalid");
        return;
    };
    const login = database.createWorkerLoginSession(daemon.io, &principal.id, one.session, now_ms, expires_ms) catch {
        fail(writer, "the scoped worker credential could not be created");
        return;
    };
    const payload = std.json.Stringify.valueAlloc(arena, WorkerTokenReply{
        .token = &login.token,
        .expires_ms = login.expires_ms,
    }, .{}) catch {
        fail(writer, "the scoped worker credential could not be encoded");
        return;
    };
    say(writer, .{ .record = .{ .id = 0, .payload = payload } });
}

fn handleAuthSessionHost(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthSessionHost) void {
    if (one.session.len == 0 or one.session.len > 128) {
        fail(writer, "the session host request is invalid");
        return;
    }
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };

    if (std.mem.eql(u8, one.action, "claim")) {
        const placement = std.meta.stringToEnum(daemon_state.SessionPlacement, one.placement) orelse {
            fail(writer, "the requested session placement is invalid");
            return;
        };
        const lease = database.claimSessionHost(
            one.session,
            &principal.id,
            placement,
            one.host_id,
            now_ms,
            std.time.ms_per_min,
        ) catch |err| {
            fail(writer, switch (err) {
                error.NotSessionOwner => "only the session owner may assign an execution host",
                error.SessionLeaseHeld => "another execution host still holds this session",
                error.InvalidHostLease => "the requested host does not match the session placement",
                else => "the session host lease could not be claimed",
            });
            return;
        };
        const attributes = [_]telemetry.Attribute{
            .{ .key = "session.placement", .value = .{ .string = @tagName(placement) } },
        };
        telemetry.event("chock.session.host.claimed", .info, &attributes);
        const json = std.json.Stringify.valueAlloc(arena, SessionHostLeaseReply{
            .generation = lease.generation,
            .expires_ms = lease.expires_ms,
        }, .{}) catch {
            fail(writer, "the session host lease response could not be encoded");
            return;
        };
        say(writer, .{ .record = .{ .id = 0, .payload = json } });
        return;
    }

    if (std.mem.eql(u8, one.action, "release")) {
        if (one.generation == 0) {
            fail(writer, "releasing a session host requires its lease generation");
            return;
        }
        const released = database.releaseSessionHost(
            one.session,
            &principal.id,
            one.host_id,
            one.generation,
            now_ms,
        ) catch {
            fail(writer, "the session host lease could not be released");
            return;
        };
        if (!released) {
            fail(writer, "that host no longer holds this session lease");
            return;
        }
        telemetry.event("chock.session.host.released", .info, &.{});
        say(writer, .{ .ok = "host released" });
        return;
    }
    fail(writer, "the session host action is unknown");
}

fn handleAuthWorkerRead(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthWorkerRead) void {
    if (one.generation == 0 or !session_paths.isValidId(one.session) or !daemon_state.isUuid(one.host_id)) {
        fail(writer, "the worker read lease identity is invalid");
        return;
    }
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the worker login session could not be checked");
        return;
    } orelse {
        fail(writer, "the worker login session is invalid or expired");
        return;
    };
    const matched = database.sessionHostMatches(
        one.session,
        &principal.id,
        .client,
        one.host_id,
        one.generation,
        now_ms,
    ) catch {
        fail(writer, "the worker lease could not be checked");
        return;
    };
    if (!matched) {
        fail(writer, "the worker no longer holds the active client execution lease");
        return;
    }
    handleRead(
        daemon,
        arena,
        writer,
        .{ .session = one.session, .after = one.after },
        true,
        max_worker_events_per_read,
    );
}

fn handleAuthWorkerEvent(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthWorkerEvent) void {
    if (one.generation == 0 or !session_paths.isValidId(one.session) or
        !daemon_state.isUuid(one.host_id))
    {
        fail(writer, "the worker event lease identity is invalid");
        return;
    }
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const event_len = decoder.calcSizeForSlice(one.event_json) catch {
        fail(writer, "the worker event is malformed");
        return;
    };
    if (event_len == 0 or event_len > 128 * 1024) {
        fail(writer, "the worker event is empty or too large");
        return;
    }
    const event_bytes = arena.alloc(u8, event_len) catch {
        fail(writer, "the worker event could not be read");
        return;
    };
    decoder.decode(event_bytes, one.event_json) catch {
        fail(writer, "the worker event is malformed");
        return;
    };
    const parsed_event = std.json.parseFromSliceLeaky(chock_proto.event.Event, arena, event_bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch {
        fail(writer, "the worker event is not a supported event");
        return;
    };
    switch (parsed_event) {
        .message => |message| if (message.role != .assistant or message.author_id.len != 0) {
            fail(writer, "workers may not author human messages or identity fields; use the authenticated prompt route");
            return;
        },
        .approval_response => {
            fail(writer, "workers may not author human approval responses");
            return;
        },
        .prompt_password => {
            fail(writer, "workers may not author human password responses");
            return;
        },
        .worker_cancel => {
            fail(writer, "workers may not author authenticated cancellation requests");
            return;
        },
        .agent_answer => {
            fail(writer, "workers may not author human answers to agent questions");
            return;
        },
        .agent_question => |question| {
            if (chock_core.ask.check(.{
                .text = question.text,
                .options = question.options,
            }) != null) {
                fail(writer, "the agent question is empty or exceeds the question limits");
                return;
            }
        },
        else => {},
    }

    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    const host_matches = database.sessionHostMatches(
        one.session,
        &principal.id,
        .client,
        one.host_id,
        one.generation,
        now_ms,
    ) catch {
        fail(writer, "the worker lease could not be checked");
        return;
    };
    if (!host_matches) {
        fail(writer, "the worker no longer holds the active client execution lease");
        return;
    }
    const project_root = database.projectRootForSession(arena, one.session) catch {
        fail(writer, "the session project could not be resolved");
        return;
    } orelse {
        fail(writer, "the session has no registered project");
        return;
    };
    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, project_root, one.session) catch {
        fail(writer, "the session log path could not be built");
        return;
    };
    defer paths.deinit();
    var opened = openLog(daemon, writer, paths.log, one.session) orelse return;
    defer opened.close(daemon.io);
    var locked = opened.storage().lock(daemon.io) catch {
        fail(writer, "the session log is already held or could not be locked");
        return;
    };
    const turn_active = database.clientTurnActive(one.session) catch {
        locked.unlock(daemon.io) catch {};
        fail(writer, "the client turn state could not be checked under the session log lock");
        return;
    };
    if (!turn_active) {
        locked.unlock(daemon.io) catch {};
        fail(writer, "there is no active client turn for this worker event");
        return;
    }
    const log_length = opened.backing.log.file.length(daemon.io) catch {
        locked.unlock(daemon.io) catch {};
        fail(writer, "the session log length could not be read");
        return;
    };
    if (log_length != one.event_id) {
        locked.unlock(daemon.io) catch {};
        fail(writer, "the worker event offset does not match the daemon log; synchronize before retrying");
        return;
    }
    const event_id = locked.append(arena, daemon.io, parsed_event, now_ms) catch {
        locked.unlock(daemon.io) catch {};
        fail(writer, "the worker event could not be appended to the session log");
        return;
    };
    if (event_id != one.event_id) {
        locked.unlock(daemon.io) catch {};
        fail(writer, "the session log changed while the worker event was being appended");
        return;
    }
    const next_offset = opened.backing.log.file.length(daemon.io) catch {
        locked.unlock(daemon.io) catch {};
        fail(writer, "the session log append offset could not be read");
        return;
    };
    if (parsed_event == .session_end) {
        const finished = database.finishClientTurnAndFenceHost(one.session) catch {
            locked.unlock(daemon.io) catch {};
            fail(writer, "the terminal worker event was appended but the client turn could not be marked complete");
            return;
        };
        if (!finished) {
            locked.unlock(daemon.io) catch {};
            fail(writer, "the terminal worker event was appended without an active client turn");
            return;
        }
    }
    locked.unlock(daemon.io) catch {
        fail(writer, "the worker event was appended but its log lock could not be released");
        return;
    };
    say(writer, .{ .ok = std.fmt.allocPrint(arena, "event {d} next {d}", .{ event_id, next_offset }) catch "event appended" });
}

const TeamCreateInput = struct { name: []const u8 };
const TeamInviteRow = struct {
    id: []const u8,
    role: []const u8,
    created_ms: i64,
    expires_ms: i64,
    revoked: bool,
    redeemed: bool,
    expired: bool,
};

const TeamInvitationCreateReply = struct { id: []const u8, token: []const u8, expires_ms: i64 };
const team_invitation_lifetime_ms: i64 = 7 * 24 * 60 * 60 * 1000;

fn handleAuthTeam(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthTeam) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    defer arena.free(principal.instance_role);

    if (std.mem.eql(u8, one.action, "export-instance-access")) {
        const snapshot = database.exportInstanceAccess(arena, &principal.id) catch |err| {
            fail(writer, if (err == error.NotInstanceAdmin)
                "only an instance administrator may export access configuration"
            else
                "the instance access configuration could not be exported");
            return;
        };
        say(writer, .{ .record = .{ .id = 0, .payload = snapshot } });
        return;
    }

    if (std.mem.eql(u8, one.action, "list")) {
        const teams = database.listTeams(arena, &principal.id) catch {
            fail(writer, "the team list could not be read");
            return;
        };
        const rows = arena.alloc(control.TeamRow, teams.len) catch {
            fail(writer, "the team list could not be encoded");
            return;
        };
        for (teams, rows) |*team, *row| row.* = .{
            .id = &team.id,
            .name = team.name,
            .role = @tagName(team.role),
        };
        const json = std.json.Stringify.valueAlloc(arena, rows, .{}) catch {
            fail(writer, "the team list could not be encoded");
            return;
        };
        say(writer, .{ .record = .{ .id = 0, .payload = json } });
        return;
    }
    if (std.mem.eql(u8, one.action, "create")) {
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const decoded_len = decoder.calcSizeForSlice(one.payload) catch {
            fail(writer, "team details were malformed");
            return;
        };
        const decoded = arena.alloc(u8, decoded_len) catch {
            fail(writer, "team details could not be read");
            return;
        };
        decoder.decode(decoded, one.payload) catch {
            fail(writer, "team details were malformed");
            return;
        };
        const input = std.json.parseFromSliceLeaky(TeamCreateInput, arena, decoded, .{}) catch {
            fail(writer, "team details need a name");
            return;
        };
        const id = database.createTeam(daemon.io, &principal.id, input.name, now_ms) catch {
            fail(writer, "the team could not be created");
            return;
        };
        telemetry.event("chock.team.created", .info, &.{});
        writer.print(control.ok_prefix ++ "{s}\n", .{&id}) catch return;
        return;
    }
    if (std.mem.eql(u8, one.action, "create-invite")) {
        const role = std.meta.stringToEnum(daemon_state.TeamRole, one.role) orelse {
            fail(writer, "the invitation role is invalid");
            return;
        };
        const expires_ms = std.math.add(i64, now_ms, team_invitation_lifetime_ms) catch {
            fail(writer, "the invitation expiry overflowed");
            return;
        };
        const invitation = database.createTeamInvitation(
            daemon.io,
            &principal.id,
            one.team,
            role,
            now_ms,
            expires_ms,
        ) catch |err| {
            fail(writer, if (err == error.NotTeamOwner)
                "only a team owner may create invitations"
            else
                "the invitation could not be created");
            return;
        };
        const attributes = [_]telemetry.Attribute{
            .{ .key = "invitation.role", .value = .{ .string = @tagName(role) } },
        };
        telemetry.event("chock.team.invitation.created", .info, &attributes);
        const payload = std.json.Stringify.valueAlloc(arena, TeamInvitationCreateReply{
            .id = &invitation.id,
            .token = &invitation.token,
            .expires_ms = invitation.expires_ms,
        }, .{}) catch {
            fail(writer, "the invitation response could not be encoded");
            return;
        };
        say(writer, .{ .ok = payload });
        return;
    }
    if (std.mem.eql(u8, one.action, "list-invites")) {
        const invitations = database.listTeamInvitations(arena, one.team, &principal.id, now_ms) catch |err| {
            fail(writer, if (err == error.NotTeamOwner)
                "only a team owner may view invitations"
            else
                "the team invitations could not be read");
            return;
        };
        const rows = arena.alloc(TeamInviteRow, invitations.len) catch {
            fail(writer, "the invitation list could not be encoded");
            return;
        };
        for (invitations, rows) |*invitation, *row| row.* = .{
            .id = &invitation.id,
            .role = @tagName(invitation.role),
            .created_ms = invitation.created_ms,
            .expires_ms = invitation.expires_ms,
            .revoked = invitation.revoked,
            .redeemed = invitation.redeemed,
            .expired = invitation.expired,
        };
        const payload = std.json.Stringify.valueAlloc(arena, rows, .{}) catch {
            fail(writer, "the invitation list could not be encoded");
            return;
        };
        say(writer, .{ .ok = payload });
        return;
    }
    if (std.mem.eql(u8, one.action, "redeem-invite")) {
        database.redeemTeamInvitation(one.identity, &principal.id, now_ms) catch {
            fail(writer, "the invitation is invalid, expired, revoked, or already used");
            return;
        };
        telemetry.event("chock.team.invitation.redeemed", .info, &.{});
        say(writer, .{ .ok = "invitation redeemed" });
        return;
    }
    if (std.mem.eql(u8, one.action, "revoke-invite")) {
        database.revokeTeamInvitation(&principal.id, one.team, one.identity, now_ms) catch |err| {
            fail(writer, if (err == error.NotTeamOwner)
                "only a team owner may revoke invitations"
            else
                "the invitation could not be revoked");
            return;
        };
        telemetry.event("chock.team.invitation.revoked", .info, &.{});
        say(writer, .{ .ok = "invitation revoked" });
        return;
    }
    if (std.mem.eql(u8, one.action, "people")) {
        const people = database.listTeamPeople(arena, one.team, &principal.id) catch |err| {
            fail(writer, if (err == error.NotTeamOwner)
                "only a team owner may view its available people"
            else
                "the team people could not be read");
            return;
        };
        const rows = arena.alloc(control.TeamPersonRow, people.len) catch {
            fail(writer, "the team people response could not be encoded");
            return;
        };
        for (people, rows) |person, *row| row.* = .{
            .identity_id = person.identity_id,
            .display_name = person.display_name,
            .email = person.email,
            .role = if (person.role) |role| @tagName(role) else null,
        };
        const json = std.json.Stringify.valueAlloc(arena, rows, .{}) catch {
            fail(writer, "the team people response could not be encoded");
            return;
        };
        say(writer, .{ .record = .{ .id = 0, .payload = json } });
        return;
    }
    if (std.mem.eql(u8, one.action, "member")) {
        if (std.mem.eql(u8, one.role, "remove")) {
            database.removeTeamMember(one.team, &principal.id, one.identity) catch |err| {
                fail(writer, if (err == error.NotTeamOwner)
                    "only a team owner may change members"
                else
                    "the team membership could not be removed");
                return;
            };
            const attributes = [_]telemetry.Attribute{
                .{ .key = "membership.resource", .value = .{ .string = "team" } },
                .{ .key = "membership.action", .value = .{ .string = "removed" } },
                .{ .key = "membership.role", .value = .{ .string = "none" } },
            };
            telemetry.event("chock.membership.changed", .info, &attributes);
            say(writer, .{ .ok = "member removed" });
            return;
        }
        const role = std.meta.stringToEnum(daemon_state.TeamRole, one.role) orelse {
            fail(writer, "the team member role is unknown");
            return;
        };
        database.setTeamMember(one.team, &principal.id, one.identity, role, now_ms) catch |err| {
            fail(writer, if (err == error.NotTeamOwner)
                "only a team owner may change members"
            else
                "the team membership could not be updated");
            return;
        };
        const attributes = [_]telemetry.Attribute{
            .{ .key = "membership.resource", .value = .{ .string = "team" } },
            .{ .key = "membership.action", .value = .{ .string = "updated" } },
            .{ .key = "membership.role", .value = .{ .string = @tagName(role) } },
        };
        telemetry.event("chock.membership.changed", .info, &attributes);
        say(writer, .{ .ok = "member updated" });
        return;
    }
    fail(writer, "the team action is unknown");
}

const AclInput = struct {
    resource_kind: []const u8,
    resource_id: []const u8,
    principal_kind: daemon_state.PrincipalKind,
    principal_id: []const u8 = "",
    capability: daemon_state.Capability,
    effect: daemon_state.Effect,
};

fn handleAuthAcl(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthAcl) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    defer arena.free(principal.instance_role);

    if (std.mem.eql(u8, one.action, "list")) {
        const rules = database.listAclRules(arena, &principal.id, one.resource_kind, one.resource_id) catch {
            fail(writer, "only a resource manager may list its ACL rules");
            return;
        };
        const json = std.json.Stringify.valueAlloc(arena, rules, .{}) catch {
            fail(writer, "ACL rules could not be encoded");
            return;
        };
        say(writer, .{ .record = .{ .id = 0, .payload = json } });
        return;
    }
    if (std.mem.eql(u8, one.action, "set")) {
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const size = decoder.calcSizeForSlice(one.payload) catch {
            fail(writer, "ACL rule details were malformed");
            return;
        };
        const decoded = arena.alloc(u8, size) catch {
            fail(writer, "ACL rule details could not be read");
            return;
        };
        decoder.decode(decoded, one.payload) catch {
            fail(writer, "ACL rule details were malformed");
            return;
        };
        const input = std.json.parseFromSliceLeaky(AclInput, arena, decoded, .{}) catch {
            fail(writer, "ACL rule details were invalid");
            return;
        };
        const id = database.setAclRule(&principal.id, .{
            .resource_kind = input.resource_kind,
            .resource_id = input.resource_id,
            .principal_kind = input.principal_kind,
            .principal_id = input.principal_id,
            .capability = input.capability,
            .effect = input.effect,
        }, now_ms) catch {
            fail(writer, "the ACL rule could not be set; check resource permissions and UUIDs");
            return;
        };
        const attributes = [_]telemetry.Attribute{
            .{ .key = "access.resource_kind", .value = .{ .string = input.resource_kind } },
            .{ .key = "access.capability", .value = .{ .string = @tagName(input.capability) } },
            .{ .key = "access.effect", .value = .{ .string = @tagName(input.effect) } },
        };
        telemetry.event("chock.access_rule.created", .info, &attributes);
        writer.print(control.ok_prefix ++ "{s}\n", .{&id}) catch return;
        return;
    }
    if (std.mem.eql(u8, one.action, "remove")) {
        const removed = database.removeAclRule(&principal.id, one.rule_id) catch {
            fail(writer, "only a resource manager may remove that ACL rule");
            return;
        };
        if (removed) telemetry.event("chock.access_rule.removed", .info, &.{});
        say(writer, .{ .ok = if (removed) "rule removed" else "rule not found" });
        return;
    }
    fail(writer, "the ACL action is unknown");
}

const ProviderInput = struct {
    name: []const u8,
    provider_kind: []const u8,
    scope_kind: daemon_state.ProviderScope,
    scope_id: []const u8 = "",
    configuration: []const u8,
    credential_ref: []const u8,
};

const ProviderRow = struct {
    id: []const u8,
    name: []const u8,
    provider_kind: []const u8,
    scope_kind: daemon_state.ProviderScope,
    scope_id: ?[]const u8,
    configuration: []const u8,
    has_credential: bool,
};

fn handleAuthProvider(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthProvider) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    defer arena.free(principal.instance_role);

    if (std.mem.eql(u8, one.action, "list")) {
        const providers = database.listLlmProviders(arena, &principal.id) catch {
            fail(writer, "providers could not be listed");
            return;
        };
        const rows = arena.alloc(ProviderRow, providers.len) catch {
            fail(writer, "provider rows could not be encoded");
            return;
        };
        for (providers, rows) |provider, *row| row.* = .{
            .id = &provider.id,
            .name = provider.name,
            .provider_kind = provider.provider_kind,
            .scope_kind = provider.scope_kind,
            .scope_id = provider.scope_id,
            .configuration = provider.configuration,
            .has_credential = provider.has_credential,
        };
        const json = std.json.Stringify.valueAlloc(arena, rows, .{}) catch {
            fail(writer, "provider rows could not be encoded");
            return;
        };
        say(writer, .{ .record = .{ .id = 0, .payload = json } });
        return;
    }
    if (std.mem.eql(u8, one.action, "create")) {
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const size = decoder.calcSizeForSlice(one.payload) catch {
            fail(writer, "provider details were malformed");
            return;
        };
        const decoded = arena.alloc(u8, size) catch {
            fail(writer, "provider details could not be read");
            return;
        };
        decoder.decode(decoded, one.payload) catch {
            fail(writer, "provider details were malformed");
            return;
        };
        const input = std.json.parseFromSliceLeaky(ProviderInput, arena, decoded, .{}) catch {
            fail(writer, "provider details were invalid");
            return;
        };
        const id = database.createLlmProvider(
            daemon.io,
            &principal.id,
            input.name,
            input.provider_kind,
            input.scope_kind,
            if (input.scope_kind == .user and input.scope_id.len == 0) &principal.id else input.scope_id,
            input.configuration,
            input.credential_ref,
            now_ms,
        ) catch {
            fail(writer, "provider creation was refused; check scope ownership and credential reference format");
            return;
        };
        const attributes = [_]telemetry.Attribute{
            .{ .key = "provider.scope", .value = .{ .string = @tagName(input.scope_kind) } },
        };
        telemetry.event("chock.provider.created", .info, &attributes);
        writer.print(control.ok_prefix ++ "{s}\n", .{&id}) catch return;
        return;
    }
    if (std.mem.eql(u8, one.action, "remove")) {
        const removed = database.removeLlmProvider(&principal.id, one.provider_id) catch {
            fail(writer, "only a provider manager may remove that provider");
            return;
        };
        if (removed) telemetry.event("chock.provider.removed", .info, &.{});
        say(writer, .{ .ok = if (removed) "provider removed" else "provider not found" });
        return;
    }
    fail(writer, "the provider action is unknown");
}

fn greet(reader: *std.Io.Reader, writer: *std.Io.Writer) bool {
    const line = (reader.takeDelimiter('\n') catch null) orelse {
        fail(writer, "the connection carried no greeting");
        return false;
    };
    const asked = control.Greeting.parse(.ask, std.mem.trimEnd(u8, line, "\r")) catch {
        fail(writer, control.no_greeting_text);
        return false;
    };
    if (!control.accepts(control.protocol_version, asked.version)) {
        control.writeMismatch(writer, control.protocol_version, asked.version) catch return false;
        writer.flush() catch return false;
        return false;
    }
    (control.Greeting{}).write(.answer, writer) catch return false;
    writer.flush() catch return false;
    return true;
}

fn handleStart(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Start) void {
    if (one.project.len == 0 or one.message.len == 0) {
        fail(writer, "start needs a project directory and a message, and neither can be empty");
        return;
    }
    if (!std.fs.path.isAbsolute(one.project)) {
        fail(writer, "the project directory has to be an absolute path");
        return;
    }

    const id = session_paths.newId(daemon.io);
    beginSession(daemon, writer, one.project, id, .{ .say = one.message });
}

fn handleAdopt(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Adopt) void {
    const id = checkedSession(writer, one.project, one.session) orelse return;

    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, one.project, &id) catch {
        fail(writer, "the session path could not be built");
        return;
    };
    defer paths.deinit();

    switch (sessions_cmd.readinessOf(daemon.gpa, daemon.io, paths.log, &id)) {
        .ready => {},
        .no_such_session => {
            fail(writer, "this machine holds no session with that identifier under that project");
            return;
        },
        .nothing_to_carry_on => {
            fail(writer, "that session holds nothing to carry on from");
            return;
        },
        .running => {
            fail(writer, "that session is running now, and the process holding its log's lock owns it");
            return;
        },
        .unknown => {
            fail(writer, "that session could not be read, or its lock could not be tested");
            return;
        },
    }

    beginSession(daemon, writer, one.project, id, .carry_on);
}

fn handleCreate(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Create) void {
    if (one.project.len == 0) {
        fail(writer, "create needs a project directory, and it cannot be empty");
        return;
    }
    if (!std.fs.path.isAbsolute(one.project)) {
        fail(writer, "the project directory has to be an absolute path");
        return;
    }

    beginSession(daemon, writer, one.project, session_paths.newId(daemon.io), .nothing);
}

fn handleFork(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Fork) void {
    const source_id = checkedSession(writer, one.project, one.session) orelse return;

    var room = std.heap.ArenaAllocator.init(daemon.gpa);
    defer room.deinit();
    const arena = room.allocator();

    const dir = session_paths.projectDir(arena, daemon.env, one.project) catch {
        fail(writer, "the session directory could not be built");
        return;
    };
    var forked: sessions_cmd.Forked = undefined;
    const code = sessions_cmd.forkSession(
        arena,
        daemon.io,
        daemon.env,
        dir,
        one.project,
        &source_id,
        one.at,
        &forked,
    ) catch {
        fail(writer, "that session could not be forked");
        return;
    };
    if (code != Exit.finished.code()) {
        fail(writer, "that session could not be forked at the requested completed turn");
        return;
    }

    beginSession(
        daemon,
        writer,
        one.project,
        forked.id,
        .{ .forked = if (forked.latest and forked.workspace) source_id else null },
    );
}

fn handleReview(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.Review) void {
    _ = checkedSession(writer, one.project, one.session) orelse return;
    const dir = session_paths.projectDir(arena, daemon.env, one.project) catch {
        fail(writer, "the session directory could not be built");
        return;
    };
    const payload = workspace_cmd.reviewJson(arena, daemon.gpa, daemon.io, one.project, dir, one.session) catch |err| {
        fail(writer, @errorName(err));
        return;
    };
    say(writer, .{ .record = .{ .id = 0, .payload = payload } });
}

fn handleSelect(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.Select) void {
    _ = checkedSession(writer, one.project, one.session) orelse return;
    const Choice = struct {
        paths: []const []const u8 = &.{},
        hunks: []const workspace_cmd.HunkSelector = &.{},
        rejected_paths: []const []const u8 = &.{},
        rejected_hunks: []const workspace_cmd.HunkSelector = &.{},
    };
    const choice = std.json.parseFromSliceLeaky(Choice, arena, one.payload, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch {
        fail(writer, "the workspace selection is not valid JSON");
        return;
    };
    const dir = session_paths.projectDir(arena, daemon.env, one.project) catch {
        fail(writer, "the session directory could not be built");
        return;
    };
    const code = workspace_cmd.selectWorkspace(arena, daemon.gpa, daemon.io, daemon.env, one.project, dir, .{
        .session = one.session,
        .paths = choice.paths,
        .hunks = choice.hunks,
        .rejected_paths = choice.rejected_paths,
        .rejected_hunks = choice.rejected_hunks,
    });
    if (code != Exit.finished.code()) {
        fail(writer, "the workspace selection was refused; the source or selected result may have changed");
        return;
    }
    say(writer, .{ .ok = "selected" });
}

fn handleUndoSelection(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.UndoSelection) void {
    _ = checkedSession(writer, one.project, one.session) orelse return;
    const dir = session_paths.projectDir(arena, daemon.env, one.project) catch {
        fail(writer, "the session directory could not be built");
        return;
    };
    const code = workspace_cmd.undoSelection(arena, daemon.io, daemon.env, one.project, dir, one.session);
    if (code != Exit.finished.code()) {
        fail(writer, "the selected workspace result could not be removed");
        return;
    }
    say(writer, .{ .ok = "undone" });
}

fn handlePrompt(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Prompt) void {
    const id = checkedSession(writer, one.project, one.session) orelse return;
    if (one.message.len == 0) {
        fail(writer, "prompt needs a message, and it cannot be empty");
        return;
    }

    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, one.project, &id) catch {
        fail(writer, "the session path could not be built");
        return;
    };
    defer paths.deinit();

    switch (sessions_cmd.readinessOf(daemon.gpa, daemon.io, paths.log, &id)) {
        .running => {
            fail(writer, "that session is running now, and the process holding its log's lock owns it");
            return;
        },
        .ready, .no_such_session, .nothing_to_carry_on, .unknown => {},
    }

    beginSession(daemon, writer, one.project, id, .{ .say = one.message });
}

fn handleAuthPrompt(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthPrompt) void {
    if (!std.fs.path.isAbsolute(one.project) or one.session.len == 0 or one.session.len > 128) {
        fail(writer, "the authenticated prompt needs an absolute project and session identifier");
        return;
    }
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    const allowed = database.authorizeSession(&principal.id, one.session, .session_prompt) catch {
        fail(writer, "session authorization could not be checked");
        return;
    };
    const project_matches = database.sessionBelongsToProject(one.session, one.project) catch {
        fail(writer, "session project authorization could not be checked");
        return;
    };
    if (!allowed or !project_matches) {
        fail(writer, "session access does not allow prompting");
        return;
    }
    const placement = database.sessionPlacement(one.session) catch {
        fail(writer, "the session execution placement could not be checked");
        return;
    } orelse {
        fail(writer, "the session is not registered with this daemon");
        return;
    };
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(one.message) catch {
        fail(writer, "the authenticated message is malformed");
        return;
    };
    if (decoded_len == 0 or decoded_len > 64 * 1024) {
        fail(writer, "the authenticated message is empty or too large");
        return;
    }
    const message = arena.alloc(u8, decoded_len) catch {
        fail(writer, "the authenticated message could not be read");
        return;
    };
    decoder.decode(message, one.message) catch {
        fail(writer, "the authenticated message is malformed");
        return;
    };
    if (placement == .client) {
        const id = checkedSession(writer, one.project, one.session) orelse return;
        const admitted = database.beginClientTurn(one.session) catch {
            fail(writer, "the client-hosted turn could not be admitted");
            return;
        };
        if (!admitted) {
            fail(writer, "the client worker is already processing a turn; wait for it to finish before prompting again");
            return;
        }
        switch (appendAuthenticatedPrompt(daemon, one.project, id, message, &principal.id)) {
            .appended => {},
            .not_written => |reason| {
                const released = database.finishClientTurn(one.session) catch {
                    fail(writer, "the prompt was not appended and the client turn guard could not be released");
                    return;
                };
                if (!released) {
                    fail(writer, "the prompt was not appended and its client turn guard was no longer active");
                    return;
                }
                fail(writer, reason);
                return;
            },
            .uncertain => |reason| {
                fail(writer, reason);
                return;
            },
        }
        say(writer, .{ .ok = "queued for client host" });
        const attributes = [_]telemetry.Attribute{
            .{ .key = "session.placement", .value = .{ .string = "client" } },
        };
        telemetry.event("chock.session.turn.queued", .info, &attributes);
        return;
    }
    const provider = resolveDaemonProvider(daemon, arena, writer, database, &principal.id) orelse return;
    const id = checkedSession(writer, one.project, one.session) orelse return;
    beginSession(daemon, writer, one.project, id, .{ .auth_say = .{
        .message = message,
        .author_id = principal.id,
        .provider = provider,
    } });
}

fn handleAuthCancel(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthCancel) void {
    if (!std.fs.path.isAbsolute(one.project) or !session_paths.isValidId(one.session)) {
        fail(writer, "the authenticated cancellation needs an absolute project and valid session identifier");
        return;
    }
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    const allowed = database.authorizeSession(&principal.id, one.session, .session_prompt) catch {
        fail(writer, "session authorization could not be checked");
        return;
    };
    const project_matches = database.sessionBelongsToProject(one.session, one.project) catch {
        fail(writer, "session project authorization could not be checked");
        return;
    };
    if (!allowed or !project_matches) {
        fail(writer, "session access does not allow cancellation");
        return;
    }
    const placement = database.sessionPlacement(one.session) catch {
        fail(writer, "the session execution placement could not be checked");
        return;
    } orelse {
        fail(writer, "the session is not registered with this daemon");
        return;
    };
    const id = checkedSession(writer, one.project, one.session) orelse return;
    if (placement == .daemon) {
        if (daemon.cancelTurn(&id)) {
            say(writer, .{ .ok = "interrupted" });
        } else {
            say(writer, .{ .ok = "that session is running nothing" });
        }
        return;
    }

    switch (appendClientCancellation(daemon, arena, database, writer, one.project, id, &principal.id)) {
        .appended => say(writer, .{ .ok = "cancellation requested" }),
        .not_written => |reason| fail(writer, reason),
        .uncertain => |reason| fail(writer, reason),
    }
}

const PromptAppendResult = union(enum) {
    appended,
    not_written: []const u8,
    uncertain: []const u8,
};

fn appendAuthenticatedPrompt(
    daemon: *Daemon,
    project: []const u8,
    id: [session_paths.id_length]u8,
    message: []const u8,
    author_id: []const u8,
) PromptAppendResult {
    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, project, &id) catch {
        return .{ .not_written = "the client-hosted session path could not be built" };
    };
    defer paths.deinit();
    makeDirAll(daemon.io, paths.dir) catch {
        return .{ .not_written = "the client-hosted session directory could not be made" };
    };
    const log = chock_proto.log.Log.open(daemon.io, paths.log, &id) catch
        return .{ .not_written = "the client-hosted session log could not be opened" };
    var opened = Opened{ .backing = .{ .log = log } };
    defer opened.close(daemon.io);
    var locked = opened.storage().lock(daemon.io) catch {
        return .{ .not_written = "the client-hosted session log could not be locked" };
    };
    defer locked.unlock(daemon.io) catch {};
    const content = [_]chock_proto.event.ContentPart{.{ .text = message }};
    _ = locked.append(daemon.gpa, daemon.io, .{ .message = .{
        .role = .user,
        .content = &content,
        .author_id = author_id,
    } }, std.Io.Timestamp.now(daemon.io, .real).toMilliseconds()) catch {
        return .{ .uncertain = "the client-hosted prompt append failed ambiguously; the turn remains locked to protect event order" };
    };
    return .appended;
}

fn appendClientCancellation(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    database: *daemon_state.Database,
    writer: *std.Io.Writer,
    project: []const u8,
    id: [session_paths.id_length]u8,
    identity_id: []const u8,
) PromptAppendResult {
    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, project, &id) catch {
        return .{ .not_written = "the client-hosted session path could not be built" };
    };
    defer paths.deinit();
    var opened = openLog(daemon, writer, paths.log, &id) orelse {
        return .{ .not_written = "the client-hosted session log could not be opened" };
    };
    defer opened.close(daemon.io);
    var locked = opened.storage().lock(daemon.io) catch {
        return .{ .not_written = "the client-hosted session log could not be locked" };
    };
    defer locked.unlock(daemon.io) catch {};
    const active = database.clientTurnActive(&id) catch {
        return .{ .not_written = "the client-hosted turn state could not be checked" };
    };
    if (!active) return .{ .not_written = "there is no active client-hosted turn to cancel" };
    var replay = opened.backing.log.replayFrom(arena, daemon.io, 0) catch {
        return .{ .not_written = "the client-hosted session history could not be read" };
    };
    defer replay.deinit();
    var latest_is_end = false;
    while (replay.next(daemon.io) catch {
        return .{ .not_written = "the client-hosted session history could not be read" };
    }) |parsed| {
        defer parsed.deinit();
        latest_is_end = parsed.value.event == .session_end;
    }
    if (latest_is_end) return .{ .not_written = "the client-hosted turn has already ended" };
    _ = locked.append(daemon.gpa, daemon.io, .{ .worker_cancel = .{
        .requested_by = identity_id,
    } }, std.Io.Timestamp.now(daemon.io, .real).toMilliseconds()) catch {
        return .{ .uncertain = "the cancellation record could not be appended unambiguously" };
    };
    return .appended;
}

fn appendAgentAnswer(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    project: []const u8,
    id: [session_paths.id_length]u8,
    request_id: u64,
    answer: []const u8,
    identity_id: []const u8,
) PromptAppendResult {
    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, project, &id) catch {
        return .{ .not_written = "the session path could not be built" };
    };
    defer paths.deinit();
    const log = chock_proto.log.Log.open(daemon.io, paths.log, &id) catch
        return .{ .not_written = "the session log could not be opened" };
    var opened = Opened{ .backing = .{ .log = log } };
    defer opened.close(daemon.io);
    var locked = opened.storage().lock(daemon.io) catch {
        return .{ .not_written = "the session log could not be locked" };
    };
    defer locked.unlock(daemon.io) catch {};

    var replay = opened.backing.log.replayFrom(arena, daemon.io, 0) catch {
        return .{ .not_written = "the session history could not be read" };
    };
    defer replay.deinit();
    var question_pending = false;
    while (replay.next(daemon.io) catch {
        return .{ .not_written = "the session history could not be read" };
    }) |parsed| {
        defer parsed.deinit();
        if (parsed.value.id == request_id and parsed.value.event == .agent_question) {
            question_pending = true;
            continue;
        }
        switch (parsed.value.event) {
            .agent_answer => |prior| {
                if (prior.request_id == request_id) question_pending = false;
            },
            .session_end => {
                if (question_pending) question_pending = false;
            },
            else => {},
        }
    }
    if (!question_pending) return .{ .not_written = "that agent question is no longer waiting for an answer" };
    _ = locked.append(daemon.gpa, daemon.io, .{ .agent_answer = .{
        .request_id = request_id,
        .answer = answer,
        .responder_id = identity_id,
    } }, std.Io.Timestamp.now(daemon.io, .real).toMilliseconds()) catch {
        return .{ .uncertain = "the agent answer could not be appended unambiguously" };
    };
    return .appended;
}

const DaemonProviderConfiguration = struct {
    base_url: ?[]const u8 = null,
    model: []const u8 = "",
    context_tokens: ?u64 = null,
    capabilities: chock_auth.config.Capabilities = .{},
};

/// Resolve opaque secret UUIDs only inside the daemon process. Service managers
/// can inject the corresponding value into this process without placing it in
/// Quarry, the browser, or the control protocol.
fn providerCredentialEnvironmentName(arena: std.mem.Allocator, credential_ref: []const u8) !?[]const u8 {
    if (std.mem.startsWith(u8, credential_ref, "env://")) return credential_ref[6..];
    if (!std.mem.startsWith(u8, credential_ref, "secret://") or
        !daemon_state.isUuid(credential_ref[9..])) return null;
    const variable = try arena.alloc(u8, "CHOCK_SECRET_".len + credential_ref.len - 9);
    @memcpy(variable[0.."CHOCK_SECRET_".len], "CHOCK_SECRET_");
    for (credential_ref[9..], 0..) |byte, index| {
        variable["CHOCK_SECRET_".len + index] = std.ascii.toLower(byte);
    }
    return variable;
}

fn resolveDaemonProvider(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    database: *daemon_state.Database,
    identity_id: []const u8,
) ?run_cmd.DaemonProvider {
    const record = database.defaultLlmProvider(arena, identity_id) catch {
        fail(writer, "the provider ACL could not be checked");
        return null;
    } orelse {
        fail(writer, "no provider is available to this identity; ask a provider manager to configure one");
        return null;
    };
    const credential_ref = database.llmProviderCredentialRef(arena, &record.id) catch {
        fail(writer, "the selected provider credential reference could not be loaded");
        return null;
    };
    const kind = chock_auth.config.Kind.fromWireName(record.provider_kind) orelse {
        fail(writer, "the selected provider kind is not supported by this daemon");
        return null;
    };
    const configuration = std.json.parseFromSliceLeaky(DaemonProviderConfiguration, arena, record.configuration, .{}) catch {
        fail(writer, "the selected provider configuration is malformed");
        return null;
    };
    if (configuration.model.len == 0 or configuration.model.len > 256) {
        fail(writer, "the selected provider needs a model in its non-secret configuration");
        return null;
    }
    const base_url = configuration.base_url orelse kind.defaultBaseUrl();
    if (!std.mem.startsWith(u8, base_url, "https://") and
        !std.mem.startsWith(u8, base_url, "http://127.0.0.1") and
        !std.mem.startsWith(u8, base_url, "http://localhost") and
        !std.mem.startsWith(u8, base_url, "http://[::1]"))
    {
        fail(writer, "provider endpoints must use HTTPS except for loopback development");
        return null;
    }
    const variable = providerCredentialEnvironmentName(arena, credential_ref) catch {
        fail(writer, "the provider credential reference could not be resolved");
        return null;
    } orelse {
        fail(writer, "the selected provider credential reference is not supported");
        return null;
    };
    const token = daemon.env.get(variable) orelse {
        fail(writer, "the selected provider's credential is not injected into the daemon environment");
        return null;
    };
    if (token.len == 0 or token.len > 16 * 1024) {
        fail(writer, "the selected provider credential is empty or too large");
        return null;
    }
    return .{
        .name = record.name,
        .kind = kind,
        .base_url = base_url,
        .token = token,
        .model = configuration.model,
        .context_tokens = configuration.context_tokens,
        .capabilities = configuration.capabilities,
    };
}

test "secret UUID references resolve only to daemon-side environment names" {
    const arena = std.testing.allocator;
    try std.testing.expectEqualStrings("OPENAI_KEY", (try providerCredentialEnvironmentName(arena, "env://OPENAI_KEY")).?);
    const secret_name = (try providerCredentialEnvironmentName(
        arena,
        "secret://00000000-0000-4000-8000-000000000123",
    )).?;
    defer arena.free(secret_name);
    try std.testing.expectEqualStrings("CHOCK_SECRET_00000000-0000-4000-8000-000000000123", secret_name);
    try std.testing.expect((try providerCredentialEnvironmentName(arena, "secret://not-a-uuid")) == null);
}

fn handleAuthAnswer(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthAnswer) void {
    if (!std.fs.path.isAbsolute(one.project) or one.session.len == 0 or one.session.len > 128) {
        fail(writer, "the authenticated approval needs an absolute project and session identifier");
        return;
    }
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    const allowed = database.authorizeSession(&principal.id, one.session, .session_approve) catch {
        fail(writer, "session authorization could not be checked");
        return;
    };
    const project_matches = database.sessionBelongsToProject(one.session, one.project) catch {
        fail(writer, "session project authorization could not be checked");
        return;
    };
    if (!allowed or !project_matches) {
        fail(writer, "session access does not allow answering approvals");
        return;
    }
    handleAnswerWithAuthor(daemon, arena, writer, .{
        .project = one.project,
        .session = one.session,
        .request_id = one.request_id,
        .decision = one.decision,
    }, &principal.id);
}

fn handleAuthAgentAnswer(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer, one: control.Request.AuthAgentAnswer) void {
    if (!std.fs.path.isAbsolute(one.project) or !session_paths.isValidId(one.session) or one.request_id == 0) {
        fail(writer, "the agent answer needs an absolute project, valid session, and question identifier");
        return;
    }
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const answer_len = decoder.calcSizeForSlice(one.answer) catch {
        fail(writer, "the agent answer is malformed");
        return;
    };
    if (answer_len == 0 or answer_len > chock_core.ask.max_answer_bytes) {
        fail(writer, "the agent answer is empty or too long");
        return;
    }
    const answer = arena.alloc(u8, answer_len) catch {
        fail(writer, "the agent answer could not be read");
        return;
    };
    decoder.decode(answer, one.answer) catch {
        fail(writer, "the agent answer is malformed");
        return;
    };
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    const now_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds();
    const principal = database.resolveLoginSession(arena, one.token, now_ms) catch {
        fail(writer, "the login session could not be checked");
        return;
    } orelse {
        fail(writer, "the login session is invalid or expired");
        return;
    };
    const allowed = database.authorizeSession(&principal.id, one.session, .session_prompt) catch {
        fail(writer, "session authorization could not be checked");
        return;
    };
    const project_matches = database.sessionBelongsToProject(one.session, one.project) catch {
        fail(writer, "session project authorization could not be checked");
        return;
    };
    if (!allowed or !project_matches) {
        fail(writer, "session access does not allow answering agent questions");
        return;
    }
    const id = checkedSession(writer, one.project, one.session) orelse return;
    const appended = appendAgentAnswer(daemon, arena, one.project, id, one.request_id, answer, &principal.id);
    switch (appended) {
        .appended => say(writer, .{ .ok = "answered" }),
        .not_written => |reason| fail(writer, reason),
        .uncertain => |reason| fail(writer, reason),
    }
}

fn handleCancel(daemon: *Daemon, writer: *std.Io.Writer, one: control.Request.Cancel) void {
    const id = checkedSession(writer, one.project, one.session) orelse return;

    if (!daemon.cancelTurn(&id)) {
        say(writer, .{ .ok = "that session is running nothing" });
        return;
    }
    say(writer, .{ .ok = "interrupted" });
}

fn checkedSession(
    writer: *std.Io.Writer,
    project: []const u8,
    given: []const u8,
) ?[session_paths.id_length]u8 {
    if (project.len == 0) {
        fail(writer, "that needs a project directory, and it cannot be empty");
        return null;
    }
    if (!std.fs.path.isAbsolute(project)) {
        fail(writer, "the project directory has to be an absolute path");
        return null;
    }
    if (!session_paths.isValidId(given)) {
        fail(writer, "that is not a session identifier");
        return null;
    }
    return given[0..session_paths.id_length].*;
}

const Begin = union(enum) {
    say: []const u8,
    auth_say: struct { message: []const u8, author_id: [36]u8, provider: run_cmd.DaemonProvider },
    carry_on,
    /// The source id is present only when this is its latest completed turn,
    /// the one an idle guest can represent.
    forked: ?[session_paths.id_length]u8,
    nothing,

    fn startsChild(self: Begin) bool {
        return switch (self) {
            .say, .auth_say, .carry_on => true,
            .forked, .nothing => false,
        };
    }
};

fn cloneDaemonProvider(gpa: std.mem.Allocator, provider: run_cmd.DaemonProvider) std.mem.Allocator.Error!run_cmd.DaemonProvider {
    const name = try gpa.dupe(u8, provider.name);
    errdefer gpa.free(name);
    const base_url = try gpa.dupe(u8, provider.base_url);
    errdefer gpa.free(base_url);
    const token = try gpa.dupe(u8, provider.token);
    errdefer {
        std.crypto.secureZero(u8, token);
        gpa.free(token);
    }
    const model = try gpa.dupe(u8, provider.model);
    return .{
        .name = name,
        .kind = provider.kind,
        .base_url = base_url,
        .token = token,
        .model = model,
        .context_tokens = provider.context_tokens,
        .capabilities = provider.capabilities,
    };
}

fn freeDaemonProvider(gpa: std.mem.Allocator, provider: run_cmd.DaemonProvider) void {
    std.crypto.secureZero(u8, @constCast(provider.token));
    gpa.free(provider.token);
    gpa.free(provider.name);
    gpa.free(provider.base_url);
    gpa.free(provider.model);
}

fn beginSession(
    daemon: *Daemon,
    writer: *std.Io.Writer,
    project: []const u8,
    id: [session_paths.id_length]u8,
    begin: Begin,
) void {
    if (daemon.sandbox.chosen() == .microvm and refuseChockOwn(daemon, writer, project)) return;

    if (daemon.database) |*database| {
        const placement = database.sessionPlacement(&id) catch {
            fail(writer, "the session execution placement could not be checked");
            return;
        };
        if (placement == .client and begin != .nothing) {
            fail(writer, "this session is client-hosted and must be run by its client worker; no daemon worker was started");
            return;
        }
    }

    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, project, &id) catch {
        fail(writer, "the session path could not be built");
        return;
    };
    defer paths.deinit();

    makeDirAll(daemon.io, paths.dir) catch {
        fail(writer, "the session directory could not be made");
        return;
    };

    const log_path = daemon.gpa.dupeSentinel(u8, paths.log, 0) catch {
        fail(writer, "out of memory");
        return;
    };
    const project_copy = daemon.gpa.dupe(u8, project) catch {
        daemon.gpa.free(log_path);
        fail(writer, "out of memory");
        return;
    };
    const snapshot_path = guestSnapshotPath(daemon, &id) orelse {
        daemon.gpa.free(log_path);
        daemon.gpa.free(project_copy);
        fail(writer, "out of memory");
        return;
    };
    const remembered = daemon.remember(.{
        .id = id,
        .log_path = log_path,
        .snapshot_path = snapshot_path,
        .project = project_copy,
        .has_snapshot = snapshotOnDisk(daemon.io, snapshot_path),
    }) catch {
        daemon.gpa.free(log_path);
        daemon.gpa.free(snapshot_path);
        daemon.gpa.free(project_copy);
        fail(writer, "out of memory");
        return;
    };
    if (!remembered) {
        daemon.gpa.free(log_path);
        daemon.gpa.free(snapshot_path);
        daemon.gpa.free(project_copy);
    }

    if (begin == .forked) {
        if (begin.forked) |source_id| {
            const target_path = if (remembered)
                snapshot_path
            else
                daemon.snapshotPathFor(&id) orelse {
                    fail(writer, "the fork's microVM checkpoint path was lost");
                    return;
                };
            if (copyForkSnapshot(daemon, &source_id, target_path)) {
                daemon.noteSnapshot(&id, true);
            }
        }
    }

    if (begin == .nothing) {
        var opened = openLog(daemon, writer, paths.log, &id) orelse return;
        opened.backing.log.close(daemon.io);
    }

    // A fork is already a complete, open child session. It stays idle until a
    // person sends the first divergent prompt; starting an adopted run here
    // would answer the inherited source prompt a second time.
    if (begin.startsChild()) {
        const child_project = daemon.gpa.dupe(u8, project) catch {
            fail(writer, "out of memory");
            return;
        };
        const child_log_path = (daemon.logPathFor(&id) catch {
            daemon.gpa.free(child_project);
            fail(writer, "out of memory");
            return;
        }) orelse {
            daemon.gpa.free(child_project);
            fail(writer, "the session log path was lost");
            return;
        };
        const owned_message: ?[]u8 = switch (begin) {
            .say => |text| daemon.gpa.dupe(u8, text) catch {
                daemon.gpa.free(child_project);
                daemon.gpa.free(child_log_path);
                fail(writer, "out of memory");
                return;
            },
            .auth_say => |auth| daemon.gpa.dupe(u8, auth.message) catch {
                daemon.gpa.free(child_project);
                daemon.gpa.free(child_log_path);
                fail(writer, "out of memory");
                return;
            },
            .carry_on => null,
            .forked, .nothing => unreachable,
        };
        const owned_provider: ?run_cmd.DaemonProvider = switch (begin) {
            .auth_say => |auth| cloneDaemonProvider(daemon.gpa, auth.provider) catch {
                daemon.gpa.free(child_project);
                daemon.gpa.free(child_log_path);
                if (owned_message) |text| daemon.gpa.free(text);
                fail(writer, "the provider configuration could not be retained for the turn");
                return;
            },
            else => null,
        };

        const turn = daemon.gpa.create(Turn) catch {
            daemon.gpa.free(child_project);
            daemon.gpa.free(child_log_path);
            if (owned_message) |text| daemon.gpa.free(text);
            if (owned_provider) |provider| freeDaemonProvider(daemon.gpa, provider);
            fail(writer, "out of memory");
            return;
        };
        turn.* = .{};
        if (!daemon.noteTurnWorker(&id, turn)) {
            daemon.gpa.destroy(turn);
            daemon.gpa.free(child_project);
            daemon.gpa.free(child_log_path);
            if (owned_message) |text| daemon.gpa.free(text);
            if (owned_provider) |provider| freeDaemonProvider(daemon.gpa, provider);
            fail(writer, "that session is already running a turn");
            return;
        }

        const worker = TurnWorker{
            .daemon = daemon,
            .id = id,
            .project = child_project,
            .log_path = child_log_path,
            .message = owned_message,
            .turn = turn,
            .author_identity_id = if (begin == .auth_say) begin.auth_say.author_id else null,
            .provider = owned_provider,
            .adopt = switch (begin) {
                .carry_on => true,
                .say, .auth_say => false,
                .forked, .nothing => unreachable,
            },
        };
        const thread = std.Thread.spawn(.{}, runTurn, .{worker}) catch {
            _ = daemon.noteTurnWorker(&id, null);
            daemon.gpa.destroy(turn);
            daemon.gpa.free(child_project);
            daemon.gpa.free(child_log_path);
            if (owned_message) |text| daemon.gpa.free(text);
            if (owned_provider) |provider| freeDaemonProvider(daemon.gpa, provider);
            fail(writer, "the session could not be started");
            return;
        };
        thread.detach();
    }

    var text_buffer: [std.fs.max_path_bytes + session_paths.id_length + 8]u8 = undefined;
    const text = std.fmt.bufPrint(&text_buffer, "{s}\t{s}", .{ id, paths.log }) catch {
        fail(writer, "the answer was longer than this daemon can write");
        return;
    };
    say(writer, .{ .ok = text });
    if (begin == .auth_say) {
        const attributes = [_]telemetry.Attribute{
            .{ .key = "session.placement", .value = .{ .string = "daemon" } },
        };
        telemetry.event("chock.session.turn.queued", .info, &attributes);
    }
}

fn refuseChockOwn(daemon: *Daemon, writer: *std.Io.Writer, project: []const u8) bool {
    var room = std.heap.ArenaAllocator.init(daemon.gpa);
    defer room.deinit();
    const arena = room.allocator();

    const held = run_cmd.chockOwnInProject(arena, daemon.io, daemon.env, project) catch {
        fail(writer, "whether a guest for that project would hold one of Chock's own directories " ++
            "cannot be answered, so no session runs for it");
        return true;
    } orelse return false;

    const said = std.fmt.allocPrint(
        arena,
        "the project {s} holds {s}, which is Chock's own, so no session runs for it. A guest " ++
            "granted that directory reads this user's credentials. Name the project itself.",
        .{ held.project, held.own },
    ) catch {
        fail(writer, "that project holds one of Chock's own directories, so no session runs for it");
        return true;
    };
    tty.print(.err, "chock daemon: {s}\n", .{said});
    fail(writer, said);
    return true;
}

const TurnWorker = struct {
    daemon: *Daemon,
    id: [session_paths.id_length]u8,
    project: []u8,
    log_path: [:0]u8,
    message: ?[]u8,
    turn: *Turn,
    author_identity_id: ?[36]u8 = null,
    provider: ?run_cmd.DaemonProvider = null,
    adopt: bool,
};

fn runTurn(child: TurnWorker) void {
    const daemon = child.daemon;
    defer {
        _ = daemon.noteTurnWorker(&child.id, null);
        daemon.gpa.destroy(child.turn);
    }
    defer daemon.gpa.free(child.project);
    defer daemon.gpa.free(child.log_path);
    defer if (child.message) |text| daemon.gpa.free(text);
    defer if (child.provider) |provider| freeDaemonProvider(daemon.gpa, provider);

    const before = logEnd(daemon.io, child.log_path, &child.id) catch |err| {
        tty.print(
            .err,
            "chock daemon: session {s} log could not be read before starting it: {t}\n",
            .{ child.id, err },
        );
        return;
    };

    const guest = startGuest(daemon, &child.id, child.project);
    const turn = daemon.noteTurn(&child.id);
    defer if (turn) |which| releaseGuestLater(daemon, child.id, which);

    var argv_buffer: [8][]const u8 = undefined;
    var argv_len: usize = 0;
    for ([_][]const u8{ "--project", child.project, "--session", &child.id }) |word| {
        argv_buffer[argv_len] = word;
        argv_len += 1;
    }
    if (guest) |socket| {
        argv_buffer[argv_len] = "--guest";
        argv_buffer[argv_len + 1] = socket;
        argv_len += 2;
    }
    if (child.message) |text| {
        argv_buffer[argv_len] = "--";
        argv_buffer[argv_len + 1] = text;
        argv_len += 2;
    } else if (child.adopt) {
        argv_buffer[argv_len] = "--adopt";
        argv_len += 1;
    }
    const argv = argv_buffer[0..argv_len];

    var arena_state = std.heap.ArenaAllocator.init(daemon.gpa);
    defer arena_state.deinit();

    const previous_stop = interrupt.useScopedStop(&child.turn.stop);
    defer _ = interrupt.useScopedStop(previous_stop);
    const previous_human_out = tty.useScopedHumanOut(false);
    defer _ = tty.useScopedHumanOut(previous_human_out);

    const status = (if (child.provider) |provider| blk: {
        const author_id = child.author_identity_id orelse return;
        break :blk run_cmd.mainForDaemonWithProviderAs(
            arena_state.allocator(),
            daemon.gpa,
            daemon.environ,
            daemon.exe_path,
            argv,
            &author_id,
            provider,
        );
    } else if (child.author_identity_id) |author_id|
        run_cmd.mainForDaemonAs(
            arena_state.allocator(),
            daemon.gpa,
            daemon.environ,
            daemon.exe_path,
            argv,
            &author_id,
        )
    else
        run_cmd.mainForDaemon(
            arena_state.allocator(),
            daemon.gpa,
            daemon.environ,
            daemon.exe_path,
            argv,
        )) catch |err| {
        tty.print(.err, "chock daemon: session {s} failed: {t}\n", .{ child.id, err });
        publishChildFailure(child, before, "the session runner failed", @errorName(err));
        return;
    };

    tty.print(.plain, "chock daemon: session {s} exited {d}\n", .{ child.id, status });
    if (status != 0) {
        var detail_buffer: [96]u8 = undefined;
        const detail = std.fmt.bufPrint(
            &detail_buffer,
            "the session runner exited with status {d}",
            .{status},
        ) catch "the session runner failed";
        publishChildFailure(child, before, detail, "");
    }
}

fn publishChildFailure(child: TurnWorker, before: u64, message: []const u8, suffix: []const u8) void {
    var detail_buffer: [512]u8 = undefined;
    const detail = if (suffix.len == 0)
        message
    else
        std.fmt.bufPrint(&detail_buffer, "{s}: {s}", .{ message, suffix }) catch message;

    const appended = appendChildFailure(
        child.daemon.gpa,
        child.daemon.io,
        child.log_path,
        &child.id,
        before,
        detail,
    ) catch |err| {
        tty.print(
            .err,
            "chock daemon: session {s} error could not be written to its log: {t}\n",
            .{ child.id, err },
        );
        return;
    };
    _ = appended;
}

fn logEnd(io: std.Io, log_path: [:0]const u8, id: []const u8) !u64 {
    var log = try chock_proto.log.Log.open(io, log_path, id);
    defer log.close(io);
    return log.file.length(io);
}

/// Adds the ending the child could not add itself. An ending written at or after `before`
/// wins, even when the process later returns a non-zero cleanup status.
fn appendChildFailure(
    gpa: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    id: []const u8,
    before: u64,
    detail: []const u8,
) !bool {
    var log = try chock_proto.log.Log.open(io, log_path, id);
    defer log.close(io);

    var locked = try log.lock(io);
    defer locked.unlock(io) catch {};

    const end = try log.file.length(io);
    if (end > before) {
        var replay = try log.replayFrom(gpa, io, before);
        defer replay.deinit();
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();
            if (parsed.value.event == .session_end) return false;
        }
    }

    _ = try locked.append(gpa, io, .{
        .session_end = .{ .reason = .errored, .detail = detail },
    }, std.Io.Timestamp.now(io, .real).toMilliseconds());
    return true;
}

fn startGuest(
    daemon: *Daemon,
    id: *const [session_paths.id_length]u8,
    project: []const u8,
) ?[:0]const u8 {
    if (daemon.sandbox.chosen() != .microvm) return null;
    while (true) switch (daemon.guestState(id)) {
        .ready => |had| return had.socket,
        .snapshotting => std.Io.sleep(
            daemon.io,
            .fromNanoseconds(guest_look_ms * std.time.ns_per_ms),
            .awake,
        ) catch return null,
        .none => break,
    };

    if (daemon.guestCount() >= max_guests) {
        tty.print(
            .warn,
            "chock daemon: session {s} gets no guest: this daemon already holds {d}, which is " ++
                "all it will\n",
            .{ id, max_guests },
        );
        return null;
    }

    const socket = guestSocketPath(daemon, id) orelse return null;
    var socket_owned = true;
    defer if (socket_owned) daemon.gpa.free(socket);

    const room = daemon.gpa.create(std.heap.ArenaAllocator) catch return null;
    var room_owned = true;
    defer if (room_owned) {
        room.deinit();
        daemon.gpa.destroy(room);
    };
    room.* = std.heap.ArenaAllocator.init(daemon.gpa);

    const shares = guestShares(room.allocator(), daemon, id, project) orelse return null;
    const snapshot_path = daemon.snapshotPathFor(id) orelse return null;
    const restore = if (daemon.takeSnapshot(id)) snapshot_path else null;

    const running = daemon.gpa.create(Running) catch return null;
    var running_owned = true;
    defer if (running_owned) daemon.gpa.destroy(running);
    running.* = .{ .thread = undefined };

    const guest_machine = chock_policy.sandbox.Machine.now();

    const console = guestConsolePath(daemon, id) orelse return null;
    var console_owned = true;
    defer if (console_owned) daemon.gpa.free(console);

    const work = GuestWork{
        .daemon = daemon,
        .running = running,
        .options = .{
            .kernel = daemon.sandbox.kernel.?,
            .initrd = daemon.sandbox.initrd,
            .session = socket,
            .memory_mb = daemon.sandbox.memory(guest_machine, builtin.os.tag),
            .cpus = daemon.sandbox.processors(guest_machine, builtin.os.tag),
            .shares = shares,
            .restore = restore,
            .save = snapshot_path,
            .control = vmm.fork_sets_control,
        },
        .shares = room,
        .console = console,
    };

    running.thread = std.Thread.spawn(.{}, runGuest, .{work}) catch |err| {
        tty.print(.err, "chock daemon: session {s} could not be given a guest: {t}\n", .{ id, err });
        return null;
    };
    room_owned = false;
    console_owned = false;

    if (!waitForGuest(daemon.io, running)) {
        tty.print(
            .err,
            "chock daemon: the guest of session {s} did not come up{s}\n",
            .{ id, if (restore != null) " from its snapshot; trying a cold boot" else ", so the session runs none" },
        );
        running.stopping.store(true, .release);
        running.thread.join();
        if (restore != null) {
            std.Io.Dir.deleteFileAbsolute(daemon.io, snapshot_path) catch {};
            return startGuest(daemon, id, project);
        }
        return null;
    }

    // A snapshot describes the quiescent guest before this one resumed. Once
    // the restored guest is ready it is the authoritative state; retaining the
    // old file would let a daemon crash roll the session back to an earlier
    // tool-side state on its next start.
    if (restore != null) std.Io.Dir.deleteFileAbsolute(daemon.io, snapshot_path) catch {};

    if (!daemon.rememberGuest(id, .{ .running = running, .socket = socket })) {
        running.stopping.store(true, .release);
        running.thread.join();
        return daemon.guestFor(id).?.socket;
    }
    socket_owned = false;
    running_owned = false;
    tty.detail("chock daemon: session {s} has a guest at {s}, console at {s}\n", .{ id, socket, console });
    return socket;
}

const GuestWork = struct {
    daemon: *Daemon,
    running: *Running,
    options: vmm.Options,
    shares: *std.heap.ArenaAllocator,
    /// Where the guest's console is written. Owned by the thread that runs the
    /// guest, and freed with it.
    console: [:0]u8,
};

fn runGuest(work: GuestWork) void {
    const daemon = work.daemon;
    const running = work.running;

    defer daemon.gpa.free(work.console);

    // A file and not this daemon's own output. A guest writes its kernel log and
    // its init script to this, and a daemon that answers many sessions would
    // otherwise have all of them spliced through its own messages.
    var console = std.Io.Dir.cwd().createFile(daemon.io, work.console, .{}) catch {
        tty.print(
            .err,
            "chock daemon: a guest's console could not be opened at {s}\n",
            .{work.console},
        );
        releaseShares(daemon, work.shares);
        running.ended.store(true, .release);
        return;
    };
    defer console.close(daemon.io);

    var child = vmm.forkHost(daemon.io, work.options, console.handle) catch |err| {
        tty.print(.err, "chock daemon: a guest's own process could not be started: {t}\n", .{err});
        releaseShares(daemon, work.shares);
        running.ended.store(true, .release);
        return;
    };
    releaseShares(daemon, work.shares);

    defer {
        child.stop();
        const code = child.wait();
        if (code == 0 and running.snapshotting.load(.acquire)) {
            running.snapshot_saved.store(true, .release);
        }
        if (code == 0) {
            tty.detail("chock daemon: a guest's own process ended, answering 0\n", .{});
        } else {
            tty.print(.err, "chock daemon: a guest's own process ended badly, answering {d}\n", .{code});
        }
        std.Io.Dir.deleteFileAbsolute(daemon.io, work.options.session) catch {};
    }
    defer running.ended.store(true, .release);

    child.sendShares(daemon.gpa, &.{}) catch |err| {
        tty.print(
            .err,
            "chock daemon: a guest's own process would not be told to start ({t}), so it is " ++
                "already gone\n",
            .{err},
        );
        return;
    };

    child.waitReady(daemon.io, guest_boot_ms) catch |err| {
        if (child.fault()) |said| {
            if (said.detail.len == 0) {
                tty.print(.err, "chock daemon: a guest: {s}.\n", .{said.said});
            } else {
                tty.print(.err, "chock daemon: a guest: {s}: {s}\n", .{ said.said, said.detail });
            }
        }
        tty.print(.err, "chock daemon: a guest did not come up: {t}\n", .{err});
        return;
    };
    if (child.sev != .off) {
        tty.print(.dim, "chock daemon: a guest's memory is encrypted ({s}).\n", .{child.sev.text()});
    }
    running.snapshot_allowed.store(vmm.snapshots and child.sev == .off, .release);
    running.ready.store(true, .release);

    while (!running.stopping.load(.acquire)) {
        if (running.snapshotting.load(.acquire)) {
            child.snapshotStop() catch |err| {
                running.snapshotting.store(false, .release);
                tty.print(.err, "chock daemon: a guest could not be asked for a snapshot: {t}\n", .{err});
            };
            return;
        }
        std.Io.sleep(daemon.io, .fromNanoseconds(guest_look_ms * std.time.ns_per_ms), .awake) catch
            return;
    }
}

fn releaseShares(daemon: *Daemon, room: *std.heap.ArenaAllocator) void {
    room.deinit();
    daemon.gpa.destroy(room);
}

pub const max_granted_roots = guest_limits.max_granted_roots;

fn guestShares(
    arena: std.mem.Allocator,
    daemon: *Daemon,
    id: *const [session_paths.id_length]u8,
    project: []const u8,
) ?[]const vmm.Options.Share {
    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = realPathOf(daemon.io, project, &project_buffer) orelse {
        tty.print(.err, "chock daemon: {s} has no real path, so no guest is started\n", .{project});
        return null;
    };

    var out: std.ArrayList(vmm.Options.Share) = .empty;
    var resolve_buffer: [std.fs.max_path_bytes]u8 = undefined;

    const toolchain = run_cmd.hostToolchainPaths(arena, daemon.io) catch return null;
    for (toolchain) |path| grant(arena, &out, daemon.io, path, false) catch return null;

    const paths = session_paths.pathsFor(arena, daemon.env, root, id) catch return null;
    session_paths.create(daemon.io, paths) catch return null;
    session_paths.markProject(daemon.io, paths, root);
    grant(arena, &out, daemon.io, paths.work, true) catch return null;

    const backing = run_cmd.projectGrantDir(arena, daemon.io, root) catch return null;

    if (run_cmd.chockOwnInProject(arena, daemon.io, daemon.env, root) catch return null) |held| {
        tty.print(
            .err,
            "chock daemon: the project {s} holds {s}, which is Chock's own, so no guest is " ++
                "started for it. A guest granted that directory reads this user's " ++
                "credentials. Name the project itself.\n",
            .{ held.project, held.own },
        );
        return null;
    }
    grant(arena, &out, daemon.io, backing, false) catch return null;

    if (imageDirFor(arena, daemon.io, daemon.env, root)) |dir| {
        session_paths.createImageDir(daemon.io, dir) catch return null;
        grant(arena, &out, daemon.io, dir, false) catch return null;
    }

    const cache_dir = session_paths.cacheDir(arena, daemon.env, root) catch return null;
    var cache_diag: ?chock_core.Diagnostic = null;
    const cache_made = session_paths.createCacheDir(
        daemon.io,
        cache_dir,
        chock_core.cache.sinkOf(arena, &cache_diag),
    ) catch {
        if (cache_diag) |fault| {
            tty.print(
                .err,
                "chock daemon: the toolchain cache {s} could not be made ({f}), so no guest is " ++
                    "started: a session whose cache is missing has nowhere but the workspace " ++
                    "to write.\n",
                .{ cache_dir, fault },
            );
        } else {
            tty.print(
                .err,
                "chock daemon: the toolchain cache {s} could not be made, so no guest is " ++
                    "started.\n",
                .{cache_dir},
            );
        }
        return null;
    };
    if (cache_made) {
        tty.print(
            .plain,
            "chock daemon: this project has no toolchain cache yet, so one is made at {s}. " ++
                "`chock cache clear` empties it.\n",
            .{cache_dir},
        );
    }
    grant(arena, &out, daemon.io, resolvedOr(daemon.io, cache_dir, &resolve_buffer), true) catch
        return null;

    const scratch_dir = session_paths.scratchpadDir(arena, daemon.env, id) catch return null;
    session_paths.createDirAll(daemon.io, scratch_dir) catch return null;
    grant(arena, &out, daemon.io, resolvedOr(daemon.io, scratch_dir, &resolve_buffer), true) catch
        return null;

    const memory_dir = session_paths.memoryDir(arena, daemon.env, root) catch return null;
    if (session_paths.createMemoryDir(daemon.io, memory_dir)) {
        grant(arena, &out, daemon.io, memory_dir, true) catch return null;
    } else |_| {}

    return out.toOwnedSlice(arena) catch null;
}

fn grant(
    arena: std.mem.Allocator,
    out: *std.ArrayList(vmm.Options.Share),
    io: std.Io,
    path: []const u8,
    writable: bool,
) std.mem.Allocator.Error!void {
    if (!isDirectory(io, path)) return;
    for (out.items) |had| {
        if (!vmm.shareCovers(path, had.host_path)) continue;
        if (had.writable or !writable) return;
    }
    try out.append(arena, .{
        .name = try vmm.shareNameFor(arena, out.items, path),
        .host_path = try arena.dupe(u8, path),
        .writable = writable,
    });
}

fn isDirectory(io: std.Io, path: []const u8) bool {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind == .directory;
}

fn imageDirFor(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    root: []const u8,
) ?[]const u8 {
    const named = switch (chock_container.config.load(arena, io, root) catch return null) {
        .named => |reference| reference,
        .none, .refused => return null,
    };
    const leaf = chock_container.reference.directoryName(arena, named) catch return null;
    return session_paths.imageDir(arena, env, leaf) catch null;
}

fn resolvedOr(io: std.Io, path: []const u8, buffer: []u8) []const u8 {
    return realPathOf(io, path, buffer) orelse path;
}

fn realPathOf(io: std.Io, path: []const u8, buffer: []u8) ?[]const u8 {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch return null;
    defer dir.close(io);
    const length = dir.realPath(io, buffer) catch return null;
    return buffer[0..length];
}

fn waitForGuest(io: std.Io, running: *Running) bool {
    var waited: u64 = 0;
    while (waited < guest_boot_ms) : (waited += guest_look_ms) {
        if (running.ready.load(.acquire)) return true;
        if (running.ended.load(.acquire)) return false;
        std.Io.sleep(io, .fromNanoseconds(guest_look_ms * std.time.ns_per_ms), .awake) catch
            return false;
    }
    return false;
}

const guest_name_bytes = session_paths.guest_name_bytes;

/// Where a guest's console is written, beside its socket and named the same.
fn guestConsolePath(
    daemon: *Daemon,
    id: *const [session_paths.id_length]u8,
) ?[:0]u8 {
    const tail = id[id.len - guest_name_bytes ..];
    return std.fmt.allocPrintSentinel(
        daemon.gpa,
        "{s}/g-{s}.console",
        .{ daemon.socket_dir, tail },
        0,
    ) catch null;
}

fn guestSnapshotPath(
    daemon: *Daemon,
    id: *const [session_paths.id_length]u8,
) ?[:0]u8 {
    const dir = if (daemon.snapshot_dir.len != 0) daemon.snapshot_dir else daemon.socket_dir;
    return session_paths.guestSnapshotPath(daemon.gpa, dir, id) catch null;
}

fn snapshotOnDisk(io: std.Io, path: []const u8) bool {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind == .file;
}

fn guestSocketPath(
    daemon: *Daemon,
    id: *const [session_paths.id_length]u8,
) ?[:0]u8 {
    const tail = id[id.len - guest_name_bytes ..];
    const path = std.fmt.allocPrintSentinel(
        daemon.gpa,
        "{s}/g-{s}.sock",
        .{ daemon.socket_dir, tail },
        0,
    ) catch return null;

    if (path.len > std.Io.net.UnixAddress.max_len) {
        tty.print(
            .err,
            "chock daemon: a guest socket at {s} would be {d} bytes and a unix socket path " ++
                "takes {d}. Give the daemon a shorter --socket path: its own directory is " ++
                "where a guest's goes.\n",
            .{ path, path.len, std.Io.net.UnixAddress.max_len },
        );
        daemon.gpa.free(path);
        return null;
    }
    return path;
}

/// Give a fork its own copy of the source session's quiescent checkpoint. The
/// source retains its copy so either branch can resume independently.
fn copyForkSnapshot(
    daemon: *Daemon,
    source_id: *const [session_paths.id_length]u8,
    target_path: []const u8,
) bool {
    const source_path = daemon.snapshotPathFor(source_id) orelse return false;

    while (true) switch (daemon.claimForkSnapshot(source_id)) {
        .wait => std.Io.sleep(
            daemon.io,
            .fromNanoseconds(guest_look_ms * std.time.ns_per_ms),
            .awake,
        ) catch return false,
        .none => return false,
        .file => break,
        .guest => |guest| {
            guest.running.snapshotting.store(true, .release);
            guest.running.thread.join();
            const saved = guest.running.snapshot_saved.load(.acquire);
            daemon.gpa.destroy(guest.running);
            daemon.gpa.free(guest.socket);
            if (!saved) {
                daemon.finishForkSnapshot(source_id, false);
                std.Io.Dir.deleteFileAbsolute(daemon.io, source_path) catch {};
                return false;
            }
            break;
        },
    };
    std.Io.Dir.copyFileAbsolute(source_path, target_path, daemon.io, .{}) catch |err| {
        std.Io.Dir.deleteFileAbsolute(daemon.io, target_path) catch {};
        daemon.finishForkSnapshot(source_id, true);
        tty.print(
            .warn,
            "chock daemon: session {s}'s microVM checkpoint could not be copied to its fork: {t}\n",
            .{ source_id, err },
        );
        return false;
    };
    daemon.finishForkSnapshot(source_id, true);
    tty.detail("chock daemon: session {s}'s microVM checkpoint copied to its fork\n", .{source_id});
    return true;
}

fn releaseGuestLater(daemon: *Daemon, id: [session_paths.id_length]u8, turn: u64) void {
    std.Io.sleep(
        daemon.io,
        .fromNanoseconds(guest_idle_ms * std.time.ns_per_ms),
        .awake,
    ) catch return;

    const one = daemon.takeGuest(&id, turn) orelse return;
    defer daemon.gpa.free(one.socket);
    defer daemon.gpa.destroy(one.running);

    if (one.running.snapshot_allowed.load(.acquire)) {
        one.running.snapshotting.store(true, .release);
    } else {
        one.running.stopping.store(true, .release);
    }
    one.running.thread.join();
    const saved = one.running.snapshot_saved.load(.acquire);
    daemon.noteSnapshot(&id, saved);
    if (saved) {
        tty.detail("chock daemon: the guest of session {s} was snapshotted after an idle spell\n", .{id});
    } else {
        tty.detail("chock daemon: the guest of session {s} was let go after an idle spell\n", .{id});
    }
}

fn handleRead(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.Read,
    include_end_offset: bool,
    event_limit: usize,
) void {
    if (!session_paths.isValidId(one.session)) {
        fail(writer, "that is not a session identifier");
        return;
    }

    const remembered = daemon.logPathFor(one.session) catch {
        fail(writer, "out of memory");
        return;
    };
    defer if (remembered) |path| daemon.gpa.free(path);

    // Session identifiers are globally unique. A daemon can therefore recover
    // an older session after a restart by looking through the same project
    // directories its `list` request already exposes; the version-1 read API
    // does not need a project field.
    const log_path = remembered orelse logPathAnywhere(daemon, arena, one.session) orelse {
        fail(writer, "no project has a session with that identifier");
        return;
    };

    var opened = openLog(daemon, writer, log_path, one.session) orelse return;
    defer opened.close(daemon.io);

    var feed = control.Feed{ .after = one.after };
    _ = feed.events(arena, daemon.io, opened.storage(), writer, event_limit) catch |err| {
        failWith(writer, "the session log could not be read from there", @errorName(err));
        return;
    };
    if (include_end_offset) writer.print(control.ok_prefix ++ "offset {d}\n", .{feed.end_offset}) catch return;
    writer.flush() catch return;
}

fn logPathAnywhere(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    session: []const u8,
) ?[:0]const u8 {
    const projects = session_paths.listProjects(arena, daemon.io, daemon.env) catch return null;
    for (projects) |project| {
        const candidate = std.fmt.allocPrintSentinel(
            arena,
            "{s}/{s}.jsonl",
            .{ project.dir, session },
            0,
        ) catch return null;
        const file = std.Io.Dir.openFileAbsolute(daemon.io, candidate, .{}) catch continue;
        file.close(daemon.io);
        return candidate;
    }
    return null;
}

fn handleWatch(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    handle: std.posix.fd_t,
    one: control.Request.Watch,
) void {
    const id = checkedSession(writer, one.project, one.session) orelse return;

    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, one.project, &id) catch {
        fail(writer, "the session path could not be built");
        return;
    };
    defer paths.deinit();

    _ = std.Io.Dir.cwd().statFile(daemon.io, paths.log, .{}) catch {
        fail(writer, "this machine holds no session with that identifier under that project");
        return;
    };

    var feed = control.Feed{ .after = one.after };
    if (one.after == 0) {
        var opened = openLog(daemon, writer, paths.log, &id) orelse return;
        defer opened.close(daemon.io);
        feed.header(daemon.io, opened.storage(), writer) catch |err| {
            failWith(writer, "the session log's header could not be read", @errorName(err));
            return;
        };
    }

    while (true) {
        const grew = grow: {
            var opened = openLog(daemon, writer, paths.log, &id) orelse return;
            defer opened.close(daemon.io);
            break :grow feed.events(arena, daemon.io, opened.storage(), writer, 0) catch |err| {
                failWith(writer, "the session log could not be read", @errorName(err));
                return;
            };
        };
        writer.flush() catch return;

        if (feed.ended and sessions_cmd.livenessOf(daemon.io, paths.log) != .live) return;

        if (!grew) {
            if (peerGone(handle, watch_idle_ms)) return;
        }
    }
}

const Opened = struct {
    backing: chock_proto.storage.JsonLines,

    fn storage(self: *Opened) chock_proto.storage.Storage {
        return self.backing.storage();
    }

    fn close(self: *Opened, io: std.Io) void {
        self.backing.log.close(io);
    }
};

fn openLog(
    daemon: *Daemon,
    writer: *std.Io.Writer,
    log_path: [:0]const u8,
    id: []const u8,
) ?Opened {
    const log = chock_proto.log.Log.open(daemon.io, log_path, id) catch |err| {
        failWith(writer, "the session log could not be opened", @errorName(err));
        return null;
    };
    return .{ .backing = .{ .log = log } };
}

fn peerGone(handle: std.posix.fd_t, timeout_ms: u64) bool {
    var fds = [_]std.posix.pollfd{.{
        .fd = handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const bounded: i32 = if (timeout_ms > std.math.maxInt(i32))
        std.math.maxInt(i32)
    else
        @intCast(timeout_ms);
    const ready = std.posix.poll(&fds, bounded) catch return false;
    if (ready == 0) return false;
    if (fds[0].revents & (std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL) != 0) return true;

    var scratch: [64]u8 = undefined;
    const read = std.posix.read(handle, &scratch) catch return true;
    return read == 0;
}

fn handleList(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.List,
) void {
    // Empty asks for every project, which is what a picker covering more than
    // one needs. A named project still has to be a real path.
    if (one.project.len == 0) {
        const found = session_paths.listProjects(arena, daemon.io, daemon.env) catch {
            fail(writer, "the projects could not be read");
            return;
        };
        for (found) |project| {
            if (!listInto(daemon, arena, writer, project.dir, project.name, project.root)) return;
        }
        writer.flush() catch return;
        return;
    }

    if (!std.fs.path.isAbsolute(one.project)) {
        fail(writer, "the project directory has to be an absolute path");
        return;
    }

    const dir = session_paths.projectDir(arena, daemon.env, one.project) catch {
        fail(writer, "the session directory could not be built");
        return;
    };

    if (!listInto(daemon, arena, writer, dir, "", one.project)) return;
    writer.flush() catch return;
}

/// Write out every session in one directory. False when something refused and
/// the caller has already been told.
fn listInto(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    dir: []const u8,
    project: []const u8,
    root: []const u8,
) bool {
    const found = sessions_cmd.list(arena, daemon.io, dir) catch {
        fail(writer, "out of memory");
        return false;
    };

    for (found) |session| {
        var row = rowOf(session);
        row.project = project;
        row.project_root = root;
        const text = row.toJson(arena) catch {
            fail(writer, "a session could not be written out");
            return false;
        };
        say(writer, .{ .record = .{ .id = session.started_ms, .payload = text } });
    }
    return true;
}

/// Every project this daemon can see, one record each.
fn handleProjects(daemon: *Daemon, arena: std.mem.Allocator, writer: *std.Io.Writer) void {
    if (daemon.oidc != null) {
        const database = if (daemon.database) |*value| value else {
            fail(writer, "the daemon database is not available");
            return;
        };
        const registered = database.listProjects(arena) catch {
            fail(writer, "the registered projects could not be read");
            return;
        };
        for (registered, 0..) |one, index| {
            const row: control.ProjectRow = .{
                .id = &one.id,
                .root = one.root,
                .source_kind = one.source_kind,
                .source_locator = one.source_locator,
                .name = one.name,
                .status = one.status,
            };
            const text = row.toJson(arena) catch {
                fail(writer, "a project could not be written out");
                return;
            };
            say(writer, .{ .record = .{ .id = index, .payload = text } });
        }
        writer.flush() catch return;
        return;
    }

    const found = session_paths.listProjects(arena, daemon.io, daemon.env) catch {
        fail(writer, "the projects could not be read");
        return;
    };

    for (found, 0..) |one, index| {
        const row: control.ProjectRow = .{
            .root = one.root,
            .name = one.name,
            .sessions = one.sessions,
        };
        const text = row.toJson(arena) catch {
            fail(writer, "a project could not be written out");
            return;
        };
        say(writer, .{ .record = .{ .id = index, .payload = text } });
    }
    writer.flush() catch return;
}

pub fn rowOf(session: sessions_cmd.Session) control.SessionRow {
    return .{
        .id = session.id,
        .started_ms = session.started_ms,
        .forked_from = session.forked_from,
        .forked_at = session.forked_at,
        .model = session.model,
        .model_count = session.model_count,
        .model_alias = session.model_alias,
        .title = session.title,
        .live = @tagName(session.live),
        .end = if (session.end) |reason| reason.wireName() else null,
        .turns = session.spend.turns,
        .input_tokens = session.spend.input_tokens,
        .output_tokens = session.spend.output_tokens,
        .amount = session.spend.amount,
        .currency = session.spend.currency,
        .spend_enforceable = session.spend.enforceable(),
        .readable = session.readable,
        .complete = session.complete,
        .chain = control.verdictName(session.chain.verdict),
        .chain_events = session.chain.events,
        .chain_chained = session.chain.chained,
        .has_work = session.has_work,
        .has_root = session.has_root,
    };
}

fn handleAnswer(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.Answer_,
) void {
    handleAnswerWithAuthor(daemon, arena, writer, one, "");
}

fn handleAnswerWithAuthor(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    one: control.Request.Answer_,
    responder_id: []const u8,
) void {
    const id = checkedSession(writer, one.project, one.session) orelse return;

    if (daemon.database) |*database| {
        const placement = database.sessionPlacement(&id) catch {
            fail(writer, "the session execution placement could not be checked");
            return;
        };
        if (placement == .client) {
            answerClientHostedApproval(daemon, writer, one, id, responder_id);
            return;
        }
    }

    const dir = session_paths.projectDir(arena, daemon.env, one.project) catch {
        fail(writer, "the session directory could not be built");
        return;
    };
    var paths = chock_broker.socket.pathsFor(arena, dir, &id) catch {
        fail(writer, "the approval socket path could not be built");
        return;
    };
    defer paths.deinit();

    const address = control.unixAddress(paths.socket) catch {
        fail(writer, "the approval socket path is too long for a socket");
        return;
    };
    const stream = address.connect(daemon.io) catch {
        fail(writer, "that session is not listening for an answer, so it has ended or asked nothing");
        return;
    };
    defer stream.close(daemon.io);

    const text = chock_proto.event.toJson(arena, .{
        .id = 0,
        .session = &id,
        .time_ms = std.Io.Timestamp.now(daemon.io, .real).toMilliseconds(),
        .event = .{
            .approval_response = .{
                .request_id = one.request_id,
                .decision = one.decision.decision(),
                .responder = "",
                .responder_id = responder_id,
            },
        },
    }) catch {
        fail(writer, "the answer could not be written out");
        return;
    };

    if (!chock_broker.socket.writeAll(stream.socket.handle, text) or
        !chock_broker.socket.writeAll(stream.socket.handle, "\n"))
    {
        fail(writer, "that session went away before it could be answered");
        return;
    }
    say(writer, .{ .ok = "answered" });
}

/// Client-hosted turns have no daemon-local approval socket. Record their
/// authenticated answer in the canonical transcript; the active worker tails
/// that log and the local Broker observes the same response event.
fn answerClientHostedApproval(
    daemon: *Daemon,
    writer: *std.Io.Writer,
    one: control.Request.Answer_,
    id: [session_paths.id_length]u8,
    responder_id: []const u8,
) void {
    const database = if (daemon.database) |*value| value else {
        fail(writer, "the daemon database is not available");
        return;
    };
    var paths = session_paths.pathsFor(daemon.gpa, daemon.env, one.project, &id) catch {
        fail(writer, "the client-hosted session log path could not be built");
        return;
    };
    defer paths.deinit();
    var opened = openLog(daemon, writer, paths.log, &id) orelse return;
    defer opened.close(daemon.io);
    var locked = opened.storage().lock(daemon.io) catch {
        fail(writer, "the session log is busy; retry the approval");
        return;
    };
    defer locked.unlock(daemon.io) catch {};

    const active = database.clientTurnActive(&id) catch {
        fail(writer, "the client-hosted turn state could not be checked");
        return;
    };
    if (!active) {
        fail(writer, "there is no active client-hosted turn to approve");
        return;
    }
    const request_id = chock_broker.Broker.openRequest(daemon.gpa, daemon.io, opened.storage()) catch {
        fail(writer, "the open approval request could not be read");
        return;
    } orelse {
        fail(writer, "that approval has already been answered or is no longer open");
        return;
    };
    if (request_id != one.request_id) {
        fail(writer, "that approval is no longer the active request");
        return;
    }
    const action = chock_broker.Broker.requestAction(daemon.gpa, daemon.io, opened.storage(), request_id) catch {
        fail(writer, "the approval action could not be read");
        return;
    } orelse {
        fail(writer, "the approval request is missing from the session log");
        return;
    };
    defer daemon.gpa.free(action);
    _ = locked.append(daemon.gpa, daemon.io, .{ .approval_response = .{
        .request_id = request_id,
        .decision = one.decision.decision(),
        .responder = "",
        .action = action,
        .responder_id = responder_id,
    } }, std.Io.Timestamp.now(daemon.io, .real).toMilliseconds()) catch {
        fail(writer, "the approval response could not be recorded");
        return;
    };
    say(writer, .{ .ok = "answered" });
}

fn say(writer: *std.Io.Writer, reply: control.Reply) void {
    reply.write(writer) catch return;
}

fn fail(writer: *std.Io.Writer, what: []const u8) void {
    say(writer, .{ .failed = what });
    writer.flush() catch return;
}

fn failWith(writer: *std.Io.Writer, what: []const u8, reason: []const u8) void {
    writer.print(control.error_prefix ++ "{s}: {s}\n", .{ what, reason }) catch return;
    writer.flush() catch return;
}

const ParseError = error{ HelpWanted, BadArguments };

const Options = struct {
    socket: ?[]const u8 = null,
    socket_group: ?[]const u8 = null,
    host: ?[]const u8 = null,
    port: u16 = control.default_port,
    database: ?[]const u8 = null,
    oidc_provider: ?[]const u8 = null,
    oidc_issuer: ?[]const u8 = null,
    oidc_client_id: ?[]const u8 = null,
    oidc_discovery_url: ?[]const u8 = null,
    oidc_admin_subject: ?[]const u8 = null,
};

fn configuredOidc(
    options: Options,
    env: *const std.process.Environ.Map,
) error{ IncompleteOidcConfiguration, InvalidOidcProvider, InvalidOidcConfiguration }!?daemon_state.Oidc {
    const provider_name = options.oidc_provider orelse env.get("CHOCK_OIDC_PROVIDER");
    const issuer = options.oidc_issuer orelse env.get("CHOCK_OIDC_ISSUER");
    const client_id = options.oidc_client_id orelse env.get("CHOCK_OIDC_CLIENT_ID");
    const discovery_url = options.oidc_discovery_url orelse env.get("CHOCK_OIDC_DISCOVERY_URL");
    const admin_subject = options.oidc_admin_subject orelse env.get("CHOCK_OIDC_ADMIN_SUBJECT");
    if (provider_name == null and issuer == null and client_id == null and discovery_url == null and admin_subject == null) return null;
    if (admin_subject) |subject| if (subject.len == 0 or subject.len > 512 or
        std.mem.indexOfAny(u8, subject, "\t\r\n\x00") != null) return error.InvalidOidcConfiguration;
    const provider_text = provider_name orelse return error.IncompleteOidcConfiguration;
    const configured_issuer = issuer orelse return error.IncompleteOidcConfiguration;
    const configured_client_id = client_id orelse return error.IncompleteOidcConfiguration;
    const provider = std.meta.stringToEnum(daemon_state.Provider, provider_text) orelse return error.InvalidOidcProvider;
    const config: daemon_state.Oidc = .{
        .provider = provider,
        .issuer = configured_issuer,
        .client_id = configured_client_id,
        .client_secret = env.get("CHOCK_OIDC_CLIENT_SECRET"),
        .discovery_url = discovery_url,
    };
    try config.validate();
    return config;
}

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var port_named = false;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;

        if (std.mem.eql(u8, argument, "--port")) {
            index += 1;
            if (index >= args.len) {
                tty.print(.err, "chock daemon: --port needs a value.\n\n", .{});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            options.port = std.fmt.parseInt(u16, args[index], 10) catch {
                tty.print(.err, "chock daemon: --port takes a number, and \"{s}\" is not one.\n", .{args[index]});
                return error.BadArguments;
            };
            port_named = true;
            continue;
        }

        if (std.mem.eql(u8, argument, "--host") or std.mem.eql(u8, argument, "--address") or
            std.mem.eql(u8, argument, "--bind"))
        {
            index += 1;
            if (index >= args.len) {
                tty.print(.err, "chock daemon: {s} needs a value.\n\n", .{argument});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            options.host = args[index];
            continue;
        }

        if (std.mem.eql(u8, argument, "--socket")) {
            index += 1;
            if (index >= args.len) {
                tty.print(.err, "chock daemon: --socket needs a value.\n\n", .{});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            if (!std.fs.path.isAbsolute(args[index])) {
                tty.print(
                    .err,
                    "chock daemon: --socket takes an absolute path, and \"{s}\" is not one.\n",
                    .{args[index]},
                );
                return error.BadArguments;
            }
            options.socket = args[index];
            continue;
        }

        if (std.mem.eql(u8, argument, "--socket-group")) {
            index += 1;
            if (index >= args.len or args[index].len == 0) {
                tty.print(.err, "chock daemon: --socket-group needs a value.\\n\\n", .{});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            options.socket_group = args[index];
            continue;
        }

        if (std.mem.eql(u8, argument, "--database")) {
            index += 1;
            if (index >= args.len or args[index].len == 0) {
                tty.print(.err, "chock daemon: --database needs a URL.\n\n", .{});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            options.database = args[index];
            continue;
        }

        const oidc_option: ?*?[]const u8 = if (std.mem.eql(u8, argument, "--oidc-provider")) &options.oidc_provider else if (std.mem.eql(u8, argument, "--oidc-issuer")) &options.oidc_issuer else if (std.mem.eql(u8, argument, "--oidc-client-id")) &options.oidc_client_id else if (std.mem.eql(u8, argument, "--oidc-discovery-url")) &options.oidc_discovery_url else if (std.mem.eql(u8, argument, "--oidc-admin-subject")) &options.oidc_admin_subject else null;
        if (oidc_option) |destination| {
            index += 1;
            if (index >= args.len or args[index].len == 0) {
                tty.print(.err, "chock daemon: {s} needs a value.\n\n", .{argument});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            destination.* = args[index];
            continue;
        }

        tty.print(.err, "chock daemon: there is no option named {s}.\n\n", .{argument});
        tty.print(.err, "{s}", .{usage_text});
        return error.BadArguments;
    }

    if (port_named and options.host == null) {
        tty.print(
            .err,
            "chock daemon: --port names the port of the TCP listener --host turns on, and there " ++
                "is no TCP listener without --host. Write `--host 127.0.0.1 --port <n>`, or drop " ++
                "--port and use the unix socket.\n",
            .{},
        );
        return error.BadArguments;
    }
    return options;
}

const testing = std.testing;

test "a child failure ends its attempted turn without duplicating the child's ending" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buffer);
    const path = try std.fs.path.joinZ(arena, &.{ root_buffer[0..root_len], "session.jsonl" });
    const id = "01JQ" ++ @as([22]u8, @splat('F'));

    {
        var log = try chock_proto.log.Log.open(io, path, id);
        defer log.close(io);
        var locked = try log.lock(io);
        defer locked.unlock(io) catch {};
        _ = try locked.append(gpa, io, .{
            .session_end = .{ .reason = .finished, .detail = "an older turn" },
        }, 1);
    }

    const before_failed_turn = try logEnd(io, path, id);
    try testing.expect(try appendChildFailure(
        gpa,
        io,
        path,
        id,
        before_failed_turn,
        "the credential collection is locked",
    ));

    const before_ended_turn = try logEnd(io, path, id);
    {
        var log = try chock_proto.log.Log.open(io, path, id);
        defer log.close(io);
        var locked = try log.lock(io);
        defer locked.unlock(io) catch {};
        _ = try locked.append(gpa, io, .{
            .session_end = .{ .reason = .finished, .detail = "the child handled this turn" },
        }, 2);
    }
    try testing.expect(!try appendChildFailure(
        gpa,
        io,
        path,
        id,
        before_ended_turn,
        "this must not be appended",
    ));

    var log = try chock_proto.log.Log.open(io, path, id);
    defer log.close(io);
    var replay = try log.replayFrom(gpa, io, 0);
    defer replay.deinit();
    var endings: usize = 0;
    var saw_daemon_error = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event == .session_end) {
            endings += 1;
            const ended = parsed.value.event.session_end;
            if (ended.reason == .errored) {
                try testing.expectEqualStrings("the credential collection is locked", ended.detail);
                saw_daemon_error = true;
            }
            try testing.expect(!std.mem.eql(u8, ended.detail, "this must not be appended"));
        }
    }
    try testing.expectEqual(@as(usize, 3), endings);
    try testing.expect(saw_daemon_error);
}

test "nothing but the unix socket is listened on until --host says so" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    var buffer: [max_listeners]control.Address = undefined;

    {
        const plain = try parseOptions(&.{});
        try testing.expect(plain.host == null);
        try testing.expect(plain.socket == null);
        try testing.expectEqual(control.default_port, plain.port);
        try testing.expect(plain.database == null);

        const set = listenSet(&buffer, "/state/daemon.sock", plain);
        try testing.expectEqual(@as(usize, 1), set.len);
        try testing.expectEqualStrings("/state/daemon.sock", set[0].unix);
        for (set) |address| try testing.expect(address != .ip);
    }

    {
        const configured = try parseOptions(&.{ "--database", "postgresql://chock@db/chock" });
        try testing.expectEqualStrings("postgresql://chock@db/chock", configured.database.?);
    }

    {
        const bound = try parseOptions(&.{ "--host", "0.0.0.0", "--port", "9999" });
        try testing.expectEqualStrings("0.0.0.0", bound.host.?);
        const set = listenSet(&buffer, "/state/daemon.sock", bound);
        try testing.expectEqual(@as(usize, 2), set.len);
        try testing.expectEqualStrings("/state/daemon.sock", set[0].unix);
        try testing.expectEqualStrings("0.0.0.0", set[1].ip.host);
        try testing.expectEqual(@as(u16, 9999), set[1].ip.port);
    }

    try testing.expectEqualStrings("", said.err());
    try testing.expectEqualStrings("", said.out());

    for ([_][]const u8{ "--address", "--bind" }) |spelling| {
        const same = try parseOptions(&.{ spelling, "10.0.0.4" });
        try testing.expectEqualStrings("10.0.0.4", same.host.?);
    }

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--port", "9999" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--host") != null);
}

test "OIDC provider configuration is explicit and validates the selected issuer" {
    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    try testing.expect((try configuredOidc(Options{}, &env)) == null);

    const options = try parseOptions(&.{
        "--oidc-provider",      "authentik",
        "--oidc-issuer",        "https://auth.example/application/o/chock/",
        "--oidc-client-id",     "chock-mobile-and-web",
        "--oidc-discovery-url", "https://auth.example/application/o/chock/.well-known/openid-configuration",
        "--oidc-admin-subject", "a4e0d-owner-subject",
    });
    const configured = (try configuredOidc(options, &env)).?;
    try testing.expectEqual(daemon_state.Provider.authentik, configured.provider);
    try testing.expectEqualStrings("https://auth.example/application/o/chock/", configured.issuer);
    try testing.expectEqualStrings("chock-mobile-and-web", configured.client_id);
    try testing.expectEqualStrings("https://auth.example/application/o/chock/.well-known/openid-configuration", configured.discovery_url.?);
    try testing.expectEqualStrings("a4e0d-owner-subject", options.oidc_admin_subject.?);

    for ([_][]const u8{ "kanidm", "authentik", "authelia" }) |provider_name| {
        const provider_config = (try configuredOidc(.{
            .oidc_provider = provider_name,
            .oidc_issuer = "https://identity.example",
            .oidc_client_id = "chock-service",
        }, &env)).?;
        try testing.expectEqualStrings(provider_name, @tagName(provider_config.provider));
        try testing.expectEqualStrings("https://identity.example", provider_config.issuer);
    }
    try testing.expectError(error.IncompleteOidcConfiguration, configuredOidc(
        try parseOptions(&.{ "--oidc-admin-subject", "owner-subject" }),
        &env,
    ));

    const partial = try parseOptions(&.{ "--oidc-issuer", "https://auth.example" });
    try testing.expectError(error.IncompleteOidcConfiguration, configuredOidc(partial, &env));
    const bad_provider = try parseOptions(&.{
        "--oidc-provider",  "other",
        "--oidc-issuer",    "https://auth.example",
        "--oidc-client-id", "chock",
    });
    try testing.expectError(error.InvalidOidcProvider, configuredOidc(bad_provider, &env));
}

test "the control socket serves the user that started the daemon and nobody else" {
    const io = testing.io;
    const mine = std.posix.system.getuid();

    try testing.expect(peerAllowed(mine, mine));
    try testing.expect(!peerAllowed(mine +% 1, mine));
    try testing.expect(!peerAllowed(0, mine +% 1));
    try testing.expect(!peerAllowed(null, mine));

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const socket_path = try std.fmt.allocPrint(
        testing.allocator,
        "{s}/d.sock",
        .{dir_buffer[0..dir_len]},
    );
    defer testing.allocator.free(socket_path);

    var listener = try (control.Address{ .unix = socket_path }).listen(io);
    defer listener.close(io);
    try testing.expect(listener.unix_path != null);

    const client = try (control.Address{ .unix = socket_path }).connect(io);
    defer client.close(io);
    const served = try listener.server.accept(io);
    defer served.close(io);

    const said_uid = control.peerUid(served.socket.handle);
    try testing.expectEqual(@as(?std.posix.uid_t, mine), said_uid);
    try testing.expect(peerAllowed(said_uid, mine));
    try testing.expect(!peerAllowed(said_uid, mine +% 1));
}

test "the daemon greets a client of its own number and refuses every other first line" {
    const agreed = std.fmt.comptimePrint(
        "{s}{d}\n",
        .{ control.Greeting.ask_prefix, control.protocol_version },
    );

    {
        var reader = std.Io.Reader.fixed(agreed ++ "list /p\n");
        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try testing.expect(greet(&reader, &writer));
        try testing.expectEqualStrings(
            std.fmt.comptimePrint(
                "{s}{d}\n",
                .{ control.Greeting.answer_prefix, control.protocol_version },
            ),
            writer.buffered(),
        );
        try testing.expectEqualStrings("list /p", (try reader.takeDelimiter('\n')).?);
    }

    {
        const other = control.protocol_version + 1;
        var line_buffer: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(
            &line_buffer,
            "{s}{d}\nstart /p\tgo\n",
            .{ control.Greeting.ask_prefix, other },
        );
        var reader = std.Io.Reader.fixed(line);
        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try testing.expect(!greet(&reader, &writer));

        const said = writer.buffered();
        try testing.expect(std.mem.startsWith(u8, said, control.error_prefix));
        var ours: [16]u8 = undefined;
        var theirs: [16]u8 = undefined;
        try testing.expect(std.mem.indexOf(
            u8,
            said,
            try std.fmt.bufPrint(&ours, "{d}", .{control.protocol_version}),
        ) != null);
        try testing.expect(std.mem.indexOf(
            u8,
            said,
            try std.fmt.bufPrint(&theirs, "{d}", .{other}),
        ) != null);
    }

    for ([_][]const u8{
        "start /p\tgo\n",
        "list /p\n",
        "adopt /p\t01JQ\n",
        "GET / HTTP/1.1\n",
        "hello chock-control\n",
        "hello something-else 1\n",
        "\n",
    }) |first| {
        var reader = std.Io.Reader.fixed(first);
        var buffer: [1024]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try testing.expect(!greet(&reader, &writer));
        try testing.expect(std.mem.startsWith(u8, writer.buffered(), control.error_prefix));
        try testing.expect(std.mem.indexOf(u8, writer.buffered(), "greeting") != null);
    }

    {
        var reader = std.Io.Reader.fixed("");
        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try testing.expect(!greet(&reader, &writer));
        try testing.expect(std.mem.startsWith(u8, writer.buffered(), control.error_prefix));
    }
}

test "the port and the socket parse, and a value that is not one is refused by name" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(
        @as(u16, 9999),
        (try parseOptions(&.{ "--host", "127.0.0.1", "--port", "9999" })).port,
    );
    try testing.expectEqual(
        @as(u16, 0),
        (try parseOptions(&.{ "--host", "127.0.0.1", "--port", "0" })).port,
    );
    try testing.expectEqualStrings(
        "/run/user/1000/chock/d.sock",
        (try parseOptions(&.{ "--socket", "/run/user/1000/chock/d.sock" })).socket.?,
    );
    try testing.expectEqualStrings(
        "chock-web",
        (try parseOptions(&.{ "--socket-group", "chock-web" })).socket_group.?,
    );
    try testing.expectEqualStrings("", said.err());

    for ([_][]const u8{ "seventy", "70000" }) |value| {
        said.clear();
        try testing.expectError(error.BadArguments, parseOptions(&.{ "--port", value }));
        try testing.expect(std.mem.indexOf(u8, said.err(), value) != null);
    }

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--socket", "d.sock" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "absolute") != null);

    for ([_][]const u8{ "--port", "--host", "--socket", "--socket-group" }) |flag| {
        said.clear();
        try testing.expectError(error.BadArguments, parseOptions(&.{flag}));
        try testing.expect(std.mem.indexOf(u8, said.err(), flag) != null);
    }

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{"--nonsense"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--nonsense") != null);
    try testing.expectEqualStrings("", said.out());
}

const Probe = struct {
    answer: []const u8,
    remembered: usize,
};

fn probeRequest(
    daemon: *Daemon,
    arena: std.mem.Allocator,
    buffer: []u8,
    line: []const u8,
) Probe {
    var writer = std.Io.Writer.fixed(buffer);
    const request = control.Request.parse(line) catch {
        return .{ .answer = "error the request did not parse", .remembered = daemon.sessions.items.len };
    };
    switch (request) {
        .adopt => |one| handleAdopt(daemon, &writer, one),
        .fork => |one| handleFork(daemon, &writer, one),
        .prompt => |one| handlePrompt(daemon, &writer, one),
        .list => |one| handleList(daemon, arena, &writer, one),
        .answer => |one| handleAnswer(daemon, arena, &writer, one),
        .read => |one| handleRead(daemon, arena, &writer, one, false, max_events_per_read),
        else => unreachable,
    }
    return .{ .answer = writer.buffered(), .remembered = daemon.sessions.items.len };
}

test "a daemon fork stays idle until its first divergent prompt" {
    const id = "01JQ" ++ @as([22]u8, @splat('F'));
    try testing.expect(!((Begin{ .forked = id.* }).startsChild()));
    try testing.expect(!((Begin{ .forked = null }).startsChild()));
    try testing.expect(!((Begin{ .nothing = {} }).startsChild()));
    try testing.expect((Begin{ .carry_on = {} }).startsChild());
    try testing.expect((Begin{ .say = "new prompt" }).startsChild());
}

test "the daemon fork request creates an idle child at the requested turn" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var home_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const home_len = try tmp.dir.realPath(io, &home_buffer);
    const home = home_buffer[0..home_len];
    const project = try std.fmt.allocPrint(arena, "{s}/project", .{home});
    try std.Io.Dir.createDirAbsolute(io, project, .default_dir);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", home);

    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    const source_id = "01JQ" ++ @as([22]u8, @splat('F'));
    var source_paths = try session_paths.pathsFor(gpa, &env, project, source_id);
    defer source_paths.deinit();
    try session_paths.create(io, source_paths);

    var end_at: u64 = 0;
    {
        const log = try chock_proto.log.Log.open(io, source_paths.log, source_id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "branch here" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        end_at = try locked.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 2);
        try locked.unlock(io);
    }

    var request_buffer: [std.fs.max_path_bytes + 128]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buffer,
        "fork {s}\t{s}\t{d}",
        .{ project, source_id, end_at },
    );
    var answer_buffer: [64 * 1024]u8 = undefined;
    const got = probeRequest(&daemon, arena, &answer_buffer, request);
    try testing.expectEqual(@as(usize, 1), got.remembered);

    const reply = try control.Reply.parse(std.mem.trimEnd(u8, got.answer, "\n"));
    const answer = switch (reply) {
        .ok => |text| text,
        else => return error.TestUnexpectedResult,
    };
    const separator = std.mem.indexOfScalar(u8, answer, '\t') orelse return error.TestUnexpectedResult;
    const child_id = answer[0..separator];
    try testing.expect(session_paths.isValidId(child_id));
    try testing.expect(!std.mem.eql(u8, source_id, child_id));

    const remembered = daemon.sessions.items[0];
    try testing.expectEqualStrings(child_id, &remembered.id);
    try testing.expect(remembered.turn == null);
    try testing.expect(remembered.guest == null);

    const sessions_dir = try session_paths.projectDir(arena, &env, project);
    const child = (try sessions_cmd.fold(arena, io, sessions_dir, child_id)) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqualStrings(source_id, child.forked_from);
    try testing.expectEqual(end_at, child.forked_at);
    try testing.expect(child.end == null);
    try testing.expectEqual(@as(u64, 0), child.spend.turns);
}

test "remembering another turn does not duplicate a daemon session" {
    const gpa = testing.allocator;
    const io = testing.io;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    const id = "01JQ" ++ @as([22]u8, @splat('R'));
    try testing.expect(try daemon.remember(.{
        .id = id.*,
        .log_path = try gpa.dupeSentinel(u8, "/nowhere/session.jsonl", 0),
        .snapshot_path = try gpa.dupeSentinel(u8, "/nowhere/session.snapshot", 0),
        .project = try gpa.dupe(u8, "/project"),
    }));

    const duplicate_log = try gpa.dupeSentinel(u8, "/nowhere/session.jsonl", 0);
    defer gpa.free(duplicate_log);
    const duplicate_snapshot = try gpa.dupeSentinel(u8, "/nowhere/session.snapshot", 0);
    defer gpa.free(duplicate_snapshot);
    const duplicate_project = try gpa.dupe(u8, "/project");
    defer gpa.free(duplicate_project);
    try testing.expect(!(try daemon.remember(.{
        .id = id.*,
        .log_path = duplicate_log,
        .snapshot_path = duplicate_snapshot,
        .project = duplicate_project,
    })));
    try testing.expectEqual(@as(usize, 1), daemon.sessions.items.len);
}

test "a quiescent checkpoint survives daemon teardown and is discoverable again" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const snapshot_path = try std.fmt.allocPrintSentinel(
        gpa,
        "{s}/session.snapshot",
        .{dir_buffer[0..dir_len]},
        0,
    );
    defer gpa.free(snapshot_path);
    var snapshot = try std.Io.Dir.createFileAbsolute(io, snapshot_path, .{});
    try snapshot.writeStreamingAll(io, "guest state");
    snapshot.close(io);
    try testing.expect(snapshotOnDisk(io, snapshot_path));
    try testing.expect(!snapshotOnDisk(io, dir_buffer[0..dir_len]));

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    const id = "01JQ" ++ @as([22]u8, @splat('Q'));
    try testing.expect(try daemon.remember(.{
        .id = id.*,
        .log_path = try gpa.dupeSentinel(u8, "/nowhere/session.jsonl", 0),
        .snapshot_path = try gpa.dupeSentinel(u8, snapshot_path, 0),
        .project = try gpa.dupe(u8, "/project"),
        .has_snapshot = true,
    }));
    daemon.deinit();

    try testing.expect(snapshotOnDisk(io, snapshot_path));
}

test "adopt refuses a session it may not take, and starts nothing when it does" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const home = dir_buffer[0..dir_len];

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", home);

    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    const project = "/some/project";
    const id = "01JQ" ++ @as([22]u8, @splat('A'));
    var answer_buffer: [4096]u8 = undefined;

    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project);
        try testing.expect(std.mem.startsWith(u8, got.answer, "error"));
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt project\t" ++ id);
        try testing.expect(std.mem.indexOf(u8, got.answer, "absolute path") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project ++ "\t../../../etc/passwd");
        try testing.expect(std.mem.indexOf(u8, got.answer, "not a session identifier") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    {
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project ++ "\t" ++ id);
        try testing.expect(std.mem.indexOf(u8, got.answer, "holds no session") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    var paths = try session_paths.pathsFor(gpa, &env, project, id);
    defer paths.deinit();
    try session_paths.create(io, paths);

    {
        var seed = try chock_proto.log.Log.open(io, paths.log, id);
        seed.close(io);
        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project ++ "\t" ++ id);
        try testing.expect(std.mem.indexOf(u8, got.answer, "nothing to carry on from") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }

    {
        const log = try chock_proto.log.Log.open(io, paths.log, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "carry this on" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        try locked.unlock(io);
    }

    {
        var owner = try chock_proto.log.Log.open(io, paths.log, id);
        defer owner.close(io);
        var held = try owner.lock(io);
        defer held.unlock(io) catch {};

        const got = probeRequest(&daemon, arena, &answer_buffer, "adopt " ++ project ++ "\t" ++ id);
        try testing.expect(std.mem.indexOf(u8, got.answer, "running now") != null);
        try testing.expectEqual(@as(usize, 0), got.remembered);
    }
}

test "a completed checkpoint is copied to a fork and retained by its source" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var daemon = Daemon{
        .gpa = gpa,
        .io = io,
        .exe_path = "/nowhere/chock",
        .env = &env,
        .socket_dir = dir,
    };
    defer daemon.deinit();

    const source_id = "01JQ" ++ @as([22]u8, @splat('S'));
    const target_id = "01JQ" ++ @as([22]u8, @splat('T'));
    const source_path = guestSnapshotPath(&daemon, source_id).?;
    const target_path = guestSnapshotPath(&daemon, target_id).?;
    defer gpa.free(target_path);
    defer std.Io.Dir.deleteFileAbsolute(io, target_path) catch {};

    const log_path = try gpa.dupeSentinel(u8, "/nowhere/source.jsonl", 0);
    const project = try gpa.dupe(u8, "/project");
    _ = try daemon.remember(.{
        .id = source_id.*,
        .log_path = log_path,
        .snapshot_path = source_path,
        .project = project,
        .has_snapshot = true,
    });

    var snapshot = try std.Io.Dir.createFileAbsolute(io, source_path, .{});
    try snapshot.writeStreamingAll(io, "guest state");
    snapshot.close(io);

    try testing.expect(copyForkSnapshot(&daemon, source_id, target_path));
    const source_bytes = try std.Io.Dir.cwd().readFileAlloc(io, source_path, gpa, .limited(64));
    defer gpa.free(source_bytes);
    try testing.expectEqualStrings("guest state", source_bytes);
    const target_bytes = try std.Io.Dir.cwd().readFileAlloc(io, target_path, gpa, .limited(64));
    defer gpa.free(target_bytes);
    try testing.expectEqualStrings("guest state", target_bytes);
    try testing.expect(daemon.takeSnapshot(source_id));
}

test "a listing over the wire says what the local fold says" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const home = dir_buffer[0..dir_len];

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", home);

    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    const project = "/some/project";
    const id = "01JQ" ++ @as([22]u8, @splat('A'));

    var paths = try session_paths.pathsFor(gpa, &env, project, id);
    defer paths.deinit();
    try session_paths.create(io, paths);
    {
        const log = try chock_proto.log.Log.open(io, paths.log, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "hello" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 2);
        try locked.unlock(io);
    }

    var answer_buffer: [64 * 1024]u8 = undefined;
    const got = probeRequest(&daemon, arena, &answer_buffer, "list " ++ project);
    try testing.expect(!std.mem.startsWith(u8, got.answer, "error"));

    const line = std.mem.trimEnd(u8, got.answer, "\n");
    const reply = try control.Reply.parse(line);
    var parsed = try control.SessionRow.fromJson(gpa, reply.record.payload);
    defer parsed.deinit();

    const dir = try session_paths.projectDir(arena, &env, project);
    const local = try sessions_cmd.list(arena, io, dir);
    try testing.expectEqual(@as(usize, 1), local.len);

    const wire = parsed.value;
    try testing.expectEqualStrings(local[0].id, wire.id);
    try testing.expectEqual(local[0].started_ms, wire.started_ms);
    try testing.expectEqualStrings(local[0].forked_from, wire.forked_from);
    try testing.expectEqual(local[0].forked_at, wire.forked_at);
    try testing.expectEqualStrings(local[0].model, wire.model);
    try testing.expectEqual(local[0].model_count, wire.model_count);
    try testing.expectEqualStrings(local[0].model_alias, wire.model_alias);
    try testing.expectEqualStrings(@tagName(local[0].live), wire.live);
    try testing.expectEqualStrings(local[0].end.?.wireName(), wire.end.?);
    try testing.expectEqual(local[0].spend.turns, wire.turns);
    try testing.expectEqual(local[0].spend.input_tokens, wire.input_tokens);
    try testing.expectEqual(local[0].spend.output_tokens, wire.output_tokens);
    try testing.expectEqual(local[0].spend.enforceable(), wire.spend_enforceable);
    try testing.expectEqual(local[0].readable, wire.readable);
    try testing.expectEqual(local[0].complete, wire.complete);
    try testing.expectEqualStrings(@tagName(local[0].chain.verdict), wire.chain);
    try testing.expectEqual(local[0].chain.events, wire.chain_events);
    try testing.expectEqual(local[0].chain.chained, wire.chain_chained);
    try testing.expectEqual(local[0].has_work, wire.has_work);
    try testing.expectEqual(local[0].has_root, wire.has_root);

    try testing.expectEqualStrings("idle", wire.live);
    try testing.expectEqualStrings("finished", wire.end.?);
}

test "a listing of a project with no sessions is an empty answer and not a refusal" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", dir_buffer[0..dir_len]);

    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    var answer_buffer: [4096]u8 = undefined;
    const got = probeRequest(&daemon, arena_state.allocator(), &answer_buffer, "list /never/run/here");
    try testing.expectEqualStrings("", got.answer);

    const relative = probeRequest(&daemon, arena_state.allocator(), &answer_buffer, "list project");
    try testing.expect(std.mem.indexOf(u8, relative.answer, "absolute path") != null);
}

test "answering a session that is not listening is a refusal and never a silent yes" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", dir_buffer[0..dir_len]);

    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    const id = "01JQ" ++ @as([22]u8, @splat('A'));
    var answer_buffer: [4096]u8 = undefined;

    const got = probeRequest(
        &daemon,
        arena_state.allocator(),
        &answer_buffer,
        "answer /some/project\t" ++ id ++ "\t128\tyes",
    );
    try testing.expect(std.mem.startsWith(u8, got.answer, control.error_prefix));
    try testing.expect(std.mem.indexOf(u8, got.answer, "answered") == null);
    try testing.expect(std.mem.indexOf(u8, got.answer, control.ok_prefix) == null);

    const traversal = probeRequest(
        &daemon,
        arena_state.allocator(),
        &answer_buffer,
        "answer /some/project\t../../../etc\t1\tyes",
    );
    try testing.expect(std.mem.indexOf(u8, traversal.answer, "not a session identifier") != null);
}

test "read keeps its version 1 shape and can find a session after daemon restart" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var home_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const home_len = try tmp.dir.realPath(io, &home_buffer);
    const home = home_buffer[0..home_len];
    const project = try std.fs.path.join(arena, &.{ home, "project" });

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", home);

    var daemon = Daemon{ .gpa = gpa, .io = io, .exe_path = "/nowhere/chock", .env = &env };
    defer daemon.deinit();

    const id = "01JQ" ++ @as([22]u8, @splat('A'));
    var paths = try session_paths.pathsFor(gpa, &env, project, id);
    defer paths.deinit();
    try session_paths.create(io, paths);
    session_paths.markProject(io, paths, project);
    const file = try std.Io.Dir.createFileAbsolute(io, paths.log, .{});
    file.close(io);

    try testing.expectEqualStrings(paths.log, logPathAnywhere(&daemon, arena, id).?);

    var answer_buffer: [4096]u8 = undefined;
    const bad = probeRequest(
        &daemon,
        arena,
        &answer_buffer,
        "read ../../etc/passwd 0",
    );
    try testing.expect(std.mem.indexOf(u8, bad.answer, "not a session identifier") != null);
}

test "the sandbox block holds no pointer into the file it was read from" {
    const gpa = testing.allocator;

    const source = try gpa.dupeSentinel(u8,
        \\.{
        \\    .providers = .{ .anthropic = .{ .token = "sk-not-a-real-one" } },
        \\    .sandbox = .{ .driver = "microvm", .kernel = "/opt/chock/Image", .initrd = "/opt/chock/initrd" },
        \\}
    , 0);
    defer gpa.free(source);

    var block = try chock_policy.sandbox.parse(gpa, source, null);
    defer block.deinit(gpa);

    std.crypto.secureZero(u8, source);

    try testing.expectEqual(chock_policy.sandbox.Driver.microvm, block.chosen());
    try testing.expectEqualStrings("/opt/chock/Image", block.kernel.?);
    try testing.expectEqualStrings("/opt/chock/initrd", block.initrd.?);
}

test "a guest can only be reached through the fork" {
    try testing.expect(!@hasDecl(vmm, "host"));
    try testing.expect(@hasDecl(vmm, "forkHost"));
}

test "a guest's grant holds every directory its session offers" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    const state = try std.fs.path.join(arena, &.{ base, "state" });
    const data = try std.fs.path.join(arena, &.{ base, "data" });
    const project = try std.fs.path.join(arena, &.{ base, "project" });
    try session_paths.createDirAll(io, project);
    var project_dir = try std.Io.Dir.openDirAbsolute(io, project, .{});
    defer project_dir.close(io);
    try project_dir.writeFile(io, .{ .sub_path = "flake.nix", .data = "{}\n" });

    var env = std.process.Environ.Map.init(arena);
    try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
    try env.put("XDG_STATE_HOME", state);
    try env.put("XDG_DATA_HOME", data);
    try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

    var daemon: Daemon = .{ .gpa = gpa, .io = io, .exe_path = "chock", .env = &env };
    const id = session_paths.newId(io);

    const shares = guestShares(arena, &daemon, &id, project).?;

    try testing.expect(std.mem.indexOf(u8, said.err(), "chock cache clear") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), try session_paths.cacheDir(arena, &env, project)) != null);

    const paths = try session_paths.pathsFor(arena, &env, project, &id);
    const wanted = [_][]const u8{
        paths.work,
        project,
        try session_paths.cacheDir(arena, &env, project),
        try session_paths.scratchpadDir(arena, &env, &id),
        try session_paths.memoryDir(arena, &env, project),
        (try run_cmd.toolStagingDir(arena, try session_paths.scratchpadDir(arena, &env, &id))).?,
    };
    for (wanted) |one| {
        var held = false;
        for (shares) |share| {
            if (vmm.shareCovers(one, share.host_path)) held = true;
        }
        if (!held) {
            const message = try std.fmt.allocPrint(arena, "no share covers {s}\n", .{one});
            try testing.expectEqualStrings("", message);
        }
    }

    for (shares) |share| {
        try testing.expect(!std.mem.eql(u8, share.host_path, paths.dir));
    }

    try testing.expect(shares.len <= max_granted_roots);

    const dev_shell_staging = try session_paths.devShellStagingDir(arena, &env, project);
    for (shares) |share| {
        if (!vmm.shareCovers(dev_shell_staging, share.host_path)) continue;
        const message = try std.fmt.allocPrint(
            arena,
            "{s} is granted as {s}\n",
            .{ dev_shell_staging, share.name },
        );
        try testing.expectEqualStrings("", message);
    }
}

test "a project with no flake.nix is granted the directory its tool calls stage into" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    const project = try std.fs.path.join(arena, &.{ base, "project" });
    try session_paths.createDirAll(io, project);

    var env = std.process.Environ.Map.init(arena);
    try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
    try env.put("XDG_STATE_HOME", try std.fs.path.join(arena, &.{ base, "state" }));
    try env.put("XDG_DATA_HOME", try std.fs.path.join(arena, &.{ base, "data" }));
    try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

    var daemon: Daemon = .{ .gpa = gpa, .io = io, .exe_path = "chock", .env = &env };
    const id = session_paths.newId(io);

    const shares = guestShares(arena, &daemon, &id, project).?;

    const scratch = try session_paths.scratchpadDir(arena, &env, &id);
    const staging = (try run_cmd.toolStagingDir(arena, scratch)) orelse
        env.get("TMPDIR").?;

    for (shares) |share| {
        if (vmm.shareCovers(staging, share.host_path) and share.writable) return;
    }
    const message = try std.fmt.allocPrint(arena, "no writable share covers {s}\n", .{staging});
    try testing.expectEqualStrings("", message);
}

test "a project that holds Chock's own data directory is refused by name" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    var env = std.process.Environ.Map.init(arena);
    try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
    try env.put("XDG_STATE_HOME", try std.fs.path.join(arena, &.{ base, "state" }));
    try env.put("XDG_DATA_HOME", try std.fs.path.join(arena, &.{ base, "data" }));
    try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

    var daemon: Daemon = .{ .gpa = gpa, .io = io, .exe_path = "chock", .env = &env };
    const id = session_paths.newId(io);

    try testing.expectEqual(@as(?[]const vmm.Options.Share, null), guestShares(arena, &daemon, &id, base));

    try testing.expect(std.mem.indexOf(u8, said.err(), base) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "Name the project itself.") != null);
}

test "no session starts for a project that holds one of Chock's own directories" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    const each = [_][]const u8{ "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME" };
    for (each) |variable| {
        var env = std.process.Environ.Map.init(arena);
        try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
        try env.put("XDG_CONFIG_HOME", try std.fs.path.join(arena, &.{ base, "away", "config" }));
        try env.put("XDG_DATA_HOME", try std.fs.path.join(arena, &.{ base, "away", "data" }));
        try env.put("XDG_STATE_HOME", try std.fs.path.join(arena, &.{ base, "away", "state" }));
        try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

        const project = try std.fs.path.join(arena, &.{ base, "project" });
        try session_paths.createDirAll(io, project);
        try env.put(variable, try std.fs.path.join(arena, &.{ project, "inside" }));

        var daemon: Daemon = .{
            .gpa = gpa,
            .io = io,
            .exe_path = "/nonexistent/chock",
            .env = &env,
            .sandbox = .{ .driver = .microvm },
        };
        defer daemon.deinit();

        var buffer: [4096]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        beginSession(&daemon, &writer, project, session_paths.newId(io), .nothing);

        const answer = writer.buffered();
        if (!std.mem.startsWith(u8, answer, control.error_prefix)) {
            const message = try std.fmt.allocPrint(arena, "{s} inside the project was answered: {s}\n", .{ variable, answer });
            try testing.expectEqualStrings("", message);
        }
        const own = try std.fs.path.join(arena, &.{ project, "inside", "chock" });
        try testing.expect(std.mem.indexOf(u8, answer, own) != null);
        try testing.expect(std.mem.indexOf(u8, answer, project) != null);
        try testing.expectEqual(@as(usize, 0), daemon.sessions.items.len);
    }
}

test "a root that holds one already granted is kept, in whichever order the two arrive" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    const outer = try std.fs.path.join(arena, &.{ base, "outer" });
    const inner = try std.fs.path.join(arena, &.{ base, "outer", "inner" });
    try session_paths.createDirAll(io, inner);

    var broad_first: std.ArrayList(vmm.Options.Share) = .empty;
    try grant(arena, &broad_first, io, outer, false);
    try grant(arena, &broad_first, io, inner, false);
    try testing.expectEqual(@as(usize, 1), broad_first.items.len);
    try testing.expectEqualStrings(outer, broad_first.items[0].host_path);

    var narrow_first: std.ArrayList(vmm.Options.Share) = .empty;
    try grant(arena, &narrow_first, io, inner, false);
    try grant(arena, &narrow_first, io, outer, false);
    var holds_outer = false;
    for (narrow_first.items) |share| {
        if (std.mem.eql(u8, share.host_path, outer)) holds_outer = true;
    }
    try testing.expect(holds_outer);

    var widening: std.ArrayList(vmm.Options.Share) = .empty;
    try grant(arena, &widening, io, outer, false);
    try grant(arena, &widening, io, inner, true);
    try testing.expectEqual(@as(usize, 2), widening.items.len);
}

test "a session is granted nothing it never asks for" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var temp = testing.tmpDir(.{});
    defer temp.cleanup();
    var where: [std.fs.max_path_bytes]u8 = undefined;
    const length = try temp.dir.realPath(io, &where);
    const base = where[0..length];

    const project = try std.fs.path.join(arena, &.{ base, "project" });
    try session_paths.createDirAll(io, project);

    var env = std.process.Environ.Map.init(arena);
    try env.put("HOME", try std.fs.path.join(arena, &.{ base, "home" }));
    try env.put("XDG_STATE_HOME", try std.fs.path.join(arena, &.{ base, "state" }));
    try env.put("XDG_DATA_HOME", try std.fs.path.join(arena, &.{ base, "data" }));
    try env.put("TMPDIR", try std.fs.path.join(arena, &.{ base, "tmp" }));

    try session_paths.createDirAll(io, try session_paths.imagesDir(arena, &env));

    var daemon: Daemon = .{ .gpa = gpa, .io = io, .exe_path = "chock", .env = &env };
    const id = session_paths.newId(io);

    const shares = guestShares(arena, &daemon, &id, project).?;

    const unwanted = [_][]const u8{
        try session_paths.imagesDir(arena, &env),
        try session_paths.devShellStagingDir(arena, &env, project),
    };
    for (unwanted) |one| {
        for (shares) |share| {
            if (!vmm.shareCovers(one, share.host_path)) continue;
            const message = try std.fmt.allocPrint(arena, "{s} is granted as {s}\n", .{ one, share.name });
            try testing.expectEqualStrings("", message);
        }
    }
}
