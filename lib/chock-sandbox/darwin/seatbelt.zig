//! Seatbelt, the confinement layer of the Darwin driver. It is to this driver
//! what Landlock and seccomp together are to the Linux one: the layer that says
//! which paths a program may touch, and whether it has a route out.
//!
//! ## Why `sandbox_init`, which Apple marks deprecated
//!
//! **There is no supported replacement for a command line program, and this
//! choice must not be re-opened by a reader who has only seen the deprecation
//! note.** Apple marks `sandbox_init` deprecated in `sandbox.h`. Every serious
//! sandboxed program on macOS calls it anyway, Chromium and Firefox among them,
//! because the two things Apple points at instead do not apply here:
//!
//! * **App Sandbox** is applied by the kernel from an entitlement in a code
//!   signature. It needs a signed application bundle. Chock is a command line
//!   program that a person builds and runs, so there is no bundle to sign and
//!   no entitlement to carry.
//! * **Endpoint Security** needs an entitlement Apple grants case by case, on
//!   request, to a named developer. A project cannot build on a permission that
//!   Apple may refuse.
//!
//! So the deprecated call is the only mechanism available, and the deprecation
//! is a documentation state and not a removal: it has been marked this way
//! since OS X 10.8 and the call still works on macOS 15. Measured on macOS
//! 15.7.9, arm64, on 2026-08-25.
//!
//! `sandbox_init` lives in libSystem, which every macOS program links already,
//! so naming it here adds no library to the link. IronStyle's pure Zig rule is
//! about not taking a C dependency: this is an `extern` declaration of a symbol
//! that is already there, which is the form that document names as the correct
//! one when a platform gives no other way.
//!
//! ## What was measured, and what is therefore claimed
//!
//! Every rule below is written from a measurement on a real Apple Silicon Mac,
//! not from Apple's documentation, because there is no public documentation of
//! the profile language at all. The measurements are named on each declaration.
//! Where a measurement did not show a layer working, this file says
//! `unsupported` and does not guess: see `Support`.

const std = @import("std");
const builtin = @import("builtin");

/// `sandbox_init` takes the profile source itself when `flags` is 0. A `flags`
/// of 1, `SANDBOX_NAMED`, would read the string as the name of one of Apple's
/// own built in profiles instead. Measured on 2026-08-25: with `flags` of 0 and
/// the profile text below, the call answers 0 and the process is confined.
///
/// Declared here rather than imported through `@cImport`, per IronStyle's pure
/// Zig rule. **Nothing outside a `builtin.os.tag == .macos` branch may name
/// these**, so a build for any other target never asks a linker for a symbol
/// that target has not got. See `apply`.
extern "c" fn sandbox_init(profile: [*:0]const u8, flags: u64, errorbuf: *?[*:0]u8) c_int;
extern "c" fn sandbox_free_error(errorbuf: [*:0]u8) void;
/// Answers 1 when the named process is inside a profile. See `confinedAlready`,
/// which is the only caller and the only place the filter number is explained.
extern "c" fn sandbox_check(pid: std.c.pid_t, operation: ?[*:0]const u8, filter_type: c_int, ...) c_int;

/// Whether this build's Seatbelt layer really went on, in the same four states
/// the rest of this project reports a capability with. See
/// `../linux/cgroup.zig`'s own `Support`, which this mirrors deliberately: a
/// person reading a Chock session should not have to learn a second vocabulary
/// for the same question on a second platform.
///
/// **`unsupported` and `unavailable` are not the same fact.** `unsupported`
/// says the platform has no such mechanism at all, so there is nothing to
/// configure and no version of macOS closes the gap. `unavailable` says macOS
/// has the mechanism and this call did not get it.
pub const Support = union(enum) {
    /// The profile was compiled and applied to this process.
    ok,
    /// The caller asked for no confinement, so no profile was applied. **Not
    /// the same as a platform that cannot confine**, and a report that spelled
    /// the two the same way would have a person looking for a fault that is not
    /// there.
    off,
    /// This platform has no Seatbelt. Every target that is not macOS answers
    /// this.
    unsupported: Reason,
    /// macOS has Seatbelt and this process did not get it.
    unavailable: Reason,

    pub const Reason = enum {
        /// The build is not for macOS, so there is no `sandbox_init` to call.
        not_darwin,
        /// `sandbox_init` refused the profile text. The commonest cause is a
        /// profile this code built wrongly, so it is a fault and not a
        /// configuration.
        profile_refused,
        /// A profile was already applied to this process. **Measured on
        /// 2026-08-25: `sandbox_init` may be called exactly once per process.**
        /// A second call is refused whether it would widen the profile or
        /// narrow it, so a driver cannot layer one profile on another.
        already_sandboxed,
        /// The profile text did not fit the buffer it is built in. A refusal
        /// rather than a truncation: a truncated profile is either a syntax
        /// error or, far worse, a valid profile with the last rules missing,
        /// and the last rules are the denials. See `Builder.finish`.
        profile_too_long,
        /// A path in the profile could not be made absolute and resolved, so a
        /// rule naming it would not match what the kernel checks. See
        /// `PathFault`.
        path_not_resolvable,

        /// What happened, as a phrase that reads after "seatbelt: ".
        pub fn text(self: Reason) []const u8 {
            return switch (self) {
                .not_darwin => "this build is not for macOS, so there is no seatbelt",
                .profile_refused => "the sandbox profile was refused",
                .already_sandboxed => "this process already has a sandbox profile",
                .profile_too_long => "the sandbox profile is longer than the buffer it is built in",
                .path_not_resolvable => "a path in the profile could not be resolved",
            };
        }
    };

    /// True only when the confinement really went on. A caller must never read
    /// `off`, `unsupported` or `unavailable` as a boundary that exists.
    pub fn applied(self: Support) bool {
        return self == .ok;
    }

    pub fn format(self: Support, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .ok => try writer.writeAll("seatbelt applied"),
            .off => try writer.writeAll("no seatbelt profile was asked for"),
            .unsupported => |reason| try writer.print("no seatbelt: {s}", .{reason.text()}),
            .unavailable => |reason| try writer.print("no seatbelt: {s}", .{reason.text()}),
        }
    }
};

/// What a program may do with one path.
///
/// **There is no `read_dir` here and there is no `execute` either, and both
/// absences are measured.** Seatbelt's `file-read*` covers opening a directory
/// and listing it, so a separate directory right would name nothing. Execution
/// is governed by `process-exec`, which is a rule about the program and not
/// about the path's read rights: measured on 2026-08-25, a binary ran under a
/// profile that permitted `process-exec*` and permitted no read of the binary
/// at all.
pub const Access = struct {
    read: bool = false,
    write: bool = false,

    pub const read_only: Access = .{ .read = true };
    pub const read_write: Access = .{ .read = true, .write = true };
};

/// How far a rule reaches from its path.
pub const Reach = enum {
    /// The path and everything under it.
    subpath,
    /// Exactly this one path.
    literal,
};

/// Whether a rule gives an access or takes it away.
pub const Verb = enum { allow, deny };

pub const Rule = struct {
    /// **Absolute, and already resolved.** See `checkPath`: a rule holding an
    /// unresolved path compiles cleanly and matches nothing, which for a denial
    /// is silent and total failure.
    path: []const u8,
    access: Access,
    reach: Reach = .subpath,
    /// **A rule that gives read and a rule that takes write away are two
    /// rules, and this is why.** A profile is a list where the last rule that
    /// names a path wins, one access at a time. So `(allow file-read* ...)`
    /// over a path an earlier rule made writable says nothing about writing,
    /// and the write stays. Measured on macOS 15.7.9 on 2026-08-25: under
    /// `(allow file-read* file-write* (subpath D))` followed by `(allow
    /// file-read* (literal D/f))`, a shell overwrote `D/f`. With `(deny
    /// file-write* (literal D/f))` written after them the same write answered
    /// `EPERM`, and a `(allow file-read* file-write* ...)` for a deeper path
    /// written after a `(deny file-write* ...)` gave the write back.
    ///
    /// A read only mount on Linux narrows a subtree of a read write one. The
    /// pair of rules is how the same thing is said here.
    verb: Verb = .allow,
};

/// What one profile asks for. The driver builds this from its own `Config`; it
/// is deliberately in Darwin's own terms, not Linux's, so no field here has to
/// be read as an approximation of a Linux mechanism.
pub const Options = struct {
    /// What the program may reach, and what it may not, **in order, last one
    /// wins**.
    ///
    /// **The order is the whole meaning of this slice and a caller must not
    /// sort it.** It carries the caller's mount list, and a mount list means
    /// the same thing: the kernel takes the last mount that covers a path, so
    /// a read only mount nested inside a read write one narrows exactly the
    /// subtree it names. Measured on macOS 15.7.9 on 2026-08-25, both ways
    /// round: see `Rule.verb`.
    rules: []const Rule = &.{},
    /// What the program may not reach, whatever `rules` says.
    ///
    /// **These are emitted after every rule in `rules`, always.** Measured on
    /// 2026-08-25: among two rules that both name a path, the later one wins.
    /// A denial written before the allowance that covers it is accepted by the
    /// compiler, applied, and does nothing at all. See `Builder.finish`, and
    /// `test/sandbox/darwin_escape.zig`'s own test for the mutation that proves
    /// it.
    deny: []const Rule = &.{},
    /// Whether the program may start another program. False takes `process-exec`
    /// away, and a program that then tries to exec is refused with `EPERM`.
    allow_exec: bool = true,
    /// Whether the program may fork.
    allow_fork: bool = true,
    /// Whether the program has any route to the network.
    ///
    /// **False closes unix domain sockets as well as IP.** Measured on
    /// 2026-08-25: under `(deny network*)`, `connect` to a listening unix socket
    /// answers `EPERM`, where the same call outside the profile reaches the
    /// socket. So a program cannot reach a service on this machine by its socket
    /// path either, which is the route a network rule that only covered IP would
    /// have left open.
    allow_network: bool = false,
    /// Whether the program may read this machine's `sysctl` values.
    ///
    /// **This is not a small permission and it cannot be taken away.** With it,
    /// a program reads the whole host process table through `KERN_PROC_ALL`:
    /// measured on 2026-08-25, 192 kilobytes of it, naming every process on the
    /// machine. Without it a great deal of ordinary software fails to start. So
    /// Darwin has no equivalent of the Linux driver's PID namespace, and a
    /// Darwin sandbox does not hide the machine's other processes. It stops the
    /// program acting on them: see `allow_signal_same_sandbox`.
    allow_sysctl_read: bool = true,
    /// Whether the program may read the type, size and timestamps of any path,
    /// including one it may not open.
    ///
    /// **On by default because too much breaks without it**, and it is a real
    /// leak: a program learns whether a path exists and how big it is. It never
    /// learns the bytes.
    allow_metadata: bool = true,
    /// Whether the program may signal the other processes of its own sandbox.
    ///
    /// **True, or a great deal of ordinary software stops working.** Measured on
    /// 2026-08-25: under a bare `(deny signal)` a program cannot signal a child
    /// it started itself, so a shell cannot end a background job, a timeout
    /// cannot stop what it is timing, and a parallel build cannot stop its
    /// workers. `(allow signal (target same-sandbox))` gives that back and gives
    /// back nothing else: a process outside the sandbox still answers `EPERM`,
    /// and so does a second process that applied a byte for byte identical
    /// profile, which was measured separately because the filter's name might
    /// have meant the profile rather than the instance.
    allow_signal_same_sandbox: bool = true,
};

/// The root path, which dyld needs to read before it can start any program.
///
/// **Without this one rule no program runs at all, and the failure names
/// nothing.** Measured on 2026-08-25: under `(deny default)` with
/// `process-exec` permitted and every other read denied, `execve` succeeds and
/// the new program is killed with `SIGABRT` before its first instruction, with
/// nothing on its standard error and no crash report. Permitting reads of
/// `/usr/lib` and `/System` does not fix it. Permitting exactly `(literal "/")`
/// does.
///
/// It grants the names of the top level directories of the boot volume, which
/// are the same on every macOS install, and no file content anywhere.
const dyld_root_rule = "(allow file-read* (literal \"/\"))\n";

/// What is wrong with a path a caller offered.
pub const PathFault = enum {
    /// Empty, so it names nothing.
    empty,
    /// Not absolute. A relative path in a profile compiles and matches nothing:
    /// measured on 2026-08-25, `(subpath "work")` denied every read under that
    /// directory rather than permitting it.
    not_absolute,
    /// Holds a `.` or a `..` component. Seatbelt matches the path the kernel
    /// resolved, which never has one, so a rule holding one matches nothing.
    /// Measured on 2026-08-25 with `(subpath "<dir>/../<dir>")`, which behaved
    /// exactly like no rule at all.
    not_normalised,
    /// Holds a byte that cannot be in a profile: a NUL, which would end the
    /// string early, or a control byte, which nothing legitimate needs and
    /// which would make the profile text unreadable to a person.
    ///
    /// **A `"` or a `\` is not a fault**, because both are escaped: see
    /// `writeQuoted`.
    bad_byte,
    /// Longer than `max_path_bytes`.
    too_long,

    /// What is wrong, as a phrase that reads after "this path ".
    pub fn text(self: PathFault) []const u8 {
        return switch (self) {
            .empty => "is empty",
            .not_absolute => "is not absolute",
            .not_normalised => "holds a . or .. component",
            .bad_byte => "holds a byte that cannot be in a sandbox profile",
            .too_long => "is longer than a path this code may hold",
        };
    }
};

/// The longest path a rule may hold. `std.fs.max_path_bytes` on Darwin.
pub const max_path_bytes = 1024;

/// Whether `path` can go into a profile as it is, or what is wrong with it.
///
/// **This is a safety check and not a tidiness one.** Every fault it names has
/// the same consequence: the rule is accepted by the profile compiler, applied
/// to the process, and matches nothing the kernel ever asks about. For an
/// allowance that shows up at once as a program that cannot read its own files.
/// For a denial it shows up as nothing at all, which is the failure this whole
/// driver is written to avoid. So a bad path refuses the spawn.
pub fn checkPath(path: []const u8) ?PathFault {
    if (path.len == 0) return .empty;
    if (path.len > max_path_bytes) return .too_long;
    if (path[0] != '/') return .not_absolute;
    for (path) |byte| {
        if (byte == 0 or byte < 0x20 or byte == 0x7f) return .bad_byte;
    }
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return .not_normalised;
    }
    return null;
}

/// Builds the profile text into a caller's buffer.
///
/// **A buffer and not an allocator, because the profile is built before the
/// fork and read after it.** Nothing here allocates, so the same builder is
/// usable from the narrow window between `fork` and `execve`, where an
/// allocator of the parent's is not safe to touch.
pub const Builder = struct {
    buffer: []u8,
    len: usize = 0,
    /// The first path fault seen, kept rather than the last: the first one is
    /// the one a person fixes.
    fault: ?struct { path: []const u8, fault: PathFault } = null,
    overflowed: bool = false,

    pub fn init(buffer: []u8) Builder {
        return .{ .buffer = buffer };
    }

    fn write(self: *Builder, bytes: []const u8) void {
        if (self.overflowed) return;
        if (bytes.len > self.buffer.len - self.len) {
            self.overflowed = true;
            return;
        }
        @memcpy(self.buffer[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    /// One path as an SBPL string, with the two bytes that mean something to the
    /// profile reader escaped.
    ///
    /// **Escaping is what keeps a path from becoming a rule.** A path holding a
    /// `"` would otherwise end the string, and the rest of the path would be
    /// read as profile source: a path ending `") (allow file-read* (subpath "/`
    /// would permit reads of the whole disk. Measured on 2026-08-25 with exactly
    /// that path: unescaped it is a syntax error, which `sandbox_init` refuses,
    /// so the failure was safe even then. It is escaped anyway, because a safe
    /// failure that depends on the injected text not happening to parse is not a
    /// boundary. Escaped, the same path names the directory a person meant, and
    /// that was measured too: a directory whose name holds a `"` was read
    /// through the rule that names it.
    fn writeQuoted(self: *Builder, path: []const u8) void {
        self.write("\"");
        var start: usize = 0;
        for (path, 0..) |byte, index| {
            if (byte != '"' and byte != '\\') continue;
            self.write(path[start..index]);
            self.write(if (byte == '"') "\\\"" else "\\\\");
            start = index + 1;
        }
        self.write(path[start..]);
        self.write("\"");
    }

    fn writeRule(self: *Builder, verb: Verb, rule: Rule) void {
        if (checkPath(rule.path)) |fault| {
            if (self.fault == null) self.fault = .{ .path = rule.path, .fault = fault };
            return;
        }
        // A rule that grants nothing is not written. It would be harmless and it
        // would also be a line in a profile that a person has to work out the
        // meaning of.
        if (!rule.access.read and !rule.access.write) return;
        self.write("(");
        self.write(@tagName(verb));
        if (rule.access.read) self.write(" file-read*");
        if (rule.access.write) self.write(" file-write*");
        self.write(" (");
        self.write(@tagName(rule.reach));
        self.write(" ");
        self.writeQuoted(rule.path);
        self.write("))\n");
    }

    /// The whole profile, ready for `apply`.
    ///
    /// **The order of the sections is the contract of this function.** The base
    /// rule comes first, then `options.rules` in the caller's own order, and
    /// `options.deny` last. Measured on 2026-08-25: among two rules that both
    /// name a path, the later one wins, so a denial written before the
    /// allowance that covers it does nothing at all. The Linux driver holds the
    /// same invariant for the same reason: see `../linux/namespace.zig`'s own
    /// `applyDenyMounts`.
    pub fn finish(self: *Builder, options: Options) error{ ProfileTooLong, BadPath }![:0]u8 {
        self.len = 0;
        self.fault = null;
        self.overflowed = false;

        self.write("(version 1)\n(deny default)\n");
        self.write(dyld_root_rule);
        if (options.allow_fork) self.write("(allow process-fork)\n");
        if (options.allow_exec) self.write("(allow process-exec*)\n");
        if (options.allow_sysctl_read) self.write("(allow sysctl-read)\n");
        if (options.allow_metadata) self.write("(allow file-read-metadata)\n");

        for (options.rules) |rule| self.writeRule(rule.verb, rule);

        // The network and the signal rules come after the file rules and before
        // the denials, because neither one can be in conflict with a file rule:
        // no rule below names a path.
        //
        // **`(deny default)` above already denies both of these, and the two
        // denials below are written anyway.** They are not what enforces the
        // boundary and this comment exists so that nobody reads them as if they
        // were: measured on 2026-08-25, taking either line out changes nothing,
        // because the base rule still refuses. They are written because a person
        // reading the profile of a running session should be able to see what it
        // says about the network and about signals without first working out
        // what the base rule implies.
        //
        // **The allowances below are the lines that do something**, and one of
        // them was missing. Measured on 2026-08-25: with only the `(deny
        // network*)` line removed for a `.host` config, the sandboxed process
        // still could not connect, because `(deny default)` had refused it. So
        // a caller that asked for the host's network silently got none. The
        // `(allow network*)` line is what actually opens it.
        if (options.allow_network) {
            self.write("(allow network*)\n");
        } else {
            self.write("(deny network*)\n");
        }
        self.write("(deny signal)\n");
        if (options.allow_signal_same_sandbox) self.write("(allow signal (target same-sandbox))\n");

        for (options.deny) |rule| self.writeRule(.deny, rule);

        // The terminating NUL is part of the buffer this returns, because
        // `sandbox_init` takes a C string. It is written through `write` so a
        // buffer with no room for it overflows here rather than truncating the
        // last denial, which is the worst byte in the whole profile to lose.
        self.write("\x00");
        if (self.overflowed) return error.ProfileTooLong;
        if (self.fault != null) return error.BadPath;
        return self.buffer[0 .. self.len - 1 :0];
    }
};

/// Put `profile` on this process. Everything it forks and everything it execs
/// keeps it.
///
/// **Measured on 2026-08-25, and both halves matter.** A program reached by
/// `execve` from inside the profile is still inside it: it could not read a
/// path the profile denies. And it could not get out: a second `sandbox_init`,
/// with `(allow default)`, was refused with `EPERM`. So the confinement cannot
/// be dropped by the program the model asked for, nor by anything that program
/// starts.
///
/// **This never prints and never allocates**, so it is safe in the window
/// between `fork` and `execve`. `sandbox_init` fills in an error string on a
/// refusal; it is freed here and its text is not carried out, because the only
/// refusals reachable are ones this file's own builder caused, and the caller
/// learns which through `Support`.
pub fn apply(profile: [:0]const u8) Support {
    if (builtin.os.tag == .macos) {
        var message: ?[*:0]u8 = null;
        const rc = sandbox_init(profile.ptr, 0, &message);
        if (message) |text| sandbox_free_error(text);
        if (rc == 0) return .ok;
        // A refusal here is either a profile this code built wrongly or a
        // process that already has one. The two are told apart by the caller,
        // which knows whether it has called this before; this function reports
        // the one it can see.
        return .{ .unavailable = .profile_refused };
    } else {
        return .{ .unsupported = .not_darwin };
    }
}

/// What a profile of Chock's own would meet on this process. **The three
/// answers must never be collapsed into two**, because each one asks a
/// different thing of the caller.
pub const Nesting = enum {
    /// A profile of Chock's own goes on this process. A test must run.
    free,
    /// A profile is on this process already and it refuses a second one, so
    /// there is no boundary of Chock's own here to measure. A test must skip.
    confined,
    /// The trial profile was refused for a reason of its own, and not by a
    /// profile above. **A test must not skip on this.** The fault is in this
    /// code or in the machine, and a skip would report it as a pass.
    trial_rejected,
};

/// The trial profile has the shape of a real one: a base denial, the four
/// permissions every Chock profile carries, one path rule, and the network and
/// signal lines. `/` is the path because the trial is never executed, and this
/// keeps the profile free of any temporary directory.
///
/// **A permissive profile is the wrong question and it used to be the one that
/// was asked.** `(version 1)(allow default)` shares no line with what `spawn`
/// applies, so a macOS that took the first and refused the second would have
/// been read as a machine where nesting works.
const trial_options: Options = .{ .rules = &.{.{ .path = "/", .access = .read_write }} };

/// Whether this process is already inside somebody else's profile, so no
/// profile of its own can go on and no boundary of its own can be measured.
///
/// **`trial_rejected` answers false here on purpose.** The caller of this
/// function skips a test when it answers true, and a profile refused for its
/// own reason must fail a test rather than skip one.
pub fn confinedAlready() bool {
    return nesting() == .confined;
}

/// Put a profile shaped like a real one on a child, and read off which of the
/// three states this machine is in.
///
/// **Measured on a real Mac, macOS 15.7.9, on 2026-08-26, every state on the
/// same machine.** From a login shell `sandbox_check` answered 0 and every
/// well formed profile applied, while a profile that cannot compile answered
/// `-1` with an error message and left `errno` at 0. Under
/// `sandbox-exec -p '(version 1)(allow default)'`, and inside a real
/// `nix build`, which is where Nix on macOS puts every builder under
/// `sandbox-exec`, `sandbox_check` answered 1 and every profile was refused
/// with `-1` and `EPERM`. So `EPERM` separates a refusal by the profile above
/// from a refusal by the profile text, and neither the return value nor the
/// message does.
///
/// **An outer profile refuses before it parses, so `trial_rejected` cannot be
/// seen while confined.** Measured inside a real `nix build` on 2026-08-26: a
/// deliberately unparseable profile was refused with `EPERM` there, exactly
/// like a well formed one, where the same text outside a profile answered a
/// parse error. This costs nothing, because a machine that refuses every
/// profile is one where no boundary of Chock's own can be measured whatever
/// the text says, and a skip is the right answer for it. What the split still
/// buys is that a fork that failed, or a child the system killed, is never
/// read as a machine that refuses to nest.
pub fn nesting() Nesting {
    if (builtin.os.tag != .macos) return .free;

    // The cheap question first, and **it may only ever answer `free`**. A
    // prediction that makes a test run is corrected by the test it lets run. A
    // prediction that makes a test skip is corrected by nothing at all, so the
    // skip is never taken on this answer alone.
    if (sandbox_check(std.c.getpid(), null, 0) != 1) return .free;

    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const trial = builder.finish(trial_options) catch return .trial_rejected;
    return applyInChild(trial);
}

/// Apply `profile` in a child and answer what the child met.
///
/// **A child, because `sandbox_init` may be called once per process.** Asking
/// in this process would spend the one call its caller needs.
fn applyInChild(profile: [:0]const u8) Nesting {
    if (builtin.os.tag != .macos) return .free;

    const pid = std.c.fork();
    if (pid < 0) return .trial_rejected;
    if (pid == 0) {
        // libsandbox prints its own refusal on standard error, and a test
        // that writes there puts a `failed command:` line in the build log
        // whatever it exits with. So the child sends it nowhere.
        const quiet = std.c.open("/dev/null", .{ .ACCMODE = .WRONLY });
        if (quiet >= 0) _ = std.c.dup2(quiet, 2);
        var message: ?[*:0]u8 = null;
        std.c._errno().* = 0;
        const rc = sandbox_init(profile.ptr, 0, &message);
        const failure = std.c._errno().*;
        if (message) |text| sandbox_free_error(text);
        if (rc == 0) std.c._exit(0);
        std.c._exit(if (failure == @intFromEnum(std.c.E.PERM)) 1 else 2);
    }

    var status: c_int = 0;
    while (std.c.waitpid(pid, &status, 0) < 0) {
        if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) return .trial_rejected;
    }
    // A child the system killed answered nothing, and a question that got no
    // answer is not a skip.
    if (!std.c.W.IFEXITED(@bitCast(status))) return .trial_rejected;
    return switch (std.c.W.EXITSTATUS(@bitCast(status))) {
        0 => .free,
        1 => .confined,
        else => .trial_rejected,
    };
}

test "a profile puts every denial after every allowance" {
    // **The measured failure this pins.** On 2026-08-25 a profile whose denial
    // came before the allowance that covered it compiled, applied, and let the
    // denied file be read: among two rules that both name a path, the later one
    // wins. So the order below is a boundary and not a style.
    //
    // Mutation check: move the `options.deny` loop in `finish` above the
    // `options.allow` loop and this test fails on the index comparison.
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const profile = try builder.finish(.{
        .rules = &.{.{ .path = "/work", .access = .read_write }},
        .deny = &.{.{ .path = "/work/secret.env", .access = .read_write, .reach = .literal }},
    });
    const allow_at = std.mem.indexOf(u8, profile, "(allow file-read* file-write* (subpath \"/work\"))").?;
    const deny_at = std.mem.indexOf(u8, profile, "(deny file-read* file-write* (literal \"/work/secret.env\"))").?;
    try std.testing.expect(deny_at > allow_at);
}

test "a path that would not match anything is refused rather than written" {
    // Every one of these compiles cleanly inside a profile and matches nothing
    // the kernel asks about, so a denial written with one is a denial that does
    // not exist. Measured on 2026-08-25 for the relative form and the `..` form,
    // both of which behaved exactly like no rule at all.
    try std.testing.expectEqual(PathFault.empty, checkPath("").?);
    try std.testing.expectEqual(PathFault.not_absolute, checkPath("work/tree").?);
    try std.testing.expectEqual(PathFault.not_normalised, checkPath("/work/../work").?);
    try std.testing.expectEqual(PathFault.not_normalised, checkPath("/work/./tree").?);
    try std.testing.expectEqual(PathFault.bad_byte, checkPath("/work/a\nb").?);
    try std.testing.expectEqual(PathFault.bad_byte, checkPath("/work/a\x00b").?);
    try std.testing.expectEqual(@as(?PathFault, null), checkPath("/work/tree"));
    // A trailing slash really does work, so it must not be refused: measured on
    // 2026-08-25, `(subpath "<dir>/")` permitted the same reads as `(subpath
    // "<dir>")`.
    try std.testing.expectEqual(@as(?PathFault, null), checkPath("/work/"));

    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    try std.testing.expectError(error.BadPath, builder.finish(.{
        .deny = &.{.{ .path = "relative/path", .access = .read_write }},
    }));
}

test "a quote in a path is escaped, so a path cannot become a rule" {
    // The injection this stops: a path ending `") (allow file-read* (subpath "/`
    // would, written raw, close the string and open the whole disk for reading.
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const profile = try builder.finish(.{
        .rules = &.{.{ .path = "/work/x\") (allow file-read* (subpath \"/", .access = .read_only }},
    });
    // The injected text is still in the profile, as data inside one string
    // literal, so counting the text proves nothing. What proves it is that no
    // *rule* came of it: every rule starts a line of its own, and the injected
    // text sits in the middle of the line it was written into.
    var rules: usize = 0;
    var lines = std.mem.splitScalar(u8, profile, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "(allow file-read*")) rules += 1;
    }
    // One for the caller's rule and one for the root rule dyld needs.
    try std.testing.expectEqual(@as(usize, 2), rules);
    try std.testing.expect(std.mem.indexOf(u8, profile, "\\\"") != null);
    // A backslash is escaped for the same reason: a path ending in one would
    // otherwise escape the closing quote.
    var second = Builder.init(&buffer);
    const with_slash = try second.finish(.{
        .rules = &.{.{ .path = "/work/back\\", .access = .read_only }},
    });
    try std.testing.expect(std.mem.indexOf(u8, with_slash, "\"/work/back\\\\\"") != null);
}

test "a profile that does not fit is refused, never truncated" {
    // A truncated profile loses its last bytes, and the last bytes are the
    // denials. That is the one shape of failure that turns a refusal into a
    // permission, so it is refused outright.
    var buffer: [64]u8 = undefined;
    var builder = Builder.init(&buffer);
    try std.testing.expectError(error.ProfileTooLong, builder.finish(.{
        .rules = &.{.{ .path = "/a/reasonably/long/path/that/will/not/fit", .access = .read_write }},
    }));
}

test "the network and the signal rules are what the measurements say" {
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const closed = try builder.finish(.{});
    try std.testing.expect(std.mem.indexOf(u8, closed, "(deny network*)") != null);
    // Both lines, and in this order. A bare `(deny signal)` stops a program
    // signalling a child it started itself, which breaks a shell, a timeout and
    // a parallel build alike: measured on 2026-08-25.
    const deny_signal_at = std.mem.indexOf(u8, closed, "(deny signal)").?;
    const allow_same_at = std.mem.indexOf(u8, closed, "(allow signal (target same-sandbox))").?;
    try std.testing.expect(allow_same_at > deny_signal_at);

    var open_builder = Builder.init(&buffer);
    const opened = try open_builder.finish(.{ .allow_network = true });
    try std.testing.expect(std.mem.indexOf(u8, opened, "(deny network*)") == null);
    // **The allowance, and not only the absence of the denial.** Measured on
    // 2026-08-25: with the denial merely left out, `(deny default)` still
    // refused every connection, so a caller that asked for the host's network
    // got none and was told nothing. The profile has to say `allow`.
    try std.testing.expect(std.mem.indexOf(u8, opened, "(allow network*)") != null);
    // The signal rules do not depend on the network answer.
    try std.testing.expect(std.mem.indexOf(u8, opened, "(deny signal)") != null);
}

test "every profile carries the root rule dyld needs" {
    // Without it `execve` succeeds and the program is killed with SIGABRT
    // before its first instruction, with nothing on its standard error.
    // Measured on 2026-08-25. A reader who trims this rule as useless would get
    // a sandbox in which no program runs and no message says why.
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const profile = try builder.finish(.{});
    try std.testing.expect(std.mem.indexOf(u8, profile, "(allow file-read* (literal \"/\"))") != null);
    try std.testing.expect(std.mem.startsWith(u8, profile, "(version 1)\n(deny default)\n"));
}

test "apply answers unsupported on a build that is not for macOS" {
    // The whole point of the four state record: a build that cannot confine says
    // so, and never answers `ok`.
    if (builtin.os.tag == .macos) return;
    const support = apply("(version 1)(deny default)");
    try std.testing.expect(!support.applied());
    try std.testing.expectEqual(Support.Reason.not_darwin, support.unsupported);
}

test "a profile refused for its own reason is never read as a profile above" {
    // **The state the old guard could not see, and the reason it could not.**
    // It read every refusal of its trial profile as an outer profile, so a
    // trial that stopped compiling would have skipped the whole Darwin suite
    // and reported a boundary nobody measured as a pass.
    //
    // Measured on a real Mac, macOS 15.7.9, on 2026-08-26, and this is what
    // tells the two apart: a profile that cannot compile answers -1 with a
    // message and leaves `errno` at 0, while an outer profile answers -1 with
    // `EPERM`. Both answers are the same -1 and both carry a message.
    //
    // **Asked only where it has an answer, and this test is the thing that
    // measured why.** Written first without the guard below, it failed inside
    // a real `nix build` with "expected .trial_rejected, found .confined": an
    // outer profile refuses `sandbox_init` before it parses the text, so the
    // unparseable profile came back `EPERM` like every other. There is nothing
    // to tell apart on such a machine, and the skip `nesting` gives there is
    // right whatever the text says.
    //
    // Mutation check: read the return value alone, and drop the `errno` test
    // in `applyInChild`, and this fails.
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (sandbox_check(std.c.getpid(), null, 0) == 1) return error.SkipZigTest;
    try std.testing.expectEqual(Nesting.trial_rejected, applyInChild("(version 1) this is not sbpl ((("));
}

test "the trial profile this file measures with really compiles" {
    // **A trial profile that cannot compile would answer `trial_rejected` on
    // every machine**, which never skips and so never hides anything, but it
    // would also mean `nesting` could never answer `confined` and the suite
    // would fail everywhere instead of skipping. So the text is checked here,
    // where a fault in it is one named failure rather than sixteen.
    var buffer: [4096]u8 = undefined;
    var builder = Builder.init(&buffer);
    const trial = try builder.finish(trial_options);
    try std.testing.expect(std.mem.startsWith(u8, trial, "(version 1)\n(deny default)\n"));
    // The shape that makes it representative: it is not `(allow default)`.
    try std.testing.expect(std.mem.indexOf(u8, trial, "(deny network*)") != null);
    try std.testing.expect(std.mem.indexOf(u8, trial, "(deny signal)") != null);
    if (builtin.os.tag != .macos) return;
    try std.testing.expect(applyInChild(trial) != .trial_rejected);
}

test "a process that already has a profile is told from one that has not" {
    // **The half that runs everywhere, a login shell and a Nix build alike**: a
    // child with a profile of its own must answer `true`, whatever this process
    // is inside. The other half, that an ordinary Mac answers `false`, is proven
    // by `test/sandbox/darwin_escape.zig` running all 13 of its tests there
    // rather than skipping them.
    //
    // Mutation check: make `confinedAlready` answer `false` always and this
    // fails. Make it answer `true` always and the Darwin escape suite skips on a
    // Mac with no sandbox around it, which is the run that catches it.
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const pid = std.c.fork();
    try std.testing.expect(pid >= 0);
    if (pid == 0) {
        // **libsandbox prints its own refusal on standard error, and this
        // child really does meet one inside a Nix builder**, where `apply`
        // below is refused by the profile the builder already carries. A test
        // binary that writes to standard error fails the build through
        // `build.zig`'s own `failOnTestStderr`, whatever it exits with, so a
        // passing test would have reddened macOS CI with a line of libsandbox
        // output. Measured on a real Mac on 2026-08-26 under
        // `sandbox-exec -p '(version 1)(allow default)'`, which prints
        // "sandbox initialization failed: Operation not permitted".
        const quiet = std.c.open("/dev/null", .{ .ACCMODE = .WRONLY });
        if (quiet >= 0) _ = std.c.dup2(quiet, 2);
        _ = apply("(version 1)(allow default)");
        std.c._exit(if (confinedAlready()) 0 else 1);
    }
    var status: c_int = 0;
    while (std.c.waitpid(pid, &status, 0) < 0) {
        if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) return error.ChildNotReaped;
    }
    try std.testing.expectEqual(@as(c_int, 0), status);
}
