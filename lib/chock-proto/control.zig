//! The daemon's control protocol: the one grammar `chock daemon` answers and
//! every client of it speaks.
//!
//! ## Why this is a module and not two halves of `src/daemon.zig`
//!
//! `chock daemon` owns sessions. `chock serve` puts a browser in front of one
//! and **owns nothing**. That split is the whole shape: in a hosted world the
//! daemon is somewhere else and the frontend is in front of it, so a frontend
//! that reached past the protocol for anything would be work somebody has to
//! unpick later. Putting the grammar here rather than inside the daemon is what
//! makes that checkable: a client links this module and gets no way at all to
//! read a log, take a lock, or resolve a session directory.
//!
//! **The test of every decision below: would this still work if the daemon were
//! on another machine?**
//!
//! ## There is no local case
//!
//! A daemon is an `Address`. A unix socket on this machine is one value of that
//! parameter and a TCP host is another, and **nothing above `Address.connect`
//! knows which it got**. The default is the unix socket, because that is the
//! common case and nobody should have to type an address to use it, and a
//! default is not a special case.
//!
//! ## The events that travel are the log's own bytes
//!
//! `chain.Verifier` hashes the bytes of a line as they sit on disk, and
//! `chock-proto/ship.zig` says plainly why a re-encoding of the parsed envelope
//! reads as tampered with: key order, the form of a number, and the escape of
//! one character all differ between two encoders and none of them changes the
//! meaning. So `watch` carries `Replay.line`, and the header line goes first
//! with the identifier zero, which is exactly what a `Verifier` wants to be
//! seeded from. **A client can therefore verify the chain of a session it has
//! only ever seen over a socket.**
//!
//! ## A client may say only what a person may say
//!
//! `lib/chock-broker/socket.zig` maps every answer that is not a plain yes onto
//! `refused_by_user`, because `allowed_by_policy` is a statement about the
//! project's own table and a client that could write it would be forging that
//! table's answer. This protocol keeps the same rule one layer earlier and more
//! narrowly: **`Answer` has two members and the wire has two words.** A decision
//! a person cannot reach is not a value this grammar can hold, so there is
//! nothing to clamp at the far end and nothing to get wrong. The broker's own
//! clamp still runs, and that is deliberate: two layers, and the outer one
//! cannot express what the inner one refuses.
//!
//! ## Two installs mean two versions, so the wire carries a number
//!
//! The moment the daemon can be on another machine, the two ends are installed
//! at two times and one of them is older. A protocol with no number gives the
//! newer end nothing to check, so a wire change arrives either as a parse
//! failure a person cannot read, or as a request that parses and means
//! something else. `Greeting` and `protocol_version` are the answer, and a
//! greeting added later would itself be a breaking change, which is why it is
//! here before the first release.
//!
//! **The check is on the numbers and never on the status alone.**
//! `lib/chock-pcsc/linux/driver.zig` measured that fault against a real
//! `pcscd`: a client that offers `9:5` gets `SCARD_S_SUCCESS` back carrying the
//! daemon's own `4:5`, so a client reading only the code talks straight over
//! the mismatch. A handshake that can succeed while the versions disagree is
//! worse than none, because it looks like it worked.
//!
//! ## What is not here
//!
//! **No authentication over a network.** A unix socket is answered by
//! `peerUid` below, which is the whole answer for a socket only this user can
//! open. A TCP address is not guarded at all: somebody who types one is being
//! deliberately insecure, and the supported way to expose it is a reverse proxy
//! such as Authelia in front. A pairing bootstrap is planned and is not this.
//!
//! **No framing beyond a line.** One greeting is one line, one request is one
//! line, and one reply is a run of lines that ends when the connection does.
//! That is what the daemon already spoke and there was no reason to invent a
//! second thing to move events with.

const std = @import("std");
const builtin = @import("builtin");

const chain = @import("chain.zig");
const event = @import("event.zig");
const storage = @import("storage.zig");

/// The port a TCP daemon listens on when nobody names one.
pub const default_port: u16 = 7373;

/// The address a TCP daemon listens on when nobody names a host.
///
/// **Loopback, and it is a default and not a rule.** See `Address` and
/// `--host`: an operator who names another address gets it.
pub const default_host = "127.0.0.1";

/// The name of the daemon's unix socket inside the state directory.
pub const socket_name = "daemon.sock";

/// The environment variable that names the daemon a client should reach.
///
/// **One variable for every client**, so a person who runs a daemon somewhere
/// else says so once rather than passing an address to each command.
pub const address_env = "CHOCK_DAEMON";

/// Where the default unix socket of the daemon lives, given the state
/// directory. Caller owns the result.
///
/// **In the state directory and never in a project.** A daemon serves every
/// project of one user, so its socket belongs to the user, and a socket inside
/// a project would be a path a sandboxed tool call could name.
pub fn socketPathIn(gpa: std.mem.Allocator, state_dir: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fs.path.join(gpa, &.{ state_dir, socket_name });
}

/// Where a daemon is. **The only thing in this file that knows a unix socket
/// and a TCP host are different**, and it knows it in `connect` and in `listen`
/// and nowhere else.
pub const Address = union(enum) {
    /// A path on the machine this client runs on.
    unix: []const u8,
    /// A host and a port, which may be this machine and may not.
    ip: Ip,

    pub const Ip = struct {
        host: []const u8,
        port: u16,
    };

    pub const ParseError = error{
        /// The text after `unix:` was empty.
        EmptyPath,
        /// The text had no port, or a port that is not a number.
        NoPort,
        /// The host part was empty.
        EmptyHost,
    };

    /// Read an address a person typed.
    ///
    /// Two spellings, and the prefix is what tells them apart rather than a
    /// guess about slashes:
    ///
    /// * `unix:/run/user/1000/chock/daemon.sock`
    /// * `127.0.0.1:7373`, and `[::1]:7373` for a literal IPv6 address.
    ///
    /// **The text is borrowed and nothing is copied.** A caller that keeps the
    /// address longer than the text keeps the text too.
    pub fn parse(text: []const u8) ParseError!Address {
        if (std.mem.startsWith(u8, text, "unix:")) {
            const path = text["unix:".len..];
            if (path.len == 0) return error.EmptyPath;
            return .{ .unix = path };
        }

        // A bracketed host is IPv6, whose own text is full of colons, so the
        // port separator is the colon after the closing bracket and never the
        // last colon in the string.
        const separator = if (std.mem.startsWith(u8, text, "["))
            (std.mem.indexOfScalar(u8, text, ']') orelse return error.NoPort) + 1
        else
            std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.NoPort;
        if (separator >= text.len or text[separator] != ':') return error.NoPort;

        const host = text[0..separator];
        if (host.len == 0) return error.EmptyHost;
        const port = std.fmt.parseInt(u16, text[separator + 1 ..], 10) catch return error.NoPort;
        return .{ .ip = .{ .host = host, .port = port } };
    }

    /// Every way reaching a daemon can fail, over either transport.
    ///
    /// **One error set for both**, so a caller writes one `catch` and gets no
    /// chance to handle a unix failure and forget a TCP one.
    pub const ConnectError = error{
        /// Nothing is listening there. The one a caller turns into "start a
        /// daemon": see `refusalFor`.
        NotListening,
        /// The address could not be read as an address at all.
        BadAddress,
        /// The path is longer than a unix socket path may be, which is not the
        /// same number on both platforms: see `max_socket_path`.
        PathTooLong,
        /// This user may not open it.
        AccessDenied,
        /// Anything else the system said.
        Unreachable,
    };

    /// Open a connection to the daemon at this address.
    ///
    /// **The one branch on transport in the whole protocol.** Everything a
    /// caller does with the stream afterwards is the same either way.
    pub fn connect(self: Address, io: std.Io) ConnectError!std.Io.net.Stream {
        switch (self) {
            .unix => |path| {
                const address = try unixAddress(path);
                return address.connect(io) catch |err| return self.classify(err);
            },
            .ip => |ip| {
                const address = std.Io.net.IpAddress.parse(ip.host, ip.port) catch return error.BadAddress;
                return address.connect(io, .{ .mode = .stream }) catch |err| return self.classify(err);
            },
        }
    }

    /// Listen on this address.
    ///
    /// **A unix socket left by a crash is removed rather than refused.** A file
    /// left by a process that is gone would otherwise wedge the address for
    /// ever, and the same rule already holds for the approval socket in
    /// `lib/chock-broker/socket.zig`.
    pub fn listen(self: Address, io: std.Io) ListenError!Listener {
        switch (self) {
            .unix => |path| {
                const address = try unixAddress(path);
                std.Io.Dir.deleteFileAbsolute(io, path) catch |err| switch (err) {
                    error.FileNotFound => {},
                    else => return error.Unavailable,
                };
                const server = address.listen(io, .{}) catch |err| switch (err) {
                    error.AddressInUse => return error.AddressInUse,
                    error.AccessDenied, error.PermissionDenied => return error.AccessDenied,
                    else => return error.Unavailable,
                };
                return .{ .server = server, .unix_path = path };
            },
            .ip => |ip| {
                const address = std.Io.net.IpAddress.parse(ip.host, ip.port) catch return error.BadAddress;
                // **A TCP listen cannot be refused for permission**, so there
                // is no `AccessDenied` arm here where the unix one has it. A
                // port under 1024 that this user may not bind arrives as
                // `AddressUnavailable`, which is not the same fact and is not
                // worth a name of its own here.
                const server = address.listen(io, .{ .reuse_address = true }) catch |err| switch (err) {
                    error.AddressInUse => return error.AddressInUse,
                    else => return error.Unavailable,
                };
                return .{ .server = server, .unix_path = null };
            },
        }
    }

    pub const ListenError = error{
        AddressInUse,
        AccessDenied,
        BadAddress,
        PathTooLong,
        Unavailable,
    };

    /// What a person reads. `unix:/path` and `host:port`, which is exactly
    /// what `parse` takes back.
    ///
    /// **The two are inverses, and there is a test that says so.** A message
    /// that named an address a client could not then type would send somebody
    /// looking for a second spelling.
    pub fn format(self: Address, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .unix => |path| try writer.print("unix:{s}", .{path}),
            .ip => |ip| try writer.print("{s}:{d}", .{ ip.host, ip.port }),
        }
    }

    /// What a failed connect means to a caller.
    ///
    /// **By what a person can do about it, and not by errno.** `NotListening`
    /// means nothing answered at this address, and it is the one that turns
    /// into "start a daemon".
    ///
    /// **A unix `Unexpected` is `NotListening`, and that is measured rather
    /// than guessed.** A socket file left behind by a daemon that is gone gives
    /// `ECONNREFUSED`, which is errno 111 on Linux, and
    /// `std.Io.net.UnixAddress.ConnectError` has no member for it, so the
    /// standard library hands it back as `Unexpected`. That is the ordinary
    /// case of a daemon somebody stopped: the file stays because a process
    /// killed by a signal runs no deferred code. Answering `Unreachable` for it
    /// would print "could not be reached" where the right sentence is "start a
    /// daemon", which is what a first reading of this got wrong.
    ///
    /// A TCP `Unexpected` keeps `Unreachable`, because that error set does name
    /// `ConnectionRefused` and so an unnamed failure there really is something
    /// else.
    ///
    /// Public so a test can drive every arm with no socket at all. A real
    /// refused unix connect makes the standard library print a stack trace on
    /// standard error in a debug build, which is not something a test suite
    /// should do to its own output.
    pub fn classify(self: Address, err: anyerror) ConnectError {
        return switch (err) {
            error.FileNotFound, error.ConnectionRefused => error.NotListening,
            error.AccessDenied, error.PermissionDenied => error.AccessDenied,
            error.Unexpected => switch (self) {
                .unix => error.NotListening,
                .ip => error.Unreachable,
            },
            else => error.Unreachable,
        };
    }
};

/// A listening daemon endpoint, with whatever it has to clean up.
pub const Listener = struct {
    server: std.Io.net.Server,
    /// The path to remove on close, for a unix socket. Null for TCP. Borrowed
    /// from the caller's own address.
    unix_path: ?[]const u8,

    /// Stop listening, and remove a unix socket file this made.
    pub fn close(self: *Listener, io: std.Io) void {
        self.server.deinit(io);
        if (self.unix_path) |path| std.Io.Dir.deleteFileAbsolute(io, path) catch {};
        self.* = undefined;
    }
};

/// The longest unix socket path Chock offers, on any platform.
///
/// **One rule, and it is "the longest path another program can also reach".**
/// A `sun_path` holds the closing zero of a path inside itself, so a name that
/// fills the field to its last byte can be spelled only by a caller that sends
/// the whole field with no terminator in it. `std.Io` is such a caller, so Chock
/// would reach its own socket and an ordinary C `connect(2)` never could. That
/// is a socket nobody can debug, so the bound is one byte below the field.
///
/// The number is therefore read from the field itself and is never written out:
/// 103 where `sun_path` is 104 bytes, and 107 where it is 108.
///
/// **A path over the field is a memory fault and not a refusal, because `std`
/// does not check it either.** `std.Io.net.UnixAddress.max_len` is a flat 108 on
/// every platform that is not Windows, `UnixAddress.init` takes anything up to
/// it, and `std.Io.Threaded.addressUnixToPosix` then copies that many bytes into
/// `sun_path`. Where the field is 104 bytes a safety checked build ends the
/// process there and a release build writes past the end of it.
///
/// Measured by calling `bind(2)` and `connect(2)` on a path of each length in
/// turn, with no help from `std.Io.net`:
///
/// * 2026-08-25, Apple Silicon, macOS 15.7.9: 103 bound with a terminator, 104
///   bound with none, and 105 to 108 passed `init` and ended the process.
/// * 2026-08-25, x86-64, Linux 6.18.42: 107 bound with a terminator and was
///   reached by a terminated `connect`, and 108 bound with none and no
///   terminated client could name it at all.
///
/// **One number for the whole program**, for the reason `peerUid` below has one
/// body: three copies of a bound drift apart, and this bound is what keeps an
/// attacker controlled path away from that `@memcpy`.
pub const max_socket_path: usize = sun_path_bytes - 1;

/// How many bytes this platform's `sun_path` holds. Read from the structure the
/// standard library itself copies into, so the two cannot disagree.
const sun_path_bytes: usize = @typeInfo(@FieldType(std.posix.sockaddr.un, "path")).array.len;

/// The address of a unix socket at `path`, or a refusal.
///
/// **Every unix socket in Chock goes through this, the ones that bind and the
/// ones that connect**, because `std` copies the path into `sun_path` at either
/// end. See `max_socket_path`.
pub fn unixAddress(path: []const u8) error{PathTooLong}!std.Io.net.UnixAddress {
    if (path.len > max_socket_path) return error.PathTooLong;
    return std.Io.net.UnixAddress.init(path) catch error.PathTooLong;
}

/// The uid on the other end of a connected unix socket, or null when the
/// kernel would not say.
///
/// The operating system already gives the identity, so there is no token. The
/// two platforms spell it differently and mean the same thing.
///
/// **This is for a unix socket only. A TCP connection carries no peer
/// identity**, and the answer for a TCP peer is null rather than a name that
/// was never checked. Authentication in front of a TCP listener is a reverse
/// proxy's job: see this file's own top comment. A caller still decides which
/// of its listeners to ask about, because null is a refusal and every TCP peer
/// would be refused.
///
/// **One implementation, and every caller in Chock reaches this one.** It sits
/// here rather than beside one of its callers because three of them are in
/// different modules: `lib/chock-broker/socket.zig` for the approval socket,
/// `src/daemon.zig` for the control socket, and `src/serve.zig` for the browser
/// socket. `src/serve.zig` is a pure client of the daemon and its own test
/// refuses an import of `chock-broker`, so a shared home below both is what
/// keeps this from becoming two copies of a security check that drift apart.
pub fn peerUid(handle: std.posix.fd_t) ?std.posix.uid_t {
    switch (builtin.os.tag) {
        .linux => {
            // `struct ucred`, the stable Linux ABI: pid, uid, gid, three 32 bit
            // words in that order.
            const Ucred = extern struct { pid: i32, uid: u32, gid: u32 };
            var credentials: Ucred = undefined;
            var length: std.posix.socklen_t = @sizeOf(Ucred);
            const rc = std.os.linux.getsockopt(
                handle,
                std.os.linux.SOL.SOCKET,
                std.os.linux.SO.PEERCRED,
                @ptrCast(&credentials),
                &length,
            );
            if (std.posix.errno(rc) != .SUCCESS) return null;
            if (length != @sizeOf(Ucred)) return null;
            // **A TCP socket does not refuse this call. It answers with
            // nothing.** Measured on Linux: `getsockopt` succeeds on a
            // connected TCP socket and fills the structure with `pid` zero and
            // `uid` (uid_t)-1, which is the kernel's own "no credential"
            // value. Reading that as a uid would hand a caller a number no
            // account has, and an absent answer must never look like a name.
            // The first reading of this function returned it, and the test in
            // `test/proto/control.zig` is what found it.
            if (credentials.pid == 0) return null;
            if (credentials.uid == std.math.maxInt(u32)) return null;
            return credentials.uid;
        },
        .macos => {
            // `struct xucred` from `<sys/ucred.h>`, asked for at level
            // `SOL_LOCAL` with `LOCAL_PEERCRED`. Neither constant nor the
            // struct is in `std.c`, so both are written out here with the
            // header's own values. `NGROUPS` is 16.
            const Xucred = extern struct {
                version: u32,
                uid: u32,
                ngroups: i16,
                groups: [16]u32,
            };
            const sol_local: i32 = 0;
            const local_peercred: u32 = 1;
            const xucred_version: u32 = 0;
            var credentials: Xucred = undefined;
            var length: std.posix.socklen_t = @sizeOf(Xucred);
            // **A TCP socket refuses this call on Darwin**, because
            // `LOCAL_PEERCRED` is a `SOL_LOCAL` option and a TCP socket is not
            // a local one, so `rc` is not zero and the answer is null. That is
            // read from the header and is not measured: there is no Darwin
            // machine in this test run. `xucred` carries no pid, so there is
            // no second guard here of the kind the Linux arm needs.
            const rc = std.c.getsockopt(handle, sol_local, local_peercred, &credentials, &length);
            if (rc != 0) return null;
            if (credentials.version != xucred_version) return null;
            if (credentials.uid == std.math.maxInt(u32)) return null;
            return credentials.uid;
        },
        else => @compileError("chock-proto/control.zig: no peer credential call for this target"),
    }
}

/// Whether the peer of a unix socket is the user that started the listener.
///
/// **The owner and nobody else.** A listener that answers for a session can
/// start work, read a log and answer an approval, so a peer that reached the
/// socket path on a machine with more than one account would be driving
/// somebody else's agent.
///
/// **A peer the kernel will not name is refused too.** An absent answer is
/// never a permissive answer, the same rule a policy keeps.
pub fn peerAllowed(uid: ?std.posix.uid_t, owner_uid: std.posix.uid_t) bool {
    const said = uid orelse return false;
    return said == owner_uid;
}

/// The sentence a person reads when a daemon could not be reached, and what to
/// do about it.
///
/// **Its own function so no test needs a network to pin it.** A daemon that is
/// not running has to be a plain refusal that names the fix, and the fix
/// depends on the address: a unix socket says start one, and a TCP address a
/// person typed says check that address.
pub fn refusalFor(writer: *std.Io.Writer, address: Address, err: Address.ConnectError) std.Io.Writer.Error!void {
    switch (err) {
        error.NotListening => switch (address) {
            .unix => try writer.print(
                "nothing is listening on {f}, so there is no daemon to talk to. " ++
                    "Start one with `chock daemon`, and then run this again.\n",
                .{address},
            ),
            .ip => try writer.print(
                "nothing is listening on {f}, so there is no daemon to talk to. " ++
                    "Start one there with `chock daemon --host <address>`, or name a " ++
                    "different one with --daemon.\n",
                .{address},
            ),
        },
        error.AccessDenied => try writer.print(
            "{f} refused this user. A daemon's socket belongs to the user that " ++
                "started it, and this is not that user.\n",
            .{address},
        ),
        // **The number is read and never written out.** This sentence said 108
        // on every platform, which is false on Darwin by five bytes, and the
        // five it was wrong about are the ones that end the process.
        error.PathTooLong => try writer.print(
            "{f} is longer than a unix socket path may be on this platform, which is {d} " ++
                "bytes. Name a shorter one with --daemon.\n",
            .{ address, max_socket_path },
        ),
        error.BadAddress => try writer.print("{f} is not an address.\n", .{address}),
        error.Unreachable => try writer.print(
            "{f} could not be reached.\n",
            .{address},
        ),
    }
}

/// The number this build speaks on the daemon's control socket.
///
/// **A number of its own, and never the program's version.** `chock --version`
/// prints what `build.zig.zon` holds, and that moves on every release: a fix to
/// the sandbox, a new tool, a word in a help text. The wire moves far less
/// often, and tying the two would make every release read as a wire break, so
/// every pair of ends would have to be upgraded together for changes that never
/// touched a byte on the socket. A person would then learn to ignore the
/// refusal, which is the one thing a refusal must never become.
///
/// **It moves when a client built against the old number would misread the new
/// one, and at no other time.** A field added to `SessionRow` is not such a
/// change: every field there has a default and `fromJson` ignores what it does
/// not know, so both directions already hold. A verb removed, a field reordered,
/// a separator changed, or a reply that means something new all are.
pub const protocol_version: u32 = 1;

/// The word both ends of the greeting carry.
///
/// **So that reaching the wrong port is a sentence and not a number.** A TCP
/// daemon is one address among many on a machine, and a client that read a
/// version out of some other program's first line would go on to speak this
/// grammar at it.
pub const protocol_name = "chock-control";

/// The first line of every connection, in either direction.
///
/// **The client speaks first and the daemon answers, and both check.** The
/// client speaking first is what lets the daemon name both numbers in its
/// refusal. The daemon answering with its own number is what lets the client
/// check as well, which is not redundant: see this file's own top comment for
/// the `pcscd` reading that a status code alone talks straight over a mismatch.
///
/// **Not pipelined, and that is measured behaviour and not taste.** A client
/// that sent the greeting and the request together would save a round trip and
/// lose the refusal: a daemon that closes a TCP connection with a request still
/// unread sends a reset, and a reset discards what the daemon already wrote. The
/// client would then see a dropped connection where a sentence was sent. So the
/// client waits for the answer, and a refused connection has nothing unread on
/// it.
pub const Greeting = struct {
    version: u32 = protocol_version,

    /// What a client sends: `hello chock-control <number>`.
    pub const ask_prefix = "hello " ++ protocol_name ++ " ";

    /// What a daemon answers: `ok chock-control <number>`.
    ///
    /// **An ordinary `ok` reply, so the reply grammar grew nothing.** A client
    /// that already reads `Reply` reads this, and a daemon that refuses uses
    /// the `error` line it uses for everything else.
    pub const answer_prefix = ok_prefix ++ protocol_name ++ " ";

    /// Which end wrote the line. **The two spellings differ**, so an answer
    /// echoed back at a daemon is not a greeting and a client cannot be made to
    /// read its own words as the far end's.
    pub const Side = enum {
        ask,
        answer,

        fn prefix(self: Side) []const u8 {
            return switch (self) {
                .ask => ask_prefix,
                .answer => answer_prefix,
            };
        }
    };

    pub const ParseError = error{
        /// The line is not a greeting of that side at all.
        NotAGreeting,
    };

    /// Read one greeting line. The line carries no newline.
    pub fn parse(side: Side, line: []const u8) ParseError!Greeting {
        const prefix = side.prefix();
        if (!std.mem.startsWith(u8, line, prefix)) return error.NotAGreeting;
        const number = std.mem.trim(u8, line[prefix.len..], " ");
        if (number.len == 0) return error.NotAGreeting;
        return .{
            .version = std.fmt.parseInt(u32, number, 10) catch return error.NotAGreeting,
        };
    }

    /// Write this greeting as one line, newline included.
    pub fn write(self: Greeting, side: Side, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{s}{d}\n", .{ side.prefix(), self.version });
    }
};

/// Whether a build that speaks `ours` may talk to one that speaks `theirs`.
///
/// **Equal, and nothing else.** A window of accepted numbers is a promise that
/// this build was run against every number in it, and it never was. The same
/// reading made `lib/chock-pcsc/linux/wire.zig`'s `Version.accepts` exact and
/// deliberately narrower than the real `libpcsclite`, which retries at the
/// daemon's own number: a silent downgrade to a protocol nothing here was ever
/// tested against is worse than a refusal a person can read and act on.
///
/// Its own function rather than a `==` at each end, so the rule is one line and
/// a test can drive it.
pub fn accepts(ours: u32, theirs: u32) bool {
    return ours == theirs;
}

/// How a handshake ended.
///
/// **Every member that is not `agreed` carries what a person has to be told.**
/// A refusal that named neither number would leave somebody guessing which end
/// to update.
pub const Handshake = union(enum) {
    /// Both ends named this number.
    agreed: u32,
    /// The far end named a number this build does not speak.
    mismatch: struct { ours: u32, theirs: u32 },
    /// The far end refused in its own words, and this is them. **A daemon built
    /// before the greeting existed lands here**: `hello` is not a verb it has a
    /// case for, so it answers `no_verb_text`. So does a daemon that turned this
    /// client away for any other reason, such as the peer credential check.
    /// Borrowed from the reader's own buffer.
    refused: []const u8,
    /// The far end answered a line that is neither a greeting nor a refusal, or
    /// said nothing at all. Borrowed likewise.
    unreadable: []const u8,

    /// Whether the connection may be used. **The one thing a caller is allowed
    /// to reduce this to**, and it is false for everything but `agreed`.
    pub fn ok(self: Handshake) bool {
        return self == .agreed;
    }
};

pub const HandshakeError = std.Io.Writer.Error || error{
    ReadFailed,
    StreamTooLong,
};

/// Send the greeting and read the answer.
///
/// **The check is `accepts` and never the shape of the reply.** A daemon that
/// answered a well formed greeting carrying another number would pass a check
/// written over the prefix alone, and the connection would then carry a grammar
/// one end does not have. That is the fault `chock-pcsc` measured against a real
/// daemon: see this file's own top comment.
///
/// An `Error` here is the transport failing. A far end that answered something
/// this build will not use is not an error: it is a `Handshake` a caller reports
/// with `handshakeRefusal`.
pub fn handshake(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    ours: u32,
) HandshakeError!Handshake {
    try (Greeting{ .version = ours }).write(.ask, writer);
    try writer.flush();

    const line = std.mem.trimEnd(u8, (try reader.takeDelimiter('\n')) orelse "", "\r");
    const said = Greeting.parse(.answer, line) catch {
        // An `error` line is the daemon's own sentence and is worth carrying
        // whole. Every other line is a program that is not this one.
        if (std.mem.startsWith(u8, line, error_prefix)) {
            return .{ .refused = line[error_prefix.len..] };
        }
        return .{ .unreadable = line };
    };
    if (!accepts(ours, said.version)) {
        return .{ .mismatch = .{ .ours = ours, .theirs = said.version } };
    }
    return .{ .agreed = said.version };
}

/// The sentence a person reads about a handshake, and what to do about it.
///
/// **Its own function so no test needs a socket to pin it**, which is the shape
/// `refusalFor` already has for a connect that failed.
pub fn handshakeRefusal(
    writer: *std.Io.Writer,
    address: Address,
    said: Handshake,
) std.Io.Writer.Error!void {
    switch (said) {
        .agreed => |version| try writer.print(
            "{f} and this build both speak control protocol {d}.\n",
            .{ address, version },
        ),
        .mismatch => |both| try writer.print(
            "{f} speaks control protocol {d} and this build speaks {d}, so nothing was asked " ++
                "of it. The two have to be the same number. Update whichever end is older.\n",
            .{ address, both.theirs, both.ours },
        ),
        // **The far end's own words go last.** They often end in a full stop of
        // their own, and a template that put anything after them read as one
        // sentence with two.
        .refused => |text| try writer.print(
            "{f} refused the greeting of control protocol {d}. A daemon older than this " ++
                "greeting refuses here too, because `hello` is not a word it knows. It said: {s}\n",
            .{ address, protocol_version, text },
        ),
        .unreadable => |text| try writer.print(
            "{f} answered the greeting of control protocol {d} with a line this build cannot " ++
                "read: {s}\n",
            .{ address, protocol_version, text },
        ),
    }
}

/// What a daemon answers a client whose first line is not a greeting.
///
/// **A client built before the greeting existed lands here**, because its first
/// line is a verb. It is told to update rather than being served a grammar
/// neither end can be sure of.
pub const no_greeting_text = "this daemon reads a greeting first, and that line is not one. " ++
    "A client of it opens with `" ++ Greeting.ask_prefix ++ "<number>`, and a client built " ++
    "before that greeting existed cannot talk to this daemon. Update it.";

/// The `error` line a daemon answers when the numbers disagree.
///
/// **Both numbers, in the daemon's own reply.** The client checks as well and
/// says the same thing from its side, and the two are not one check written
/// twice: this one is what a client too old to check anything still reads.
pub fn writeMismatch(writer: *std.Io.Writer, ours: u32, theirs: u32) std.Io.Writer.Error!void {
    try writer.print(
        error_prefix ++ "this daemon speaks control protocol {d} and that client speaks {d}, " ++
            "so nothing was done. The two have to be the same number. Update whichever end " ++
            "is older.\n",
        .{ ours, theirs },
    );
}

/// What a daemon answers to.
///
/// **One list, and every other list in this file is built from it**, so a verb
/// can never be dispatched and unlisted, or listed and unhandled. That is the
/// rule `src/main.zig` keeps for its own command table and `src/daemon.zig`
/// already kept for the three verbs it had.
pub const Verb = enum {
    /// Start a new session in a project.
    start,
    /// Take over a session that already exists and that nobody owns.
    adopt,
    /// Read a session's events from an offset, and stop at the end of what is
    /// there now.
    read,
    /// List the sessions of one project.
    list,
    /// Read a session's events from an offset, and keep sending as it grows.
    watch,
    /// Answer one open approval of one session.
    answer,
};

/// One request, parsed.
///
/// **The three verbs that existed keep their exact grammar**, because
/// `src/detach.zig` speaks them and this milestone does not own that file. The
/// three new ones are tab separated throughout, which is the shape `start` and
/// `adopt` already had and the one that lets a field hold a space.
pub const Request = union(Verb) {
    start: Start,
    adopt: Adopt,
    read: Read,
    list: List,
    watch: Watch,
    answer: Answer_,

    pub const Start = struct { project: []const u8, message: []const u8 };
    pub const Adopt = struct { project: []const u8, session: []const u8 };
    pub const Read = struct { session: []const u8, after: u64 };
    pub const List = struct { project: []const u8 };
    pub const Watch = struct { project: []const u8, session: []const u8, after: u64 };
    pub const Answer_ = struct {
        project: []const u8,
        session: []const u8,
        request_id: u64,
        /// **Two members, and that is the clamp.** See this file's own top
        /// comment: a decision a person cannot reach is not a value this
        /// grammar can hold.
        decision: Answer,
    };

    pub const ParseError = error{
        /// The line named no verb this daemon has.
        NoVerb,
        /// The verb was right and what followed it was not.
        BadArguments,
    };

    /// Read one request line. The line carries no newline.
    ///
    /// **Everything points into `line`.** A caller that keeps a request keeps
    /// the line, which is the same rule the event decoder keeps.
    pub fn parse(line: []const u8) ParseError!Request {
        const asked = verbOf(line) orelse return error.NoVerb;
        return switch (asked.verb) {
            .start => .{ .start = .{
                .project = try field(asked.rest, 0, 2),
                .message = try field(asked.rest, 1, 2),
            } },
            .adopt => .{ .adopt = .{
                .project = try field(asked.rest, 0, 2),
                .session = try field(asked.rest, 1, 2),
            } },
            // `read` is space separated, which is what it always was.
            .read => read: {
                const space = std.mem.indexOfScalar(u8, asked.rest, ' ') orelse
                    return error.BadArguments;
                break :read .{ .read = .{
                    .session = asked.rest[0..space],
                    .after = std.fmt.parseInt(
                        u64,
                        std.mem.trim(u8, asked.rest[space + 1 ..], " "),
                        10,
                    ) catch return error.BadArguments,
                } };
            },
            .list => .{ .list = .{ .project = try field(asked.rest, 0, 1) } },
            .watch => .{ .watch = .{
                .project = try field(asked.rest, 0, 3),
                .session = try field(asked.rest, 1, 3),
                .after = std.fmt.parseInt(u64, try field(asked.rest, 2, 3), 10) catch
                    return error.BadArguments,
            } },
            .answer => .{
                .answer = .{
                    .project = try field(asked.rest, 0, 4),
                    .session = try field(asked.rest, 1, 4),
                    .request_id = std.fmt.parseInt(u64, try field(asked.rest, 2, 4), 10) catch
                        return error.BadArguments,
                    // **The only place a decision enters this program from a
                    // socket**, and it takes two words. See `Answer`.
                    .decision = Answer.parse(try field(asked.rest, 3, 4)) orelse
                        return error.BadArguments,
                },
            },
        };
    }

    /// Write this request as the one line a daemon reads, newline included.
    ///
    /// **The inverse of `parse`, and there is a test over every verb that says
    /// so.** A client and a server that each held their own spelling is how a
    /// protocol drifts, and this file is the only spelling either has.
    pub fn write(self: Request, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .start => |one| try writer.print("start {s}\t{s}\n", .{ one.project, one.message }),
            .adopt => |one| try writer.print("adopt {s}\t{s}\n", .{ one.project, one.session }),
            .read => |one| try writer.print("read {s} {d}\n", .{ one.session, one.after }),
            .list => |one| try writer.print("list {s}\n", .{one.project}),
            .watch => |one| try writer.print(
                "watch {s}\t{s}\t{d}\n",
                .{ one.project, one.session, one.after },
            ),
            .answer => |one| try writer.print("answer {s}\t{s}\t{d}\t{s}\n", .{
                one.project,
                one.session,
                one.request_id,
                @tagName(one.decision),
            }),
        }
    }
};

/// The verb a request names, and everything after it. Null for a request that
/// names none.
///
/// **A verb is a whole word followed by a space.** A request of `started ...`
/// is not `start`, and a client that meant something else is told so rather
/// than having its first two characters eaten.
pub fn verbOf(request: []const u8) ?struct { verb: Verb, rest: []const u8 } {
    inline for (std.enums.values(Verb)) |verb| {
        const prefix = @tagName(verb) ++ " ";
        if (std.mem.startsWith(u8, request, prefix)) {
            return .{ .verb = verb, .rest = request[prefix.len..] };
        }
    }
    return null;
}

/// What a client is told when it used a word this daemon has no case for.
/// Built from `Verb` itself, so adding a verb and forgetting this sentence is
/// not something a person has to remember.
pub const no_verb_text = text: {
    var built: []const u8 = "the request is none of";
    for (std.enums.values(Verb), 0..) |verb, index| {
        if (index != 0) built = built ++ (if (index + 1 == std.enums.values(Verb).len) " and" else ",");
        built = built ++ " `" ++ @tagName(verb) ++ "`";
    }
    break :text built;
};

/// Field `want` of a tab separated rest, when there are exactly `count` of
/// them. **Exactly**, so a request with an extra field is refused rather than
/// having the extra quietly ignored.
fn field(rest: []const u8, want: usize, count: usize) Request.ParseError![]const u8 {
    var found: usize = 0;
    var start: usize = 0;
    var answer: ?[]const u8 = null;
    var index: usize = 0;
    while (index <= rest.len) : (index += 1) {
        if (index != rest.len and rest[index] != '\t') continue;
        if (found == want) answer = rest[start..index];
        found += 1;
        start = index + 1;
    }
    if (found != count) return error.BadArguments;
    return answer orelse error.BadArguments;
}

/// Everything a client may decide about an approval.
///
/// **Two members, which is the whole trust boundary of this protocol.**
/// `event.ApprovalDecision` also holds `allowed_by_policy` and
/// `approved_by_review`, and both of those are statements about a decision
/// somebody other than the answering person reached: the project's own table,
/// or a panel. A client that could name one would be forging that answer.
///
/// `lib/chock-broker/socket.zig` maps every answer that is not a plain yes onto
/// a refusal, which is the same rule from the other side. This is narrower on
/// purpose: **there is no wider value to map down**, so a future reader cannot
/// widen this by deleting a `switch` arm. Both layers stay, because the outer
/// one being unable to express what the inner one refuses is what makes the
/// pair worth having.
pub const Answer = enum {
    /// A person said yes.
    yes,
    /// A person said no, or said something that was not yes, or said nothing.
    no,

    /// The word a client wrote, or null. Nothing else is a word.
    pub fn parse(word: []const u8) ?Answer {
        inline for (std.enums.values(Answer)) |one| {
            if (std.mem.eql(u8, word, @tagName(one))) return one;
        }
        return null;
    }

    /// The log's own decision for this answer.
    ///
    /// **A total function over two members with no `else`**, so a member added
    /// here fails the build rather than falling into whichever arm an `else`
    /// happened to name.
    pub fn decision(self: Answer) event.ApprovalDecision {
        return switch (self) {
            .yes => .approved_by_user,
            .no => .refused_by_user,
        };
    }
};

/// One session of one project, as it travels.
///
/// **Its own type and not `src/sessions.zig`'s `Session`.** That one holds a
/// `chain.Report`, a seal reading, and paths, and this module may import
/// neither the command nor `chock-pcsc`. More to the point, a wire type that
/// was an alias of a local struct is a wire type that changes whenever
/// somebody adds a field to the local one, and a client built against
/// yesterday's daemon would then stop parsing. So the two are converted
/// between, by `src/daemon.zig`, and a test there compares them field by
/// field.
///
/// Every field has a default, so a daemon that grows one does not break a
/// client that was built before it.
pub const SessionRow = struct {
    id: []const u8,
    /// When the session started, from the identifier's own timestamp.
    started_ms: u64 = 0,
    /// The first model a `usage` event named. Empty when no turn named one.
    model: []const u8 = "",
    /// How many models the session used.
    model_count: usize = 0,
    /// The alias the caller asked for, which is not always what the provider
    /// answered with.
    model_alias: []const u8 = "",
    /// `live`, `idle`, or `unknown`. **Never absent and never a guess**: an
    /// absent answer is never a permissive answer, so a lock that could not be
    /// tested says `unknown` and not `idle`.
    live: []const u8 = "unknown",
    /// Why the session ended. Null for one that is running or one that was
    /// killed.
    end: ?[]const u8 = null,
    turns: u64 = 0,
    input_tokens: u64 = 0,
    output_tokens: u64 = 0,
    /// The money, and `currency` is what says what it is in. Meaningless
    /// unless `spend_enforceable`.
    amount: f64 = 0,
    currency: []const u8 = "",
    /// False as soon as one turn could not be priced. A reader that showed the
    /// number without this would be showing a total that is not one.
    spend_enforceable: bool = true,
    /// False when the log could not be opened or replayed at all.
    readable: bool = true,
    /// False when the log could not be read to its end. The numbers are then a
    /// floor.
    complete: bool = true,
    /// What the hash chain said: a `chain.Verdict` by name. **This is what
    /// tells "somebody edited this" from "the power went out"**, and a client
    /// that dropped it would hide the one fact worth acting on. The default is
    /// `unreadable`, which is never a pass.
    chain: []const u8 = "unreadable",
    /// How many events the chain reading got through, and how many of those
    /// carried a chain at all. A reader compares the two to tell a log that
    /// was never chained from one somebody stripped.
    chain_events: u64 = 0,
    chain_chained: u64 = 0,
    /// Whether the session's scratch directories still hold anything.
    has_work: bool = false,
    has_root: bool = false,

    /// This row as one JSON object. Caller owns the result.
    pub fn toJson(self: SessionRow, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return std.fmt.allocPrint(gpa, "{f}", .{std.json.fmt(self, .{})});
    }

    /// Read one row back. The caller owns the parse and must free it.
    ///
    /// **Unknown fields are ignored**, so a client built against an older
    /// daemon still reads a newer one's listing. That is the other half of
    /// every field having a default.
    pub fn fromJson(gpa: std.mem.Allocator, text: []const u8) !std.json.Parsed(SessionRow) {
        return std.json.parseFromSlice(SessionRow, gpa, text, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
    }
};

/// The name a `chain.Verdict` travels under. `@tagName`, written out as a
/// function so the one direction and the other are in one place.
pub fn verdictName(verdict: chain.Verdict) []const u8 {
    return @tagName(verdict);
}

/// The first word of every reply line that is not a record.
pub const ok_prefix = "ok ";
pub const error_prefix = "error ";

/// One line of a reply, read.
pub const Reply = union(enum) {
    /// `ok <text>`: the daemon did it, and the text is whatever that verb
    /// gives back.
    ok: []const u8,
    /// `error <text>`: the daemon would not, and the text says why. **Never a
    /// hint and never a code**: a person reads it.
    failed: []const u8,
    /// `<id>\t<payload>`: one record of a stream. `list` sends rows and
    /// `read` and `watch` send the log's own lines.
    record: Record,

    pub const Record = struct {
        id: u64,
        /// For `read` and `watch`, **the bytes of that line exactly as the log
        /// holds them**. See this file's own top comment for why a re-encoding
        /// would read as tampered with.
        payload: []const u8,
    };

    pub const ParseError = error{Malformed};

    /// Read one reply line. The line carries no newline. Everything points
    /// into it.
    pub fn parse(line: []const u8) ParseError!Reply {
        if (std.mem.startsWith(u8, line, ok_prefix)) return .{ .ok = line[ok_prefix.len..] };
        if (std.mem.startsWith(u8, line, error_prefix)) return .{ .failed = line[error_prefix.len..] };
        const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return error.Malformed;
        const id = std.fmt.parseInt(u64, line[0..tab], 10) catch return error.Malformed;
        return .{ .record = .{ .id = id, .payload = line[tab + 1 ..] } };
    }

    pub fn write(self: Reply, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .ok => |text| try writer.print(ok_prefix ++ "{s}\n", .{text}),
            .failed => |text| try writer.print(error_prefix ++ "{s}\n", .{text}),
            .record => |one| try writer.print("{d}\t{s}\n", .{ one.id, one.payload }),
        }
    }
};

/// The largest request line a daemon reads. A request holds a project path and
/// a message, both of which a person typed.
pub const max_request_bytes: usize = 1024 * 1024;

/// One session log on its way to a client, and where that has got to.
///
/// **The daemon sends with this and `test/proto/control.zig` receives what it
/// sent**, so the protocol is never proved against a stand-in. That fault has
/// been caught in this project once already: a wire tested only against a fake
/// server which accepted more than the real one did.
///
/// It touches no path and takes no lock. A caller opens the log, hands over a
/// `storage.Storage`, and this reads through the interface, which is the same
/// rule `lib/chock-proto/ship.zig` keeps for a shipper.
pub const Feed = struct {
    /// The identifier the next replay starts at. **Inclusive**, so the first
    /// event it reads back is one the client already has and is dropped. Zero
    /// means the client has nothing yet.
    after: u64 = 0,
    /// Whether a `session.end` has gone out.
    ended: bool = false,
    /// How many events have gone out on this feed.
    sent: usize = 0,

    pub const Error = std.Io.Writer.Error || storage.ReplayError;

    /// Send the log's header line as record zero.
    ///
    /// **Zero is the header line's own byte offset**, and it is what
    /// `chain.Verifier` calls the line before the first event. A client that
    /// never got it cannot check the chain of anything that follows, so this
    /// goes first to a client that is starting from nothing. A client resuming
    /// from an offset already has it.
    pub fn header(
        self: *Feed,
        io: std.Io,
        store: storage.Storage,
        writer: *std.Io.Writer,
    ) Error!void {
        _ = self;
        var buffer: [storage.max_header_bytes]u8 = undefined;
        const line = try store.headerLine(io, &buffer);
        try (Reply{ .record = .{ .id = 0, .payload = line } }).write(writer);
    }

    /// Send every event from the cursor onward. True when at least one went.
    ///
    /// **The bytes of the line and never a re-encoding.** See this file's own
    /// top comment: two encoders of one envelope differ in key order without
    /// differing in meaning, and a client that hashed a re-encoding would call
    /// a sound log tampered with.
    ///
    /// `limit` bounds one call, for a reader that is catching up on a log
    /// somebody else wrote. Zero means no bound.
    pub fn events(
        self: *Feed,
        gpa: std.mem.Allocator,
        io: std.Io,
        store: storage.Storage,
        writer: *std.Io.Writer,
        limit: usize,
    ) Error!bool {
        var replay = try store.replay(gpa, io, self.after);
        defer replay.deinit();

        var any = false;
        var first = true;
        var this_call: usize = 0;
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();

            if (first) {
                first = false;
                if (self.after != 0) continue;
            }

            try (Reply{ .record = .{
                .id = parsed.value.id,
                .payload = replay.line(),
            } }).write(writer);

            self.after = parsed.value.id;
            self.sent += 1;
            this_call += 1;
            any = true;
            if (parsed.value.event == .session_end) self.ended = true;
            if (limit != 0 and this_call >= limit) break;
        }
        return any;
    }
};

/// Read one whole exchange: greet the daemon, send a request, take every line
/// it sends back, and hand each to `each`.
///
/// **The seam, and it is a pair of streams rather than a socket.** Nothing in
/// this function opens anything, so every test drives the very code a client
/// runs, over buffers, and **no test in this suite reaches a network**. That is
/// the shape `provision.Runner`, `approval.Console`, `Client.Wire`,
/// `lsp.Server` and `ship.Sink` already have.
///
/// **The request is not written until the greeting agreed.** So a refusal
/// reaches a client with nothing of its own left unread on the connection, and
/// a daemon that would not speak to this build was never asked to do anything.
///
/// `said` takes the handshake's own answer, and a handshake that did not agree
/// is `error.HandshakeFailed` as well. **Both**, because a caller that read only
/// `said` could go on, and a caller that read only the error could not say which
/// numbers disagreed. It points into `reader`'s own buffer for the two members
/// that carry text.
///
/// `each` gives back false to stop reading, which is what makes `watch`
/// stoppable without closing the connection from inside this loop.
pub fn exchange(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    request: Request,
    said: *Handshake,
    context: anytype,
    comptime each: fn (@TypeOf(context), Reply) anyerror!bool,
) anyerror!void {
    said.* = try handshake(reader, writer, protocol_version);
    if (!said.ok()) return error.HandshakeFailed;

    try request.write(writer);
    try writer.flush();

    while (true) {
        // **`takeDelimiter` and never `takeDelimiterExclusive`.** The exclusive
        // one advances up to the line break and not past it, so a second call
        // sees that break at once and gives back an empty line, for ever. A
        // reader of one line per connection never meets that, which is why the
        // daemon's own request read did not. This reads every line of a reply.
        const line = (try reader.takeDelimiter('\n')) orelse return;
        const reply = Reply.parse(std.mem.trimEnd(u8, line, "\r")) catch continue;
        if (!try each(context, reply)) return;
    }
}

const testing = std.testing;

test "an address a person typed reads back as the address they typed" {
    // **`parse` and `format` are inverses**, and that is not tidiness: a
    // message that named an address a client could not then type would send
    // somebody looking for a second spelling. Mutation check: make `format`
    // print `unix://` and this fails.
    const spellings = [_][]const u8{
        "unix:/run/user/1000/chock/daemon.sock",
        "127.0.0.1:7373",
        "0.0.0.0:8080",
        "[::1]:7373",
        "chock.example:443",
    };
    for (spellings) |text| {
        const address = try Address.parse(text);
        var buffer: [256]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try address.format(&writer);
        try testing.expectEqualStrings(text, writer.buffered());
    }

    // The bracketed form is IPv6 and its port is the colon after the bracket,
    // never the last colon in the text. Mutation check: use `lastIndexOfScalar`
    // for every spelling and `[::1]:7373` parses as a host of `[:` and a port
    // of nothing.
    const six = try Address.parse("[::1]:7373");
    try testing.expectEqualStrings("[::1]", six.ip.host);
    try testing.expectEqual(@as(u16, 7373), six.ip.port);

    const unix = try Address.parse("unix:/tmp/x.sock");
    try testing.expectEqualStrings("/tmp/x.sock", unix.unix);
}

test "an address that is not one is refused by name and never guessed at" {
    try testing.expectError(error.EmptyPath, Address.parse("unix:"));
    try testing.expectError(error.NoPort, Address.parse("127.0.0.1"));
    try testing.expectError(error.NoPort, Address.parse("127.0.0.1:"));
    try testing.expectError(error.NoPort, Address.parse("127.0.0.1:seventy"));
    try testing.expectError(error.NoPort, Address.parse("127.0.0.1:70000"));
    try testing.expectError(error.EmptyHost, Address.parse(":7373"));
    // A path with no `unix:` in front of it is not a path. Guessing from the
    // leading slash would make `/tmp/x` an address and `tmp/x` a host with no
    // port, which are two answers to one shape.
    try testing.expectError(error.NoPort, Address.parse("/run/chock.sock"));
}

test "a client can decide exactly two things, and neither of them is the policy's" {
    // **The trust boundary of this protocol, at its narrowest.**
    // `event.ApprovalDecision` holds decisions that are statements about
    // somebody other than the answering person: `allowed_by_policy` is the
    // project's own table and `approved_by_review` is a panel. A client that
    // could name one would be forging that answer.
    //
    // Mutation check: add a member to `Answer` that maps to
    // `allowed_by_policy` and this fails on both counts.
    try testing.expectEqual(@as(usize, 2), std.enums.values(Answer).len);

    var reached = std.EnumSet(std.meta.Tag(event.ApprovalDecision)).initEmpty();
    for (std.enums.values(Answer)) |one| reached.insert(std.meta.activeTag(one.decision()));
    try testing.expect(reached.contains(.approved_by_user));
    try testing.expect(reached.contains(.refused_by_user));
    try testing.expect(!reached.contains(.allowed_by_policy));
    try testing.expect(!reached.contains(.approved_by_review));
    try testing.expect(!reached.contains(.unknown));
    try testing.expectEqual(@as(usize, 2), reached.count());

    // And every decision the log knows that is not one of those two is
    // unreachable through this grammar. This is written over the event type's
    // own members rather than a list typed out here, so a decision added to
    // the log is checked the day it lands.
    inline for (@typeInfo(event.ApprovalDecision).@"union".fields) |one| {
        const permitted = std.mem.eql(u8, one.name, "approved_by_user") or
            std.mem.eql(u8, one.name, "refused_by_user");
        if (!permitted) try testing.expect(Answer.parse(one.name) == null);
    }
}

test "the only words a client can put in an answer are yes and no" {
    // The wire half of the same fact. A word that is not one of the two is not
    // mapped down to a refusal here: it is not a request at all, so the daemon
    // never reaches its approval path with it.
    try testing.expectEqual(Answer.yes, Answer.parse("yes").?);
    try testing.expectEqual(Answer.no, Answer.parse("no").?);
    for ([_][]const u8{
        "allowed_by_policy",
        "approved_by_policy",
        "approved_by_review",
        "approved_by_user",
        "refused_by_user",
        "YES",
        "y",
        "",
        "yes no",
    }) |word| try testing.expect(Answer.parse(word) == null);

    // And a whole request carrying one of those is refused, rather than parsed
    // with the decision dropped. Mutation check: default the decision to `.no`
    // when the word is not known, and this passes while a client that typed
    // `allowed_by_policy` silently gets a refusal recorded instead of being
    // told its request was nonsense.
    try testing.expectError(
        error.BadArguments,
        Request.parse("answer /p\t01JQ" ++ "A" ** 22 ++ "\t128\tallowed_by_policy"),
    );
}

test "every verb round trips from a request to a line and back" {
    // **The client and the server have one spelling**, and this is what says
    // so. A protocol with a writer in one file and a reader in another is one
    // that drifts on the next field somebody adds.
    const id = "01JQ" ++ "A" ** 22;
    const requests = [_]Request{
        .{ .start = .{ .project = "/home/ross/chock", .message = "fix the parser please" } },
        .{ .adopt = .{ .project = "/home/ross/chock", .session = id } },
        .{ .read = .{ .session = id, .after = 0 } },
        .{ .read = .{ .session = id, .after = 4096 } },
        .{ .list = .{ .project = "/home/ross/chock" } },
        .{ .watch = .{ .project = "/home/ross/chock", .session = id, .after = 128 } },
        .{ .answer = .{ .project = "/home/ross/chock", .session = id, .request_id = 9, .decision = .yes } },
        .{ .answer = .{ .project = "/home/ross/chock", .session = id, .request_id = 9, .decision = .no } },
    };

    var seen = std.EnumSet(Verb).initEmpty();
    for (requests) |one| {
        seen.insert(std.meta.activeTag(one));

        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try one.write(&writer);
        const line = writer.buffered();
        try testing.expectEqual(@as(u8, '\n'), line[line.len - 1]);

        const back = try Request.parse(line[0 .. line.len - 1]);
        try testing.expectEqual(std.meta.activeTag(one), std.meta.activeTag(back));
        try testing.expectEqualDeep(one, back);
    }

    // Every verb is covered, so adding one to `Verb` and forgetting it here
    // fails rather than passing quietly.
    try testing.expectEqual(std.enums.values(Verb).len, seen.count());
}

test "a message with a tab in it cannot smuggle a field into a request" {
    // `start` takes a project and a message, and a message is text a person or
    // an agent wrote. If an extra tab made the request grow a field, a message
    // could reach a verb that has more of them.
    //
    // Mutation check: change `field` to take the first `count` fields and
    // ignore the rest, and this passes while `answer` becomes forgeable by
    // anything that can write a session identifier.
    try testing.expectError(
        error.BadArguments,
        Request.parse("start /p\thello\textra"),
    );
    try testing.expectError(error.BadArguments, Request.parse("list /p\textra"));
    try testing.expectError(
        error.BadArguments,
        Request.parse("answer /p\t01\t1\tyes\textra"),
    );
    // And a field short is refused too, rather than read as an empty one.
    try testing.expectError(error.BadArguments, Request.parse("watch /p\t01"));
    try testing.expectError(error.BadArguments, Request.parse("answer /p\t01\t1"));
}

test "a verb has to be a whole word, and every verb is one a client is told about" {
    // The two lists cannot drift, because there is only one: `verbOf`
    // dispatches on `Verb` and `no_verb_text` is built from `Verb`.
    inline for (std.enums.values(Verb)) |verb| {
        const asked = verbOf(@tagName(verb) ++ " the rest of it").?;
        try testing.expectEqual(verb, asked.verb);
        try testing.expectEqualStrings("the rest of it", asked.rest);
        try testing.expect(std.mem.indexOf(u8, no_verb_text, @tagName(verb)) != null);
    }

    // Without the trailing space, `started` would be read as `start` with a
    // rest of `ed ...`, and the client would get a fault about a project
    // directory it never wrote.
    try testing.expect(verbOf("started /p\tmessage") == null);
    try testing.expect(verbOf("listen /p") == null);
    try testing.expect(verbOf("watched /p") == null);
    try testing.expect(verbOf("answered /p") == null);
    try testing.expect(verbOf("") == null);
    try testing.expect(verbOf("list") == null);
    try testing.expectError(error.NoVerb, Request.parse("nonsense /p"));
}

test "a reply line reads back as what was written, records included" {
    const replies = [_]Reply{
        .{ .ok = "answered" },
        .{ .failed = "this daemon started no session with that identifier" },
        .{ .record = .{ .id = 0, .payload = "{\"chock\":1}" } },
        .{ .record = .{ .id = 4096, .payload = "{\"id\":4096}" } },
    };
    for (replies) |one| {
        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try one.write(&writer);
        const line = writer.buffered();
        const back = try Reply.parse(line[0 .. line.len - 1]);
        try testing.expectEqualDeep(one, back);
    }

    // A record's payload may hold a tab of its own, and only the first one is
    // the separator. A log line is JSON, which escapes a tab, so this is a
    // guard and not a case Chock produces.
    const split = try Reply.parse("7\ta\tb");
    try testing.expectEqual(@as(u64, 7), split.record.id);
    try testing.expectEqualStrings("a\tb", split.record.payload);

    try testing.expectError(error.Malformed, Reply.parse("no tab here"));
    try testing.expectError(error.Malformed, Reply.parse("notanumber\tpayload"));
}

test "a listing row survives a daemon that grew a field and a client that has not" {
    // Both halves of the compatibility rule in one drive. **A frontend is
    // built and deployed apart from the daemon it talks to**, which is the
    // whole point of the split, so a listing must not stop parsing because one
    // side moved first.
    const gpa = testing.allocator;

    const row = SessionRow{
        .id = "01JQ" ++ "A" ** 22,
        .started_ms = 1_700_000_000_000,
        .model = "claude-opus-5",
        .model_alias = "main",
        .live = "live",
        .turns = 3,
        .chain = "intact",
        .chain_events = 12,
        .chain_chained = 12,
    };
    const text = try row.toJson(gpa);
    defer gpa.free(text);

    var parsed = try SessionRow.fromJson(gpa, text);
    defer parsed.deinit();
    try testing.expectEqualStrings(row.id, parsed.value.id);
    try testing.expectEqualStrings("live", parsed.value.live);
    try testing.expectEqualStrings("intact", parsed.value.chain);
    try testing.expectEqual(@as(u64, 3), parsed.value.turns);

    // A field the daemon grew and this client has never heard of.
    const newer =
        \\{"id":"01JQAAAAAAAAAAAAAAAAAAAAAA","live":"idle","something_new":{"a":1}}
    ;
    var older = try SessionRow.fromJson(gpa, newer);
    defer older.deinit();
    try testing.expectEqualStrings("idle", older.value.live);
    // And a field the daemon did not send keeps a default that is never a
    // pass. Mutation check: default `chain` to `intact` and a client shows a
    // sound chain for a log nothing verified.
    try testing.expectEqualStrings("unreadable", older.value.chain);
    try testing.expect(!older.value.readable == false);
}

test "a row's chain default is never a pass, and every verdict has a name" {
    // `unreadable` is the default because an absent answer is never a
    // permissive answer, which is the same rule a policy keeps. A row that
    // arrived with no chain field must not read as intact.
    const bare = SessionRow{ .id = "x" };
    try testing.expectEqualStrings(@tagName(chain.Verdict.unreadable), bare.chain);
    try testing.expect(!std.mem.eql(u8, bare.chain, @tagName(chain.Verdict.intact)));

    // Every verdict travels under its own name, so a client can switch over
    // them without a catch all that would swallow a new one.
    var names: [std.enums.values(chain.Verdict).len][]const u8 = undefined;
    for (std.enums.values(chain.Verdict), 0..) |verdict, index| {
        names[index] = verdictName(verdict);
        for (names[0..index]) |other| try testing.expect(!std.mem.eql(u8, other, names[index]));
    }
}

test "an exchange sends one line and reads every line back, and stops when told" {
    // The client loop, driven over buffers. **This is the seam**: a test of the
    // real code with no socket at all.
    var out_buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    const greeting = std.fmt.comptimePrint(
        "{s}{d}\n",
        .{ Greeting.answer_prefix, protocol_version },
    );
    const script = greeting ++
        "0\t{\"chock\":1}\n" ++
        "128\t{\"id\":128}\n" ++
        "256\t{\"id\":256}\n";
    var reader = std.Io.Reader.fixed(script);

    const Collected = struct {
        ids: [8]u64 = @splat(0),
        count: usize = 0,
        stop_after: usize = 8,

        fn take(self: *@This(), reply: Reply) anyerror!bool {
            self.ids[self.count] = reply.record.id;
            self.count += 1;
            return self.count < self.stop_after;
        }
    };

    var all = Collected{};
    var said: Handshake = .{ .unreadable = "" };
    try exchange(&reader, &writer, .{ .watch = .{
        .project = "/p",
        .session = "01JQ" ++ "A" ** 22,
        .after = 0,
    } }, &said, &all, Collected.take);

    // The greeting went first and the request after it, each whole and each
    // ending in a newline.
    try testing.expectEqualStrings(
        std.fmt.comptimePrint("{s}{d}\n", .{ Greeting.ask_prefix, protocol_version }) ++
            "watch /p\t01JQAAAAAAAAAAAAAAAAAAAAAA\t0\n",
        writer.buffered(),
    );
    try testing.expectEqual(protocol_version, said.agreed);
    // **The greeting is not handed to `each`.** A caller counting records must
    // not have to know the handshake happened.
    try testing.expectEqual(@as(usize, 3), all.count);
    try testing.expectEqual(@as(u64, 0), all.ids[0]);
    try testing.expectEqual(@as(u64, 256), all.ids[2]);

    // And a caller that stops reading stops the loop, which is what makes a
    // `watch` a client can walk away from. Mutation check: ignore the answer
    // from `each` and a browser that closed its tab keeps this reading for
    // ever.
    var early = Collected{ .stop_after = 2 };
    var again = std.Io.Reader.fixed(script);
    var second_out: [256]u8 = undefined;
    var second = std.Io.Writer.fixed(&second_out);
    try exchange(&again, &second, .{ .list = .{ .project = "/p" } }, &said, &early, Collected.take);
    try testing.expectEqual(@as(usize, 2), early.count);
}

test "an exchange asks nothing of a daemon whose number this build does not speak" {
    // **The whole point of the greeting, at the seam every client goes
    // through.** A daemon that speaks another number must be left alone, and
    // the client must be able to say which two numbers disagreed.
    //
    // Mutation check: check only that the answer starts with `Greeting
    // .answer_prefix` and drop the `accepts` call, which is exactly the fault
    // `lib/chock-pcsc/linux/driver.zig` measured against a real `pcscd`, and
    // this test fails on both counts below: the handshake reads as agreed and
    // the request goes out.
    const Nothing = struct {
        fn take(_: *@This(), _: Reply) anyerror!bool {
            return true;
        }
    };
    var nothing = Nothing{};

    const older = std.fmt.comptimePrint("{s}{d}\n", .{ Greeting.answer_prefix, protocol_version + 1 });
    var reader = std.Io.Reader.fixed(older ++ "0\t{\"chock\":1}\n");
    var out_buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    var said: Handshake = .{ .unreadable = "" };
    try testing.expectError(error.HandshakeFailed, exchange(
        &reader,
        &writer,
        .{ .list = .{ .project = "/p" } },
        &said,
        &nothing,
        Nothing.take,
    ));

    try testing.expect(!said.ok());
    try testing.expectEqual(protocol_version, said.mismatch.ours);
    try testing.expectEqual(protocol_version + 1, said.mismatch.theirs);

    // **Nothing but the greeting went out.** A daemon this build will not speak
    // to was never asked to start, adopt or answer anything.
    try testing.expectEqualStrings(
        std.fmt.comptimePrint("{s}{d}\n", .{ Greeting.ask_prefix, protocol_version }),
        writer.buffered(),
    );

    // And the sentence names both numbers, so a person knows which end to
    // update rather than only that something is wrong.
    var text_buffer: [512]u8 = undefined;
    var text = std.Io.Writer.fixed(&text_buffer);
    try handshakeRefusal(&text, .{ .unix = "/run/user/1000/chock/daemon.sock" }, said);
    const sentence = text.buffered();
    var ours_text: [16]u8 = undefined;
    var theirs_text: [16]u8 = undefined;
    try testing.expect(std.mem.indexOf(
        u8,
        sentence,
        try std.fmt.bufPrint(&ours_text, "{d}", .{protocol_version}),
    ) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        sentence,
        try std.fmt.bufPrint(&theirs_text, "{d}", .{protocol_version + 1}),
    ) != null);
    try testing.expect(std.mem.indexOf(u8, sentence, "daemon.sock") != null);
}

test "a daemon older than the greeting is named as one, and so is anything else" {
    // **What a newer client meets in the field.** A daemon built before this
    // greeting reads `hello ...` as a verb it has no case for and answers
    // `no_verb_text`. That has to reach a person as words and not as a parse
    // failure, which is the whole complaint the greeting answers.
    const Nothing = struct {
        fn take(_: *@This(), _: Reply) anyerror!bool {
            return true;
        }
    };
    var nothing = Nothing{};
    var out_buffer: [256]u8 = undefined;

    {
        var reader = std.Io.Reader.fixed(error_prefix ++ no_verb_text ++ "\n");
        var writer = std.Io.Writer.fixed(&out_buffer);
        var said: Handshake = .{ .unreadable = "" };
        try testing.expectError(error.HandshakeFailed, exchange(
            &reader,
            &writer,
            .{ .list = .{ .project = "/p" } },
            &said,
            &nothing,
            Nothing.take,
        ));
        try testing.expectEqualStrings(no_verb_text, said.refused);

        var text_buffer: [1024]u8 = undefined;
        var text = std.Io.Writer.fixed(&text_buffer);
        try handshakeRefusal(&text, .{ .ip = .{ .host = "10.0.0.4", .port = 7373 } }, said);
        try testing.expect(std.mem.indexOf(u8, text.buffered(), no_verb_text) != null);
        try testing.expect(std.mem.indexOf(u8, text.buffered(), "10.0.0.4:7373") != null);
    }

    // A peer the daemon turned away for another reason is the same shape, and
    // its own sentence travels whole rather than being replaced by a guess.
    {
        var reader = std.Io.Reader.fixed(error_prefix ++ "this daemon serves the user that started it\n");
        var writer = std.Io.Writer.fixed(&out_buffer);
        var said: Handshake = .{ .unreadable = "" };
        try testing.expectError(error.HandshakeFailed, exchange(
            &reader,
            &writer,
            .{ .list = .{ .project = "/p" } },
            &said,
            &nothing,
            Nothing.take,
        ));
        try testing.expectEqualStrings("this daemon serves the user that started it", said.refused);
    }

    // Something that is not this protocol at all, which is what a client that
    // reached the wrong port meets.
    {
        var reader = std.Io.Reader.fixed("HTTP/1.1 400 Bad Request\n");
        var writer = std.Io.Writer.fixed(&out_buffer);
        var said: Handshake = .{ .unreadable = "" };
        try testing.expectError(error.HandshakeFailed, exchange(
            &reader,
            &writer,
            .{ .list = .{ .project = "/p" } },
            &said,
            &nothing,
            Nothing.take,
        ));
        try testing.expectEqualStrings("HTTP/1.1 400 Bad Request", said.unreadable);
    }

    // And a daemon that said nothing at all, which is a socket that was closed
    // between the accept and the answer.
    {
        var reader = std.Io.Reader.fixed("");
        var writer = std.Io.Writer.fixed(&out_buffer);
        var said: Handshake = .{ .unreadable = "" };
        try testing.expectError(error.HandshakeFailed, exchange(
            &reader,
            &writer,
            .{ .list = .{ .project = "/p" } },
            &said,
            &nothing,
            Nothing.take,
        ));
        try testing.expectEqualStrings("", said.unreadable);
    }
}

test "a greeting round trips, each side has its own spelling, and only equal numbers agree" {
    // **The two spellings differ**, so a daemon cannot be made to read its own
    // answer back as a client's greeting.
    var buffer: [128]u8 = undefined;

    inline for ([_]Greeting.Side{ .ask, .answer }) |side| {
        const other: Greeting.Side = if (side == .ask) .answer else .ask;
        for ([_]u32{ 0, 1, protocol_version, 4_294_967_295 }) |number| {
            var writer = std.Io.Writer.fixed(&buffer);
            try (Greeting{ .version = number }).write(side, &writer);
            const line = writer.buffered();
            try testing.expectEqual(@as(u8, '\n'), line[line.len - 1]);

            const bare = line[0 .. line.len - 1];
            try testing.expectEqual(number, (try Greeting.parse(side, bare)).version);
            try testing.expectError(error.NotAGreeting, Greeting.parse(other, bare));
        }
    }

    // A line that is not a greeting is refused rather than read as version
    // zero, which would be a number two ends could agree on by accident.
    for ([_][]const u8{
        "",
        "hello",
        "hello chock-control",
        "hello chock-control ",
        "hello chock-control one",
        "hello chock-control -1",
        "hello chock-control 4294967296",
        "hello something-else 1",
        "start /p\tmessage",
        error_prefix ++ "no",
    }) |line| {
        try testing.expectError(error.NotAGreeting, Greeting.parse(.ask, line));
    }
    try testing.expectError(error.NotAGreeting, Greeting.parse(.answer, ok_prefix ++ "answered"));

    // **Equal and nothing else.** Mutation check: make `accepts` answer true
    // whenever `theirs` is not greater than `ours`, which is the window a
    // reader reaches for first, and this fails: a client would then speak a
    // grammar an older daemon does not have.
    try testing.expect(accepts(protocol_version, protocol_version));
    try testing.expect(!accepts(protocol_version, protocol_version + 1));
    try testing.expect(!accepts(protocol_version + 1, protocol_version));
    try testing.expect(!accepts(1, 0));
    try testing.expect(!accepts(0, 1));
}

test "the version on the wire is the protocol's own number and not the program's" {
    // **The decision, pinned where somebody would otherwise undo it.** A wire
    // number tied to `build.zig.zon` would make every release read as a wire
    // break, so a person would learn to ignore the refusal.
    //
    // Mutation check: set `protocol_version` from the program's version text
    // and this fails, because that text is `0.1.0` and not a number.
    try testing.expectEqual(u32, @TypeOf(protocol_version));
    try testing.expect(protocol_version >= 1);

    // And a daemon's own refusal names both numbers as well, which is what a
    // client too old to check anything still reads.
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writeMismatch(&writer, 1, 7);
    const said = writer.buffered();
    try testing.expect(std.mem.startsWith(u8, said, error_prefix));
    try testing.expect(std.mem.indexOf(u8, said, " 1 ") != null);
    try testing.expect(std.mem.indexOf(u8, said, " 7") != null);
    // It is one line, because a reply line is one line.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, said, "\n"));

    // The sentence for a first line that is not a greeting says what a client
    // has to open with, so a person is not left to read this file for it.
    try testing.expect(std.mem.indexOf(u8, no_greeting_text, Greeting.ask_prefix) != null);
}

test "a daemon that is not running is a plain refusal that names what to do" {
    // **The one every first time user meets.** It has to say what is wrong and
    // what to type, and the sentence differs by address: a unix socket says
    // start a daemon, and an address a person typed says check that address.
    //
    // No network: `refusalFor` takes the error rather than making one, which is
    // why it is a function of its own.
    var buffer: [512]u8 = undefined;

    {
        var writer = std.Io.Writer.fixed(&buffer);
        try refusalFor(&writer, .{ .unix = "/run/user/1000/chock/daemon.sock" }, error.NotListening);
        const said = writer.buffered();
        try testing.expect(std.mem.indexOf(u8, said, "unix:/run/user/1000/chock/daemon.sock") != null);
        try testing.expect(std.mem.indexOf(u8, said, "chock daemon") != null);
    }
    {
        var writer = std.Io.Writer.fixed(&buffer);
        try refusalFor(&writer, .{ .ip = .{ .host = "10.0.0.4", .port = 7373 } }, error.NotListening);
        const said = writer.buffered();
        try testing.expect(std.mem.indexOf(u8, said, "10.0.0.4:7373") != null);
        try testing.expect(std.mem.indexOf(u8, said, "--host") != null);
    }

    // Every reason a connect can fail says something, and each one names the
    // address. A `catch` that fell through to an empty sentence is the fault
    // this pins. Written over the error set itself so a reason added later is
    // checked the day it lands.
    inline for (@typeInfo(Address.ConnectError).error_set.?) |one| {
        var writer = std.Io.Writer.fixed(&buffer);
        const err = @field(Address.ConnectError, one.name);
        try refusalFor(&writer, .{ .ip = .{ .host = "127.0.0.1", .port = 7373 } }, err);
        try testing.expect(std.mem.indexOf(u8, writer.buffered(), "127.0.0.1:7373") != null);
        try testing.expect(writer.buffered().len > 20);
    }
}

test "a daemon somebody stopped reads as one that is not listening" {
    // **The ordinary way a daemon goes away, and it was wrong at first.** A
    // process killed by a signal runs no deferred code, so its unix socket file
    // stays. A connect to that file gives `ECONNREFUSED`, and
    // `std.Io.net.UnixAddress.ConnectError` has no member for it, so it arrives
    // as `Unexpected`. Measured, on a real stopped daemon: the first reading of
    // this printed "could not be reached" where the right sentence is "start a
    // daemon".
    //
    // Driven through `classify` rather than a real refused connect, because a
    // refused unix connect makes the standard library print a stack trace on
    // standard error in a debug build, and a test suite must not do that to its
    // own output. See `test/proto/lock.zig`, which guards a silent build log.
    //
    // Mutation check: fold the unix `Unexpected` back into `Unreachable` and a
    // person whose daemon was stopped is told to check their network.
    const unix = Address{ .unix = "/run/user/1000/chock/daemon.sock" };
    const ip = Address{ .ip = .{ .host = "127.0.0.1", .port = 7373 } };

    try testing.expectEqual(Address.ConnectError.NotListening, unix.classify(error.Unexpected));
    try testing.expectEqual(Address.ConnectError.NotListening, unix.classify(error.FileNotFound));
    try testing.expectEqual(Address.ConnectError.NotListening, ip.classify(error.ConnectionRefused));

    // A TCP error set does name `ConnectionRefused`, so an unnamed failure
    // there really is something else and must not be reported as a daemon
    // nobody started.
    try testing.expectEqual(Address.ConnectError.Unreachable, ip.classify(error.Unexpected));
    try testing.expectEqual(Address.ConnectError.Unreachable, ip.classify(error.NetworkDown));

    // And a socket this user may not open is its own answer, because starting a
    // second daemon would not fix it.
    try testing.expectEqual(Address.ConnectError.AccessDenied, unix.classify(error.AccessDenied));
    try testing.expectEqual(Address.ConnectError.AccessDenied, unix.classify(error.PermissionDenied));
}

test "the socket path is under the state directory and nowhere near a project" {
    // A daemon serves every project of one user, so its socket belongs to the
    // user. A socket inside a project would be a path a sandboxed tool call
    // could name, which is the rule `lib/chock-broker/socket.zig` keeps for the
    // approval socket.
    const gpa = testing.allocator;
    const path = try socketPathIn(gpa, "/home/ross/.local/state/chock");
    defer gpa.free(path);
    try testing.expectEqualStrings("/home/ross/.local/state/chock/" ++ socket_name, path);
}

/// A directory below `TMPDIR`, and socket paths of an exact length inside it.
///
/// **`std.testing.tmpDir` makes its directory below the build directory, and on
/// macos inside a Nix build that is already past the bound.** What
/// `max_socket_path` bounds is the whole path, so a bench that cannot build a
/// path of exactly the bound proves nothing about the bound.
/// `lib/chock-broker/socket.zig` has the same bench, and it cannot be shared:
/// `chock-proto` sits below `chock-broker` and may not import it.
const BoundBench = struct {
    parent: std.Io.Dir,
    sub: [sub_len]u8,
    dir_path: [std.fs.max_path_bytes]u8,
    dir_len: usize,

    /// The same count `std.testing.tmpDir` uses, so a name here is as unlikely
    /// to collide as one there.
    const random_bytes_count = 12;
    const sub_len = std.base64.url_safe.Encoder.calcSize(random_bytes_count);

    /// Make the directory, or answer `error.SkipZigTest` on a machine where no
    /// socket could live in it at all.
    fn open(io: std.Io) !BoundBench {
        const root = root: {
            const given = std.process.Environ.getPosix(testing.environ, "TMPDIR") orelse "/tmp";
            const trimmed = std.mem.trimEnd(u8, given, "/");
            break :root if (trimmed.len == 0) "/" else trimmed;
        };

        var self: BoundBench = undefined;
        var random_bytes: [random_bytes_count]u8 = undefined;
        io.random(&random_bytes);
        _ = std.base64.url_safe.Encoder.encode(&self.sub, &random_bytes);

        const written = try std.fmt.bufPrint(&self.dir_path, "{s}/{s}", .{ root, &self.sub });
        self.dir_len = written.len;
        // A separator and one character of file name. A machine with less room
        // than that holds no socket at all, and a skip is the honest answer
        // rather than a failure.
        if (self.dir_len + 2 > max_socket_path) return error.SkipZigTest;

        self.parent = try std.Io.Dir.cwd().openDir(io, root, .{});
        errdefer self.parent.close(io);
        var made = try self.parent.createDirPathOpen(io, &self.sub, .{});
        made.close(io);
        return self;
    }

    /// A socket path of exactly `want` bytes in that directory, written into
    /// `buffer`.
    fn pathOfLength(self: *const BoundBench, buffer: []u8, want: usize) []const u8 {
        const path = buffer[0..want];
        @memcpy(path[0..self.dir_len], self.dir_path[0..self.dir_len]);
        path[self.dir_len] = '/';
        @memset(path[self.dir_len + 1 ..], 'n');
        return path;
    }

    fn cleanup(self: *BoundBench, io: std.Io) void {
        self.parent.deleteTree(io, &self.sub) catch {};
        self.parent.close(io);
        self.* = undefined;
    }
};

test "the daemon binds and is reached at exactly the bound, and refuses one byte more" {
    // **Both ends of `Address`, because `std` copies the path into `sun_path` at
    // both.** `chock daemon` binds through `Address.listen` and `chock serve`,
    // `chock approve` and `chock detach` all reach it through `Address.connect`,
    // and until 2026-08-25 each one called `std.Io.net.UnixAddress.init`, whose
    // only bound is `max_len`.
    //
    // Mutation check: make `max_socket_path` read
    // `std.Io.net.UnixAddress.max_len`. On Darwin the first half ends the whole
    // test binary inside `listen`, because `addressUnixToPosix` copies 108
    // bytes into a 104 byte field. **On Linux both halves still pass**, since
    // `std` binds and connects an unterminated 108 at either end, which is why
    // the same suite has to run on a Mac and why the bound itself is pinned by
    // the last test in this file.
    const io = testing.io;

    var bench = try BoundBench.open(io);
    defer bench.cleanup(io);

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const at_bound = bench.pathOfLength(&buffer, max_socket_path);
    try testing.expectEqual(max_socket_path, at_bound.len);

    var listener = try (Address{ .unix = at_bound }).listen(io);
    defer listener.close(io);

    const stream = try (Address{ .unix = at_bound }).connect(io);
    stream.close(io);

    // One byte more is a refusal a caller can read, and never a copy past the
    // end of `sun_path`.
    var over_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const over = bench.pathOfLength(&over_buffer, max_socket_path + 1);
    try testing.expectError(
        Address.ListenError.PathTooLong,
        (Address{ .unix = over }).listen(io),
    );
    try testing.expectError(
        Address.ConnectError.PathTooLong,
        (Address{ .unix = over }).connect(io),
    );
}

test "the refusal a person reads names this platform's own bound and not 108" {
    // The sentence said 108 on every platform. On Darwin the true number is
    // 103, and the five bytes it was wrong about are the ones that reach an
    // `@memcpy` past the end of `sun_path`, so a person shortening a path to
    // 108 would still meet the fault.
    //
    // Mutation check: write the number out as text again and this fails on
    // macos and passes on Linux.
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try refusalFor(&writer, .{ .unix = "/tmp/x.sock" }, error.PathTooLong);

    var number: [8]u8 = undefined;
    try testing.expect(std.mem.indexOf(
        u8,
        writer.buffered(),
        try std.fmt.bufPrint(&number, "{d}", .{max_socket_path}),
    ) != null);
}

test "the bound always leaves room inside sun_path for the closing zero" {
    // **Two properties in one line, and the second is what makes the bound the
    // same rule on both platforms.**
    //
    // Memory safety: `max_len` is a flat 108 everywhere but Windows and
    // `sun_path` is 104 bytes on Darwin, so `std` copies past the end of the
    // field for a path of 105 to 108. Nothing Chock hands it may reach that.
    //
    // Reachability: a path that fills the field to its last byte leaves nowhere
    // for the zero, so only a caller that sends the whole field with no
    // terminator can name it. Measured with raw `bind(2)`: Linux binds such a
    // path at 108 and no terminated `connect` reaches it, which is the same
    // fault that rules out 104 on Darwin. So the comparison is strict.
    //
    // `test/sandbox/darwin_escape.zig` and `test/pcsc/pcscd.zig` read the same
    // field, because neither test target may import this module, and this is
    // what says the two readings agree.
    //
    // Mutation check: make `max_socket_path` read `UnixAddress.max_len` and
    // this fails on **both** platforms, because 108 is not below 108 on Linux
    // and not below 104 on Darwin.
    try testing.expect(max_socket_path < sun_path_bytes);
}
