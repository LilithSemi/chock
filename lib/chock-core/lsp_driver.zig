//! The production `lsp.Server`: a real language server, in the sandbox, over a
//! `helper.Helper`, speaking the Language Server Protocol on descriptors 0 and
//! 1.
//!
//! `lib/chock-core/lsp.zig` is everything above the seam and holds every
//! decision this file only carries out: where the server runs, why the agent
//! cannot drive it, how much reaches the model, and what a session with no
//! server costs. Read that file first.
//!
//! ## The file's text goes on the wire, and the file is still the truth
//!
//! `lsp.Ask` carries a path and no content, deliberately, and that stays true.
//! The protocol has no way to ask about a file without opening it, and an open
//! document's text is the client's to supply, so this driver reads the file
//! **at the moment of the ask** and sends the whole of it.
//!
//! That is not a second source of truth. Every ask reads the file again and
//! replaces the whole document, so the server's copy is never merged with
//! anything and never older than the last ask. The file it reads is the one
//! the tool just wrote, through the same workspace the sandbox mounts.
//!
//! **A document is opened once and never closed**, and an earlier version of
//! this driver closed it at the end of every ask, for what read as a good
//! reason: a server that holds no copy between two asks has no copy to drift.
//! Measured against `zls` 0.16 on 2026-08-22, that was the worst fault this
//! file has had. A real server **publishes an empty diagnostic list for a
//! document the moment it is told the document is closed**, and that empty
//! list names the very URI the next ask is about, so the next ask read it as
//! its own answer and the model was told the file it had just broken was
//! clean. Every edit of one file after the first, silently, for the rest of
//! the session.
//!
//! So the close is gone, `didChange` carries every later ask, and
//! `Driver.discardStale` throws away anything the server said before an ask
//! rather than after it. Both are needed: the second alone is a race against a
//! server that has not finished writing.
//!
//! ## One capability is read, and it is the one that changes what a number
//! means
//!
//! **A real `zls` counts the `character` of a position in UTF-16 code units**,
//! which is the protocol's own default and was measured against `zls` 0.16 on
//! 2026-08-22. A driver that copied that number into a column told a model the
//! wrong place on every line that holds a character above ASCII, and told it
//! the right place on every line that does not, which is the shape of fault
//! that survives a test suite written over ASCII.
//!
//! So `initialize` now offers `utf-8` first and `utf-16` after it, and the
//! reply's own `positionEncoding` decides how `character` is read: see
//! `Encoding` and `byteColumn`. `zls` answers `utf-8` and the conversion then
//! does nothing, and a server that answers nothing at all leaves the
//! protocol's own default in place and the conversion really runs.
//!
//! **This is the only thing a capability changes**, and it changes the meaning
//! of a number rather than what this driver does. Nothing else in the reply is
//! read, and no capability decides which requests are sent.
//!
//! ## A late reply is dropped and the bytes are kept
//!
//! `lsp.zig` says a diagnostic that arrives too late is dropped, never waited
//! for, and `Channel.read` is built so that dropping one costs nothing: the
//! reply is still in the pipe and `inbox` still holds whatever was read, so
//! the next ask consumes it. A driver that threw its buffer away on a timeout
//! would read the tail of one reply as the head of the next.
//!
//! **A message this driver did not ask for is skipped, not refused.** A real
//! server logs, publishes progress, and asks the client questions of its own.
//! None of that is an error, and a driver that treated an unknown method as
//! one would give up on the first server that says hello.

const std = @import("std");
const helper = @import("helper.zig");
const lsp = @import("lsp.zig");

/// The name of the configuration file, in the project root. The same file
/// `lib/chock-policy/table.zig` and `lib/chock-policy/subagents.zig` read, and
/// the same split: this reader is strict inside its own block and says nothing
/// about any other.
pub const file_name = "chock.zon";

/// The largest `chock.zon` this reader accepts, matching every other reader of
/// the same file: it comes from the project directory, so a hostile project
/// supplies it.
pub const max_file_bytes = 1 << 20;

/// The largest source file whose text this driver puts on the wire.
///
/// One mebibyte. Above it the ask answers `unsupported`, which says nothing to
/// the model, rather than spending the time to copy a file that is not source
/// code into a server that will not thank anybody for it.
pub const max_source_bytes = 1 << 20;

/// The most this driver will hold of a reply that has not finished arriving.
///
/// **A bound is needed because the sender is a third party program.** A server
/// that publishes a header with no body, or a `Content-Length` it never
/// fulfils, would otherwise grow this buffer until the machine complains. Four
/// mebibytes is far above any real reply: `lsp.max_shown` means twelve
/// diagnostics reach the model, and a server that publishes four hundred still
/// writes well under this.
pub const max_inbox_bytes = 4 << 20;

/// What one project says about its language server.
///
/// **One server, and the block is a list anyway.** `lsp.Session` holds one
/// program and one suffix set, so a reader that accepted a list and used the
/// first entry would silently ignore what an author wrote. It refuses a second
/// entry instead, and the list shape is already right for the day a second
/// server is really supported.
pub const Settings = struct {
    /// The program and its arguments, program first. **From the project and
    /// never from the model.**
    command: []const []const u8,
    /// The file suffixes this server serves, for example `.zig`. Handed
    /// straight to `lsp.Session.suffixes`, which is what decides whether the
    /// seam is reached at all.
    suffixes: []const []const u8,
};

/// The shape one entry of the block is parsed into.
const WireServer = struct {
    command: []const []const u8 = &.{},
    suffixes: []const []const u8 = &.{},
};

pub const ParseError = error{
    OutOfMemory,
    /// The file is not valid ZON, or the `language_servers` block does not
    /// match the schema. Pass a `Diagnostic` to learn which line, and why.
    InvalidLanguageServers,
};

pub const LoadError = ParseError || error{
    /// The file is larger than `max_file_bytes`.
    LanguageServerFileTooLarge,
    /// The file exists and could not be read.
    ReadFailed,
};

/// What went wrong while the `language_servers` block was read, and the facts
/// the error name alone throws away. The same shape, and the same ownership
/// rule, as `chock_policy.subagents.Diagnostic`: the two ZON variants own the
/// syntax trees their message points into, so a caller that receives one must
/// call `deinit`.
pub const Diagnostic = union(enum) {
    /// The file is not valid ZON at all.
    file_not_zon: std.zon.parse.Diagnostics,
    /// The file is valid ZON, and this block does not match the schema.
    block_not_valid: std.zon.parse.Diagnostics,
    /// The top level of the file is not a struct literal.
    not_a_struct_literal,
    /// The block names more than one server. See `Settings`.
    more_than_one: usize,
    /// An entry names no program to start.
    empty_command,
    /// An entry serves no file, so nothing would ever reach it.
    no_suffixes,
    /// The file is larger than `max_file_bytes`, so it was not read.
    file_too_large: usize,
    /// The file exists and the read failed. The fault is the filesystem's.
    read_failed: anyerror,

    /// Release what the diagnostic owns. Safe on every variant.
    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .file_not_zon, .block_not_valid => |*zon_diag| zon_diag.deinit(gpa),
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .file_not_zon => |*zon_diag| try writer.print(
                "{s} is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .block_not_valid => |*zon_diag| try writer.print(
                "{s}: the language_servers block is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{file_name},
            ),
            .more_than_one => |count| try writer.print(
                "{s}: the language_servers block names {d} servers, and this build runs one",
                .{ file_name, count },
            ),
            .empty_command => try writer.print(
                "{s}: a language_servers entry names no command to run",
                .{file_name},
            ),
            .no_suffixes => try writer.print(
                "{s}: a language_servers entry names no suffixes, so nothing would reach it",
                .{file_name},
            ),
            .file_too_large => |limit| try writer.print(
                "{s}: the file is larger than {d} bytes, so it was not read",
                .{ file_name, limit },
            ),
            .read_failed => |err| try writer.print(
                "{s}: the file could not be read: {t}",
                .{ file_name, err },
            ),
        }
    }
};

/// Fill `out` when the caller asked for one, and say whether it took `value`.
/// The first fault is kept, not the last. The answer matters because two
/// variants own memory.
fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// Read the `language_servers` block out of `source`, the whole content of a
/// `chock.zon`. **Null is the ordinary answer**: a project that named no
/// server has none, every ask answers `unsupported` before the seam is
/// touched, and the session costs exactly what it cost before this file
/// existed.
///
/// The result borrows nothing from `source` and is owned by `gpa`. Give an
/// arena that outlives the session, the way every other reader of this file
/// is given one.
pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!?Settings {
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    var ast_owned = true;
    defer if (ast_owned) ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        if (note(diag, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidLanguageServers;
    }

    const node = try findBlockNode(zoir, diag) orelse return null;

    var zon_diag: std.zon.parse.Diagnostics = .{};
    // From here the diagnostics own the two trees, the same handover
    // `lib/chock-policy/subagents.zig` makes.
    ast_owned = false;
    zoir_owned = false;
    var zon_diag_owned = true;
    defer if (zon_diag_owned) zon_diag.deinit(gpa);

    const wire = std.zon.parse.fromZoirNodeAlloc(
        []const WireServer,
        gpa,
        ast,
        zoir,
        node,
        &zon_diag,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            if (note(diag, .{ .block_not_valid = zon_diag })) zon_diag_owned = false;
            return error.InvalidLanguageServers;
        },
    };
    defer std.zon.parse.free(gpa, wire);

    // A block that is there and empty is the same answer as no block at all:
    // this project has no language server.
    if (wire.len == 0) return null;
    if (wire.len > 1) {
        _ = note(diag, .{ .more_than_one = wire.len });
        return error.InvalidLanguageServers;
    }
    // A mistake in the file is reported when Chock reads the file, never on
    // the turn the agent happens to write a file.
    if (wire[0].command.len == 0) {
        _ = note(diag, .empty_command);
        return error.InvalidLanguageServers;
    }
    if (wire[0].suffixes.len == 0) {
        _ = note(diag, .no_suffixes);
        return error.InvalidLanguageServers;
    }

    return .{
        .command = try copyStrings(gpa, wire[0].command),
        .suffixes = try copyStrings(gpa, wire[0].suffixes),
    };
}

fn copyStrings(gpa: std.mem.Allocator, from: []const []const u8) std.mem.Allocator.Error![]const []const u8 {
    const to = try gpa.alloc([]const u8, from.len);
    var made: usize = 0;
    errdefer {
        for (to[0..made]) |one| gpa.free(one);
        gpa.free(to);
    }
    for (from, to) |one, *slot| {
        slot.* = try gpa.dupe(u8, one);
        made += 1;
    }
    return to;
}

/// Read `chock.zon` from `project_root` and take its `language_servers` block.
/// A project with no such file has no server, the same answer a file with no
/// such block gets.
pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) LoadError!?Settings {
    const path = try std.fs.path.join(gpa, &.{ project_root, file_name });
    defer gpa.free(path);

    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileNotFound, error.NotDir => return null,
        error.StreamTooLong => {
            _ = note(diag, .{ .file_too_large = max_file_bytes });
            return error.LanguageServerFileTooLarge;
        },
        else => {
            _ = note(diag, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

/// The node of the `language_servers` field at the top of the file. Null when
/// the file has no such field. Every other top level field is skipped, because
/// other milestones own the other blocks of this one file.
fn findBlockNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), "language_servers")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidLanguageServers;
        },
    }
}

/// The JSON object with no fields in it.
///
/// **`.{}` is a tuple in Zig and `std.json.Stringify` writes a tuple as `[]`.**
/// So a `params` written as `.{}` reaches the server as `"params":[]`, and the
/// protocol says every one of them is an object. A server with a typed parser
/// answers a parse error and the whole handshake stops; a server that parses
/// into a generic tree, which is what every test in this file did before a
/// real one ran, never notices.
///
/// Measured against `zls` 0.16 on 2026-08-22: it wrote `ParseError` on its own
/// standard error and answered nothing, so the session reported that the
/// language server had stopped answering and ran on with no diagnostics at
/// all. **The whole feature had never worked against a real server**, and no
/// test in this project could have said so, because both of its servers were
/// written here.
const empty_object = struct {}{};

/// How a server counts the `character` of a position on a line.
///
/// **The protocol's own default is `utf-16`**, which is a count of UTF-16 code
/// units and is neither a byte offset nor a character count: one emoji is two
/// of them. `lsp.Diagnostic.column` is a byte column, because that is what a
/// compiler prints and what a person counts, so the two have to be told apart.
///
/// A client states which encodings it can read in `general.positionEncodings`
/// and the server answers with the one it picked. See `Driver.handshake`.
pub const Encoding = enum {
    /// A byte offset. What this driver asks for, and what `zls` answers.
    utf8,
    /// A UTF-16 code unit offset. **The protocol's default**, so it is what a
    /// server that says nothing is read as.
    utf16,
    /// A codepoint offset.
    utf32,

    /// The encoding a wire name states, or null for a name no member has.
    ///
    /// Null and never a default: the name comes off a wire a third party
    /// program wrote, and a caller that gets null keeps the protocol's own
    /// default rather than this function guessing one.
    pub fn fromWire(name: []const u8) ?Encoding {
        if (std.mem.eql(u8, name, "utf-8")) return .utf8;
        if (std.mem.eql(u8, name, "utf-16")) return .utf16;
        if (std.mem.eql(u8, name, "utf-32")) return .utf32;
        return null;
    }
};

/// The encodings this driver offers, in the order it prefers them.
///
/// **`utf-8` first, because a byte offset is what a diagnostic carries.**
/// `utf-16` is second because the protocol requires every client to read it,
/// and a list that left it out would leave a server free to answer it anyway.
pub const offered_encodings: []const []const u8 = &.{ "utf-8", "utf-16" };

/// The sentence a session reads when the server would not start. Static text,
/// because it is set from a path that has already run out of resources or lost
/// a process, and neither is a good moment to allocate a message.
pub const start_failed = "it could not be started";
/// The sentence a session reads when the server stopped answering part way
/// through. See `helper.Channel`: a channel nothing can resynchronise is
/// poisoned and never reused.
pub const stopped_answering = "it stopped answering, so nothing checks the rest of this session";

/// One language server, from the first ask of a session to the last.
///
/// **Owned by the caller that owns the session**, beside the `helper.Helper`
/// it drives and the `lsp.Session` that drives it.
pub const Driver = struct {
    /// The allocator `inbox` lives in. It outlives one ask by definition, so
    /// it cannot be the arena the seam hands over.
    gpa: std.mem.Allocator,

    /// The helper this driver speaks to. **Not owned**: the caller starts the
    /// session, ends the session, and owns everything that lasts as long.
    process: *helper.Helper,

    /// What to start, if it is not started yet. The sandbox in it is the same
    /// one a tool call gets: see `helper.Request`.
    request: helper.Request,

    /// Where the workspace's own files are **on the host**, so this driver can
    /// read the text of the file it is asking about. A tool call wrote that
    /// file through the mount tree, and this is the other side of that mount.
    work_root: []const u8,

    /// Where the same files are **inside the sandbox**, which is the project's
    /// own real path. Every URI on the wire is built from this, because the
    /// server resolves paths in its own mount namespace and not in ours.
    sandbox_root: []const u8,

    /// Bytes read from the helper and not yet consumed. **It survives an ask
    /// that ran out of budget**, which is the whole reason it is a field: see
    /// this file's own top comment.
    inbox: std.ArrayList(u8) = .empty,

    /// Whether `initialize` and `initialized` have been through.
    ready: bool = false,

    /// How this server counts the `character` of a position, taken from the
    /// reply to `initialize`. **The protocol's own default until a server says
    /// otherwise**, so a server that answers nothing is read the way the
    /// protocol says to read it and not the way this driver would prefer.
    encoding: Encoding = .utf16,

    /// The id of the last request this driver sent, so a reply can be told
    /// from a notification.
    last_id: i64 = 0,

    /// The version number of the last document sent, so a server that keeps
    /// its own record of one never sees the same version twice. One counter
    /// for every document, because the protocol only asks that the number
    /// rises.
    version: i64 = 0,

    /// Every document URI this driver has opened, so a second ask about the
    /// same file changes it rather than opening it twice. The keys are owned
    /// by `gpa` and freed by `deinit`.
    ///
    /// **Nothing is ever removed**, because nothing is ever closed: see this
    /// file's own top comment. The set holds one short string per file the
    /// agent edited in the session, which is the same order of size as the
    /// session's own edit history.
    opened: std.StringHashMapUnmanaged(void) = .empty,

    /// Why the server is finished with, or null while it still works. Static
    /// text: see `start_failed`.
    failure: ?[]const u8 = null,

    pub fn server(self: *Driver) lsp.Server {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = lsp.Server.VTable{ .diagnose = diagnoseFn };

    pub fn deinit(self: *Driver) void {
        self.inbox.deinit(self.gpa);
        var keys = self.opened.keyIterator();
        while (keys.next()) |one| self.gpa.free(one.*);
        self.opened.deinit(self.gpa);
        self.* = undefined;
    }

    fn diagnoseFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        ask: lsp.Ask,
    ) lsp.Error!lsp.Answer {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        if (self.failure) |reason| return .{ .unavailable = reason };

        const deadline = helper.Channel.deadlineIn(io, ask.budget_ns);
        return self.exchange(arena, io, ask, deadline) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.Late => .late,
            error.Gone => blk: {
                // The one place a running server becomes a finished one. Said
                // once by `lsp.Session`, never on every later edit.
                if (self.failure == null) self.failure = stopped_answering;
                break :blk .{ .unavailable = self.failure.? };
            },
        };
    }

    /// What one ask really does. Every failure below is a value in
    /// `lsp.Answer`, and `diagnoseFn` above is the only place that decides
    /// which.
    const Exchange = error{ Gone, Late } || std.mem.Allocator.Error;

    fn exchange(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        ask: lsp.Ask,
        deadline: std.Io.Clock.Timestamp,
    ) Exchange!lsp.Answer {
        // The text first, because a file this driver cannot read is a reason
        // to say nothing at all and there is no point starting a server for
        // it. **`unsupported` and not an empty report**: nothing was asked, so
        // nothing may be presented as a clean answer.
        const text = self.readSource(arena, io, ask.path) orelse return .unsupported;

        if (!self.process.started) {
            self.process.start(io, self.request) catch {
                self.failure = start_failed;
                return error.Gone;
            };
        }
        const channel = self.process.live() orelse {
            self.failure = if (self.failure) |kept| kept else start_failed;
            return error.Gone;
        };

        if (!self.ready) {
            try self.handshake(arena, io, channel, deadline);
            self.ready = true;
        }

        // Nothing the server said before this moment is an answer to this ask.
        // See `discardStale`, and see the fault a real server showed that made
        // it necessary.
        self.discardStale(io, channel);

        const uri = try self.uriFor(arena, ask.path);
        self.version += 1;
        // **Opened once, changed after that, and never closed.** See this
        // file's own top comment for the fault a close produced against a real
        // server. A document that is already open is replaced whole, so the
        // server's copy is the file as it is now and never a merge of two.
        if (self.opened.contains(uri)) {
            try self.send(arena, io, channel, .{
                .jsonrpc = "2.0",
                .method = "textDocument/didChange",
                .params = .{
                    .textDocument = .{ .uri = uri, .version = self.version },
                    // One change covering the whole document, which is the
                    // form a server must accept whatever sync mode it named.
                    .contentChanges = &[_]struct { text: []const u8 }{.{ .text = text }},
                },
            }, deadline);
        } else {
            try self.send(arena, io, channel, .{
                .jsonrpc = "2.0",
                .method = "textDocument/didOpen",
                .params = .{ .textDocument = .{
                    .uri = uri,
                    .languageId = languageIdFor(ask.path),
                    .version = self.version,
                    .text = text,
                } },
            }, deadline);
            // Recorded after the write, so a write that failed does not leave
            // this driver believing a document is open on a server that never
            // heard of it.
            try self.opened.put(self.gpa, try self.gpa.dupe(u8, uri), {});
        }

        // The text goes down with the ask because a column is a byte offset
        // and the wire may not carry one: see `byteColumn`. It is the text
        // this driver just sent, and `collect` answers only the publication
        // for the document it names, so the two never belong to two files.
        return .{ .reported = try self.collect(arena, io, channel, uri, text, deadline) };
    }

    /// `initialize`, then `initialized`. Once per session.
    ///
    /// **Exactly one field of the reply is read: `positionEncoding`.** See
    /// this file's own top comment for the measurement that put it here. It
    /// says how to read a number the server is about to send, and it decides
    /// nothing else: no capability here changes which requests go out, and a
    /// reply with no capabilities at all leaves this driver doing exactly what
    /// it would have done. Anything more would be a second road for a third
    /// party program to change what Chock does.
    fn handshake(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
    ) Exchange!void {
        self.last_id += 1;
        const id = self.last_id;
        const root_uri = try self.uriFor(arena, "");
        try self.send(arena, io, channel, .{
            .jsonrpc = "2.0",
            .id = id,
            .method = "initialize",
            .params = .{
                // Null, and not this process's own pid. The number would mean
                // nothing to a server inside a pid namespace of its own, and a
                // server that acted on it would be watching the wrong process.
                .processId = @as(?i64, null),
                .rootUri = root_uri,
                .capabilities = .{
                    .general = .{ .positionEncodings = offered_encodings },
                    .textDocument = .{ .publishDiagnostics = empty_object },
                },
            },
        }, deadline);

        // Every message until the reply to this id. A server is allowed to log,
        // to report progress, and to ask its own questions first.
        while (true) {
            const message = try self.receive(arena, io, channel, deadline);
            const object = objectOf(message) orelse continue;
            const answered = object.get("id") orelse continue;
            if (answered != .integer or answered.integer != id) continue;
            if (encodingOf(object)) |named| self.encoding = named;
            break;
        }

        try self.send(arena, io, channel, .{
            .jsonrpc = "2.0",
            .method = "initialized",
            .params = empty_object,
        }, deadline);
    }

    /// Read messages until the server publishes diagnostics for `uri`, and
    /// answer what it said. The result is in `arena`, which the caller frees
    /// whole.
    fn collect(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        uri: []const u8,
        text: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Exchange![]const lsp.Diagnostic {
        while (true) {
            const message = try self.receive(arena, io, channel, deadline);
            const object = objectOf(message) orelse continue;

            const method = object.get("method") orelse continue;
            if (method != .string) continue;
            if (!std.mem.eql(u8, method.string, "textDocument/publishDiagnostics")) continue;

            const params = object.get("params") orelse continue;
            if (params != .object) continue;
            const published = params.object.get("uri") orelse continue;
            if (published != .string) continue;
            // A server publishes for every file it knows about, so a
            // publication for another file is somebody else's answer and
            // waiting continues.
            if (!std.mem.eql(u8, published.string, uri)) continue;

            const list = params.object.get("diagnostics") orelse continue;
            if (list != .array) continue;
            // The file every diagnostic in this publication is about. **The
            // protocol names it once, on the publication**, and a diagnostic
            // carries no path of its own, so it is resolved here and handed
            // down rather than looked for on each entry.
            const path = self.relativePath(try pathFromUri(arena, published.string));
            return try self.convert(arena, list.array.items, path, text);
        }
    }

    /// Turn what one `publishDiagnostics` carried into `lsp.Diagnostic`
    /// values.
    ///
    /// **Every field comes off a wire a third party program wrote**, so a
    /// missing one, a wrong type, and a number no `u32` holds are all ordinary
    /// input here and none of them ends anything. An entry this cannot read is
    /// skipped, which loses one line of a report rather than the report.
    fn convert(
        self: *Driver,
        arena: std.mem.Allocator,
        items: []const std.json.Value,
        path: []const u8,
        text: []const u8,
    ) std.mem.Allocator.Error![]const lsp.Diagnostic {
        var out: std.ArrayList(lsp.Diagnostic) = .empty;
        errdefer out.deinit(arena);

        for (items) |item| {
            if (item != .object) continue;
            const object = item.object;

            const range = object.get("range") orelse continue;
            if (range != .object) continue;
            const start = range.object.get("start") orelse continue;
            if (start != .object) continue;

            // **The protocol counts from zero and `lsp.Diagnostic` counts from
            // one**, the way a person and every compiler count, so the
            // addition happens here and the wire's own numbering never leaves
            // this file.
            const line = countFrom(start.object.get("line")) orelse continue;
            const character = countFrom(start.object.get("character")) orelse continue;
            // **A column is a byte offset and `character` may not be one.**
            // See `byteColumn`, and this file's own top comment for the
            // measurement against a real server that made this necessary.
            const column = byteColumn(text, self.encoding, line, character);

            const message = object.get("message") orelse continue;
            if (message != .string) continue;

            // A severity the enum has no member for is read as a warning,
            // which is the safe reading of a diagnostic nothing can classify:
            // see `lsp.Severity.fromWire`, which answers null rather than
            // guessing, and leaves this decision to its caller.
            const severity = blk: {
                const raw = object.get("severity") orelse break :blk lsp.Severity.warning;
                if (raw != .integer) break :blk lsp.Severity.warning;
                break :blk lsp.Severity.fromWire(raw.integer) orelse .warning;
            };

            try out.append(arena, .{
                .path = path,
                .line = line,
                .column = column,
                .severity = severity,
                .message = try arena.dupe(u8, message.string),
            });
        }
        return out.toOwnedSlice(arena);
    }

    /// The workspace relative path a URI names, or the URI itself when it
    /// names nothing inside this workspace.
    ///
    /// **An exact prefix on a whole component.** A server that reports a file
    /// outside the project, such as one in its own standard library, keeps a
    /// path a reader can act on rather than being folded into a relative path
    /// that lies about where it is. `lsp.orderOf` then ranks it below the
    /// edited file, which is where it belongs.
    fn relativePath(self: *const Driver, path: []const u8) []const u8 {
        var root = self.sandbox_root;
        while (root.len > 1 and root[root.len - 1] == '/') root = root[0 .. root.len - 1];
        if (!std.mem.startsWith(u8, path, root)) return path;
        if (path.len == root.len) return path;
        if (path[root.len] != '/') return path;
        return path[root.len + 1 ..];
    }

    /// The `file://` URI of a workspace relative path, inside the sandbox. An
    /// empty `path` gives the workspace root itself, which is what
    /// `initialize` wants.
    fn uriFor(self: *const Driver, arena: std.mem.Allocator, path: []const u8) std.mem.Allocator.Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(arena);
        try out.appendSlice(arena, "file://");
        try appendEncoded(arena, &out, self.sandbox_root);
        if (path.len != 0) {
            if (self.sandbox_root.len == 0 or self.sandbox_root[self.sandbox_root.len - 1] != '/') {
                try out.append(arena, '/');
            }
            try appendEncoded(arena, &out, path);
        }
        return out.toOwnedSlice(arena);
    }

    /// The whole text of one workspace file, from the host side of the mount,
    /// or null when it cannot be read or is larger than `max_source_bytes`.
    fn readSource(
        self: *const Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        path: []const u8,
    ) ?[]const u8 {
        const full = std.fs.path.join(arena, &.{ self.work_root, path }) catch return null;
        return std.Io.Dir.cwd().readFileAlloc(io, full, arena, .limited(max_source_bytes)) catch null;
    }

    /// Write one JSON-RPC message, with its header, in **one** `writeAll`.
    ///
    /// One call and not two, so a failure can never leave a header on the wire
    /// with no body behind it. `helper.Channel.writeAll` poisons the channel on
    /// a partial write for the same reason, one layer down.
    fn send(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        message: anytype,
        deadline: std.Io.Clock.Timestamp,
    ) Exchange!void {
        _ = self;
        const body = try std.json.Stringify.valueAlloc(arena, message, .{});
        const framed = try std.fmt.allocPrint(arena, "Content-Length: {d}\r\n\r\n{s}", .{ body.len, body });
        channel.writeAll(io, framed, deadline) catch |err| return switch (err) {
            // A write that ran out of budget left half a request behind and
            // poisoned the channel, so the helper is finished with even though
            // the reason was a clock. Never `Late`, which would say the session
            // can ask again.
            error.Late, error.HelperGone => error.Gone,
        };
    }

    /// The next whole message from the server, parsed.
    ///
    /// The parsed tree lives in `arena` and so does every string in it, which
    /// is why `convert` copies what it keeps: the arena is the caller's and
    /// goes at the end of the ask, and that is exactly what
    /// `lsp.Server.diagnose` promises.
    fn receive(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
    ) Exchange!std.json.Value {
        while (true) {
            if (try self.takeMessage(arena)) |body| {
                // A message that is not JSON at all is skipped rather than
                // treated as the end of the world: the framing is still in
                // step, because the header said how long it was.
                const parsed = std.json.parseFromSlice(std.json.Value, arena, body, .{}) catch continue;
                return parsed.value;
            }

            var scratch: [4096]u8 = undefined;
            const count = channel.read(io, &scratch, deadline) catch |err| return switch (err) {
                error.Late => error.Late,
                error.HelperGone => error.Gone,
            };
            if (self.inbox.items.len + count > max_inbox_bytes) {
                // A server that sends more than this in one message is one
                // this driver cannot talk to. Poison the channel so nothing
                // tries again with a buffer that is already out of step.
                channel.poisoned = true;
                return error.Gone;
            }
            try self.inbox.appendSlice(self.gpa, scratch[0..count]);
        }
    }

    /// The body of the first whole message in `inbox`, copied into `arena`,
    /// and that message removed. Null when a whole one has not arrived.
    fn takeMessage(self: *Driver, arena: std.mem.Allocator) std.mem.Allocator.Error!?[]const u8 {
        while (true) {
            const front = self.frameFront() orelse return null;
            // A header block this driver could not frame is already gone, and
            // a whole message may be waiting behind it. Looping here rather
            // than answering null is what keeps that message from waiting on
            // a read of bytes the server has no reason to send.
            const range = front orelse continue;
            const body = try arena.dupe(u8, self.inbox.items[range.body_start..range.end]);
            self.inbox.replaceRange(self.gpa, 0, range.end, &.{}) catch unreachable;
            return body;
        }
    }

    const Range = struct { body_start: usize, end: usize };

    /// The range of the first whole message in `inbox`, or null when a whole
    /// one has not arrived. The inner null means a header block this driver
    /// cannot frame was removed and the caller should look again.
    ///
    /// **Nothing is removed for a message that is only partly here.** A reply
    /// is read once `Content-Length` bytes are really there, so a helper that
    /// died mid sentence leaves an incomplete message that is never mistaken
    /// for a whole one.
    fn frameFront(self: *Driver) ??Range {
        const separator = "\r\n\r\n";
        const head_end = std.mem.indexOf(u8, self.inbox.items, separator) orelse return null;

        const length = contentLengthOf(self.inbox.items[0..head_end]) orelse {
            // A header block with no length is not a message this driver can
            // frame. Drop it and carry on with whatever follows: the
            // alternative is to stop reading a server that wrote one odd line.
            self.inbox.replaceRange(self.gpa, 0, head_end + separator.len, &.{}) catch unreachable;
            return @as(?Range, null);
        };
        if (length > max_inbox_bytes) {
            self.inbox.replaceRange(self.gpa, 0, head_end + separator.len, &.{}) catch unreachable;
            return @as(?Range, null);
        }

        const body_start = head_end + separator.len;
        if (self.inbox.items.len < body_start + length) return null;
        return @as(?Range, .{ .body_start = body_start, .end = body_start + length });
    }

    /// Throw away everything the server has already said, before this ask says
    /// anything.
    ///
    /// **A message that arrived before the ask is not an answer to it.** See
    /// this file's own top comment for the fault a real server showed, and
    /// `test/core/lsp_zls_probe.zig`, which asks about one file twice for
    /// exactly this reason.
    ///
    /// It also ends the one edit lag an ask that ran out of budget would
    /// otherwise start: that ask's publication arrives late, and without this
    /// every later ask would answer the one before it, forever.
    ///
    /// **What it does not reach**: a message the server is part way through
    /// writing at this moment. Only whole messages are dropped, because the
    /// head of a partial one is the only thing that can frame the bytes still
    /// to come, so a publication split across this instant is still read as
    /// this ask's answer. The protocol offers no way to close that: a
    /// publication carries an optional document version and `zls` sends none.
    fn discardStale(self: *Driver, io: std.Io, channel: *helper.Channel) void {
        // A deadline that has already passed, so each read answers with
        // whatever is there and never waits. Nothing here measures a duration.
        const past = std.Io.Clock.Timestamp.now(io, .awake);
        var scratch: [4096]u8 = undefined;
        while (self.inbox.items.len <= max_inbox_bytes) {
            const count = channel.read(io, &scratch, past) catch break;
            self.inbox.appendSlice(self.gpa, scratch[0..count]) catch break;
        }

        while (self.frameFront()) |front| {
            const range = front orelse continue;
            self.inbox.replaceRange(self.gpa, 0, range.end, &.{}) catch unreachable;
        }
    }
};

/// The filesystem path a `file://` URI names, with every percent escape
/// decoded. The result is in `arena`.
///
/// **A URI that is not a `file://` one comes back whole.** A server is allowed
/// to publish about something that is not a file at all, and a path invented
/// from one of those would name a file that does not exist. `lsp.samePath`
/// then simply never matches it, which puts it below the edited file in the
/// report, which is right.
///
/// A malformed escape at the end of the string is copied as it is rather than
/// read past the end: the input is written by a third party program.
fn pathFromUri(arena: std.mem.Allocator, uri: []const u8) std.mem.Allocator.Error![]const u8 {
    const scheme = "file://";
    if (!std.mem.startsWith(u8, uri, scheme)) return arena.dupe(u8, uri);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(arena);

    const body = uri[scheme.len..];
    var index: usize = 0;
    while (index < body.len) {
        if (body[index] == '%' and index + 2 < body.len) {
            if (std.fmt.parseInt(u8, body[index + 1 .. index + 3], 16)) |byte| {
                try out.append(arena, byte);
                index += 3;
                continue;
            } else |_| {}
        }
        try out.append(arena, body[index]);
        index += 1;
    }
    return out.toOwnedSlice(arena);
}

/// The `Content-Length` a header block names, or null when it names none or
/// names something that is not a number.
fn contentLengthOf(headers: []const u8) ?usize {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        // The protocol spells the header this way, and a header name is case
        // insensitive by the rule the protocol borrows from HTTP.
        if (!std.ascii.eqlIgnoreCase(name, "Content-Length")) continue;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        return std.fmt.parseInt(usize, value, 10) catch null;
    }
    return null;
}

/// One protocol position turned into the numbering a person reads, or null
/// when the wire held something no position can be built from.
fn countFrom(value: ?std.json.Value) ?u32 {
    const raw = value orelse return null;
    if (raw != .integer) return null;
    if (raw.integer < 0) return null;
    // The protocol has no bound of its own, and a number a `u32` cannot hold
    // names no line in any file anybody edits.
    if (raw.integer >= std.math.maxInt(u32)) return null;
    return @intCast(raw.integer + 1);
}

/// The `positionEncoding` a reply to `initialize` named, or null when it named
/// none. A caller that gets null keeps the protocol's own default.
///
/// Every step is checked, because the whole reply comes off a wire a third
/// party program wrote: a missing field, a field of the wrong type, and a name
/// no member has are all ordinary input here.
fn encodingOf(reply: std.json.ObjectMap) ?Encoding {
    const result = reply.get("result") orelse return null;
    if (result != .object) return null;
    const capabilities = result.object.get("capabilities") orelse return null;
    if (capabilities != .object) return null;
    const named = capabilities.object.get("positionEncoding") orelse return null;
    if (named != .string) return null;
    return Encoding.fromWire(named.string);
}

/// The byte column, counting from one, that a position on `line` names.
///
/// `line` and `character` both count from one already, because `countFrom` has
/// run. `character` counts in whatever `encoding` says, and the answer counts
/// in bytes, which is what `lsp.Diagnostic.column` holds and what a compiler
/// prints.
///
/// **A line this cannot find keeps the number it was given.** The text is the
/// text this driver sent, so a server that reports a line past its end is
/// reporting about something else, and the honest answer there is the server's
/// own number rather than a byte offset invented from the wrong line.
///
/// A byte that starts no valid character counts as one unit, so a file that is
/// not valid UTF-8 still produces a column instead of stopping the walk.
fn byteColumn(text: []const u8, encoding: Encoding, line: u32, character: u32) u32 {
    // A byte offset already, and column one is byte one in every encoding.
    if (encoding == .utf8 or character <= 1) return character;
    const source = lineAt(text, line) orelse return character;

    const target = character - 1;
    var units: u32 = 0;
    var index: usize = 0;
    while (units < target and index < source.len) {
        const width = characterAt(source[index..]) orelse {
            index += 1;
            units += 1;
            continue;
        };
        index += width.bytes;
        units += switch (encoding) {
            .utf16 => width.utf16_units,
            else => 1,
        };
    }

    // A character past the end of the line names one past the last byte, and
    // every unit left over is one byte, which is what an encoder does with a
    // position nothing on the line reaches.
    const offset = index + (target - units);
    if (offset >= std.math.maxInt(u32)) return character;
    return @intCast(offset + 1);
}

/// How wide the character at the front of `source` is, or null when the bytes
/// there are not one.
fn characterAt(source: []const u8) ?struct { bytes: usize, utf16_units: u32 } {
    const length = std.unicode.utf8ByteSequenceLength(source[0]) catch return null;
    if (length > source.len) return null;
    const point = std.unicode.utf8Decode(source[0..length]) catch return null;
    // Every codepoint above the basic plane is a surrogate pair in UTF-16,
    // which is the whole reason a UTF-16 offset is not a character count.
    return .{ .bytes = length, .utf16_units = if (point >= 0x10000) 2 else 1 };
}

/// The text of one line of `text`, counting from one, with any carriage return
/// at its end removed. Null when the text has no such line.
fn lineAt(text: []const u8, line: u32) ?[]const u8 {
    if (line == 0) return null;
    var walk = std.mem.splitScalar(u8, text, '\n');
    var seen: u32 = 0;
    while (walk.next()) |one| {
        seen += 1;
        if (seen != line) continue;
        if (one.len != 0 and one[one.len - 1] == '\r') return one[0 .. one.len - 1];
        return one;
    }
    return null;
}

/// The object of a message, or null when the message is not one. A server that
/// sends an array, a bare number, or null is answered with silence rather than
/// with an error.
fn objectOf(value: std.json.Value) ?std.json.ObjectMap {
    if (value != .object) return null;
    return value.object;
}

/// The language identifier for a path, which is its suffix with no dot.
///
/// **A guess, and it costs nothing when it is wrong.** A server that already
/// serves this suffix, which is the only way this driver is reached at all,
/// decided that from `chock.zon` and not from this string. No table of
/// languages lives here.
fn languageIdFor(path: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, path, '.') orelse return "plaintext";
    if (dot + 1 >= path.len) return "plaintext";
    return path[dot + 1 ..];
}

/// Append `path` to `out`, percent encoding every byte a URI path may not
/// carry raw.
///
/// The unreserved set of RFC 3986, plus `/`, which separates the components of
/// the path itself. Everything else, including a space and every byte above
/// ASCII, is written as `%XX`. A path Chock never chose can hold any of them.
fn appendEncoded(
    arena: std.mem.Allocator,
    out: *std.ArrayList(u8),
    path: []const u8,
) std.mem.Allocator.Error!void {
    const hex = "0123456789ABCDEF";
    for (path) |byte| {
        const plain = switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '_', '~', '/' => true,
            else => false,
        };
        if (plain) {
            try out.append(arena, byte);
            continue;
        }
        try out.append(arena, '%');
        try out.append(arena, hex[byte >> 4]);
        try out.append(arena, hex[byte & 0x0F]);
    }
}

// No test here starts a real language server, and none reads a clock to decide
// anything. The tests that speak the protocol run a peer of their own on a
// thread, over two ordinary pipes, writing the real bytes a server writes: the
// framing, the JSON and the seam are the production ones, so a broken
// serialiser or a broken parser fails here rather than passing on an `eql`
// nobody wrote. The sandbox half, where a real `Sandbox.spawn` starts a real
// helper, is `test/core/lsp.zig`, which is Linux only because `Sandbox.spawn`
// is, and which also runs a real `zls`.
//
// **Three of the tests below exist because that real server found a fault a
// written one cannot**: the empty JSON array, the units a column is counted
// in, and the publication that arrives before the ask it is read as the answer
// to. Each one is checked here as well as there, so a machine with no `zls`,
// and Darwin, still carry the check.

const testing = std.testing;

test "a project that names no language server has no settings, and no block is the same answer" {
    // The first rule of `lsp.zig`: a project with no server must cost nothing.
    // This is where that starts, and all three spellings of "nothing" have to
    // reach it.
    const gpa = testing.allocator;

    try testing.expect(try parse(gpa, ".{}", null) == null);
    try testing.expect(try parse(gpa, ".{ .subagents = .{ .max_width = 2 } }", null) == null);
    try testing.expect(try parse(gpa, ".{ .language_servers = .{} }", null) == null);
}

test "the program and the suffixes come from the file, and the model never sees the file" {
    // The whole safety argument of `lsp.zig`'s own `Session.program`: the
    // program name is the project's. This is the reader that makes it so.
    const gpa = testing.allocator;
    const settings = (try parse(
        gpa,
        \\.{
        \\    .language_servers = .{
        \\        .{ .command = .{ "zls", "--enable-debug-log" }, .suffixes = .{ ".zig", ".zon" } },
        \\    },
        \\}
    ,
        null,
    )).?;
    defer freeSettings(gpa, settings);

    try testing.expectEqual(@as(usize, 2), settings.command.len);
    try testing.expectEqualStrings("zls", settings.command[0]);
    try testing.expectEqualStrings("--enable-debug-log", settings.command[1]);
    try testing.expectEqual(@as(usize, 2), settings.suffixes.len);
    try testing.expectEqualStrings(".zig", settings.suffixes[0]);
    try testing.expectEqualStrings(".zon", settings.suffixes[1]);
}

test "a block this build cannot honour is refused when the file is read, not on the turn it bites" {
    // `Settings`'s own doc comment: one server, and a reader that took the
    // first of two would silently ignore what an author wrote. The other two
    // entries below would each start a server that can never answer.
    const gpa = testing.allocator;

    try testing.expectError(error.InvalidLanguageServers, parse(
        gpa,
        \\.{ .language_servers = .{
        \\    .{ .command = .{"zls"}, .suffixes = .{".zig"} },
        \\    .{ .command = .{"rust-analyzer"}, .suffixes = .{".rs"} },
        \\} }
    ,
        null,
    ));
    try testing.expectError(error.InvalidLanguageServers, parse(
        gpa,
        ".{ .language_servers = .{ .{ .command = .{}, .suffixes = .{\".zig\"} } } }",
        null,
    ));
    try testing.expectError(error.InvalidLanguageServers, parse(
        gpa,
        ".{ .language_servers = .{ .{ .command = .{\"zls\"}, .suffixes = .{} } } }",
        null,
    ));
}

test "a misspelled field is a refusal and never a default" {
    // The same rule every other reader of this file keeps: strict inside its
    // own block. `.commnad` must not read as "no command", which the empty
    // default would otherwise make it.
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    try testing.expectError(error.InvalidLanguageServers, parse(
        gpa,
        ".{ .language_servers = .{ .{ .commnad = .{\"zls\"}, .suffixes = .{\".zig\"} } } }",
        &diag,
    ));
    try testing.expect(diag != null);
}

fn freeSettings(gpa: std.mem.Allocator, settings: Settings) void {
    for (settings.command) |one| gpa.free(one);
    gpa.free(settings.command);
    for (settings.suffixes) |one| gpa.free(one);
    gpa.free(settings.suffixes);
}

test "a URI is built from the sandbox path, and every byte a URI cannot carry is encoded" {
    // The server resolves paths in its own mount namespace, so the URI is the
    // project's real path and never the host side of the mount. A space in a
    // file name is the cheapest proof the encoder runs at all: a raw one makes
    // a URI a strict server refuses.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var driver = Driver{
        .gpa = testing.allocator,
        .process = undefined,
        .request = undefined,
        .work_root = "/host/work",
        .sandbox_root = "/srv/project",
    };

    try testing.expectEqualStrings("file:///srv/project", try driver.uriFor(arena, ""));
    try testing.expectEqualStrings(
        "file:///srv/project/src/main.zig",
        try driver.uriFor(arena, "src/main.zig"),
    );
    try testing.expectEqualStrings(
        "file:///srv/project/a%20b.zig",
        try driver.uriFor(arena, "a b.zig"),
    );
}

test "a path inside the workspace comes back relative, and one outside it keeps its own path" {
    // `lsp.orderOf` ranks the edited file first and compares paths exactly, so
    // a path that came back in the wrong form would put the agent's own file
    // anywhere in the list. A file outside the project keeps its whole path,
    // because folding it into a relative one would say it is somewhere it is
    // not.
    var driver = Driver{
        .gpa = testing.allocator,
        .process = undefined,
        .request = undefined,
        .work_root = "/host/work",
        .sandbox_root = "/srv/project",
    };

    try testing.expectEqualStrings("src/main.zig", driver.relativePath("/srv/project/src/main.zig"));
    try testing.expectEqualStrings("/nix/store/zig/std/mem.zig", driver.relativePath("/nix/store/zig/std/mem.zig"));
    // A prefix that is not a whole component is not inside the project.
    try testing.expectEqualStrings("/srv/project-old/x.zig", driver.relativePath("/srv/project-old/x.zig"));
}

test "a header block with no Content-Length names no message" {
    // The framing is the one thing that keeps a partial reply from being read
    // as a whole one, so the two ways it can be absent both have to answer
    // null rather than a length of zero.
    try testing.expectEqual(@as(?usize, 42), contentLengthOf("Content-Length: 42"));
    try testing.expectEqual(@as(?usize, 42), contentLengthOf("content-length:42\r\nContent-Type: x"));
    try testing.expectEqual(@as(?usize, null), contentLengthOf("Content-Type: x"));
    try testing.expectEqual(@as(?usize, null), contentLengthOf("Content-Length: soon"));
}

test "the protocol counts from zero and a diagnostic counts from one" {
    // The off by one that would put every diagnostic on the wrong line. It is
    // done in exactly one place, and this is that place.
    try testing.expectEqual(@as(?u32, 1), countFrom(.{ .integer = 0 }));
    try testing.expectEqual(@as(?u32, 88), countFrom(.{ .integer = 87 }));
    // Input a third party program wrote: none of these is a position.
    try testing.expectEqual(@as(?u32, null), countFrom(null));
    try testing.expectEqual(@as(?u32, null), countFrom(.{ .integer = -1 }));
    try testing.expectEqual(@as(?u32, null), countFrom(.{ .string = "3" }));
    try testing.expectEqual(@as(?u32, null), countFrom(.{ .integer = std.math.maxInt(u32) }));
}

/// A language server that answers from a table, over two real pipes, in real
/// protocol bytes. **It runs on a thread of its own and frames its own
/// messages**, so the driver under test does the whole of its real job: it
/// writes a header a peer must parse, and it parses a header a peer wrote.
const FakeServer = struct {
    /// The end this server reads requests from, which the driver writes.
    reads: std.Io.File,
    /// The end this server writes replies to, which the driver reads.
    writes: std.Io.File,
    io: std.Io,
    /// The whole `diagnostics` array, as a server would publish it.
    diagnostics: []const u8,
    /// Set once the server has published, so the test can join the thread.
    published: std.atomic.Value(bool) = .init(false),
    inbox: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,
    /// The URI of the document the driver opened, so the publication names the
    /// same one the driver is waiting for. A server that published some other
    /// URI would make the driver wait out its whole budget, which is a real
    /// failure this test would catch.
    opened_uri: []const u8 = "",
    /// What this server names as its `positionEncoding`, or null to name none
    /// and leave the protocol's own default in place.
    encoding: ?[]const u8 = null,
    /// Bytes written **before** the reply to `initialize`, exactly as they
    /// are. A caller frames them itself, or deliberately does not: a header
    /// block with no length is one of the things a driver must survive.
    before_reply: []const u8 = "",
    /// Bytes written after the reply and before the publication, on the same
    /// terms.
    before_publish: []const u8 = "",
    /// Whether this server writes an empty publication for the same URI
    /// straight after the real one, in the same write, which is what a real
    /// server leaves behind when it says something about a document between
    /// two asks. See `Driver.discardStale`.
    stale_publication: bool = false,
    /// Set when the driver told this server to close a document. **Nothing
    /// may**: see this file's own top comment for what a close cost against a
    /// real server. `closeRig` is where it is read.
    saw_close: std.atomic.Value(bool) = .init(false),
    /// Set when a message arrived whose `params` was not a JSON object.
    ///
    /// **A real server has a typed parser and this is what it refuses.** See
    /// `empty_object`: a `params` written as `.{}` reaches the wire as `[]`,
    /// every test here parsed into a generic tree and never minded, and a real
    /// `zls` answered a parse error and nothing else. So the tree is checked
    /// here now, and every protocol test in this file carries the check.
    bad_params: std.atomic.Value(bool) = .init(false),

    fn run(self: *FakeServer) void {
        self.serve() catch {};
        self.published.store(true, .release);
    }

    fn serve(self: *FakeServer) !void {
        while (true) {
            const body = (try self.nextMessage()) orelse return;
            defer self.gpa.free(body);

            const parsed = std.json.parseFromSlice(std.json.Value, self.gpa, body, .{}) catch continue;
            defer parsed.deinit();
            if (parsed.value != .object) continue;
            const object = parsed.value.object;

            // **An empty array anywhere in the message is the fault
            // `empty_object` describes**, at whatever depth it sits. No
            // message this driver sends holds a legitimate empty array, and
            // the one that reached a real server was three levels down inside
            // the client capabilities, so a check that named one field would
            // have missed it.
            if (holdsEmptyArray(parsed.value)) self.bad_params.store(true, .release);

            if (object.get("method")) |method| {
                if (method == .string and std.mem.eql(u8, method.string, "initialize")) {
                    const id = object.get("id").?.integer;
                    const capabilities = if (self.encoding) |named|
                        try std.fmt.allocPrint(self.gpa, "{{\"positionEncoding\":\"{s}\"}}", .{named})
                    else
                        try self.gpa.dupe(u8, "{}");
                    defer self.gpa.free(capabilities);
                    const reply = try std.fmt.allocPrint(
                        self.gpa,
                        "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":{{\"capabilities\":{s}}}}}",
                        .{ id, capabilities },
                    );
                    defer self.gpa.free(reply);
                    // One line of log first, unasked for, the way a real
                    // server does. A driver that treated it as the reply, or
                    // as an error, fails here.
                    try self.write("{\"jsonrpc\":\"2.0\",\"method\":\"window/logMessage\"," ++
                        "\"params\":{\"type\":3,\"message\":\"starting\"}}");
                    try self.raw(self.before_reply);
                    try self.write(reply);
                    continue;
                }
                const opens = method == .string and
                    (std.mem.eql(u8, method.string, "textDocument/didOpen") or
                        std.mem.eql(u8, method.string, "textDocument/didChange"));
                if (opens) {
                    const uri = object.get("params").?.object.get("textDocument").?.object.get("uri").?.string;
                    if (self.opened_uri.len != 0) self.gpa.free(self.opened_uri);
                    self.opened_uri = try self.gpa.dupe(u8, uri);
                    // A publication for another file first, which the driver
                    // must skip rather than answer with.
                    const other = try std.fmt.allocPrint(
                        self.gpa,
                        "{{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/publishDiagnostics\"," ++
                            "\"params\":{{\"uri\":\"file:///elsewhere.zig\",\"diagnostics\":[]}}}}",
                        .{},
                    );
                    defer self.gpa.free(other);
                    try self.write(other);
                    try self.raw(self.before_publish);

                    const publication = try std.fmt.allocPrint(
                        self.gpa,
                        "{{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/publishDiagnostics\"," ++
                            "\"params\":{{\"uri\":\"{s}\",\"diagnostics\":{s}}}}}",
                        .{ uri, self.diagnostics },
                    );
                    defer self.gpa.free(publication);
                    if (self.stale_publication) {
                        // The real publication and an empty one for the same
                        // URI, **in one write**, so the driver's next read has
                        // both and the stale one is really in the buffer when
                        // the next ask starts. That is what a real server
                        // leaves behind when it says something about a
                        // document between two asks, with no race in it.
                        const stale = try std.fmt.allocPrint(
                            self.gpa,
                            "{{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/publishDiagnostics\"," ++
                                "\"params\":{{\"uri\":\"{s}\",\"diagnostics\":[]}}}}",
                            .{uri},
                        );
                        defer self.gpa.free(stale);
                        const both = try std.fmt.allocPrint(
                            self.gpa,
                            "Content-Length: {d}\r\n\r\n{s}Content-Length: {d}\r\n\r\n{s}",
                            .{ publication.len, publication, stale.len, stale },
                        );
                        defer self.gpa.free(both);
                        try self.raw(both);
                        continue;
                    }
                    try self.write(publication);
                    continue;
                }
                if (method == .string and std.mem.eql(u8, method.string, "textDocument/didClose")) {
                    self.saw_close.store(true, .release);
                    return;
                }
            }
        }
    }

    fn write(self: *FakeServer, body: []const u8) !void {
        const framed = try std.fmt.allocPrint(
            self.gpa,
            "Content-Length: {d}\r\n\r\n{s}",
            .{ body.len, body },
        );
        defer self.gpa.free(framed);
        try std.Io.File.writeStreamingAll(self.writes, self.io, framed);
    }

    /// Write bytes with no framing of this server's own, so a test can put a
    /// header block with no length, or something that is not a message at all,
    /// on the wire.
    fn raw(self: *FakeServer, bytes: []const u8) !void {
        if (bytes.len == 0) return;
        try std.Io.File.writeStreamingAll(self.writes, self.io, bytes);
    }

    fn nextMessage(self: *FakeServer) !?[]u8 {
        while (true) {
            if (std.mem.indexOf(u8, self.inbox.items, "\r\n\r\n")) |head_end| {
                if (contentLengthOf(self.inbox.items[0..head_end])) |length| {
                    const start = head_end + 4;
                    if (self.inbox.items.len >= start + length) {
                        const body = try self.gpa.dupe(u8, self.inbox.items[start .. start + length]);
                        try self.inbox.replaceRange(self.gpa, 0, start + length, &.{});
                        return body;
                    }
                }
            }
            var scratch: [1024]u8 = undefined;
            var data: [1][]u8 = .{&scratch};
            const count = std.Io.File.readStreaming(self.reads, self.io, &data) catch return null;
            if (count == 0) return null;
            try self.inbox.appendSlice(self.gpa, scratch[0..count]);
        }
    }

    fn deinit(self: *FakeServer) void {
        self.inbox.deinit(self.gpa);
        if (self.opened_uri.len != 0) self.gpa.free(self.opened_uri);
    }
};

/// Everything one protocol test needs: a workspace with a real file in it, a
/// helper whose channel is two real pipes, and a driver over both.
const Rig = struct {
    tmp: std.testing.TmpDir,
    root_buffer: [std.fs.max_path_bytes]u8 = undefined,
    root_len: usize = 0,
    process: helper.Helper,
    driver: Driver,
    fake: FakeServer,
    thread: std.Thread = undefined,

    fn root(self: *const Rig) []const u8 {
        return self.root_buffer[0..self.root_len];
    }
};

/// What a rig's server does beyond answering, for the tests about a server
/// that behaves in a way this driver never asked for.
const RigOptions = struct {
    encoding: ?[]const u8 = null,
    before_reply: []const u8 = "",
    before_publish: []const u8 = "",
    stale_publication: bool = false,
};

fn openRig(rig: *Rig, gpa: std.mem.Allocator, io: std.Io, source: []const u8, diagnostics: []const u8) !void {
    return openRigWith(rig, gpa, io, source, diagnostics, .{});
}

fn openRigWith(
    rig: *Rig,
    gpa: std.mem.Allocator,
    io: std.Io,
    source: []const u8,
    diagnostics: []const u8,
    options: RigOptions,
) !void {
    rig.tmp = std.testing.tmpDir(.{});
    // `std.testing.tmpDir` hands back a directory only a relative path
    // reaches, and `work_root` has to resolve the same way whatever this test
    // binary's own working directory is. The same helper every other reader of
    // a project directory keeps for the same reason.
    rig.root_len = try rig.tmp.dir.realPath(io, &rig.root_buffer);

    try rig.tmp.dir.createDirPath(io, "src");
    try rig.tmp.dir.writeFile(io, .{ .sub_path = "src/main.zig", .data = source });

    const chock_io = @import("chock-io");
    const driver_io = chock_io.default();
    const requests = try driver_io.pipeCloseOnExec();
    const replies = try driver_io.pipeCloseOnExec();

    rig.process = helper.Helper.init(gpa);
    rig.process.started = true;
    rig.process.channel = .{
        .to_helper = .{ .handle = requests.write_fd, .flags = .{ .nonblocking = false } },
        .from_helper = .{ .handle = replies.read_fd, .flags = .{ .nonblocking = false } },
    };

    rig.fake = .{
        .reads = .{ .handle = requests.read_fd, .flags = .{ .nonblocking = false } },
        .writes = .{ .handle = replies.write_fd, .flags = .{ .nonblocking = false } },
        .io = io,
        .diagnostics = diagnostics,
        .gpa = gpa,
        .encoding = options.encoding,
        .before_reply = options.before_reply,
        .before_publish = options.before_publish,
        .stale_publication = options.stale_publication,
    };

    rig.driver = .{
        .gpa = gpa,
        .process = &rig.process,
        .request = undefined,
        .work_root = rig.root(),
        .sandbox_root = "/srv/project",
    };

    rig.thread = try std.Thread.spawn(.{}, FakeServer.run, .{&rig.fake});
}

/// Close the rig, and **check that every message the driver sent was one a
/// server with a typed parser accepts**. Read after the join, so nothing races
/// the server's own thread.
///
/// This is in the teardown and not in one test on purpose: see
/// `FakeServer.bad_params`. The fault it catches shipped because both of this
/// project's servers parsed into a generic tree, so the check belongs to every
/// protocol test here and not to the one somebody remembers to write it in.
fn closeRig(rig: *Rig, io: std.Io) void {
    // The driver's own end first: the server's read then reaches end of file
    // and its thread returns, so the join below is bounded by the kernel.
    if (rig.process.channel) |channel| std.Io.File.close(channel.to_helper, io);
    rig.thread.join();
    if (rig.fake.bad_params.load(.acquire)) {
        std.debug.panic(
            "the driver sent a message holding an empty JSON array, which a real server refuses",
            .{},
        );
    }
    if (rig.fake.saw_close.load(.acquire)) {
        std.debug.panic(
            "the driver closed a document, and a real server then publishes an empty list for it",
            .{},
        );
    }
    if (rig.process.channel) |channel| std.Io.File.close(channel.from_helper, io);
    std.Io.File.close(rig.fake.reads, io);
    std.Io.File.close(rig.fake.writes, io);
    rig.process.channel = null;
    rig.fake.deinit();
    rig.driver.deinit();
    rig.process.deinit(io);
    rig.tmp.cleanup();
}

test "a real diagnostic arrives through the real seam, framed and parsed both ways" {
    // **The end to end proof, above the sandbox.** Every byte between the
    // driver and the server on this test's two pipes is the protocol: the
    // driver frames and serialises its own `initialize` and `didOpen`, and it
    // parses a header and a JSON body somebody else wrote. Nothing here rests
    // on an `eql` method, which is the thirteenth vacuous shape this project
    // has already caught.
    //
    // The server also sends a log line before its reply and a publication for
    // another file before the real one, so a driver that answered the first
    // message it saw fails here.
    //
    // Mutation check: drop the `+ 1` in `countFrom` and the line and column
    // below are 3 and 8. Compare the published URI with anything looser in
    // `collect` and the answer becomes the empty list belonging to the other
    // file. Send the header and the body as two writes and the framing still
    // works, which is why `send` is checked by the write that fails, in
    // `helper.zig`, and not here.
    const gpa = testing.allocator;
    const io = testing.io;

    var rig: Rig = undefined;
    try openRig(&rig, gpa, io,
        \\const x = 1
    ,
        \\[{"range":{"start":{"line":3,"character":8},"end":{"line":3,"character":9}},
        \\  "severity":1,"message":"expected ';' after declaration"}]
    );
    defer closeRig(&rig, io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const answer = try rig.driver.server().diagnose(arena_state.allocator(), io, .{
        .path = "src/main.zig",
        .budget_ns = 30 * std.time.ns_per_s,
    });

    const list = switch (answer) {
        .reported => |one| one,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(@as(usize, 1), list.len);
    try testing.expectEqualStrings("src/main.zig", list[0].path);
    try testing.expectEqual(@as(u32, 4), list[0].line);
    try testing.expectEqual(@as(u32, 9), list[0].column);
    try testing.expectEqual(lsp.Severity.err, list[0].severity);
    try testing.expectEqualStrings("expected ';' after declaration", list[0].message);
}

test "a diagnostic a real server published reaches the model through lsp.Session" {
    // One step further out than the test above: the whole path a tool call
    // takes, from the seam to the block a model actually reads. This is what
    // "wired" means, and it is the half `lsp.zig` said was missing.
    //
    // Mutation check: answer `.unsupported` from `exchange` and the block is
    // null. Leave `Session.suffixes` empty and the seam is never reached, which
    // the next test is about.
    const gpa = testing.allocator;
    const io = testing.io;

    var rig: Rig = undefined;
    try openRig(&rig, gpa, io,
        \\const x = 1
    ,
        \\[{"range":{"start":{"line":0,"character":10},"end":{"line":0,"character":11}},
        \\  "severity":1,"message":"expected ';'"}]
    );
    defer closeRig(&rig, io);

    var session = lsp.Session{
        .program = "zls",
        .suffixes = &.{".zig"},
        .server = rig.driver.server(),
    };

    const block = (try session.afterWrite(gpa, io, "src/main.zig")).?;
    defer gpa.free(block);

    try testing.expect(std.mem.startsWith(u8, block, "[chock: 1 problem after this edit]\n"));
    try testing.expect(std.mem.indexOf(u8, block, "src/main.zig:1:11: error: expected ';'") != null);
}

test "a file this driver cannot read is asked about at all, so nothing is called clean" {
    // The difference between "the server said the file is fine" and "nothing
    // ran". `reported` with an empty list is the first, and a driver that used
    // it for the second would tell a model its file compiles because the
    // driver could not open it.
    //
    // Mutation check: answer `.{ .reported = &.{} }` for an unreadable file and
    // this test fails, and a model is told a lie on every edit of a file that
    // was moved between the write and the ask.
    const gpa = testing.allocator;
    const io = testing.io;

    var rig: Rig = undefined;
    try openRig(&rig, gpa, io, "const x = 1;", "[]");
    defer closeRig(&rig, io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const answer = try rig.driver.server().diagnose(arena_state.allocator(), io, .{
        .path = "src/never-written.zig",
        .budget_ns = 30 * std.time.ns_per_s,
    });
    try testing.expect(answer == .unsupported);
}

/// Whether any array with nothing in it appears in `value`, at any depth.
///
/// **The signature of a `.{}` that was meant to be an object**: Zig writes an
/// empty tuple as `[]`, and no message this driver sends carries an empty
/// array on purpose. See `empty_object`.
fn holdsEmptyArray(value: std.json.Value) bool {
    switch (value) {
        .array => |items| {
            if (items.items.len == 0) return true;
            for (items.items) |one| {
                if (holdsEmptyArray(one)) return true;
            }
            return false;
        },
        .object => |fields| {
            var walk = fields.iterator();
            while (walk.next()) |entry| {
                if (holdsEmptyArray(entry.value_ptr.*)) return true;
            }
            return false;
        },
        else => return false,
    }
}

/// One message with its header, built at compile time so a test never states a
/// length by hand and never states one that is wrong.
fn framedLiteral(comptime body: []const u8) []const u8 {
    return std.fmt.comptimePrint("Content-Length: {d}\r\n\r\n{s}", .{ body.len, body });
}

/// The same, with a second header behind the length, which is what a server
/// built on the reference implementation really writes.
fn framedWithType(comptime body: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "Content-Length: {d}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n{s}",
        .{ body.len, body },
    );
}

test "every message this driver sends is one a server with a typed parser accepts" {
    // **The fault that made this whole feature not work, found by running a
    // real server and by nothing else.** `.{}` is an empty tuple in Zig and
    // `std.json.Stringify` writes a tuple as `[]`, so the handshake went out
    // with `"params":[]` and `"publishDiagnostics":[]` where the protocol
    // requires objects. Every server in this project parsed into a
    // `std.json.Value` and never minded. `zls` 0.16 wrote `ParseError` and
    // answered nothing, so a session reported that its language server had
    // stopped answering and ran on with no diagnostics for the rest of it.
    //
    // Mutation check: put `.{}` back in either place in `handshake` and this
    // fails, and so does every other protocol test in this file, because the
    // check is in the rig's own teardown: see `closeRig`.
    const gpa = testing.allocator;
    const io = testing.io;

    var rig: Rig = undefined;
    try openRig(&rig, gpa, io, "const x = 1;", "[]");
    defer closeRig(&rig, io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    _ = try rig.driver.server().diagnose(arena_state.allocator(), io, .{
        .path = "src/main.zig",
        .budget_ns = 30 * std.time.ns_per_s,
    });
    try testing.expect(!rig.fake.bad_params.load(.acquire));

    // And the check really can fail, or it would pass for a rig that never
    // looked. Every one of these is a message this driver must never build.
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, "{\"params\":[]}", .{});
    defer parsed.deinit();
    try testing.expect(holdsEmptyArray(parsed.value));
    var nested = try std.json.parseFromSlice(
        std.json.Value,
        gpa,
        "{\"params\":{\"capabilities\":{\"textDocument\":{\"publishDiagnostics\":[]}}}}",
        .{},
    );
    defer nested.deinit();
    try testing.expect(holdsEmptyArray(nested.value));
    // An object with nothing in it is the right shape and must not be caught.
    var fine = try std.json.parseFromSlice(
        std.json.Value,
        gpa,
        "{\"params\":{\"capabilities\":{\"textDocument\":{\"publishDiagnostics\":{}}}}}",
        .{},
    );
    defer fine.deinit();
    try testing.expect(!holdsEmptyArray(fine.value));
}

test "what a server said before an ask is never read as the answer to it" {
    // **The worst fault a real server found**, and the one that reaches a
    // model as a lie rather than as silence. `zls` publishes an empty
    // diagnostic list for a document the moment it is told the document is
    // closed. That empty list names the same URI the next ask is about, so the
    // next ask answered with it, and the model was told that the file it had
    // just broken was clean, for every edit of that file after the first, for
    // the rest of the session.
    //
    // Two things answer it and both are needed. The close is gone, so the
    // server is never given the reason to say it. And anything the server said
    // before an ask is thrown away by `discardStale`, so a server that
    // publishes twice of its own accord, which is ordinary, cannot answer the
    // next question either. **The server below is the second case**: it writes
    // the real publication and an empty one in a single write, so the stale
    // one is really in the buffer when the second ask begins and nothing here
    // races.
    //
    // Mutation check: take out the `discardStale` call in `exchange` and the
    // second ask says nothing at all. Send `didClose` again and every test in
    // this file panics in `closeRig`.
    const gpa = testing.allocator;
    const io = testing.io;

    var rig: Rig = undefined;
    try openRigWith(&rig, gpa, io,
        \\const x = 1
    ,
        \\[{"range":{"start":{"line":0,"character":10},"end":{"line":0,"character":11}},
        \\  "severity":1,"message":"expected ';'"}]
    , .{ .stale_publication = true });
    defer closeRig(&rig, io);

    var session = lsp.Session{
        .program = "zls",
        .suffixes = &.{".zig"},
        .server = rig.driver.server(),
    };

    const first = (try session.afterWrite(gpa, io, "src/main.zig")) orelse
        return error.TestUnexpectedResult;
    defer gpa.free(first);
    try testing.expect(std.mem.indexOf(u8, first, "src/main.zig:1:11: error: expected ';'") != null);

    // The same file again, which is the ordinary case: an agent edits one file
    // several times in a session.
    const second = (try session.afterWrite(gpa, io, "src/main.zig")) orelse
        return error.TestUnexpectedResult;
    defer gpa.free(second);
    try testing.expectEqualStrings(first, second);

    // And a third, so the fix is not one that only survives one repeat.
    const third = (try session.afterWrite(gpa, io, "src/main.zig")) orelse
        return error.TestUnexpectedResult;
    defer gpa.free(third);
    try testing.expectEqualStrings(first, third);
}

test "a column is a byte offset whatever units the server counted in" {
    // **Measured against `zls` 0.16 on 2026-08-22**: with no
    // `general.positionEncodings` from the client it answers
    // `positionEncoding: "utf-16"` and counts a `character` in UTF-16 code
    // units, and with `utf-8` offered it answers `utf-8` and counts bytes.
    // Every column in this project is a byte column, so the two have to be
    // told apart, and a suite written over ASCII never notices because the
    // three encodings agree on every ASCII line.
    //
    // The source below holds one character that is four bytes, two UTF-16
    // code units and one codepoint, so the wire number differs in all three
    // encodings and the answer must not.
    //
    // Mutation check: answer `character` unchanged from `byteColumn` and the
    // UTF-16 case says column 27 rather than 29. Drop `encodingOf` and the
    // UTF-8 case is converted as if it were UTF-16 and says 31. Count a
    // codepoint above the basic plane as one UTF-16 unit and the UTF-16 case
    // says 30.
    const gpa = testing.allocator;
    const io = testing.io;

    const source = "const a = \"\u{1F363}\"; const x = 1\n";

    // The wire number each encoding puts on the same `1`, which is byte 28,
    // UTF-16 unit 26 and codepoint 25, all counting from zero.
    const cases = [_]struct { named: ?[]const u8, character: u32 }{
        .{ .named = "utf-8", .character = 28 },
        .{ .named = "utf-16", .character = 26 },
        .{ .named = "utf-32", .character = 25 },
        // A server that names nothing is read as UTF-16, which is what the
        // protocol says and not what this driver would prefer.
        .{ .named = null, .character = 26 },
    };

    for (cases) |case| {
        const diagnostics = try std.fmt.allocPrint(
            gpa,
            "[{{\"range\":{{\"start\":{{\"line\":0,\"character\":{d}}}," ++
                "\"end\":{{\"line\":0,\"character\":{d}}}}}," ++
                "\"severity\":1,\"message\":\"expected ';' after declaration\"}}]",
            .{ case.character, case.character + 1 },
        );
        defer gpa.free(diagnostics);

        var rig: Rig = undefined;
        try openRigWith(&rig, gpa, io, source, diagnostics, .{ .encoding = case.named });
        defer closeRig(&rig, io);

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();

        const answer = try rig.driver.server().diagnose(arena_state.allocator(), io, .{
            .path = "src/main.zig",
            .budget_ns = 30 * std.time.ns_per_s,
        });
        const list = switch (answer) {
            .reported => |one| one,
            else => return error.TestUnexpectedResult,
        };
        try testing.expectEqual(@as(usize, 1), list.len);
        try testing.expectEqual(@as(u32, 1), list[0].line);
        try testing.expectEqual(@as(u32, 29), list[0].column);
    }
}

test "a server that says things this driver never asked for cannot wedge the session" {
    // **The whole class this test exists for**: a real server logs, reports
    // progress, sends telemetry, asks the client questions of its own, and
    // publishes about files nobody opened. None of it is an error, and a
    // driver that stopped, refused, or lost its place in the framing on any
    // one of them would give up on the first real server it met.
    //
    // Eight separate shapes are on the wire below, and the driver has to walk
    // past all of them and still answer the one publication that was asked
    // for. Note the third one especially: a **request from the server that
    // carries the same id number the driver used**, which is legal because
    // the two sides number their own requests, and which is the message most
    // likely to be read as the reply to `initialize`.
    //
    // Mutation check: treat an unknown method as an error in `collect` and
    // nothing is answered. Treat a body that is not JSON as the end of the
    // stream in `receive` and the same. Drop the header block with no length
    // in `takeMessage` instead of skipping it and the framing goes out of
    // step, so every later message is read from the middle of this one.
    const gpa = testing.allocator;
    const io = testing.io;

    const before_reply = comptime
        // A request from the server with a string id, which no reply of this
        // driver's ever carries.
        framedLiteral(
            \\{"jsonrpc":"2.0","id":"server-1","method":"window/showMessageRequest","params":{"type":1,"message":"hi"}}
        ) ++
        // A request from the server numbered 1, the same number the driver
        // just used for `initialize`.
        framedLiteral(
            \\{"jsonrpc":"2.0","id":1,"method":"window/workDoneProgress/create","params":{"token":"t"}}
        ) ++
        // A header block with no length at all.
        "Content-Type: application/json\r\n\r\n" ++
        framedLiteral(
            \\{"jsonrpc":"2.0","method":"$/progress","params":{"token":"t","value":{"kind":"begin","title":"indexing"}}}
        );

    const before_publish = comptime
        // A framed body that is not JSON.
        framedLiteral("this is not a message") ++
        // A JSON-RPC batch, which is an array and not an object.
        framedLiteral("[1,2,3]") ++
        framedLiteral(
            \\{"jsonrpc":"2.0","method":"telemetry/event","params":{"kind":"parse","ms":4}}
        ) ++
        // A publication for a file nobody opened, carrying a real diagnostic.
        // A driver that answered the first publication it saw reports this
        // one, about a file the agent never touched.
        framedLiteral(
            \\{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{"uri":"file:///srv/project/other.zig","diagnostics":[{"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":1}},"severity":1,"message":"somebody else's problem"}]}}
        ) ++
        // A message with a second header behind the length.
        framedWithType(
            \\{"jsonrpc":"2.0","method":"window/logMessage","params":{"type":4,"message":"still here"}}
        );

    var rig: Rig = undefined;
    try openRigWith(&rig, gpa, io,
        \\const x = 1
    ,
        \\[{"range":{"start":{"line":0,"character":10},"end":{"line":0,"character":11}},
        \\  "severity":1,"message":"expected ';'"}]
    , .{ .before_reply = before_reply, .before_publish = before_publish });
    defer closeRig(&rig, io);

    var session = lsp.Session{
        .program = "zls",
        .suffixes = &.{".zig"},
        .server = rig.driver.server(),
    };

    // A wedged driver answers `late` once the budget runs out, and
    // `afterWrite` turns that into null, so a null here is the failure this
    // test is looking for and not a pass.
    const block = (try session.afterWrite(gpa, io, "src/main.zig")) orelse
        return error.TestUnexpectedResult;
    defer gpa.free(block);

    try testing.expect(std.mem.startsWith(u8, block, "[chock: 1 problem after this edit]\n"));
    try testing.expect(std.mem.indexOf(u8, block, "src/main.zig:1:11: error: expected ';'") != null);
    // And the diagnostic belonging to the file nobody opened is not in it.
    try testing.expect(std.mem.indexOf(u8, block, "somebody else's problem") == null);
}

test "a project directory with no chock.zon, and one whose file names no server, both have none" {
    // The production entry point of `lsp.zig`'s first rule: a project with no
    // server must cost nothing. `parse` is checked above over source text;
    // this is the road `src/run.zig` really takes, which is a directory on
    // disk, and both spellings of "no server" have to come back null there.
    //
    // Mutation check: answer an error rather than null for a missing file in
    // `load` and a project that never asked for a language server stops
    // starting at all.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try tmp.dir.realPath(io, &root_buffer)];

    try testing.expect(try load(gpa, io, root, null) == null);

    try tmp.dir.writeFile(io, .{
        .sub_path = file_name,
        .data = ".{ .subagents = .{ .max_width = 2 } }\n",
    });
    try testing.expect(try load(gpa, io, root, null) == null);

    // And a file that does name one is found by the same call, or the two
    // nulls above would pass for a reader that never reads anything.
    try tmp.dir.writeFile(io, .{
        .sub_path = file_name,
        .data = ".{ .language_servers = .{ .{ .command = .{\"zls\"}, .suffixes = .{\".zig\"} } } }\n",
    });
    const settings = (try load(gpa, io, root, null)).?;
    defer freeSettings(gpa, settings);
    try testing.expectEqualStrings("zls", settings.command[0]);
}

test "a server that stopped answering is unavailable once, and never asked again" {
    // A helper that dies must not leave the session waiting, and must not
    // leave it asking either. The channel is poisoned before the first ask, so
    // this reaches the same state a server that died mid session leaves.
    //
    // Mutation check: leave `failure` unset in `diagnoseFn` and every later
    // edit pays the cost of a start that will never work.
    const gpa = testing.allocator;
    const io = testing.io;

    var rig: Rig = undefined;
    try openRig(&rig, gpa, io, "const x = 1;", "[]");
    defer closeRig(&rig, io);

    rig.process.channel.?.poisoned = true;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const first = try rig.driver.server().diagnose(arena_state.allocator(), io, .{
        .path = "src/main.zig",
        .budget_ns = 30 * std.time.ns_per_s,
    });
    try testing.expect(first == .unavailable);

    // And the second ask answers from the field, without touching a
    // descriptor: `lsp.Session` is what turns the repeat into silence.
    const second = try rig.driver.server().diagnose(arena_state.allocator(), io, .{
        .path = "src/main.zig",
        .budget_ns = 30 * std.time.ns_per_s,
    });
    try testing.expect(second == .unavailable);

    var session = lsp.Session{
        .program = "zls",
        .suffixes = &.{".zig"},
        .server = rig.driver.server(),
    };
    const said = (try session.afterWrite(gpa, io, "src/main.zig")).?;
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "did not start") != null);
    // Said once. The second edit of the session gets the tool result byte for
    // byte as the tool built it.
    try testing.expect(try session.afterWrite(gpa, io, "src/main.zig") == null);
}
