//! The production lsp.Server: a language server in the sandbox, over a
//! helper.Helper, speaking the Language Server Protocol on descriptors 0
//! and 1.

const std = @import("std");
const helper = @import("helper.zig");
const lsp = @import("lsp.zig");
const mcp = @import("mcp.zig");

pub const file_name = "chock.zon";

pub const max_file_bytes = 1 << 20;

pub const max_source_bytes = 1 << 20;

pub const max_inbox_bytes = 4 << 20;

pub const action_prefix = "lsp";

pub const max_name_bytes: usize = mcp.max_name_bytes;

pub const max_action_bytes = action_prefix.len + 1 + max_name_bytes;

pub const policy_tool = "language_server";

pub fn programLabel(command: []const []const u8) ?[]const u8 {
    if (command.len == 0) return null;
    const program = command[0];
    const cut = if (std.mem.lastIndexOfScalar(u8, program, '/')) |at|
        program[at + 1 ..]
    else
        program;
    if (!mcp.nameIsUsable(cut)) return null;
    return cut;
}

pub fn actionInto(buffer: []u8, command: []const []const u8) ?[]const u8 {
    const label = programLabel(command) orelse return null;
    return std.fmt.bufPrint(buffer, action_prefix ++ ".{s}", .{label}) catch null;
}

pub const Settings = struct {
    command: []const []const u8,
    suffixes: []const []const u8,
};

const WireServer = struct {
    command: []const []const u8 = &.{},
    suffixes: []const []const u8 = &.{},
};

pub const ParseError = error{
    OutOfMemory,
    InvalidLanguageServers,
};

pub const LoadError = ParseError || error{
    LanguageServerFileTooLarge,
    ReadFailed,
};

pub const Diagnostic = union(enum) {
    file_not_zon: std.zon.parse.Diagnostics,
    block_not_valid: std.zon.parse.Diagnostics,
    not_a_struct_literal,
    more_than_one: usize,
    empty_command,
    no_suffixes,
    file_too_large: usize,
    read_failed: anyerror,

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

fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

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

    if (wire.len == 0) return null;
    if (wire.len > 1) {
        _ = note(diag, .{ .more_than_one = wire.len });
        return error.InvalidLanguageServers;
    }
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

const empty_object = struct {}{};

pub const Encoding = enum {
    utf8,
    utf16,
    utf32,

    pub fn fromWire(name: []const u8) ?Encoding {
        if (std.mem.eql(u8, name, "utf-8")) return .utf8;
        if (std.mem.eql(u8, name, "utf-16")) return .utf16;
        if (std.mem.eql(u8, name, "utf-32")) return .utf32;
        return null;
    }
};

pub const offered_encodings: []const []const u8 = &.{ "utf-8", "utf-16" };

pub const start_failed = "it could not be started";
pub const stopped_answering = "it stopped answering, so nothing checks the rest of this session";

pub const Driver = struct {
    gpa: std.mem.Allocator,

    process: *helper.Helper,

    request: helper.Request,

    work_root: []const u8,

    sandbox_root: []const u8,

    inbox: std.ArrayList(u8) = .empty,

    ready: bool = false,

    encoding: Encoding = .utf16,

    last_id: i64 = 0,

    version: i64 = 0,

    opened: std.StringHashMapUnmanaged(void) = .empty,

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
                if (self.failure == null) self.failure = stopped_answering;
                break :blk .{ .unavailable = self.failure.? };
            },
        };
    }

    const Exchange = error{ Gone, Late } || std.mem.Allocator.Error;

    fn exchange(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        ask: lsp.Ask,
        deadline: std.Io.Clock.Timestamp,
    ) Exchange!lsp.Answer {
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

        self.discardStale(io, channel);

        const uri = try self.uriFor(arena, ask.path);
        self.version += 1;
        if (self.opened.contains(uri)) {
            try self.send(arena, io, channel, .{
                .jsonrpc = "2.0",
                .method = "textDocument/didChange",
                .params = .{
                    .textDocument = .{ .uri = uri, .version = self.version },
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
            try self.opened.put(self.gpa, try self.gpa.dupe(u8, uri), {});
        }

        return .{ .reported = try self.collect(arena, io, channel, uri, text, deadline) };
    }

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
                .processId = @as(?i64, null),
                .rootUri = root_uri,
                .capabilities = .{
                    .general = .{ .positionEncodings = offered_encodings },
                    .textDocument = .{ .publishDiagnostics = empty_object },
                },
            },
        }, deadline);

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
            if (!std.mem.eql(u8, published.string, uri)) continue;

            const list = params.object.get("diagnostics") orelse continue;
            if (list != .array) continue;
            const path = self.relativePath(try pathFromUri(arena, published.string));
            return try self.convert(arena, list.array.items, path, text);
        }
    }

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

            const line = countFrom(start.object.get("line")) orelse continue;
            const character = countFrom(start.object.get("character")) orelse continue;
            const column = byteColumn(text, self.encoding, line, character);

            const message = object.get("message") orelse continue;
            if (message != .string) continue;

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

    fn relativePath(self: *const Driver, path: []const u8) []const u8 {
        var root = self.sandbox_root;
        while (root.len > 1 and root[root.len - 1] == '/') root = root[0 .. root.len - 1];
        if (!std.mem.startsWith(u8, path, root)) return path;
        if (path.len == root.len) return path;
        if (path[root.len] != '/') return path;
        return path[root.len + 1 ..];
    }

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

    fn readSource(
        self: *const Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        path: []const u8,
    ) ?[]const u8 {
        const full = std.fs.path.join(arena, &.{ self.work_root, path }) catch return null;
        return std.Io.Dir.cwd().readFileAlloc(io, full, arena, .limited(max_source_bytes)) catch null;
    }

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
            error.Late, error.HelperGone => error.Gone,
        };
    }

    fn receive(
        self: *Driver,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
    ) Exchange!std.json.Value {
        while (true) {
            if (try self.takeMessage(arena)) |body| {
                const parsed = std.json.parseFromSlice(std.json.Value, arena, body, .{}) catch continue;
                return parsed.value;
            }

            var scratch: [4096]u8 = undefined;
            const count = channel.read(io, &scratch, deadline) catch |err| return switch (err) {
                error.Late => error.Late,
                error.HelperGone => error.Gone,
            };
            if (self.inbox.items.len + count > max_inbox_bytes) {
                channel.poisoned = true;
                return error.Gone;
            }
            try self.inbox.appendSlice(self.gpa, scratch[0..count]);
        }
    }

    fn takeMessage(self: *Driver, arena: std.mem.Allocator) std.mem.Allocator.Error!?[]const u8 {
        while (true) {
            const front = self.frameFront() orelse return null;
            const range = front orelse continue;
            const body = try arena.dupe(u8, self.inbox.items[range.body_start..range.end]);
            self.inbox.replaceRange(self.gpa, 0, range.end, &.{}) catch unreachable;
            return body;
        }
    }

    const Range = struct { body_start: usize, end: usize };

    fn frameFront(self: *Driver) ??Range {
        const separator = "\r\n\r\n";
        const head_end = std.mem.indexOf(u8, self.inbox.items, separator) orelse return null;

        const length = contentLengthOf(self.inbox.items[0..head_end]) orelse {
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

    fn discardStale(self: *Driver, io: std.Io, channel: *helper.Channel) void {
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

fn contentLengthOf(headers: []const u8) ?usize {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "Content-Length")) continue;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        return std.fmt.parseInt(usize, value, 10) catch null;
    }
    return null;
}

fn countFrom(value: ?std.json.Value) ?u32 {
    const raw = value orelse return null;
    if (raw != .integer) return null;
    if (raw.integer < 0) return null;
    if (raw.integer >= std.math.maxInt(u32)) return null;
    return @intCast(raw.integer + 1);
}

fn encodingOf(reply: std.json.ObjectMap) ?Encoding {
    const result = reply.get("result") orelse return null;
    if (result != .object) return null;
    const capabilities = result.object.get("capabilities") orelse return null;
    if (capabilities != .object) return null;
    const named = capabilities.object.get("positionEncoding") orelse return null;
    if (named != .string) return null;
    return Encoding.fromWire(named.string);
}

fn byteColumn(text: []const u8, encoding: Encoding, line: u32, character: u32) u32 {
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

    const offset = index + (target - units);
    if (offset >= std.math.maxInt(u32)) return character;
    return @intCast(offset + 1);
}

fn characterAt(source: []const u8) ?struct { bytes: usize, utf16_units: u32 } {
    const length = std.unicode.utf8ByteSequenceLength(source[0]) catch return null;
    if (length > source.len) return null;
    const point = std.unicode.utf8Decode(source[0..length]) catch return null;
    return .{ .bytes = length, .utf16_units = if (point >= 0x10000) 2 else 1 };
}

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

fn objectOf(value: std.json.Value) ?std.json.ObjectMap {
    if (value != .object) return null;
    return value.object;
}

fn languageIdFor(path: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, path, '.') orelse return "plaintext";
    if (dot + 1 >= path.len) return "plaintext";
    return path[dot + 1 ..];
}

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

const testing = std.testing;

test "a project that names no language server has no settings, and no block is the same answer" {
    const gpa = testing.allocator;

    try testing.expect(try parse(gpa, ".{}", null) == null);
    try testing.expect(try parse(gpa, ".{ .subagents = .{ .max_width = 2 } }", null) == null);
    try testing.expect(try parse(gpa, ".{ .language_servers = .{} }", null) == null);
}

test "the program and the suffixes come from the file, and the model never sees the file" {
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
    var driver = Driver{
        .gpa = testing.allocator,
        .process = undefined,
        .request = undefined,
        .work_root = "/host/work",
        .sandbox_root = "/srv/project",
    };

    try testing.expectEqualStrings("src/main.zig", driver.relativePath("/srv/project/src/main.zig"));
    try testing.expectEqualStrings("/nix/store/zig/std/mem.zig", driver.relativePath("/nix/store/zig/std/mem.zig"));
    try testing.expectEqualStrings("/srv/project-old/x.zig", driver.relativePath("/srv/project-old/x.zig"));
}

test "a header block with no Content-Length names no message" {
    try testing.expectEqual(@as(?usize, 42), contentLengthOf("Content-Length: 42"));
    try testing.expectEqual(@as(?usize, 42), contentLengthOf("content-length:42\r\nContent-Type: x"));
    try testing.expectEqual(@as(?usize, null), contentLengthOf("Content-Type: x"));
    try testing.expectEqual(@as(?usize, null), contentLengthOf("Content-Length: soon"));
}

test "the protocol counts from zero and a diagnostic counts from one" {
    try testing.expectEqual(@as(?u32, 1), countFrom(.{ .integer = 0 }));
    try testing.expectEqual(@as(?u32, 88), countFrom(.{ .integer = 87 }));
    try testing.expectEqual(@as(?u32, null), countFrom(null));
    try testing.expectEqual(@as(?u32, null), countFrom(.{ .integer = -1 }));
    try testing.expectEqual(@as(?u32, null), countFrom(.{ .string = "3" }));
    try testing.expectEqual(@as(?u32, null), countFrom(.{ .integer = std.math.maxInt(u32) }));
}

const FakeServer = struct {
    reads: std.Io.File,
    writes: std.Io.File,
    io: std.Io,
    diagnostics: []const u8,
    published: std.atomic.Value(bool) = .init(false),
    inbox: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,
    opened_uri: []const u8 = "",
    encoding: ?[]const u8 = null,
    before_reply: []const u8 = "",
    before_publish: []const u8 = "",
    stale_publication: bool = false,
    saw_close: std.atomic.Value(bool) = .init(false),
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

fn closeRig(rig: *Rig, io: std.Io) void {
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

fn framedLiteral(comptime body: []const u8) []const u8 {
    return std.fmt.comptimePrint("Content-Length: {d}\r\n\r\n{s}", .{ body.len, body });
}

fn framedWithType(comptime body: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "Content-Length: {d}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n{s}",
        .{ body.len, body },
    );
}

test "every message this driver sends is one a server with a typed parser accepts" {
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

    const second = (try session.afterWrite(gpa, io, "src/main.zig")) orelse
        return error.TestUnexpectedResult;
    defer gpa.free(second);
    try testing.expectEqualStrings(first, second);

    const third = (try session.afterWrite(gpa, io, "src/main.zig")) orelse
        return error.TestUnexpectedResult;
    defer gpa.free(third);
    try testing.expectEqualStrings(first, third);
}

test "a column is a byte offset whatever units the server counted in" {
    const gpa = testing.allocator;
    const io = testing.io;

    const source = "const a = \"\u{1F363}\"; const x = 1\n";

    const cases = [_]struct { named: ?[]const u8, character: u32 }{
        .{ .named = "utf-8", .character = 28 },
        .{ .named = "utf-16", .character = 26 },
        .{ .named = "utf-32", .character = 25 },
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
    const gpa = testing.allocator;
    const io = testing.io;

    const before_reply = comptime framedLiteral(
        \\{"jsonrpc":"2.0","id":"server-1","method":"window/showMessageRequest","params":{"type":1,"message":"hi"}}
    ) ++
        framedLiteral(
            \\{"jsonrpc":"2.0","id":1,"method":"window/workDoneProgress/create","params":{"token":"t"}}
        ) ++
        "Content-Type: application/json\r\n\r\n" ++
        framedLiteral(
            \\{"jsonrpc":"2.0","method":"$/progress","params":{"token":"t","value":{"kind":"begin","title":"indexing"}}}
        );

    const before_publish = comptime framedLiteral("this is not a message") ++
        framedLiteral("[1,2,3]") ++
        framedLiteral(
            \\{"jsonrpc":"2.0","method":"telemetry/event","params":{"kind":"parse","ms":4}}
        ) ++
        framedLiteral(
            \\{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{"uri":"file:///srv/project/other.zig","diagnostics":[{"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":1}},"severity":1,"message":"somebody else's problem"}]}}
        ) ++
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

    const block = (try session.afterWrite(gpa, io, "src/main.zig")) orelse
        return error.TestUnexpectedResult;
    defer gpa.free(block);

    try testing.expect(std.mem.startsWith(u8, block, "[chock: 1 problem after this edit]\n"));
    try testing.expect(std.mem.indexOf(u8, block, "src/main.zig:1:11: error: expected ';'") != null);
    try testing.expect(std.mem.indexOf(u8, block, "somebody else's problem") == null);
}

test "a project directory with no chock.zon, and one whose file names no server, both have none" {
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

    try tmp.dir.writeFile(io, .{
        .sub_path = file_name,
        .data = ".{ .language_servers = .{ .{ .command = .{\"zls\"}, .suffixes = .{\".zig\"} } } }\n",
    });
    const settings = (try load(gpa, io, root, null)).?;
    defer freeSettings(gpa, settings);
    try testing.expectEqualStrings("zls", settings.command[0]);
}

test "a server that stopped answering is unavailable once, and never asked again" {
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
    try testing.expect(try session.afterWrite(gpa, io, "src/main.zig") == null);
}

test "a language server's action name is its program, and a path does not change it" {
    var buffer: [max_action_bytes]u8 = undefined;

    try testing.expectEqualStrings("lsp.zls", actionInto(&buffer, &.{"zls"}).?);
    try testing.expectEqualStrings("lsp.zls", actionInto(&buffer, &.{"/nix/store/aaa/bin/zls"}).?);
    try testing.expectEqualStrings(
        "lsp.rust-analyzer",
        actionInto(&buffer, &.{ "/usr/bin/rust-analyzer", "--stdio" }).?,
    );
}

test "a program that cannot be one label of a rule gets no action name at all" {
    var buffer: [max_action_bytes]u8 = undefined;

    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, &.{"node.js"}));
    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, &.{"zls*"}));
    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, &.{""}));
    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, &.{}));
    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, &.{"/usr/bin/"}));
}
