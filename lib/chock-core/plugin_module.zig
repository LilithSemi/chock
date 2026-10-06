//! Reading a plugin out of a WebAssembly module, with no engine at all.

const std = @import("std");

const core = @import("chock-plugin-core");

pub const max_module_bytes: usize = 64 << 20;

pub const max_sections: u32 = 1 << 10;

pub const max_section_entries: u32 = 1 << 16;

pub const max_export_name_bytes: u32 = 1 << 10;

pub const wasm_version: u32 = 1;

pub const wasm_preamble = [_]u8{ 0x00, 'a', 's', 'm' };

pub const ExportKind = enum(u8) {
    function = 0,
    table = 1,
    memory = 2,
    global = 3,

    pub fn name(self: ExportKind) []const u8 {
        return switch (self) {
            .function => "a function",
            .table => "a table",
            .memory => "a memory",
            .global => "a global",
        };
    }
};

pub const Error = core.ParseError || error{
    NotWasm,
    MalformedModule,
    IncompletePlugin,
    UnreadableSymbol,
    AbiDisagrees,
};

pub const Refusal = union(enum) {
    not_wasm: NotWasm,
    unknown_wasm_version: UnknownWasmVersion,
    malformed_module: MalformedModule,
    too_large: TooLarge,
    missing_symbol: MissingSymbol,
    wrong_symbol_kind: WrongSymbolKind,
    unreadable_symbol: UnreadableSymbol,
    abi_disagrees: AbiDisagrees,
    metadata: core.Refusal,

    pub const NotWasm = struct {
        found: []const u8,
    };

    pub const UnknownWasmVersion = struct {
        found: u32,
        speaks: u32,
    };

    pub const MalformedModule = struct {
        what: []const u8,
        at: usize,
    };

    pub const TooLarge = struct {
        what: []const u8,
        found: u64,
        bound: u64,
    };

    pub const MissingSymbol = struct {
        symbol: []const u8,
    };

    pub const WrongSymbolKind = struct {
        symbol: []const u8,
        found: ExportKind,
        expected: ExportKind,
    };

    pub const UnreadableSymbol = struct {
        symbol: []const u8,
        why: []const u8,
    };

    pub const AbiDisagrees = struct {
        symbol_says: u32,
        metadata_says: u32,
    };

    pub fn format(self: Refusal, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .not_wasm => |d| try writer.print(
                "not a WebAssembly module: it starts with {f}, and every module starts with {f}",
                .{ std.ascii.hexEscape(d.found, .lower), std.ascii.hexEscape(&wasm_preamble, .lower) },
            ),
            .unknown_wasm_version => |d| try writer.print(
                "built for WebAssembly binary format {d}, this reader knows {d}",
                .{ d.found, d.speaks },
            ),
            .malformed_module => |d| try writer.print(
                "the module is malformed at byte {d}: {s}",
                .{ d.at, d.what },
            ),
            .too_large => |d| try writer.print(
                "{s} is {d}, above the bound of {d} this reader keeps",
                .{ d.what, d.found, d.bound },
            ),
            .missing_symbol => |d| try writer.print(
                "the module exports no {s}, so it is not a Chock plugin",
                .{d.symbol},
            ),
            .wrong_symbol_kind => |d| try writer.print(
                "the module exports {s} as {s}, and a plugin exports it as {s}",
                .{ d.symbol, d.found.name(), d.expected.name() },
            ),
            .unreadable_symbol => |d| try writer.print(
                "{s} cannot be read without running the module: {s}",
                .{ d.symbol, d.why },
            ),
            .abi_disagrees => |d| try writer.print(
                "the module says it is plugin ABI {d} and its metadata says ABI {d}",
                .{ d.symbol_says, d.metadata_says },
            ),
            .metadata => |d| try d.format(writer),
        }
    }
};

fn note(slot: ?*?Refusal, refusal: Refusal, err: anytype) @TypeOf(err) {
    if (slot) |s| {
        if (s.* == null) s.* = refusal;
    }
    return err;
}

pub const Module = struct {
    abi_word: u32,
    init_function: u32,
    parsed: core.Parsed,

    pub fn record(self: *const Module) core.Metadata {
        return self.parsed.record;
    }

    pub fn deinit(self: Module) void {
        self.parsed.deinit();
    }
};

const Segment = struct {
    addr: u64,
    bytes: []const u8,

    fn end(self: Segment) u64 {
        return self.addr + self.bytes.len;
    }

    fn lessThan(_: void, a: Segment, b: Segment) bool {
        return a.addr < b.addr;
    }
};

const Memory = struct {
    segments: []Segment,

    fn sort(self: *Memory, refusal: ?*?Refusal) Error!void {
        std.mem.sort(Segment, self.segments, {}, Segment.lessThan);
        var previous_end: u64 = 0;
        for (self.segments, 0..) |segment, index| {
            if (index > 0 and segment.addr < previous_end) {
                return note(refusal, .{ .malformed_module = .{
                    .what = "two active data segments cover the same address",
                    .at = index,
                } }, error.MalformedModule);
            }
            previous_end = segment.end();
        }
    }

    fn readInto(self: Memory, addr: u64, out: []u8) bool {
        var cursor = addr;
        var written: usize = 0;
        for (self.segments) |segment| {
            if (written == out.len) break;
            if (segment.end() <= cursor) continue;
            if (segment.addr > cursor) return false;
            const from: usize = @intCast(cursor - segment.addr);
            const take = @min(segment.bytes.len - from, out.len - written);
            @memcpy(out[written..][0..take], segment.bytes[from..][0..take]);
            written += take;
            cursor += take;
        }
        return written == out.len;
    }
};

const Cursor = struct {
    bytes: []const u8,
    at: usize = 0,
    base: usize = 0,
    refusal: ?*?Refusal,

    fn left(self: Cursor) usize {
        return self.bytes.len - self.at;
    }

    fn fault(self: Cursor, what: []const u8) Error {
        return note(self.refusal, .{ .malformed_module = .{
            .what = what,
            .at = self.base + self.at,
        } }, error.MalformedModule);
    }

    fn byte(self: *Cursor, what: []const u8) Error!u8 {
        if (self.left() < 1) return self.fault(what);
        const value = self.bytes[self.at];
        self.at += 1;
        return value;
    }

    fn take(self: *Cursor, want: usize, what: []const u8) Error![]const u8 {
        if (self.left() < want) return self.fault(what);
        const out = self.bytes[self.at..][0..want];
        self.at += want;
        return out;
    }

    fn uleb(self: *Cursor, comptime T: type, what: []const u8) Error!T {
        const bits = @typeInfo(T).int.bits;
        const max_bytes = (bits + 6) / 7;
        var result: u64 = 0;
        var shift: u32 = 0;
        var bytes_read: usize = 0;
        while (true) {
            if (bytes_read == max_bytes) return self.fault(what);
            const b = try self.byte(what);
            bytes_read += 1;
            const payload: u64 = b & 0x7F;
            if (shift >= bits and payload != 0) return self.fault(what);
            if (shift < bits) result |= payload << @intCast(shift);
            if (b & 0x80 == 0) break;
            shift += 7;
        }
        if (result > std.math.maxInt(T)) return self.fault(what);
        return @intCast(result);
    }

    fn sleb32(self: *Cursor, what: []const u8) Error!i32 {
        var result: i64 = 0;
        var shift: u6 = 0;
        var bytes_read: usize = 0;
        while (true) {
            if (bytes_read == 5) return self.fault(what);
            const b = try self.byte(what);
            bytes_read += 1;
            result |= @as(i64, b & 0x7F) << shift;
            shift += 7;
            if (b & 0x80 == 0) {
                if (shift < 64 and b & 0x40 != 0) result |= @as(i64, -1) << shift;
                break;
            }
        }
        if (result < std.math.minInt(i32) or result > std.math.maxInt(i32)) {
            return self.fault(what);
        }
        return @intCast(result);
    }

    fn count(self: *Cursor, what: []const u8) Error!u32 {
        const value = try self.uleb(u32, what);
        const bound: u64 = @min(max_section_entries, self.left());
        if (value > bound) {
            return note(self.refusal, .{ .too_large = .{
                .what = what,
                .found = value,
                .bound = bound,
            } }, error.TooLarge);
        }
        return value;
    }

    fn name(self: *Cursor, what: []const u8) Error![]const u8 {
        const length = try self.uleb(u32, what);
        if (length > max_export_name_bytes) {
            return note(self.refusal, .{ .too_large = .{
                .what = what,
                .found = length,
                .bound = max_export_name_bytes,
            } }, error.TooLarge);
        }
        return self.take(length, what);
    }

    fn blob(self: *Cursor, what: []const u8) Error![]const u8 {
        const length = try self.uleb(u32, what);
        return self.take(length, what);
    }

    fn skipLimits(self: *Cursor, what: []const u8) Error!void {
        const flags = try self.byte(what);
        if (flags > 1) return self.fault(what);
        _ = try self.uleb(u64, what);
        if (flags == 1) _ = try self.uleb(u64, what);
    }

    fn constExpr(self: *Cursor, what: []const u8) Error!?i32 {
        var value: ?i32 = null;
        var opcodes: usize = 0;
        while (true) {
            if (opcodes > 16) return self.fault(what);
            opcodes += 1;
            const op = try self.byte(what);
            switch (op) {
                0x0B => break, // end
                0x41 => value = try self.sleb32(what), // i32.const
                0x42 => _ = try self.uleb(u64, what), // i64.const, sign is not read
                0x43 => _ = try self.take(4, what), // f32.const
                0x44 => _ = try self.take(8, what), // f64.const
                0x23 => _ = try self.uleb(u32, what), // global.get
                0xD0 => _ = try self.byte(what), // ref.null
                0xD2 => _ = try self.uleb(u32, what), // ref.func
                else => return self.fault(what),
            }
        }
        return value;
    }
};

const Export = struct {
    kind: ExportKind,
    index: u32,
};

pub fn read(gpa: std.mem.Allocator, module: []const u8, refusal: ?*?Refusal) Error!Module {
    if (module.len > max_module_bytes) {
        return note(refusal, .{ .too_large = .{
            .what = "the module",
            .found = module.len,
            .bound = max_module_bytes,
        } }, error.TooLarge);
    }
    if (module.len < wasm_preamble.len + 4 or
        !std.mem.eql(u8, module[0..wasm_preamble.len], &wasm_preamble))
    {
        return note(refusal, .{ .not_wasm = .{
            .found = module[0..@min(module.len, wasm_preamble.len)],
        } }, error.NotWasm);
    }
    const version = std.mem.readInt(u32, module[4..8], .little);
    if (version != wasm_version) {
        return note(refusal, .{ .unknown_wasm_version = .{
            .found = version,
            .speaks = wasm_version,
        } }, error.NotWasm);
    }

    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();
    const work = scratch.allocator();

    var exports: std.StringHashMapUnmanaged(Export) = .empty;
    var globals: std.ArrayList(?i32) = .empty;
    var segments: std.ArrayList(Segment) = .empty;
    var imported_globals: u32 = 0;

    var cursor: Cursor = .{ .bytes = module, .at = 8, .refusal = refusal };
    var sections: u32 = 0;
    while (cursor.left() > 0) {
        if (sections == max_sections) {
            return note(refusal, .{ .too_large = .{
                .what = "the section count",
                .found = sections + 1,
                .bound = max_sections,
            } }, error.TooLarge);
        }
        sections += 1;

        const id = try cursor.byte("a section id");
        const size = try cursor.uleb(u32, "a section length");
        const body = try cursor.take(size, "a section body");
        var inner: Cursor = .{
            .bytes = body,
            .base = cursor.at - size,
            .refusal = refusal,
        };
        switch (id) {
            2 => imported_globals = try countImportedGlobals(&inner),
            6 => try readGlobals(work, &inner, &globals),
            7 => try readExports(work, &inner, &exports),
            11 => try readData(work, &inner, &segments),
            else => {},
        }
    }

    var memory: Memory = .{ .segments = segments.items };
    try memory.sort(refusal);

    const magic_address = try addressOf(
        core.Magic.symbol,
        exports,
        globals.items,
        imported_globals,
        refusal,
        error.NotAPlugin,
    );
    const metadata_address = try addressOf(
        core.Metadata.symbol,
        exports,
        globals.items,
        imported_globals,
        refusal,
        error.IncompletePlugin,
    );

    const init_export = exports.get(core.init_symbol) orelse return note(refusal, .{
        .missing_symbol = .{ .symbol = core.init_symbol },
    }, error.IncompletePlugin);
    if (init_export.kind != .function) {
        return note(refusal, .{ .wrong_symbol_kind = .{
            .symbol = core.init_symbol,
            .found = init_export.kind,
            .expected = .function,
        } }, error.IncompletePlugin);
    }

    var abi_bytes: [4]u8 = undefined;
    if (!memory.readInto(magic_address, &abi_bytes)) {
        return note(refusal, .{ .unreadable_symbol = .{
            .symbol = core.Magic.symbol,
            .why = "it points at an address no data segment of the module covers",
        } }, error.UnreadableSymbol);
    }
    const abi_word = std.mem.readInt(u32, &abi_bytes, .little);

    var prefix_bytes: [core.Prefix.len]u8 = undefined;
    if (!memory.readInto(metadata_address, &prefix_bytes)) {
        return note(refusal, .{ .unreadable_symbol = .{
            .symbol = core.Metadata.symbol,
            .why = "it points at an address no data segment of the module covers",
        } }, error.UnreadableSymbol);
    }

    var blob_refusal: ?core.Refusal = null;
    const prefix = core.Prefix.read(&prefix_bytes, &blob_refusal) catch |err| {
        return note(refusal, .{ .metadata = blob_refusal.? }, err);
    };

    if (abi_word != prefix.abi_version) {
        return note(refusal, .{ .abi_disagrees = .{
            .symbol_says = abi_word,
            .metadata_says = prefix.abi_version,
        } }, error.AbiDisagrees);
    }

    const blob = try gpa.alloc(u8, prefix.total_len);
    defer gpa.free(blob);
    if (!memory.readInto(metadata_address, blob)) {
        return note(refusal, .{ .unreadable_symbol = .{
            .symbol = core.Metadata.symbol,
            .why = "the blob it points at runs past the data segments of the module",
        } }, error.UnreadableSymbol);
    }

    const parsed = core.parse(gpa, blob, &blob_refusal) catch |err| {
        return note(refusal, .{ .metadata = blob_refusal.? }, err);
    };

    return .{
        .abi_word = abi_word,
        .init_function = init_export.index,
        .parsed = parsed,
    };
}

pub const Imported = struct {
    module: []const u8,
    field: []const u8,
    kind: u8,
};

pub fn readImports(
    gpa: std.mem.Allocator,
    module: []const u8,
    refusal: ?*?Refusal,
) Error![]const Imported {
    if (module.len < wasm_preamble.len + 4 or
        !std.mem.eql(u8, module[0..wasm_preamble.len], &wasm_preamble))
    {
        return note(refusal, .{ .not_wasm = .{
            .found = module[0..@min(module.len, wasm_preamble.len)],
        } }, error.NotWasm);
    }

    var out: std.ArrayList(Imported) = .empty;
    errdefer out.deinit(gpa);

    var cursor: Cursor = .{ .bytes = module, .at = 8, .refusal = refusal };
    var sections: u32 = 0;
    while (cursor.left() > 0) {
        if (sections == max_sections) {
            return note(refusal, .{ .too_large = .{
                .what = "the section count",
                .found = sections + 1,
                .bound = max_sections,
            } }, error.TooLarge);
        }
        sections += 1;

        const id = try cursor.byte("a section id");
        const size = try cursor.uleb(u32, "a section length");
        const body = try cursor.take(size, "a section body");
        if (id != 2) continue;

        var inner: Cursor = .{
            .bytes = body,
            .base = cursor.at - size,
            .refusal = refusal,
        };
        const total = try inner.count("the import count");
        var index: u32 = 0;
        while (index < total) : (index += 1) {
            const name = try inner.name("an import module name");
            const field = try inner.name("an import field name");
            const kind = try inner.byte("an import kind");
            switch (kind) {
                0 => _ = try inner.uleb(u32, "an imported function type"),
                1 => {
                    _ = try inner.byte("an imported table element type");
                    try inner.skipLimits("an imported table's limits");
                },
                2 => try inner.skipLimits("an imported memory's limits"),
                3 => {
                    _ = try inner.byte("an imported global's value type");
                    _ = try inner.byte("an imported global's mutability");
                },
                else => return inner.fault("an import kind this reader does not know"),
            }
            try out.append(gpa, .{ .module = name, .field = field, .kind = kind });
        }
    }
    return out.toOwnedSlice(gpa);
}

fn addressOf(
    symbol: []const u8,
    exports: std.StringHashMapUnmanaged(Export),
    globals: []const ?i32,
    imported_globals: u32,
    refusal: ?*?Refusal,
    comptime absent: Error,
) Error!u64 {
    const found = exports.get(symbol) orelse return note(refusal, .{
        .missing_symbol = .{ .symbol = symbol },
    }, absent);

    if (found.kind != .global) {
        return note(refusal, .{ .wrong_symbol_kind = .{
            .symbol = symbol,
            .found = found.kind,
            .expected = .global,
        } }, error.IncompletePlugin);
    }

    if (found.index < imported_globals) {
        return note(refusal, .{ .unreadable_symbol = .{
            .symbol = symbol,
            .why = "it is an imported global, whose value arrives only when the module runs",
        } }, error.UnreadableSymbol);
    }
    const defined = found.index - imported_globals;
    if (defined >= globals.len) {
        return note(refusal, .{ .unreadable_symbol = .{
            .symbol = symbol,
            .why = "it names a global the module does not define",
        } }, error.UnreadableSymbol);
    }
    const value = globals[defined] orelse return note(refusal, .{ .unreadable_symbol = .{
        .symbol = symbol,
        .why = "its initialiser is not a constant, so only a running module knows it",
    } }, error.UnreadableSymbol);

    if (value < 0) {
        return note(refusal, .{ .unreadable_symbol = .{
            .symbol = symbol,
            .why = "it holds a negative address",
        } }, error.UnreadableSymbol);
    }
    return @intCast(value);
}

fn countImportedGlobals(cursor: *Cursor) Error!u32 {
    const total = try cursor.count("the import count");
    var globals: u32 = 0;
    var index: u32 = 0;
    while (index < total) : (index += 1) {
        _ = try cursor.name("an import module name");
        _ = try cursor.name("an import field name");
        const kind = try cursor.byte("an import kind");
        switch (kind) {
            0 => _ = try cursor.uleb(u32, "an imported function type"),
            1 => {
                _ = try cursor.byte("an imported table element type");
                try cursor.skipLimits("an imported table's limits");
            },
            2 => try cursor.skipLimits("an imported memory's limits"),
            3 => {
                _ = try cursor.byte("an imported global's value type");
                _ = try cursor.byte("an imported global's mutability");
                globals += 1;
            },
            else => return cursor.fault("an import kind this reader does not know"),
        }
    }
    return globals;
}

fn readGlobals(work: std.mem.Allocator, cursor: *Cursor, out: *std.ArrayList(?i32)) Error!void {
    const total = try cursor.count("the global count");
    try out.ensureUnusedCapacity(work, total);
    var index: u32 = 0;
    while (index < total) : (index += 1) {
        _ = try cursor.byte("a global's value type");
        _ = try cursor.byte("a global's mutability");
        const value = try cursor.constExpr("a global's initialiser");
        out.appendAssumeCapacity(value);
    }
}

fn readExports(
    work: std.mem.Allocator,
    cursor: *Cursor,
    out: *std.StringHashMapUnmanaged(Export),
) Error!void {
    const total = try cursor.count("the export count");
    try out.ensureUnusedCapacity(work, total);
    var index: u32 = 0;
    while (index < total) : (index += 1) {
        const name = try cursor.name("an export name");
        const raw = try cursor.byte("an export kind");
        const at = try cursor.uleb(u32, "an export index");
        const kind = std.enums.fromInt(ExportKind, raw) orelse
            return cursor.fault("an export kind this reader does not know");
        const slot = out.getOrPutAssumeCapacity(name);
        if (slot.found_existing) return cursor.fault("the module exports one name twice");
        slot.value_ptr.* = .{ .kind = kind, .index = at };
    }
}

fn readData(work: std.mem.Allocator, cursor: *Cursor, out: *std.ArrayList(Segment)) Error!void {
    const total = try cursor.count("the data segment count");
    try out.ensureUnusedCapacity(work, total);
    var index: u32 = 0;
    while (index < total) : (index += 1) {
        const flags = try cursor.uleb(u32, "a data segment's flags");
        var memory_index: u32 = 0;
        var address: ?i32 = null;
        switch (flags) {
            0 => address = try cursor.constExpr("a data segment's offset"),
            1 => {}, // passive
            2 => {
                memory_index = try cursor.uleb(u32, "a data segment's memory index");
                address = try cursor.constExpr("a data segment's offset");
            },
            else => return cursor.fault("a data segment kind this reader does not know"),
        }
        const bytes = try cursor.blob("a data segment's bytes");
        if (memory_index != 0) continue;
        const at = address orelse continue;
        if (at < 0) continue;
        if (bytes.len == 0) continue;
        out.appendAssumeCapacity(.{ .addr = @intCast(at), .bytes = bytes });
    }
}

const testing = std.testing;

const Sample = struct {
    imported_globals: u32 = 0,
    globals: []const ?i32 = &.{},
    exports: []const Exported = &.{},
    segments: []const Placed = &.{},
    memory_pages: u32 = 1,

    const Exported = struct {
        name: []const u8,
        kind: u8,
        index: u32,
    };

    const Placed = struct {
        addr: ?i32,
        bytes: []const u8,
    };
};

fn putUleb(out: *std.ArrayList(u8), value: u64) !void {
    var rest = value;
    while (true) {
        const byte: u8 = @intCast(rest & 0x7F);
        rest >>= 7;
        try out.append(testing.allocator, if (rest == 0) byte else byte | 0x80);
        if (rest == 0) break;
    }
}

fn putSleb(out: *std.ArrayList(u8), value: i64) !void {
    var rest = value;
    while (true) {
        const byte: u8 = @intCast(rest & 0x7F);
        rest >>= 7;
        const done = (rest == 0 and byte & 0x40 == 0) or (rest == -1 and byte & 0x40 != 0);
        try out.append(testing.allocator, if (done) byte else byte | 0x80);
        if (done) break;
    }
}

fn putSection(out: *std.ArrayList(u8), id: u8, body: []const u8) !void {
    try out.append(testing.allocator, id);
    try putUleb(out, body.len);
    try out.appendSlice(testing.allocator, body);
}

fn buildModule(sample: Sample) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(testing.allocator);
    try out.appendSlice(testing.allocator, &wasm_preamble);
    try out.appendSlice(testing.allocator, &.{ 1, 0, 0, 0 });

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);

    if (sample.imported_globals > 0) {
        body.clearRetainingCapacity();
        try putUleb(&body, sample.imported_globals);
        var index: u32 = 0;
        while (index < sample.imported_globals) : (index += 1) {
            try putUleb(&body, 3);
            try body.appendSlice(testing.allocator, "env");
            try putUleb(&body, 1);
            try body.appendSlice(testing.allocator, "g");
            try body.appendSlice(testing.allocator, &.{ 3, 0x7F, 0 });
        }
        try putSection(&out, 2, body.items);
    }

    body.clearRetainingCapacity();
    try putUleb(&body, 1);
    try body.appendSlice(testing.allocator, &.{0});
    try putUleb(&body, sample.memory_pages);
    try putSection(&out, 5, body.items);

    if (sample.globals.len > 0) {
        body.clearRetainingCapacity();
        try putUleb(&body, sample.globals.len);
        for (sample.globals) |initial| {
            try body.appendSlice(testing.allocator, &.{ 0x7F, 0 });
            if (initial) |value| {
                try body.append(testing.allocator, 0x41);
                try putSleb(&body, value);
            } else {
                try body.append(testing.allocator, 0x23);
                try putUleb(&body, 0);
            }
            try body.append(testing.allocator, 0x0B);
        }
        try putSection(&out, 6, body.items);
    }

    body.clearRetainingCapacity();
    try putUleb(&body, sample.exports.len);
    for (sample.exports) |one| {
        try putUleb(&body, one.name.len);
        try body.appendSlice(testing.allocator, one.name);
        try body.append(testing.allocator, one.kind);
        try putUleb(&body, one.index);
    }
    try putSection(&out, 7, body.items);

    if (sample.segments.len > 0) {
        body.clearRetainingCapacity();
        try putUleb(&body, sample.segments.len);
        for (sample.segments) |segment| {
            if (segment.addr) |addr| {
                try putUleb(&body, 0);
                try body.append(testing.allocator, 0x41);
                try putSleb(&body, addr);
                try body.append(testing.allocator, 0x0B);
            } else {
                try putUleb(&body, 1);
            }
            try putUleb(&body, segment.bytes.len);
            try body.appendSlice(testing.allocator, segment.bytes);
        }
        try putSection(&out, 11, body.items);
    }

    return out.toOwnedSlice(testing.allocator);
}

const sample_record: core.Metadata = .{
    .name = "sample",
    .version = .{ .major = 1, .minor = 0, .patch = 0 },
    .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
    .author = "somebody",
    .tools = &.{.{ .name = "greet", .capabilities = &.{"fs.read"} }},
};

const sample_address: i32 = 1024;

fn sampleData(abi_word: u32) ![]u8 {
    const blob = try core.serializeAlloc(testing.allocator, sample_record);
    defer testing.allocator.free(blob);
    const out = try testing.allocator.alloc(u8, 4 + blob.len);
    std.mem.writeInt(u32, out[0..4], abi_word, .little);
    @memcpy(out[4..], blob);
    return out;
}

fn sampleModule(data: []const u8) ![]u8 {
    return buildModule(.{
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
}

fn sentence(refusal: Refusal) ![]u8 {
    var text: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer text.deinit();
    try refusal.format(&text.writer);
    return text.toOwnedSlice();
}

test "a module built to the shape a plugin has reads back the record it carries" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try sampleModule(data);
    defer testing.allocator.free(module);

    var read_module = try read(testing.allocator, module, null);
    defer read_module.deinit();

    try testing.expect(sample_record.eql(read_module.record()));
    try testing.expectEqual(@as(u32, @intFromEnum(core.AbiVersion.current)), read_module.abi_word);
    try testing.expectEqual(@as(u32, 0), read_module.init_function);
}

test "a symbol that is an imported global is refused rather than guessed at" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .imported_globals = 1,
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 2 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.UnreadableSymbol, read(testing.allocator, module, &refusal));
    try testing.expectEqualStrings(core.Magic.symbol, refusal.?.unreadable_symbol.symbol);
}

test "the import section shifts the global index space this reader reads" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .imported_globals = 2,
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 2 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 3 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
    defer testing.allocator.free(module);

    var read_module = try read(testing.allocator, module, null);
    defer read_module.deinit();
    try testing.expect(sample_record.eql(read_module.record()));
}

test "a global whose initialiser is not a constant is refused" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ sample_address, null },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.UnreadableSymbol, read(testing.allocator, module, &refusal));
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "only a running module knows it") != null);
}

test "a symbol pointing at an address no data segment covers is refused" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ sample_address, sample_address + 4096 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.UnreadableSymbol, read(testing.allocator, module, &refusal));
    try testing.expectEqualStrings(core.Metadata.symbol, refusal.?.unreadable_symbol.symbol);
}

test "a passive data segment is in no memory, so a symbol into one is refused" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = null, .bytes = data }},
    });
    defer testing.allocator.free(module);

    try testing.expectError(error.UnreadableSymbol, read(testing.allocator, module, null));
}

test "two data segments over one address are refused rather than resolved" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{
            .{ .addr = sample_address, .bytes = data },
            .{ .addr = sample_address + 8, .bytes = "overlapping" },
        },
    });
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.MalformedModule, read(testing.allocator, module, &refusal));
    try testing.expectEqualStrings(
        "two active data segments cover the same address",
        refusal.?.malformed_module.what,
    );
}

test "a blob split across two touching segments still reads" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const cut = data.len / 2;
    const module = try buildModule(.{
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{
            .{ .addr = sample_address + @as(i32, @intCast(cut)), .bytes = data[cut..] },
            .{ .addr = sample_address, .bytes = data[0..cut] },
        },
    });
    defer testing.allocator.free(module);

    var read_module = try read(testing.allocator, module, null);
    defer read_module.deinit();
    try testing.expect(sample_record.eql(read_module.record()));
}

test "a hole between two segments is not read as zeros" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const cut = data.len / 2;
    const module = try buildModule(.{
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{
            .{ .addr = sample_address, .bytes = data[0..cut] },
            .{ .addr = sample_address + @as(i32, @intCast(cut)) + 1, .bytes = data[cut..] },
        },
    });
    defer testing.allocator.free(module);

    try testing.expectError(error.UnreadableSymbol, read(testing.allocator, module, null));
}

test "a module with no chock_plugin_magic is not a Chock plugin" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.NotAPlugin, read(testing.allocator, module, &refusal));
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "the module exports no chock_plugin_magic, so it is not a Chock plugin",
        text,
    );
}

test "a plugin with no chock_plugin_init is refused at load and not at call" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.IncompletePlugin, read(testing.allocator, module, &refusal));
    try testing.expectEqualStrings(core.init_symbol, refusal.?.missing_symbol.symbol);
}

test "a symbol exported as the wrong kind of thing is refused by name" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 0, .index = 0 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.IncompletePlugin, read(testing.allocator, module, &refusal));
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "the module exports chock_plugin_metadata as a function, and a plugin exports it as a global",
        text,
    );
}

test "a module that exports one name twice is refused" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ sample_address, sample_address + 4, 0 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 2 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.MalformedModule, read(testing.allocator, module, &refusal));
    try testing.expectEqualStrings(
        "the module exports one name twice",
        refusal.?.malformed_module.what,
    );
}

test "the ABI in the magic symbol and the ABI in the blob must agree" {
    const data = try sampleData(9);
    defer testing.allocator.free(data);
    const module = try sampleModule(data);
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.AbiDisagrees, read(testing.allocator, module, &refusal));
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    const want = try std.fmt.allocPrint(
        testing.allocator,
        "the module says it is plugin ABI 9 and its metadata says ABI {d}",
        .{@intFromEnum(core.AbiVersion.current)},
    );
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, text);
}

test "a file that is not wasm is refused before a section is walked" {
    var refusal: ?Refusal = null;
    try testing.expectError(
        error.NotWasm,
        read(testing.allocator, "#!/bin/sh\necho hello\n", &refusal),
    );
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "not a WebAssembly module: it starts with #!/b, " ++
            "and every module starts with \\x00asm",
        text,
    );
}

test "an all zero file is refused, and so is one shorter than the preamble" {
    var zeros: [4096]u8 = @splat(0);
    try testing.expectError(error.NotWasm, read(testing.allocator, &zeros, null));
    try testing.expectError(error.NotWasm, read(testing.allocator, "\x00asm", null));
    try testing.expectError(error.NotWasm, read(testing.allocator, "", null));
}

test "a wasm binary format this reader does not know is refused by number" {
    var module: [8]u8 = undefined;
    @memcpy(module[0..4], &wasm_preamble);
    std.mem.writeInt(u32, module[4..8], 2, .little);

    var refusal: ?Refusal = null;
    try testing.expectError(error.NotWasm, read(testing.allocator, &module, &refusal));
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "built for WebAssembly binary format 2, this reader knows 1",
        text,
    );
}

test "a section that runs past the end of the file is refused" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try sampleModule(data);
    defer testing.allocator.free(module);

    module[9] = 0x7F;
    var refusal: ?Refusal = null;
    try testing.expectError(error.MalformedModule, read(testing.allocator, module, &refusal));
    try testing.expectEqualStrings("a section body", refusal.?.malformed_module.what);
}

test "a LEB128 with no end byte is refused rather than read past" {
    var module: std.ArrayList(u8) = .empty;
    defer module.deinit(testing.allocator);
    try module.appendSlice(testing.allocator, &wasm_preamble);
    try module.appendSlice(testing.allocator, &.{ 1, 0, 0, 0 });
    try module.append(testing.allocator, 7);
    try module.appendSlice(testing.allocator, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 });

    try testing.expectError(error.MalformedModule, read(testing.allocator, module.items, null));
}

test "a count above the bytes left in its own section is refused before anything is held" {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    try putUleb(&body, 60000);

    var module: std.ArrayList(u8) = .empty;
    defer module.deinit(testing.allocator);
    try module.appendSlice(testing.allocator, &wasm_preamble);
    try module.appendSlice(testing.allocator, &.{ 1, 0, 0, 0 });
    try putSection(&module, 7, body.items);

    var refusal: ?Refusal = null;
    try testing.expectError(error.TooLarge, read(testing.allocator, module.items, &refusal));
    try testing.expectEqual(@as(u64, 60000), refusal.?.too_large.found);
    try testing.expectEqual(@as(u64, 0), refusal.?.too_large.bound);
}

test "the memory a module declares costs this reader nothing" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .memory_pages = 65536,
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
    defer testing.allocator.free(module);

    var read_module = try read(testing.allocator, module, null);
    defer read_module.deinit();
    try testing.expect(sample_record.eql(read_module.record()));
}

test "a blob that states a length above the bound is refused before it is allocated" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    std.mem.writeInt(u32, data[4 + core.Prefix.total_len_offset ..][0..4], std.math.maxInt(u32), .little);

    const module = try sampleModule(data);
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.TooLarge, read(testing.allocator, module, &refusal));
    try testing.expectEqual(@as(u64, core.wire.max_blob_bytes), refusal.?.metadata.too_large.bound);
}

test "a blob that states more bytes than the module carries is refused" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const stated = @as(u32, @intCast(data.len - 4)) + 64;
    std.mem.writeInt(u32, data[4 + core.Prefix.total_len_offset ..][0..4], stated, .little);

    const module = try sampleModule(data);
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.UnreadableSymbol, read(testing.allocator, module, &refusal));
    try testing.expectEqualStrings(core.Metadata.symbol, refusal.?.unreadable_symbol.symbol);
}

test "a symbol holding a negative address is refused rather than cast" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ -4, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.UnreadableSymbol, read(testing.allocator, module, &refusal));
    try testing.expectEqualStrings("it holds a negative address", refusal.?.unreadable_symbol.why);
}

test "a passive segment is not read as though it sat at address zero" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ 0, 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 0, .index = 0 },
        },
        .segments = &.{.{ .addr = null, .bytes = data }},
    });
    defer testing.allocator.free(module);

    try testing.expectError(error.UnreadableSymbol, read(testing.allocator, module, null));
}

test "a LEB128 padded out past the width it claims is refused" {
    var module: std.ArrayList(u8) = .empty;
    defer module.deinit(testing.allocator);
    try module.appendSlice(testing.allocator, &wasm_preamble);
    try module.appendSlice(testing.allocator, &.{ 1, 0, 0, 0 });
    try module.append(testing.allocator, 7);
    try module.appendSlice(testing.allocator, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 });

    var refusal: ?Refusal = null;
    try testing.expectError(error.MalformedModule, read(testing.allocator, module.items, &refusal));
    try testing.expectEqualStrings("a section length", refusal.?.malformed_module.what);
}

test "chock_plugin_init exported as anything but a function is refused" {
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            .{ .name = core.Metadata.symbol, .kind = 3, .index = 1 },
            .{ .name = core.init_symbol, .kind = 3, .index = 0 },
        },
        .segments = &.{.{ .addr = sample_address, .bytes = data }},
    });
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.IncompletePlugin, read(testing.allocator, module, &refusal));
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "the module exports chock_plugin_init as a global, and a plugin exports it as a function",
        text,
    );
}
