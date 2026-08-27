//! Reading a plugin out of a WebAssembly module, with no engine at all.
//!
//! `lib/chock-core/plugin.zig` is the other half, and it holds every decision:
//! the collision rule, the capability declarations, and the policy keys. This
//! file is only the parse. It is the same split `lib/chock-core/lsp.zig` and
//! `lib/chock-core/mcp.zig` already keep with their drivers, turned the other
//! way round: here the mechanism is where the security properties are, so it
//! gets the harder tests.
//!
//! ## Discovery must not execute a byte of guest code
//!
//! A host that had to call an export to read a plugin's metadata could not
//! inspect a plugin and then refuse it, because inspecting it would already
//! have run it. So the whole of this file is a walk over the module's own
//! sections. It starts no engine, builds no linear memory, calls nothing, and
//! never even learns what the plugin's code does.
//!
//! ## What a guest really exports, measured
//!
//! `lib/chock-plugin-sdk/exports.zig` writes `@export(&abi_word, ...)` and
//! `@export(&blob, ...)`. On `wasm32-freestanding` the linker turns a data
//! export into an **exported global holding the address** of the bytes, not
//! into the bytes. Read off `plugins/hello.zig` built in tree:
//!
//! ```text
//! export "chock_plugin_magic"     kind 3 (global)   global 1 = i32.const 1048596
//! export "chock_plugin_metadata"  kind 3 (global)   global 2 = i32.const 1048600
//! export "chock_plugin_init"      kind 0 (function) function 2
//! data segment 0                  active, offset i32.const 1048576, 266 bytes
//! ```
//!
//! So reading the metadata is: find the export, read the global's initialiser,
//! and resolve that address inside the module's own active data segments. All
//! three steps are a parse of bytes that are already in the file.
//!
//! ## Nothing in a module is trusted
//!
//! Every count and every length below comes from a file somebody else wrote.
//! Each one is bounded and each refusal names the bound it passed. The reader
//! never allocates from a number a module states before that number has been
//! checked, and it never allocates from the module's declared memory size at
//! all, which is the number a module can make enormous for free.

const std = @import("std");

const core = @import("chock-plugin-core");

/// The largest module this reader accepts. A debug build of the smallest
/// possible plugin is about half a megabyte, and a tree-sitter grammar plus
/// its runtime is a few megabytes. This bound only has to stop a runaway read.
pub const max_module_bytes: usize = 64 << 20;

/// How many sections one module may hold. The format defines twelve, and a
/// module may repeat the custom section, which is where debug information
/// goes. The plugin built in tree has fifteen.
pub const max_sections: u32 = 1 << 10;

/// How many entries this reader walks in one section.
pub const max_section_entries: u32 = 1 << 16;

/// The longest export name this reader accepts. A name longer than this is
/// none of the three symbols, so nothing is lost by refusing to hold it.
pub const max_export_name_bytes: u32 = 1 << 10;

/// The wasm binary format version this reader knows. There has only ever been
/// one, and a module that states another is refused by number rather than
/// guessed at.
pub const wasm_version: u32 = 1;

/// The first four bytes of every wasm module.
pub const wasm_preamble = [_]u8{ 0x00, 'a', 's', 'm' };

/// What an export names. The numbers are the format's own.
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

/// What can go wrong reading a module. `core.ParseError` is folded in whole,
/// because the last step of this reader is `core.parse` over the bytes it
/// resolved, and a fault in the blob is the blob reader's fault to name.
pub const Error = core.ParseError || error{
    /// The file does not start with the wasm preamble, or states a binary
    /// format version this reader does not know.
    NotWasm,
    /// The file is wasm and this reader cannot walk it: a section that runs
    /// past the end, a length that does not fit, or a construct it cannot
    /// step over safely.
    MalformedModule,
    /// The module is a plugin and something a plugin must carry is not there,
    /// or is there as the wrong kind of thing.
    IncompletePlugin,
    /// An exported symbol's address cannot be read out of the module: it is an
    /// import, or its initialiser is not a constant this reader evaluates, or
    /// it names an address no active data segment covers.
    UnreadableSymbol,
    /// `chock_plugin_magic` and the metadata blob's own prefix state different
    /// ABI versions.
    AbiDisagrees,
};

/// The detail behind a refusal, for the message a person reads. Nothing here
/// allocates, and every borrowed slice points either into the caller's own
/// module bytes or at a constant.
pub const Refusal = union(enum) {
    not_wasm: NotWasm,
    unknown_wasm_version: UnknownWasmVersion,
    malformed_module: MalformedModule,
    too_large: TooLarge,
    missing_symbol: MissingSymbol,
    wrong_symbol_kind: WrongSymbolKind,
    unreadable_symbol: UnreadableSymbol,
    abi_disagrees: AbiDisagrees,
    /// The module was walked, the blob was found, and the blob is bad. See
    /// `lib/chock-plugin-core/wire.zig`.
    metadata: core.Refusal,

    pub const NotWasm = struct {
        /// The first four bytes of the file, or as many as there are.
        found: []const u8,
    };

    /// Both numbers, for the same reason `core.Refusal.UnknownAbiVersion`
    /// names both: one of them tells the reader what to do next.
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
        /// What the `chock_plugin_magic` global holds.
        symbol_says: u32,
        /// What the blob's own fixed prefix holds.
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

/// One plugin, read out of one module. Holds the metadata and the two facts
/// about the module a host needs after it has decided to load the plugin.
pub const Module = struct {
    /// The number the `chock_plugin_magic` global holds, which is the plugin
    /// ABI the guest was built for. Equal to `parsed.abi_version`, checked.
    abi_word: u32,
    /// Where `chock_plugin_init` is in the function index space. The only
    /// function of a plugin that ever runs, and it runs only after a host has
    /// read everything below and decided to load the plugin.
    init_function: u32,
    /// The metadata, and the memory behind it.
    parsed: core.Parsed,

    /// What the plugin says about itself.
    pub fn record(self: *const Module) core.Metadata {
        return self.parsed.record;
    }

    pub fn deinit(self: Module) void {
        self.parsed.deinit();
    }
};

/// One active data segment of memory zero, with a constant address.
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

/// The bytes a module puts in memory before it runs anything, and the only
/// place this reader ever looks for a value.
///
/// **Not a linear memory.** A module states how many pages it wants and that
/// number is free to be enormous, so nothing here is allocated from it. This
/// holds the segments the module carries and answers reads out of them.
const Memory = struct {
    /// Sorted by address, and proven not to overlap. See `sort`.
    segments: []Segment,

    /// Put the segments in address order and refuse a module whose segments
    /// cover the same address twice.
    ///
    /// Overlapping active segments are legal WebAssembly, where the later one
    /// wins. They are refused here rather than resolved, because a plugin's
    /// metadata sitting under two segments would mean the bytes a host reads
    /// and the bytes an engine would put in memory are decided by a rule this
    /// reader would have to copy exactly. A plugin has no reason to do it, and
    /// a plugin that does gets a named refusal instead of a guess.
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

    /// Fill `out` with the bytes at `addr`, and say whether every one of them
    /// was there. Segments are contiguous or the read fails: a range that runs
    /// into a hole is a range whose value a running module would read as zero,
    /// and a zero this reader invented is a value the module never wrote.
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

/// A cursor over a module, or over one section of one. Every read is bounded
/// and every refusal says what was being read.
const Cursor = struct {
    bytes: []const u8,
    at: usize = 0,
    /// Where this cursor's bytes start inside the whole module, so a refusal
    /// names an offset a person can find in the file.
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

    /// An unsigned LEB128, bounded to the width it claims to be. A LEB128 with
    /// no end byte is how a small file asks a reader to walk off the end of
    /// it, so the byte count is capped as well as the value.
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

    /// A signed LEB128 of at most 32 bits, which is what an `i32.const` in a
    /// constant expression holds.
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

    /// A count from the file, refused before anything is allocated or walked
    /// for it.
    ///
    /// Two bounds, and the second is the one that matters. `max_section_entries`
    /// is a ceiling. **The bytes left in the section is the real bound**: no
    /// entry of any section is shorter than one byte, so a count above the
    /// bytes remaining is a count the file cannot possibly satisfy. Without it
    /// a twenty byte file could ask a caller to make room for sixty five
    /// thousand entries, which is how a small module becomes a large
    /// allocation. With it, what this reader holds stays proportional to the
    /// size of the file it was given.
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

    /// A length prefixed name, bounded.
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

    /// A length prefixed run of bytes with no name bound: a data segment.
    fn blob(self: *Cursor, what: []const u8) Error![]const u8 {
        const length = try self.uleb(u32, what);
        return self.take(length, what);
    }

    /// Step over a `limits`, which is what a memory or a table declares. The
    /// numbers are read and thrown away: nothing here allocates from them.
    fn skipLimits(self: *Cursor, what: []const u8) Error!void {
        const flags = try self.byte(what);
        // 0 is a floor alone and 1 is a floor and a ceiling. The threads
        // proposal adds 2 and 3 for a shared memory, which a plugin has no
        // use for and which this reader refuses rather than steps over.
        if (flags > 1) return self.fault(what);
        _ = try self.uleb(u64, what);
        if (flags == 1) _ = try self.uleb(u64, what);
    }

    /// The value a constant expression produces, when it is one this reader
    /// evaluates, and null when it is not. Either way the cursor ends after
    /// the expression's `end` byte, because a reader that could not step over
    /// a construct could not find the next entry of the section.
    ///
    /// Only `i32.const` is evaluated. A `global.get` is the one other form a
    /// linker emits, and its value is not in the module at all when the global
    /// is imported, so there is nothing to read without an engine.
    fn constExpr(self: *Cursor, what: []const u8) Error!?i32 {
        var value: ?i32 = null;
        var opcodes: usize = 0;
        while (true) {
            // A constant expression is one instruction and an `end`. The cap
            // is far above that and stops a run of them from being a loop.
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
                // Anything else leaves this reader unable to find the end of
                // the expression, and a reader that guessed would read the
                // next section's bytes as this one's.
                else => return self.fault(what),
            }
        }
        return value;
    }
};

/// One export, kept while the sections are walked.
const Export = struct {
    kind: ExportKind,
    index: u32,
};

/// Read `module` and answer the plugin in it. Nothing is executed.
///
/// `refusal` is optional, the same bargain `core.parse` offers: a caller that
/// passes null pays nothing and learns only the error, and a caller that
/// passes a slot gets the sentence a person reads.
///
/// The order of the checks is the point. The preamble comes first, then the
/// magic symbol, then the ABI version, and only then is any length in the
/// metadata trusted.
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
    // The initialiser of each global this module defines, in index order.
    // Null where the initialiser is not a constant this reader evaluates.
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
            // Every other section says nothing about where the metadata is.
            // Skipping one is free and reading one is a parser this file does
            // not need: the code section alone is the whole instruction set.
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

    // The fixed prefix first, because it is the only part of a blob whose
    // shape every ABI promises. It carries the magic word, so the length that
    // follows is a length this reader is willing to allocate against.
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

    // Both numbers before either is acted on. A module whose two halves
    // disagree is a build gone wrong, and reading either one of them and
    // trusting it would hide that.
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

/// One import a module states: the module name and the field name, and which
/// kind of thing it is. Both names borrow from the caller's own module bytes.
pub const Imported = struct {
    module: []const u8,
    field: []const u8,
    /// The format's own kind byte: 0 a function, 1 a table, 2 a memory, 3 a
    /// global.
    kind: u8,
};

/// Every import `module` states, in the module's own order.
///
/// **Every kind, and not only the functions.** An engine may track one kind
/// and step over the rest: Vulcan keeps the imported functions and skips an
/// imported table, memory or global entirely. A gate that asked the engine
/// what a module imports would therefore never see those, and a module could
/// import a memory it did not declare. So the gate reads this, which is the
/// same walk `read` already makes and which refuses the same malformed
/// modules. See `chock_core.plugin_engine.gate`.
///
/// The caller owns the returned slice and frees it with `gpa.free`. The names
/// in it point into `module`, which the caller already owns.
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

/// The address one exported data symbol holds, or a refusal saying why it
/// cannot be read without running the module.
///
/// `absent` is the error for a missing export, because the two symbols mean
/// different things by their absence: no `chock_plugin_magic` is not a Chock
/// plugin at all, and no `chock_plugin_metadata` beside one is a plugin that
/// was built wrong.
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

    // The global index space starts with the imported globals, and an import
    // carries no initialiser at all: its value arrives when the module is
    // instantiated, which is the one thing this reader never does.
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

/// Walk the import section and answer how many globals it brings in. The other
/// kinds are stepped over, because an import of any kind shifts the index
/// space of its own kind and a reader that miscounted would read the wrong
/// global.
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

/// Walk the global section and keep each initialiser this reader can evaluate.
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

/// Walk the export section. A repeated name is refused rather than resolved:
/// the format allows one export of each name, and a module with two would be
/// asking this reader to choose which one a host reads.
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

/// Walk the data section and keep the active segments of memory zero whose
/// address is a constant.
///
/// A passive segment is not in memory until a running module copies it there,
/// and an active segment whose offset is not a constant has no address without
/// an engine. Both are stepped over. A symbol that pointed into one of them is
/// then an address no segment covers, which is a refusal with a message rather
/// than a guess.
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

/// A module built here, one field at a time.
///
/// **The tests that matter run against a real module.** See
/// `test/plugin/wasm.zig`, which reads `plugins/hello.zig` built for
/// `wasm32-freestanding` and mutates it. This builder is here for the cases a
/// real module cannot be made to show: an imported global, an initialiser that
/// is not a constant, and two data segments over one address. Vulcan's own
/// eighty three wasm tests were all hand built blobs, which is exactly why it
/// could not run a single real toolchain module, so nothing here is allowed to
/// be the only test of anything.
const Sample = struct {
    /// How many globals an import section brings in. They shift the global
    /// index space, so every export index below counts from after them.
    imported_globals: u32 = 0,
    /// The initialiser of each global this module defines. Null means
    /// `global.get 0`, which is a constant expression whose value is not in
    /// the file at all.
    globals: []const ?i32 = &.{},
    exports: []const Exported = &.{},
    segments: []const Placed = &.{},
    /// The floor of the memory section, in pages. Nothing is allocated from
    /// it, which is what one of the tests below states.
    memory_pages: u32 = 1,

    const Exported = struct {
        name: []const u8,
        kind: u8,
        index: u32,
    };

    const Placed = struct {
        /// Null for a passive segment, which is in no memory until a running
        /// module puts it there.
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

/// The bytes of one module. The caller frees them.
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

/// Where the built modules below put their data: the ABI word first, then the
/// blob straight after it, which is the arrangement the real module has.
const sample_address: i32 = 1024;

/// The bytes at `sample_address`: the ABI word and then the blob.
fn sampleData(abi_word: u32) ![]u8 {
    const blob = try core.serializeAlloc(testing.allocator, sample_record);
    defer testing.allocator.free(blob);
    const out = try testing.allocator.alloc(u8, 4 + blob.len);
    std.mem.writeInt(u32, out[0..4], abi_word, .little);
    @memcpy(out[4..], blob);
    return out;
}

/// A module that carries `sample_record` and reads back.
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
    // The positive control for everything below. It is not the acceptance
    // test: that one reads the real module, in `test/plugin/wasm.zig`.
    const data = try sampleData(@intFromEnum(core.AbiVersion.current));
    defer testing.allocator.free(data);
    const module = try sampleModule(data);
    defer testing.allocator.free(module);

    var read_module = try read(testing.allocator, module, null);
    defer read_module.deinit();

    try testing.expect(sample_record.eql(read_module.record()));
    try testing.expectEqual(@as(u32, 1), read_module.abi_word);
    try testing.expectEqual(@as(u32, 0), read_module.init_function);
}

test "a symbol that is an imported global is refused rather than guessed at" {
    // An import's value arrives when the module is instantiated, which is the
    // one thing this reader never does. A reader that read the defined globals
    // by the raw export index would read the wrong global here and hand a host
    // whatever bytes lay at that address.
    const data = try sampleData(1);
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .imported_globals = 1,
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            // Index 0 is the import. The two defined globals are 1 and 2.
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
    // The other side of the test above, and the one that would fail silently:
    // the very same module with the export indices moved up by the import
    // count must read correctly. A reader that ignored imports would pass the
    // test above by accident and fail this one.
    const data = try sampleData(1);
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
    // `global.get` is the other form a linker emits. Its value is not in the
    // file, so there is nothing to read without running the module, and a
    // reader that took zero for it would answer with the wrong address.
    const data = try sampleData(1);
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
    const data = try sampleData(1);
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        // The metadata global points a kilobyte past the end of the segment.
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
    // A passive segment is copied into memory by a running module. Reading one
    // as though it were already there would be this reader deciding what the
    // module would have done, which is the one thing it must not do.
    const data = try sampleData(1);
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
    // Legal WebAssembly, where the later segment wins. Refused here because
    // the bytes a host reads and the bytes an engine would put in memory would
    // then be decided by a rule this reader has to copy exactly, and a plugin
    // has no reason to ask for it.
    const data = try sampleData(1);
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
    // The other side of the rule above. Segments that touch and do not overlap
    // are ordinary linker output, so a blob that starts in one and ends in the
    // next must read: a reader that demanded one segment would break the first
    // time a linker split a section.
    const data = try sampleData(1);
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
            // Out of address order as well, which is what `Memory.sort` is for.
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
    // A byte no segment covers is a byte a running module would read as zero,
    // and a zero this reader invented is a value the module never wrote.
    const data = try sampleData(1);
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
    // The symbol name is the magic. Its absence is the whole answer, and it is
    // a different answer from a plugin built for another Chock.
    const data = try sampleData(1);
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
    // A plugin whose tool bodies can never be bound is a plugin that half
    // works, which is the failure the collision rule is written against too.
    const data = try sampleData(1);
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
    const data = try sampleData(1);
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        .globals = &.{ sample_address, sample_address + 4 },
        .exports = &.{
            .{ .name = core.Magic.symbol, .kind = 3, .index = 0 },
            // A function where the metadata belongs. Calling it is what the
            // whole design is written to avoid.
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
    // Two exports of one name would ask this reader to choose which of them a
    // host reads, and a module that could choose that could show one thing to
    // a reader and hand another to an engine.
    const data = try sampleData(1);
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
    // Two numbers that say the same thing, from two places in the file.
    // Reading one of them and trusting it would hide a build gone wrong.
    const data = try sampleData(9);
    defer testing.allocator.free(data);
    const module = try sampleModule(data);
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.AbiDisagrees, read(testing.allocator, module, &refusal));
    const text = try sentence(refusal.?);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "the module says it is plugin ABI 9 and its metadata says ABI 1",
        text,
    );
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
    // A zeroed page, an erased flash page, or a file of the right length full
    // of nothing. None of them is a module, and none of them may hand this
    // reader a length to trust.
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
    const data = try sampleData(1);
    defer testing.allocator.free(data);
    const module = try sampleModule(data);
    defer testing.allocator.free(module);

    // The first section's length, which is one byte here because every
    // section this builder writes is small. Claim the rest of the file and
    // more.
    module[9] = 0x7F;
    var refusal: ?Refusal = null;
    try testing.expectError(error.MalformedModule, read(testing.allocator, module, &refusal));
    try testing.expectEqualStrings("a section body", refusal.?.malformed_module.what);
}

test "a LEB128 with no end byte is refused rather than read past" {
    // A run of continuation bytes is how a short file asks a reader to walk
    // off the end of it, and a shift that ran on would be undefined behaviour
    // before it ever got there.
    var module: std.ArrayList(u8) = .empty;
    defer module.deinit(testing.allocator);
    try module.appendSlice(testing.allocator, &wasm_preamble);
    try module.appendSlice(testing.allocator, &.{ 1, 0, 0, 0 });
    try module.append(testing.allocator, 7);
    try module.appendSlice(testing.allocator, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 });

    try testing.expectError(error.MalformedModule, read(testing.allocator, module.items, null));
}

test "a count above the bytes left in its own section is refused before anything is held" {
    // A small module must not be able to ask this reader to make room for
    // sixty five thousand exports. No entry is shorter than one byte, so the
    // bytes left is a bound the file cannot argue with.
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
    // A module states how many pages it wants and that number is free to be
    // enormous. Nothing here is allocated from it, and the only bytes this
    // reader holds are the ones the file really carries.
    const data = try sampleData(1);
    defer testing.allocator.free(data);
    const module = try buildModule(.{
        // Four gibibytes, the most a wasm32 module can name.
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
    // The length is the first number in a blob that a reader could act on, and
    // it comes from a file somebody else wrote. `core.Prefix.read` bounds it,
    // and this pins that the bound is read before the allocation is made.
    const data = try sampleData(1);
    defer testing.allocator.free(data);
    std.mem.writeInt(u32, data[4 + core.Prefix.total_len_offset ..][0..4], std.math.maxInt(u32), .little);

    const module = try sampleModule(data);
    defer testing.allocator.free(module);

    var refusal: ?Refusal = null;
    try testing.expectError(error.TooLarge, read(testing.allocator, module, &refusal));
    try testing.expectEqual(@as(u64, core.wire.max_blob_bytes), refusal.?.metadata.too_large.bound);
}

test "a blob that states more bytes than the module carries is refused" {
    // Under the bound, so the length is one this reader would allocate for,
    // and past the end of the data the module really holds. A reader that
    // filled the rest with zeros would hand a host a record the plugin never
    // wrote.
    const data = try sampleData(1);
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
    // A global's initialiser is a signed i32 and a memory address is not. A
    // reader that cast one to the other would turn a small negative number
    // into an enormous address, which is a different question from the one the
    // module asked.
    const data = try sampleData(1);
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
    // The same rule as the passive test above, put where a reader that placed
    // a passive segment at zero would get away with it: the symbols point at
    // address zero as well, so only a reader that leaves a passive segment out
    // of memory altogether refuses this.
    const data = try sampleData(1);
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
    // Ten bytes that decode to one. The value is in range and the bytes are
    // all there, so nothing but the byte count says this is wrong, and a
    // reader that let it pass would let a module hide bytes from anything that
    // walked it by the same numbers.
    var module: std.ArrayList(u8) = .empty;
    defer module.deinit(testing.allocator);
    try module.appendSlice(testing.allocator, &wasm_preamble);
    try module.appendSlice(testing.allocator, &.{ 1, 0, 0, 0 });
    // An export section whose length is written in six bytes rather than one.
    try module.append(testing.allocator, 7);
    try module.appendSlice(testing.allocator, &.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 });

    var refusal: ?Refusal = null;
    try testing.expectError(error.MalformedModule, read(testing.allocator, module.items, &refusal));
    try testing.expectEqualStrings("a section length", refusal.?.malformed_module.what);
}

test "chock_plugin_init exported as anything but a function is refused" {
    // The host calls this symbol and nothing else. A module that exported a
    // global under the name would have the host calling whatever function
    // index that global's value happened to be.
    const data = try sampleData(1);
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
