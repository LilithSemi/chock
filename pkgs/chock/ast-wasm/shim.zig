//! The C library surface tree-sitter needs, for a module with no libc and a
//! fixed heap. Blocks are carved from large chunks because C's `free` carries
//! no size, so every block keeps a header.

const std = @import("std");

const Header = extern struct {
    size: usize,
};

// The heap is the linear memory above what the linker placed, so none of it
// lands in the module as literal zeros. The module declares its memory with
// `--initial-memory` and `--max-memory` equal, so growth is impossible and
// this is the whole heap there will ever be.
extern const __heap_base: u8;

var next: usize = 0;
var top: usize = 0;

var bottom: usize = 0;

fn ensure() void {
    if (top != 0) return;
    bottom = std.mem.alignForward(usize, @intFromPtr(&__heap_base), 16);
    next = bottom;
    top = @wasmMemorySize(0) * std.wasm.page_size;
}

/// Where the next block would go. `free` gives nothing back on its own, so a
/// caller that knows nothing of its own lives above a mark gives every byte
/// above it back at once.
export fn heap_mark() usize {
    ensure();
    return next;
}

export fn heap_reset(mark: usize) void {
    ensure();
    if (mark >= bottom and mark <= next) next = mark;
}

fn carve(size: usize) ?[*]u8 {
    ensure();
    const want = std.mem.alignForward(usize, @sizeOf(Header) + size, 16);
    if (next + want > top) return null;
    const block: [*]u8 = @ptrFromInt(next);
    next += want;
    const header: *Header = @ptrCast(@alignCast(block));
    header.size = size;
    return block + @sizeOf(Header);
}

export fn malloc(size: usize) ?*anyopaque {
    if (size == 0) return null;
    return @ptrCast(carve(size) orelse return null);
}

export fn calloc(count: usize, size: usize) ?*anyopaque {
    const total = std.math.mul(usize, count, size) catch return null;
    const got = carve(total) orelse return null;
    @memset(got[0..total], 0);
    return @ptrCast(got);
}

export fn realloc(ptr: ?*anyopaque, size: usize) ?*anyopaque {
    const old = ptr orelse return malloc(size);
    const bytes: [*]u8 = @ptrCast(old);
    const header: *Header = @ptrCast(@alignCast(bytes - @sizeOf(Header)));
    if (header.size >= size) return old;
    const got = carve(size) orelse return null;
    @memcpy(got[0..header.size], bytes[0..header.size]);
    return @ptrCast(got);
}

export fn free(ptr: ?*anyopaque) void {
    _ = ptr;
}

export fn abort() noreturn {
    unreachable;
}

export fn memcmp(lhs: [*]const u8, rhs: [*]const u8, count: usize) c_int {
    for (lhs[0..count], rhs[0..count]) |a, b| {
        if (a != b) return @as(c_int, a) - @as(c_int, b);
    }
    return 0;
}

export fn strncmp(lhs: [*:0]const u8, rhs: [*:0]const u8, count: usize) c_int {
    var at: usize = 0;
    while (at < count) : (at += 1) {
        const a = lhs[at];
        const b = rhs[at];
        if (a != b) return @as(c_int, a) - @as(c_int, b);
        if (a == 0) return 0;
    }
    return 0;
}

export fn strlen(text: [*:0]const u8) usize {
    var end: usize = 0;
    while (text[end] != 0) end += 1;
    return end;
}

export fn iswalnum(wc: c_int) c_int {
    if (wc < 0 or wc > 0x10FFFF) return 0;
    const point: u21 = @intCast(wc);
    return @intFromBool(point < 128 and std.ascii.isAlphanumeric(@intCast(point)));
}

export fn iswspace(wc: c_int) c_int {
    if (wc < 0 or wc > 0x10FFFF) return 0;
    const point: u21 = @intCast(wc);
    return @intFromBool(point < 128 and std.ascii.isWhitespace(@intCast(point)));
}

// Formatting, which tree-sitter reaches only for a node's s-expression and for
// its dot graph. Enough of the format surface for those two.
fn formatInto(buffer: []u8, format: [*:0]const u8, args: *std.builtin.VaList) usize {
    var at: usize = 0;
    var read: usize = 0;
    while (format[read] != 0) {
        const c = format[read];
        if (c != '%') {
            if (at < buffer.len) buffer[at] = c;
            at += 1;
            read += 1;
            continue;
        }
        read += 1;
        while (format[read] == 'z' or format[read] == 'l' or format[read] == 'u') {
            if (format[read] == 'u') break;
            read += 1;
        }
        const kind = format[read];
        read += 1;
        var scratch: [64]u8 = undefined;
        const written: []const u8 = switch (kind) {
            's' => blk: {
                const text: [*:0]const u8 = @cVaArg(args, [*:0]const u8);
                break :blk std.mem.span(text);
            },
            'd', 'i' => blk: {
                const value = @cVaArg(args, c_int);
                break :blk std.fmt.bufPrint(&scratch, "{d}", .{value}) catch "";
            },
            'u' => blk: {
                const value = @cVaArg(args, c_uint);
                break :blk std.fmt.bufPrint(&scratch, "{d}", .{value}) catch "";
            },
            'p' => blk: {
                const value = @cVaArg(args, usize);
                break :blk std.fmt.bufPrint(&scratch, "0x{x}", .{value}) catch "";
            },
            'c' => blk: {
                scratch[0] = @truncate(@as(c_uint, @bitCast(@cVaArg(args, c_int))));
                break :blk scratch[0..1];
            },
            '%' => "%",
            else => "",
        };
        for (written) |byte| {
            if (at < buffer.len) buffer[at] = byte;
            at += 1;
        }
    }
    return at;
}

export fn vsnprintf(buffer: ?[*]u8, size: usize, format: [*:0]const u8, args: *std.builtin.VaList) c_int {
    var nothing: [0]u8 = undefined;
    const into: []u8 = if (buffer) |ptr| ptr[0..if (size == 0) 0 else size - 1] else &nothing;
    const want = formatInto(into, format, args);
    if (buffer) |ptr| {
        if (size != 0) ptr[@min(want, size - 1)] = 0;
    }
    return @intCast(want);
}

export fn snprintf(buffer: ?[*]u8, size: usize, format: [*:0]const u8, ...) callconv(.c) c_int {
    var args = @cVaStart();
    defer @cVaEnd(&args);
    return vsnprintf(buffer, size, format, &args);
}

// stderr and the file writers: tree-sitter reaches these for the allocation
// failure message and for the dot graph, and neither is a path this module is
// asked to take.
export var stderr: usize = 0;

export fn fprintf(stream: usize, format: [*:0]const u8, ...) callconv(.c) c_int {
    _ = stream;
    _ = format;
    return 0;
}

export fn fputs(text: [*:0]const u8, stream: usize) c_int {
    _ = text;
    _ = stream;
    return 0;
}

export fn fputc(c: c_int, stream: usize) c_int {
    _ = stream;
    return c;
}

export fn fwrite(ptr: usize, size: usize, count: usize, stream: usize) usize {
    _ = ptr;
    _ = size;
    _ = stream;
    return count;
}

export fn fclose(stream: usize) c_int {
    _ = stream;
    return 0;
}

export fn fdopen(fd: c_int, mode: [*:0]const u8) usize {
    _ = fd;
    _ = mode;
    return 0;
}
