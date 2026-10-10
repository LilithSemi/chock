//! Where things sit and how wide they are. The split of a terminal into bands,
//! the measurement of a font, and the room a widget has to draw in.

const std = @import("std");
const phantom = @import("phantom");

const testing = std.testing;

pub const Split = struct {
    header: u16,
    transcript: u16,
    approval: u16,
    input: u16,
};

const band_rows: u16 = 1;

pub fn split(rows: u16, wanted: u16) Split {
    if (rows == 0) return .{ .header = 0, .transcript = 0, .approval = 0, .input = 0 };
    if (rows == 1) return .{ .header = 0, .transcript = 0, .approval = 0, .input = band_rows };
    const room = rows - 2 * band_rows;
    const asked = @min(wanted, room);
    return .{
        .header = band_rows,
        .transcript = room - asked,
        .approval = asked,
        .input = band_rows,
    };
}

const first_printable: u21 = ' ';
const last_printable: u21 = '~';
const printable_count = last_printable - first_printable + 1;

pub const Measure = struct {
    metrics: phantom.text.mono.TextMetrics,
    dpr: f32,
    font: *phantom.text.Font,
    size: f32,
    known: ?Known = null,

    const Known = struct {
        line: f32,
        typical: f32,
        ascii: [printable_count]f32,
    };

    pub fn of(ctx: *phantom.BuildContext) Measure {
        const theme = phantom.theme.defaultTheme(ctx.owner);
        const view = ctx.owner.activeView();
        return (Measure{
            .metrics = ctx.owner.text_metrics,
            .dpr = if (view) |one| one.metrics.dpr else 1,
            .font = theme.body_font,
            .size = theme.text_size,
        }).measured();
    }

    pub fn measured(self: Measure) Measure {
        var made = self;
        made.known = null;
        var found: Known = undefined;
        var total: f32 = 0;
        for (&found.ascii, 0..) |*one, at| {
            one.* = made.advanceOf(first_printable + @as(u21, @intCast(at)));
            total += one.*;
        }
        const mean = total / printable_count;
        found.line = made.height();
        found.typical = if (mean > 0) mean else made.size;
        made.known = found;
        return made;
    }

    pub fn ratio(self: Measure) f32 {
        return if (self.dpr > 0) self.dpr else 1;
    }

    pub fn height(self: Measure) f32 {
        if (self.known) |one| return one.line;
        return switch (self.metrics) {
            .mono => |cell| cell.line / self.ratio(),
            .proportional => blk: {
                const per_em: f32 = @floatFromInt(self.font.unitsPerEm());
                if (per_em <= 0) break :blk self.size;
                const up: f32 = @floatFromInt(self.font.ascent());
                const down: f32 = @floatFromInt(self.font.descent());
                break :blk (up - down) * self.size / per_em;
            },
        };
    }

    pub fn logicalMetrics(self: Measure) phantom.text.mono.TextMetrics {
        return switch (self.metrics) {
            .mono => |cell| .{ .mono = .{
                .advance = cell.advance / self.ratio(),
                .line = cell.line / self.ratio(),
                .ascent = cell.ascent / self.ratio(),
            } },
            .proportional => .proportional,
        };
    }

    pub fn advanceOf(self: Measure, point: u21) f32 {
        if (point >= first_printable and point <= last_printable) {
            if (self.known) |one| return one.ascii[point - first_printable];
        }
        return switch (self.metrics) {
            .mono => |cell| blk: {
                const columns: f32 = @floatFromInt(phantom.text.mono.wcwidth(point));
                break :blk cell.advance * columns / self.ratio();
            },
            .proportional => self.font.advance(point, self.size),
        };
    }

    pub fn widthOf(self: Measure, text: []const u8) f32 {
        var index: usize = 0;
        var used: f32 = 0;
        while (index < text.len) {
            const one = drawnAt(text, index);
            used += self.advanceOf(one.point);
            index += one.length;
        }
        return used;
    }

    pub fn step(self: Measure) f32 {
        if (self.known) |one| return one.typical;
        var total: f32 = 0;
        var point: u21 = first_printable;
        while (point <= last_printable) : (point += 1) total += self.advanceOf(point);
        const mean = total / printable_count;
        return if (mean > 0) mean else self.size;
    }

    pub fn rowsIn(self: Measure, logical_height: f32) u16 {
        return countIn(logical_height, self.height());
    }
};

pub const grid_measure: Measure = .{
    .metrics = .{ .mono = .{ .advance = 1, .line = 1, .ascent = 0.8 } },
    .dpr = 1,
    .font = undefined,
    .size = 1,
};

pub const Room = struct {
    measure: Measure,
    width: f32,

    pub fn grid(columns: f32) Room {
        return .{ .measure = grid_measure, .width = columns };
    }

    pub fn less(self: Room, text: []const u8) Room {
        const taken = self.measure.widthOf(text);
        return .{
            .measure = self.measure,
            .width = if (self.width > taken) self.width - taken else 0,
        };
    }

    pub fn upTo(self: Room, width: f32) Room {
        return .{ .measure = self.measure, .width = @min(self.width, width) };
    }

    pub fn holds(self: Room, text: []const u8) bool {
        return self.measure.widthOf(text) <= self.width;
    }

    pub fn isNarrow(self: Room) bool {
        return self.width < @as(f32, narrow_columns) * self.measure.step();
    }
};

fn countIn(room: f32, step: f32) u16 {
    if (!(room > 0) or !(step > 0)) return 0;
    const whole = @floor(room / step);
    if (whole >= @as(f32, std.math.maxInt(u16))) return std.math.maxInt(u16);
    return @intFromFloat(whole);
}

pub fn spread(
    arena: std.mem.Allocator,
    left: []const u8,
    right: []const u8,
    room: Room,
) std.mem.Allocator.Error![]const u8 {
    if (right.len == 0) return visibleLine(arena, left, room);
    const pinned = room.measure.widthOf(right);
    if (pinned >= room.width) return visibleLine(arena, right, room);

    const gap = room.measure.advanceOf(' ');
    const cut = try visibleLine(arena, left, room.upTo(room.width - pinned - gap));
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, cut);
    const starts = room.width - pinned;
    var filled = room.measure.widthOf(cut);
    while (filled + gap <= starts) : (filled += gap) try out.append(arena, ' ');
    try out.appendSlice(arena, right);
    return out.items;
}

test "a viewport with no room and a measurement with no size are counted as nothing" {
    try testing.expectEqual(@as(u16, 0), countIn(0, 16));
    try testing.expectEqual(@as(u16, 0), countIn(400, 0));
    try testing.expectEqual(@as(u16, 0), countIn(-400, 16));
    try testing.expectEqual(@as(u16, 25), countIn(400, 16));
    try testing.expectEqual(@as(u16, 24), countIn(399, 16));
    try testing.expectEqual(std.math.maxInt(u16), countIn(1e9, 1));
}

pub const narrow_columns: u16 = 60;

pub const Drawn = struct {
    point: u21,
    length: usize,
    whole: bool,
};

pub fn drawnAt(raw: []const u8, at: usize) Drawn {
    const size = std.unicode.utf8ByteSequenceLength(raw[at]) catch return .{
        .point = '?',
        .length = 1,
        .whole = false,
    };
    if (at + size > raw.len) return .{ .point = '?', .length = 1, .whole = false };
    const point = std.unicode.utf8Decode(raw[at..][0..size]) catch return .{
        .point = '?',
        .length = 1,
        .whole = false,
    };
    if (point < 0x20 or point == 0x7f) return .{ .point = ' ', .length = size, .whole = false };
    return .{ .point = point, .length = size, .whole = true };
}

pub fn visibleLine(
    arena: std.mem.Allocator,
    raw: []const u8,
    room: Room,
) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    var used: f32 = 0;

    while (index < raw.len) {
        const one = drawnAt(raw, index);
        const advance = room.measure.advanceOf(one.point);
        if (used + advance > room.width) break;
        if (one.whole) {
            try out.appendSlice(arena, raw[index..][0..one.length]);
        } else {
            try out.append(arena, @intCast(one.point));
        }
        index += one.length;
        used += advance;
    }

    return out.items;
}
