//! Text a person reads: durations, sizes, clock times, and the one line that
//! stands for a tool call. Pure functions over plain data, so the terminal, the
//! window and the browser all render the same words.

const std = @import("std");

pub fn durationText(arena: std.mem.Allocator, ms: i64) std.mem.Allocator.Error![]const u8 {
    const took: u64 = if (ms <= 0) 0 else @intCast(ms);
    if (took < 60 * 1000) {
        return std.fmt.allocPrint(arena, "{d}.{d}s", .{ took / 1000, (took % 1000) / 100 });
    }
    const seconds = took / 1000;
    return std.fmt.allocPrint(arena, "{d}m{d:0>2}s", .{ seconds / 60, seconds % 60 });
}

pub fn sizeText(arena: std.mem.Allocator, bytes: usize) std.mem.Allocator.Error![]const u8 {
    if (bytes < 1024) return std.fmt.allocPrint(arena, "{d} B", .{bytes});
    if (bytes < 1024 * 1024) {
        return std.fmt.allocPrint(arena, "{d}.{d} KB", .{ bytes / 1024, (bytes % 1024) * 10 / 1024 });
    }
    const mb = bytes / (1024 * 1024);
    const rest = bytes % (1024 * 1024);
    return std.fmt.allocPrint(arena, "{d}.{d} MB", .{ mb, rest * 10 / (1024 * 1024) });
}

const last_second: u64 = 253402300799;

pub fn clockText(
    arena: std.mem.Allocator,
    epoch_ms: i64,
    offset_minutes: i32,
) std.mem.Allocator.Error![]const u8 {
    const shifted = @divFloor(epoch_ms, 1000) + @as(i64, offset_minutes) * 60;
    const seconds: u64 = if (shifted < 0) 0 else @min(@as(u64, @intCast(shifted)), last_second);
    const day = (std.time.epoch.EpochSeconds{ .secs = seconds }).getDaySeconds();
    return std.fmt.allocPrint(arena, "{d:0>2}:{d:0>2}", .{
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
    });
}

const argument_keys = [_][]const u8{
    "pattern",
    "path",
    "name",
    "program",
    "agent_kind",
    "action",
};

pub fn argumentText(
    arena: std.mem.Allocator,
    arguments: []const u8,
) std.mem.Allocator.Error![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, arguments, .{}) catch {
        return arguments;
    };
    const object = switch (parsed.value) {
        .object => |one| one,
        else => return arguments,
    };

    if (object.get("argv")) |argv| {
        if (argv == .array) {
            var out: std.ArrayList(u8) = .empty;
            for (argv.array.items) |item| {
                if (item != .string) continue;
                if (out.items.len != 0) try out.append(arena, ' ');
                try out.appendSlice(arena, item.string);
            }
            if (out.items.len != 0) return out.items;
        }
    }

    var out: std.ArrayList(u8) = .empty;
    for (argument_keys) |key| {
        const value = object.get(key) orelse continue;
        if (value != .string or value.string.len == 0) continue;
        if (out.items.len != 0) try out.append(arena, ' ');
        try out.appendSlice(arena, value.string);
    }
    if (out.items.len != 0) return out.items;

    var only: ?[]const u8 = null;
    var members = object.iterator();
    while (members.next()) |member| {
        if (member.value_ptr.* != .string) continue;
        if (only != null) return arguments;
        only = member.value_ptr.string;
    }
    return only orelse arguments;
}

pub fn askArgumentText(
    arena: std.mem.Allocator,
    arguments: []const u8,
) std.mem.Allocator.Error![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, arguments, .{}) catch {
        return argumentText(arena, arguments);
    };
    const object = switch (parsed.value) {
        .object => |one| one,
        else => return argumentText(arena, arguments),
    };
    const question = object.get("question") orelse return argumentText(arena, arguments);
    if (question != .string or question.string.len == 0) return argumentText(arena, arguments);

    const first = question.string[0 .. std.mem.indexOfScalar(u8, question.string, '\n') orelse
        question.string.len];

    const options = object.get("options") orelse return first;
    if (options != .array or options.array.items.len == 0) return first;
    return std.fmt.allocPrint(arena, "{s}  ({d} to choose from)", .{
        first,
        options.array.items.len,
    });
}

pub fn summaryText(
    arena: std.mem.Allocator,
    output: []const u8,
    is_error: bool,
    truncated: bool,
) std.mem.Allocator.Error![]const u8 {
    var rest = output;
    var lead: []const u8 = "";

    const status_prefix = "exit status: ";
    if (std.mem.startsWith(u8, rest, status_prefix)) {
        const at = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const code = rest[status_prefix.len..at];
        if (!std.mem.eql(u8, code, "0")) {
            lead = try std.fmt.allocPrint(arena, "exit {s}", .{code});
        }
        rest = if (at == rest.len) rest[at..] else rest[at + 1 ..];
    }

    const failed = is_error or lead.len != 0;
    var said = if (failed) firstLine(rest) else lastLine(rest);
    const note = firstLine(rest);
    if (std.mem.startsWith(u8, note, "[chock: ") and std.mem.endsWith(u8, note, "]")) {
        said = note["[chock: ".len .. note.len - 1];
    }

    var out: std.ArrayList(u8) = .empty;
    if (lead.len != 0) try out.appendSlice(arena, lead);
    if (said.len != 0) {
        if (out.items.len != 0) try out.appendSlice(arena, " \u{b7} ");
        try out.appendSlice(arena, said);
    }
    if (truncated) {
        if (out.items.len != 0) try out.appendSlice(arena, " \u{b7} ");
        try out.appendSlice(arena, "output truncated");
    }
    if (out.items.len == 0) return "no output";
    return out.items;
}

fn firstLine(text: []const u8) []const u8 {
    var rest = text;
    while (rest.len != 0) {
        const at = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const line = std.mem.trim(u8, rest[0..at], " \t\r");
        if (line.len != 0) return line;
        if (at == rest.len) break;
        rest = rest[at + 1 ..];
    }
    return "";
}

fn lastLine(text: []const u8) []const u8 {
    var rest = text;
    var found: []const u8 = "";
    while (rest.len != 0) {
        const at = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const line = std.mem.trim(u8, rest[0..at], " \t\r");
        if (line.len != 0) found = line;
        if (at == rest.len) break;
        rest = rest[at + 1 ..];
    }
    return found;
}
