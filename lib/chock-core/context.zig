//! Turns a folded session into the messages a model request carries. The
//! context the model sees is a view over the log, never the log itself.

const std = @import("std");
const chock_proto = @import("chock-proto");
const chock_provider = @import("chock-provider");

const Session = chock_proto.state.Session;
const Message = chock_provider.message.Message;
const ContentPart = chock_provider.message.ContentPart;

pub const Error = std.mem.Allocator.Error;

pub fn build(allocator: std.mem.Allocator, session: *const Session) Error![]Message {
    var messages: std.ArrayList(Message) = .empty;
    errdefer messages.deinit(allocator);

    for (session.context.items) |entry| {
        switch (entry.data) {
            .message => |m| try messages.append(allocator, .{
                .role = m.role,
                .content = m.content,
                .model_alias = entry.model_alias,
            }),
            .summary => |text| {
                const parts = try allocator.alloc(ContentPart, 1);
                parts[0] = .{ .text = text };
                try messages.append(allocator, .{
                    .role = .system,
                    .content = parts,
                    .model_alias = entry.model_alias,
                });
            },
        }
    }

    return messages.toOwnedSlice(allocator);
}

test "a plain message entry becomes a request message with the same role and text" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "hello" }} },
    } });

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const messages = try build(arena_state.allocator(), &session);
    try std.testing.expectEqual(@as(usize, 1), messages.len);
    try std.testing.expectEqual(chock_provider.message.Role.user, messages[0].role);
    try std.testing.expectEqualStrings("hello", messages[0].content[0].text);
}

test "a summary entry becomes a system role message carrying the summary text" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();

    try session.apply(.{ .id = 1, .session = "01S", .time_ms = 1, .event = .{
        .message = .{ .role = .user, .content = &.{.{ .text = "one" }} },
    } });
    try session.apply(.{ .id = 2, .session = "01S", .time_ms = 2, .event = .{
        .compaction = .{
            .summary = "folded away",
            .from_id = 1,
            .through_id = 1,
            .kept_ranges = &.{},
            .model_alias = "compact",
        },
    } });

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const messages = try build(arena_state.allocator(), &session);
    try std.testing.expectEqual(@as(usize, 1), messages.len);
    try std.testing.expectEqual(chock_provider.message.Role.system, messages[0].role);
    try std.testing.expectEqualStrings("folded away", messages[0].content[0].text);
}
