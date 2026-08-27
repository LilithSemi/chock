//! Turns a folded session into the messages a model request carries. The
//! context the model sees is a view over the log, never the log itself.
//! `chock_proto.state.Session.apply` already does the folding; this file only
//! reshapes the result, `Session.context`, into
//! `chock_provider.message.Request.messages`.
//!
//! `build` never copies a `.message` entry's own content: every slice on the
//! `chock_provider.message.Message` it returns is borrowed straight from
//! `session`'s own arena, so the result is only valid, and only worth
//! building at all, for as long as `session` stays alive. Only a `.summary`
//! entry, left behind by a compaction, needs a fresh allocation, one
//! content part holding its summary text: pass an arena as `allocator`, the
//! same convention `lib/chock-core/tools.zig`'s own `Registry.definitions`
//! uses, and the whole result frees at once with the arena, `.summary`
//! allocations included.

const std = @import("std");
const chock_proto = @import("chock-proto");
const chock_provider = @import("chock-provider");

const Session = chock_proto.state.Session;
const Message = chock_provider.message.Message;
const ContentPart = chock_provider.message.ContentPart;

pub const Error = std.mem.Allocator.Error;

/// Build one request message per context entry, in the order `session`
/// already holds them: the same order the log itself was written in, since
/// `Session.apply` only ever appends to `context`, or folds a run of it into
/// one summary entry in the range's own place. See `Session.applyCompaction`'s
/// own doc comment.
///
/// A `.summary` entry becomes a `system` role message carrying the summary
/// text. `system`, not `user` or `assistant`, because a summary is not
/// something either side of the conversation said: it stands in for a run
/// of turns a compaction folded away, and a system role keeps a reader, model
/// included, from mistaking it for a real turn.
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
