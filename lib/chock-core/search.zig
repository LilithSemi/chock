//! How the loop answers a web_search call for the agent.

const std = @import("std");

const chock_policy = @import("chock-policy");

const ratchet = chock_policy.ratchet;

pub const Ask = struct {
    query: []const u8,
    self_policy: []const ratchet.Restriction = &.{},
    tool: []const u8,
};

pub const Answer = struct {
    text: []u8,
    is_error: bool,
    note: []u8 = &.{},
};

pub const Error = std.mem.Allocator.Error;

pub const Searcher = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        search: *const fn (
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            io: std.Io,
            ask: Ask,
        ) Error!Answer,
    };

    pub fn search(
        self: Searcher,
        gpa: std.mem.Allocator,
        io: std.Io,
        ask: Ask,
    ) Error!Answer {
        return self.vtable.search(self.ptr, gpa, io, ask);
    }
};

pub const has_no_searcher = "nothing was searched: this session was started with no search " ++
    "engine configured. One is set in the user's own config.zon; work from what is in the " ++
    "project, or ask the user for the content.";

const testing = std.testing;

test "the no-engine message names where an engine is set" {
    try testing.expect(std.mem.indexOf(u8, has_no_searcher, "config.zon") != null);
    try testing.expect(std.mem.indexOf(u8, has_no_searcher, "nothing was searched") != null);
}
