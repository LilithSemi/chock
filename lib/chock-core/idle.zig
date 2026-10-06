//! What the caller does while this library waits for something slow, so
//! a display stays live through a turn without a second thread.

const std = @import("std");

pub const slice_ms: u64 = 100;

pub const slice_ns: u64 = slice_ms * std.time.ns_per_ms;

pub const Idle = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        step: *const fn (ptr: *anyopaque) void,
    };

    pub fn step(self: Idle) void {
        self.vtable.step(self.ptr);
    }
};

const testing = std.testing;

const Counter = struct {
    steps: usize = 0,

    fn idle(self: *Counter) Idle {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Idle.VTable{ .step = stepFn };

    fn stepFn(ptr: *anyopaque) void {
        const self: *Counter = @ptrCast(@alignCast(ptr));
        self.steps += 1;
    }
};

test "a step reaches the value behind the seam" {
    var counter = Counter{};
    const one = counter.idle();
    one.step();
    one.step();
    try testing.expectEqual(@as(usize, 2), counter.steps);
}

test "one slice is short enough that a key is not left waiting" {
    try testing.expect(slice_ms <= 100);
    try testing.expectEqual(slice_ms * std.time.ns_per_ms, slice_ns);
}
