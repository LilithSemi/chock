//! Somebody else's word, and the one thing the agent loop is allowed to do
//! about it.
//!
//! **This file is to `chock detach` what `src/interrupt.zig` is to Ctrl-C.**
//! Both turn an event from outside the session into an answer at a safe point
//! inside it, and both keep the loop ignorant of where the answer came from.
//! `chock_core.Loop.Deps.handover` is a plain function that gives a yes or a
//! no, exactly as `Deps.canceled` is, and neither one knows about a signal or a
//! socket.
//!
//! ## Why there is a file here at all, and not a call from `src/run.zig`
//!
//! Two reasons, and either one alone is enough.
//!
//! * **`Deps.handover` carries no state.** It is a bare function pointer, for
//!   the reason `Deps.canceled` is one: the caller owns how the answer is
//!   reached, and a session with a cancel button in a window would answer it a
//!   different way. So the listening socket has to be reachable from a plain
//!   function, and a file scope variable set once is the smallest thing that
//!   does that. `chock_core.tools.cancelRunningTool` keeps its handles the same
//!   way and for the same reason.
//! * **`chock-core` must not import `chock-broker`.** The loop counts what a
//!   session holds and knows nothing about sockets; the broker owns the socket
//!   and knows nothing about turns. This file is the one place the two shapes
//!   meet, and it is in `src/` because `src/` is the caller that already owns
//!   both.
//!
//! ## What `arm` promises, and what happens without it
//!
//! A session that never calls `arm` answers no to every ask, so no process can
//! take it. That is the safe direction and it is what every session did before
//! this existed: `chock detach` then reports that the session is running and
//! will not hand over, which is true.
//!
//! **A session whose handover socket could not be opened is in exactly that
//! state**, and it says so on its own standard error when it starts. A path
//! longer than a unix socket allows is the measured cause: see
//! `src/detach.zig`'s own `answerableAt`, which reads the same bound for the
//! approval socket.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_core = @import("chock-core");

/// The socket this session listens on, or null for a session nothing can take.
///
/// **Read, and never taken.** A caller that cleared it while a client was in
/// the middle of the exchange would leave that client waiting for an answer
/// that no longer has anywhere to come from.
var listening: ?*chock_broker.handover.Endpoint = null;

/// How long a look waits for a client to confirm, once the session has answered
/// `ready`. A variable so a test can drive `requested` with no clock at all,
/// the same shape `chock_broker.socket.Waiter.nap` uses and for the same
/// reason: **no test in this suite measures elapsed time**.
var confirm_budget_ms: u64 = chock_broker.handover.default_confirm_budget_ms;

/// Listen for a handover ask on `endpoint` from here on.
///
/// The caller keeps owning the endpoint and closes it. **It has to outlive
/// every turn**, which in `src/run.zig` it does: the endpoint is opened in
/// phase 1 and closed in phase 3, and the loop runs in phase 2 between them.
pub fn arm(endpoint: *chock_broker.handover.Endpoint) void {
    listening = endpoint;
}

/// Stop listening. **The caller must call this before it closes the
/// endpoint**, or a look after the close would read a descriptor that is gone.
pub fn disarm() void {
    listening = null;
}

/// Whether another process should own this session now. This is the shape
/// `chock_core.Loop.Deps.handover` wants, so it is passed there by name.
///
/// **It answers no at once when nobody has asked**, which is every turn of
/// every ordinary session: `Endpoint.look` accepts what the kernel already
/// holds and reads what a peer already sent, and waits for nothing else. It
/// spends the confirm budget only after it has answered a real client `ready`.
pub fn requested(io: std.Io, in_flight: chock_core.Loop.InFlight) bool {
    const endpoint = listening orelse return false;
    const decision = endpoint.look(io, .{
        .tasks = in_flight.tasks,
        .children = in_flight.children,
    }, confirm_budget_ms);
    return decision == .hand_over;
}

/// Answer every ask with no wait at all. **Only a test may call this**: a real
/// session gives a client time to answer the `ready` it was just sent, and a
/// budget of zero would refuse every client that did not have its confirm
/// already in the socket.
pub fn setConfirmBudgetForTest(budget_ms: u64) void {
    confirm_budget_ms = budget_ms;
}

const testing = std.testing;

test "a session that armed nothing refuses every ask, and one that armed a socket does not" {
    // **The safe direction, and the one this file must never get backwards.**
    // A session with no handover socket is a session no process can take, and
    // that is what every session did before this file existed. A `requested`
    // that answered yes with nothing armed would end sessions that nobody had
    // asked about at all.
    //
    // Mutation check: make `requested` return true when `listening` is null and
    // the first line below stops holding, which is every session ending on its
    // first turn.
    const gpa = testing.allocator;
    const io = testing.io;

    disarm();
    try testing.expect(!requested(io, .{}));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &path_buffer);

    var paths = try chock_broker.handover.pathsFor(gpa, path_buffer[0..len], "01ARMED");
    defer paths.deinit();
    var endpoint = try chock_broker.handover.Endpoint.open(io, paths, null);
    defer endpoint.close(io);

    arm(&endpoint);
    defer disarm();

    // Armed, and still nobody has asked. A turn of an ordinary session reaches
    // exactly this, and it must cost nothing and decide nothing.
    try testing.expect(!requested(io, .{}));

    // A real client, doing the whole exchange. The confirm is in the socket
    // before the look that reads it, so this test states a budget and measures
    // no time.
    setConfirmBudgetForTest(1000);
    defer setConfirmBudgetForTest(chock_broker.handover.default_confirm_budget_ms);

    const address = try chock_broker.socket.addressFor(paths.socket, null);
    const client = try address.connect(io);
    defer client.close(io);
    try testing.expect(chock_broker.socket.writeAll(
        client.socket.handle,
        chock_broker.handover.ask_frame ++ "\n",
    ));
    try testing.expect(chock_broker.socket.writeAll(
        client.socket.handle,
        chock_broker.handover.take_frame ++ "\n",
    ));
    try testing.expect(requested(io, .{}));
}

test "what the loop counts reaches the socket, so a refusal names the right work" {
    // `chock_core.Loop.InFlight` and `chock_broker.handover.InFlight` are two
    // types with the same shape, and this file is the only thing that copies
    // one into the other. A copy that dropped a field would let a session hand
    // itself over with a build still running, which loses that build's own
    // `task.complete`.
    //
    // Mutation check: pass `.{}` to `look` instead of the caller's counts, and
    // the two refusals below become handovers.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &path_buffer);

    var paths = try chock_broker.handover.pathsFor(gpa, path_buffer[0..len], "01COUNTS");
    defer paths.deinit();
    var endpoint = try chock_broker.handover.Endpoint.open(io, paths, null);
    defer endpoint.close(io);

    arm(&endpoint);
    defer disarm();
    setConfirmBudgetForTest(1000);
    defer setConfirmBudgetForTest(chock_broker.handover.default_confirm_budget_ms);

    const address = try chock_broker.socket.addressFor(paths.socket, null);

    const held = [_]chock_core.Loop.InFlight{ .{ .tasks = 1 }, .{ .children = 1 } };
    for (held) |in_flight| {
        const client = try address.connect(io);
        defer client.close(io);
        try testing.expect(chock_broker.socket.writeAll(
            client.socket.handle,
            chock_broker.handover.ask_frame ++ "\n",
        ));
        try testing.expect(chock_broker.socket.writeAll(
            client.socket.handle,
            chock_broker.handover.take_frame ++ "\n",
        ));
        try testing.expect(!requested(io, in_flight));
    }

    // And with both counts back at zero the same client shape is taken, so the
    // refusal above was the counts and not something else about this session.
    const taker = try address.connect(io);
    defer taker.close(io);
    try testing.expect(chock_broker.socket.writeAll(
        taker.socket.handle,
        chock_broker.handover.ask_frame ++ "\n",
    ));
    try testing.expect(chock_broker.socket.writeAll(
        taker.socket.handle,
        chock_broker.handover.take_frame ++ "\n",
    ));
    try testing.expect(requested(io, .{}));
}
