//! Why the broker refused an act, or could not carry one out. A library must
//! not decide what a person sees, so nothing here prints. Some variants own
//! memory and the rest borrow from the `Ask` the caller holds for the call.

const std = @import("std");

const chock_policy = @import("chock-policy");

pub const Diagnostic = union(enum) {
    path_read_failed: PathFailed,
    git_refused_a_description: []const u8,
    scratch_store_unreadable: PathFailed,
    scratch_store_walk_failed: anyerror,
    /// A notice, not a fault. The call still succeeds.
    scratch_store_holds_a_non_object: []const u8,

    git_refused_the_act: []const u8,
    branch_moved: BranchMoved,
    scheme_not_fetchable: []const u8,
    host_not_approved: HostNotApproved,
    nix_daemon_unreachable: PathFailed,
    file_not_openable: PathFailed,
    file_not_writable: PathFailed,
    object_missing: []const u8,
    object_not_moved: PathFailed,
    model_not_on_roster: []const u8,
    command_not_started: PathFailed,
    command_output_unreadable: []const u8,
    command_wait_failed: PathFailed,

    cannot_wait_for_a_person: DecisionAbout,
    review_for_a_decision_that_asks_for_none: DecisionAbout,
    no_reviewer: DecisionAbout,
    reviewer_reviews_itself: ReviewerReviewsItself,
    answer_is_about_another_request: MismatchedAnswer,
    answer_claims_a_review: ReviewClaimed,
    answer_names_an_unknown_decision: AnswerNames,

    socket_path_too_long: SocketPathTooLong,
    socket_dir_not_made: PathFailed,
    socket_dir_not_opened: PathFailed,
    socket_dir_not_private: PathFailed,
    socket_not_opened: PathFailed,
    socket_not_removed: PathFailed,
    client_uid_refused: ClientUidRefused,
    waiter_step_failed: PathFailed,

    net_host_not_a_name: NetHost,
    net_host_not_permitted: NetRefused,
    net_host_not_resolved: NetHost,
    net_address_not_permitted: NetHost,
    net_not_connected: NetHost,

    fetch_host_not_permitted: FetchRefused,
    /// Convention parity and not a boundary. See `lib/chock-broker/fetch.zig`.
    fetch_robots_disallow: FetchPath,

    secret_handle_unterminated,
    secret_not_named: []const u8,

    pub const PathFailed = struct {
        path: []const u8,
        err: anyerror,
    };

    pub const BranchMoved = struct {
        branch: []const u8,
        at: []const u8,
        approved: []const u8,
    };

    pub const HostNotApproved = struct {
        approved: []const u8,
        named: []const u8,
    };

    pub const DecisionAbout = struct {
        decision: chock_policy.table.Decision,
        action: []const u8,
    };

    pub const ReviewerReviewsItself = struct {
        reviewer_kind: []const u8,
        action: []const u8,
    };

    pub const MismatchedAnswer = struct {
        request_id: u64,
        answer_action: []const u8,
        answer_tool_call_id: []const u8,
        ask_action: []const u8,
        ask_tool_call_id: []const u8,
    };

    pub const AnswerNames = struct {
        request_id: u64,
        name: []const u8,
    };

    /// An enumeration and not a string, so this field has no lifetime.
    pub const ReviewDecision = enum {
        approved_by_review,
        refused_by_review,
        review_unavailable,

        pub fn text(self: ReviewDecision) []const u8 {
            return switch (self) {
                .approved_by_review => "approved_by_review",
                .refused_by_review => "refused_by_review",
                .review_unavailable => "review_unavailable",
            };
        }
    };

    pub const ReviewClaimed = struct {
        request_id: u64,
        decision: ReviewDecision,
    };

    pub const SocketPathTooLong = struct {
        path: []const u8,
        bound: usize,
    };

    pub const ClientUidRefused = struct {
        uid: std.posix.uid_t,
        owner_uid: std.posix.uid_t,
    };

    pub const NetHost = struct {
        host: []const u8,
        port: u16,
    };

    pub const NetRefused = struct {
        host: []const u8,
        port: u16,
        decision: chock_policy.table.Decision,
    };

    pub const FetchRefused = struct {
        host: []const u8,
        decision: chock_policy.table.Decision,
        /// The policy key the host builds, or null for a host that builds none.
        action: ?[]const u8 = null,
    };

    pub const FetchPath = struct {
        host: []const u8,
        path: []const u8,
    };

    /// Every variant is named here and there is no `else`, so a variant added
    /// later must say whether it owns memory. An `else` once folded a
    /// `@tagName` pointer into `.rodata` in with a copied name, and `gpa.free`
    /// on the literal ended the process.
    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .git_refused_a_description,
            .git_refused_the_act,
            .scratch_store_holds_a_non_object,
            => |text| gpa.free(text),
            .branch_moved => |names| {
                gpa.free(names.branch);
                gpa.free(names.at);
                gpa.free(names.approved);
            },
            .host_not_approved => |names| gpa.free(names.named),
            .answer_is_about_another_request => |names| {
                gpa.free(names.answer_action);
                gpa.free(names.answer_tool_call_id);
            },
            .answer_names_an_unknown_decision => |names| gpa.free(names.name),
            .net_host_not_a_name,
            .net_host_not_resolved,
            .net_address_not_permitted,
            .net_not_connected,
            => |about| gpa.free(about.host),
            .net_host_not_permitted => |about| gpa.free(about.host),
            .fetch_host_not_permitted => |about| {
                gpa.free(about.host);
                if (about.action) |key| gpa.free(key);
            },
            .fetch_robots_disallow => |about| {
                gpa.free(about.host);
                gpa.free(about.path);
            },

            // Every one below owns nothing.
            .path_read_failed,
            .scratch_store_unreadable,
            .scratch_store_walk_failed,
            .scheme_not_fetchable,
            .nix_daemon_unreachable,
            .file_not_openable,
            .file_not_writable,
            .object_missing,
            .object_not_moved,
            .model_not_on_roster,
            .command_not_started,
            .command_output_unreadable,
            .command_wait_failed,
            .cannot_wait_for_a_person,
            .review_for_a_decision_that_asks_for_none,
            .no_reviewer,
            .reviewer_reviews_itself,
            .answer_claims_a_review,
            .socket_path_too_long,
            .socket_dir_not_made,
            .socket_dir_not_opened,
            .socket_dir_not_private,
            .socket_not_opened,
            .socket_not_removed,
            .client_uid_refused,
            .waiter_step_failed,
            .secret_handle_unterminated,
            .secret_not_named,
            => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .path_read_failed => |fault| try writer.print(
                "reading what is at {s} failed: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .git_refused_a_description => |said| try writer.print(
                "the broker could not read what an act would do, and git said: {s}",
                .{said},
            ),
            .scratch_store_unreadable => |fault| try writer.print(
                "the scratch object store at {s} could not be read: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .scratch_store_walk_failed => |err| try writer.print(
                "walking the scratch object store failed: {s}",
                .{@errorName(err)},
            ),
            .scratch_store_holds_a_non_object => |name| try writer.print(
                "the scratch object store holds {s}, which is not an object, so it does not move",
                .{name},
            ),
            .git_refused_the_act => |said| try writer.print(
                "the broker's git call did not do the act, and git said: {s}",
                .{said},
            ),
            .branch_moved => |names| try writer.print(
                "the branch {s} is at {s}, and the approved act named {s}, so the branch is not deleted",
                .{ names.branch, names.at, names.approved },
            ),
            .scheme_not_fetchable => |scheme| try writer.print(
                "the broker fetches http and https, and this names {s}",
                .{scheme},
            ),
            .host_not_approved => |names| try writer.print(
                "the approval covers the host {s}, and this address names {s}, so nothing is fetched",
                .{ names.approved, names.named },
            ),
            .nix_daemon_unreachable => |fault| try writer.print(
                "the Nix daemon socket at {s} cannot be reached ({s}), so nothing is built",
                .{ fault.path, @errorName(fault.err) },
            ),
            .file_not_openable => |fault| try writer.print(
                "the broker could not open {s} to write: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .file_not_writable => |fault| try writer.print(
                "the broker could not write {s}: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .object_missing => |id| try writer.print(
                "the object {s} is in neither store, so the ref does not move",
                .{id},
            ),
            .object_not_moved => |fault| try writer.print(
                "the object {s} could not be put in the project: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .model_not_on_roster => |alias| try writer.print(
                "the roster of this session does not name the model {s}",
                .{alias},
            ),
            .command_not_started => |fault| try writer.print(
                "the broker could not start {s}: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .command_output_unreadable => |command| try writer.print(
                "the broker could not read what {s} printed",
                .{command},
            ),
            .command_wait_failed => |fault| try writer.print(
                "waiting for {s} failed: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .cannot_wait_for_a_person => |about| try writer.print(
                "the policy answers {t} for {s}, and this request cannot wait for a person, so no " ++
                    "review was paid for and the action does not happen",
                .{ about.decision, about.action },
            ),
            .review_for_a_decision_that_asks_for_none => |about| try writer.print(
                "a review of {s} came back for the decision {t}, which asks for no review, so " ++
                    "the action does not happen",
                .{ about.action, about.decision },
            ),
            .no_reviewer => |about| try writer.print(
                "the policy answers {t} for {s}, and this session can start no reviewer, so the " ++
                    "action does not happen",
                .{ about.decision, about.action },
            ),
            .reviewer_reviews_itself => |names| try writer.print(
                "the reviewer kind {s} is already in the chain that asked for {s}, so the review " ++
                    "would be the requester reviewing itself and the action does not happen",
                .{ names.reviewer_kind, names.action },
            ),
            .answer_is_about_another_request => |names| try writer.print(
                "the answer to approval request {d} says it is about {s}/{s}, and the request is " ++
                    "about {s}/{s}, so the action does not happen",
                .{
                    names.request_id,
                    names.answer_action,
                    names.answer_tool_call_id,
                    names.ask_action,
                    names.ask_tool_call_id,
                },
            ),
            .answer_claims_a_review => |claim| try writer.print(
                "the answer to approval request {d} names the decision {s}, which only the " ++
                    "broker's own review writes, so the action does not happen",
                .{ claim.request_id, claim.decision.text() },
            ),
            .answer_names_an_unknown_decision => |names| try writer.print(
                "the answer to approval request {d} names the decision {s}, which this build does " ++
                    "not know, so the action does not happen",
                .{ names.request_id, names.name },
            ),
            .socket_path_too_long => |fault| try writer.print(
                "the socket path {s} is {d} bytes, and a unix socket path on this platform is " ++
                    "bounded at {d}, so nothing was bound",
                .{ fault.path, fault.path.len, fault.bound },
            ),
            .socket_dir_not_made => |fault| try writer.print(
                "the approval socket directory {s} could not be made: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .socket_dir_not_opened => |fault| try writer.print(
                "the approval socket directory {s} could not be opened: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .socket_dir_not_private => |fault| try writer.print(
                "the approval socket directory {s} could not be made private: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .socket_not_opened => |fault| try writer.print(
                "the approval socket {s} could not be opened: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .socket_not_removed => |fault| try writer.print(
                "the socket {s} was already there and could not be removed: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .client_uid_refused => |who| try writer.print(
                "a client of uid {d} tried to attach to this session, and only uid {d} may",
                .{ who.uid, who.owner_uid },
            ),
            .waiter_step_failed => |fault| try writer.print(
                "{s}: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .secret_handle_unterminated => try writer.print(
                "a secret handle has no closing {s}",
                .{"}}"},
            ),
            .secret_not_named => |name| try writer.print(
                "no credential is named {s}",
                .{name},
            ),
            .net_host_not_a_name => |about| try writer.print(
                "a sandboxed process asked to reach something that is not a host name, on port {d}",
                .{about.port},
            ),
            .net_host_not_permitted => |about| try writer.print(
                "the policy answers {t} for reaching {s} on port {d}, and only allow opens a connection",
                .{ about.decision, about.host, about.port },
            ),
            .net_host_not_resolved => |about| try writer.print(
                "{s} did not resolve, so nothing was reached on port {d}",
                .{ about.host, about.port },
            ),
            .net_address_not_permitted => |about| try writer.print(
                "{s} resolved onto this machine rather than onto the network, so port {d} was not reached",
                .{ about.host, about.port },
            ),
            .net_not_connected => |about| try writer.print(
                "the connection to {s} on port {d} did not open",
                .{ about.host, about.port },
            ),
            // The agent is told a different sentence for the same refusal: see
            // `chock_broker.fetch.Session.refusalForHost`.
            .fetch_host_not_permitted => |about| {
                try writer.print("nothing was read from {s}. ", .{about.host});
                const action = about.action orelse {
                    return writer.writeAll("That is not a host name a policy key is built " ++
                        "from, so no rule of chock.zon can name it. Give a plain host name.");
                };
                // A rule that is there wins, so do not tell a person to add an
                // `allow` row for a host a rule already denies.
                if (about.decision == .deny) {
                    return writer.print(
                        "A rule of this project's policy denies that host. Change the rule " ++
                            "for {s} in the .policy.rules block of chock.zon, then start the " ++
                            "session again.",
                        .{action},
                    );
                }
                try writer.print(
                    "This project's policy answers \"{t}\" for that host, and only \"allow\" " ++
                        "lets Chock read one. To permit it, add " ++
                        ".{{ .action = \"{s}\", .decision = .allow }} to the .policy.rules " ++
                        "block of chock.zon, then start the session again.",
                    .{ about.decision, action },
                );
            },
            .fetch_robots_disallow => |about| try writer.print(
                "the robots.txt of {s} disallows {s} for {s}, so nothing was read",
                .{ about.host, about.path, "chock" },
            ),
        }
    }
};

/// The first fault is kept, not the last. The answer matters because several
/// variants own memory: a site that hands one over must release it itself when
/// the answer is false.
pub fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// Wanted and still empty, which is the one case in which a site should copy
/// a string for it.
pub fn wants(out: ?*?Diagnostic) bool {
    const slot = out orelse return false;
    return slot.* == null;
}

const testing = std.testing;

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    try testing.expect(note(&diag, .{ .no_reviewer = .{ .decision = .agent_review, .action = "git.push" } }));
    try testing.expect(!note(&diag, .{ .model_not_on_roster = "sonnet" }));
    try testing.expectEqualStrings("git.push", diag.?.no_reviewer.action);

    try testing.expect(!note(null, .{ .model_not_on_roster = "sonnet" }));
    try testing.expect(!wants(null));
    try testing.expect(!wants(&diag));
}

test "a message is released by the allocator that filled it, and by nothing else" {
    // A dangling read alone often does not fail, because a freed page still
    // holds the text. It is the invalid free that never passes.
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer testing.expect(debug.deinit() == .ok) catch @panic("a leak");
    const gpa = debug.allocator();

    for (everyVariant(gpa)) |built| {
        var one = built;
        one.deinit(gpa);
    }
}

/// Owned strings are copies of `gpa`, and borrowed ones are literals.
fn everyVariant(gpa: std.mem.Allocator) [12]Diagnostic {
    return .{
        .{ .git_refused_a_description = gpa.dupe(u8, "no") catch @panic("no memory") },
        .{ .git_refused_the_act = gpa.dupe(u8, "no") catch @panic("no memory") },
        .{ .scratch_store_holds_a_non_object = gpa.dupe(u8, "lock") catch @panic("no memory") },
        .{ .branch_moved = .{
            .branch = gpa.dupe(u8, "b") catch @panic("no memory"),
            .at = gpa.dupe(u8, "a1") catch @panic("no memory"),
            .approved = gpa.dupe(u8, "a2") catch @panic("no memory"),
        } },
        .{ .host_not_approved = .{
            .approved = "a",
            .named = gpa.dupe(u8, "b") catch @panic("no memory"),
        } },
        .{ .answer_is_about_another_request = .{
            .request_id = 1,
            .answer_action = gpa.dupe(u8, "a") catch @panic("no memory"),
            .answer_tool_call_id = gpa.dupe(u8, "b") catch @panic("no memory"),
            .ask_action = "c",
            .ask_tool_call_id = "d",
        } },
        .{ .answer_claims_a_review = .{ .request_id = 1, .decision = .approved_by_review } },
        .{ .answer_names_an_unknown_decision = .{
            .request_id = 1,
            .name = gpa.dupe(u8, "whatever") catch @panic("no memory"),
        } },
        .{ .net_host_not_permitted = .{
            .host = gpa.dupe(u8, "h") catch @panic("no memory"),
            .port = 443,
            .decision = .ask,
        } },
        .{
            .fetch_host_not_permitted = .{
                .host = gpa.dupe(u8, "h") catch @panic("no memory"),
                .decision = .ask,
                .action = gpa.dupe(u8, "net.fetch.h") catch @panic("no memory"),
            },
        },
        .{ .fetch_robots_disallow = .{
            .host = gpa.dupe(u8, "h") catch @panic("no memory"),
            .path = gpa.dupe(u8, "/p") catch @panic("no memory"),
        } },
        .{ .path_read_failed = .{ .path = "/p", .err = error.AccessDenied } },
    };
}

test "every decision a review writes reads as itself" {
    var seen: [std.meta.fields(Diagnostic.ReviewDecision).len][]const u8 = undefined;
    inline for (std.meta.fields(Diagnostic.ReviewDecision), 0..) |field, i| {
        const text = (@field(Diagnostic.ReviewDecision, field.name)).text();
        try testing.expect(text.len > 0);
        for (seen[0..i]) |other| try testing.expect(!std.mem.eql(u8, text, other));
        seen[i] = text;
    }
}

test "no two faults of this module read the same" {
    const cases: []const Diagnostic = &.{
        .{ .path_read_failed = .{ .path = "/p", .err = error.AccessDenied } },
        .{ .git_refused_a_description = "no" },
        .{ .scratch_store_unreadable = .{ .path = "/p", .err = error.AccessDenied } },
        .{ .scratch_store_walk_failed = error.AccessDenied },
        .{ .scratch_store_holds_a_non_object = "maintenance.lock" },
        .{ .git_refused_the_act = "no" },
        .{ .branch_moved = .{ .branch = "b", .at = "a1", .approved = "a2" } },
        .{ .scheme_not_fetchable = "ftp" },
        .{ .host_not_approved = .{ .approved = "a", .named = "b" } },
        .{ .nix_daemon_unreachable = .{ .path = "/s", .err = error.FileNotFound } },
        .{ .file_not_openable = .{ .path = "/p", .err = error.AccessDenied } },
        .{ .file_not_writable = .{ .path = "/p", .err = error.AccessDenied } },
        .{ .object_missing = "abc" },
        .{ .object_not_moved = .{ .path = "abc", .err = error.AccessDenied } },
        .{ .model_not_on_roster = "sonnet" },
        .{ .command_not_started = .{ .path = "nix", .err = error.FileNotFound } },
        .{ .command_output_unreadable = "nix" },
        .{ .command_wait_failed = .{ .path = "nix", .err = error.Unexpected } },
        .{ .cannot_wait_for_a_person = .{ .decision = .ask, .action = "git.push" } },
        .{ .review_for_a_decision_that_asks_for_none = .{ .decision = .ask, .action = "git.push" } },
        .{ .no_reviewer = .{ .decision = .agent_review, .action = "git.push" } },
        .{ .reviewer_reviews_itself = .{ .reviewer_kind = "r", .action = "git.push" } },
        .{ .answer_is_about_another_request = .{
            .request_id = 1,
            .answer_action = "a",
            .answer_tool_call_id = "b",
            .ask_action = "c",
            .ask_tool_call_id = "d",
        } },
        .{ .answer_claims_a_review = .{ .request_id = 1, .decision = .approved_by_review } },
        .{ .answer_names_an_unknown_decision = .{ .request_id = 1, .name = "whatever" } },
        .{ .socket_path_too_long = .{ .path = "/d/s", .bound = 103 } },
        .{ .socket_dir_not_made = .{ .path = "/d", .err = error.AccessDenied } },
        .{ .socket_dir_not_opened = .{ .path = "/d", .err = error.AccessDenied } },
        .{ .socket_dir_not_private = .{ .path = "/d", .err = error.AccessDenied } },
        .{ .socket_not_opened = .{ .path = "/d/s", .err = error.AccessDenied } },
        .{ .socket_not_removed = .{ .path = "/d/s", .err = error.AccessDenied } },
        .{ .client_uid_refused = .{ .uid = 1001, .owner_uid = 1000 } },
        .{ .waiter_step_failed = .{ .path = "the approval socket", .err = error.Unexpected } },
        .secret_handle_unterminated,
        .{ .secret_not_named = "aiand" },
        .{ .net_host_not_a_name = .{ .host = "", .port = 443 } },
        .{ .net_host_not_permitted = .{ .host = "h", .port = 443, .decision = .ask } },
        .{ .net_host_not_resolved = .{ .host = "h", .port = 443 } },
        .{ .net_address_not_permitted = .{ .host = "h", .port = 443 } },
        .{ .net_not_connected = .{ .host = "h", .port = 443 } },
        .{ .fetch_host_not_permitted = .{ .host = "h", .decision = .ask, .action = "net.fetch.h" } },
        .{ .fetch_robots_disallow = .{ .host = "h", .path = "/p" } },
    };
    var buffers: [cases.len][512]u8 = undefined;
    var lines: [cases.len][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{&case});
        try testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, line, other));
    }
}

test "a refused host tells the person the rule to write, and never tells them to write the wrong one" {
    var buffer: [512]u8 = undefined;

    const asked = Diagnostic{ .fetch_host_not_permitted = .{
        .host = "ziglang.org",
        .decision = .ask,
        .action = "net.fetch.org.ziglang",
    } };
    const said = try std.fmt.bufPrint(&buffer, "{f}", .{&asked});
    try testing.expect(std.mem.indexOf(
        u8,
        said,
        ".{ .action = \"net.fetch.org.ziglang\", .decision = .allow }",
    ) != null);
    try testing.expect(std.mem.indexOf(u8, said, ".policy.rules") != null);
    try testing.expect(std.mem.indexOf(u8, said, "chock.zon") != null);

    var deny_buffer: [512]u8 = undefined;
    const denied = Diagnostic{ .fetch_host_not_permitted = .{
        .host = "ziglang.org",
        .decision = .deny,
        .action = "net.fetch.org.ziglang",
    } };
    const refused = try std.fmt.bufPrint(&deny_buffer, "{f}", .{&denied});
    try testing.expect(std.mem.indexOf(u8, refused, "denies that host") != null);
    try testing.expect(std.mem.indexOf(u8, refused, ".decision = .allow }") == null);

    var none_buffer: [512]u8 = undefined;
    const unnamed = Diagnostic{ .fetch_host_not_permitted = .{
        .host = "..",
        .decision = .ask,
    } };
    const nothing = try std.fmt.bufPrint(&none_buffer, "{f}", .{&unnamed});
    try testing.expect(std.mem.indexOf(u8, nothing, "not a host name") != null);
}
