//! Why the broker refused an act, or could not carry one out.
//!
//! **A library must not decide what a person sees.** Every fault below used
//! to print a line to the terminal and then return a coarse error, or in
//! several cases return nothing at all and leave the print as the only
//! record. That put a library in charge of what a person reads, and it left
//! a caller that is not a terminal, such as `chockd`, with an error name or
//! with silence.
//!
//! **This is one type for the whole module.** A caller of `actions.run` does
//! not know in advance whether it will hear from the approval flow, from the
//! act itself, or from the socket the answer arrives on, so it holds one
//! slot and reads one answer.
//!
//! **Several variants own memory, and `deinit` releases all of them.** What
//! `git` wrote on its error stream, and a field read out of the session log,
//! both live in buffers their reader frees on the way out, so the diagnostic
//! keeps a copy. A variant that names a path or an action inside an `Ask`
//! borrows it: the caller of `actions.run` holds that `Ask` for the whole
//! call, and `deinit` frees nothing there.
//!
//! **`deinit` names every variant and has no `else`.** A variant added later
//! must say which of the two groups it is in before this file compiles again.
//! The `else` this had is how `answer_claims_a_review` came to share an arm
//! with `answer_names_an_unknown_decision`: the first held `@tagName` of a
//! decision, which is a pointer into `.rodata`, and the second holds a copy.
//! `gpa.free` on the literal ended the process. That field is now a
//! `ReviewDecision`, which removes the lifetime rather than answering it.
//!
//! **One variant is a notice and not a fault.** See
//! `scratch_store_holds_a_non_object`.

const std = @import("std");

const chock_policy = @import("chock-policy");

pub const Diagnostic = union(enum) {
    /// What is at a path could not be read, so the request cannot show it.
    /// The path is borrowed from the `Ask`.
    path_read_failed: PathFailed,
    /// A `git` call refused while a description was being read. Its error
    /// stream is copied.
    git_refused_a_description: []const u8,
    /// The scratch object store could not be opened. The path is borrowed.
    scratch_store_unreadable: PathFailed,
    /// The scratch object store could not be walked.
    scratch_store_walk_failed: anyerror,
    /// **A notice, not a fault.** The scratch object store holds a file that
    /// is not an object, so that file does not move. The call still
    /// succeeds. A caller that reads its slot after a call that returned
    /// normally finds this, and nothing else ever lands there on that path.
    /// The name is copied.
    scratch_store_holds_a_non_object: []const u8,

    /// A `git` call refused while the act was being done. Its error stream
    /// is copied.
    git_refused_the_act: []const u8,
    /// The branch is not where the approved act said it was, so it is not
    /// deleted. Every name is copied.
    branch_moved: BranchMoved,
    /// The URL names a scheme this broker does not fetch. Borrowed from the
    /// `Ask`'s own URL.
    scheme_not_fetchable: []const u8,
    /// The URL names a host other than the one the approval covers. The
    /// approved host is borrowed from the `Ask`; the one the URL named is
    /// copied.
    host_not_approved: HostNotApproved,
    /// The Nix daemon socket cannot be reached, so nothing is built. The
    /// path is borrowed.
    nix_daemon_unreachable: PathFailed,
    /// A file the act writes could not be opened. The path is borrowed.
    file_not_openable: PathFailed,
    /// A file the act writes could not be written. The path is borrowed.
    file_not_writable: PathFailed,
    /// An object the request listed is in neither store, so the ref does not
    /// move. The id is borrowed from the `Ask`.
    object_missing: []const u8,
    /// An object could not be put in the project. The id is borrowed.
    object_not_moved: PathFailed,
    /// The roster of this session does not name the model. Borrowed.
    model_not_on_roster: []const u8,
    /// A command could not be started. The name is borrowed from its own
    /// argument vector, which the caller built.
    command_not_started: PathFailed,
    /// What a command printed could not be read.
    command_output_unreadable: []const u8,
    /// Waiting for a command failed.
    command_wait_failed: PathFailed,

    /// The policy asks for a person and this request cannot wait for one, so
    /// no review was paid for. The action name is borrowed from the `Ask`.
    cannot_wait_for_a_person: DecisionAbout,
    /// A review came back for a decision that asks for no review.
    review_for_a_decision_that_asks_for_none: DecisionAbout,
    /// The policy asks for a review and this session can start no reviewer.
    no_reviewer: DecisionAbout,
    /// The reviewer's own kind is already in the chain that asked, so the
    /// review would be the requester reviewing itself. Both are borrowed.
    reviewer_reviews_itself: ReviewerReviewsItself,
    /// The answer in the log is about a different request. Every field read
    /// out of the log is copied; the two from the `Ask` are borrowed.
    answer_is_about_another_request: MismatchedAnswer,
    /// The answer claims a decision only the broker's own review writes.
    /// **The decision is an enumeration and not a string**, so this variant
    /// owns nothing and has no lifetime to get wrong: see `ReviewDecision`.
    answer_claims_a_review: ReviewClaimed,
    /// The answer names a decision this build does not know. The name is
    /// copied.
    answer_names_an_unknown_decision: AnswerNames,

    /// The path is longer than a unix socket path may be on this platform, so
    /// nothing was bound. Borrowed. See `chock-broker/socket.zig`'s own
    /// `max_socket_path` for why the bound is not the same on both platforms.
    socket_path_too_long: SocketPathTooLong,
    /// The approval socket directory could not be made. Borrowed.
    socket_dir_not_made: PathFailed,
    /// The approval socket directory could not be opened. Borrowed.
    socket_dir_not_opened: PathFailed,
    /// The approval socket directory could not be made private. Borrowed.
    socket_dir_not_private: PathFailed,
    /// The approval socket itself could not be opened. Borrowed.
    socket_not_opened: PathFailed,
    /// A socket file was already at the path and could not be removed.
    /// Borrowed.
    socket_not_removed: PathFailed,
    /// A client of another user tried to attach. **Not a fault of Chock's**,
    /// and the connection is closed either way: this is what a person needs
    /// to see when their own client will not attach.
    client_uid_refused: ClientUidRefused,
    /// A step of the waiter failed. `what` is a literal of this module.
    waiter_step_failed: PathFailed,

    /// The bytes a sandboxed process asked to reach are not a host name.
    net_host_not_a_name: NetHost,
    /// The policy does not permit that host and port for this spawn chain.
    /// `decision` is what the table really answered, so a person reads which
    /// rule turned it away and not only that something did.
    net_host_not_permitted: NetRefused,
    /// The policy permits the host and the name did not resolve.
    net_host_not_resolved: NetHost,
    /// The name resolved onto this machine rather than onto the network: the
    /// loopback interface, a link local address such as the cloud metadata
    /// service, the unspecified address, or a multicast one. See
    /// `network.addressIsReachable`.
    net_address_not_permitted: NetHost,
    /// The address was permitted and the connection did not open.
    net_not_connected: NetHost,

    /// The policy does not permit that host for this spawn chain. `decision`
    /// is what the table really answered, so a person reads which rule turned
    /// it away and not only that something did.
    fetch_host_not_permitted: FetchRefused,
    /// The host's own `robots.txt` disallows that path. **Convention parity
    /// and not a boundary**: see `lib/chock-broker/fetch.zig`.
    fetch_robots_disallow: FetchPath,

    /// A secret handle has no closing brace.
    secret_handle_unterminated,
    /// No credential is named by a handle. Borrowed from the text, which the
    /// caller holds.
    secret_not_named: []const u8,

    /// A path, or another name, and the fault it gave. `path` is borrowed
    /// unless the variant's own comment says otherwise.
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
        /// **Owned**, and released by `deinit`. The name is read out of a log
        /// event the reader moves past at once.
        name: []const u8,
    };

    /// Which of the three decisions a review writes an answer claimed.
    ///
    /// **An enumeration and not a string**, so this field has no lifetime and
    /// cannot dangle. It used to hold `@tagName` of the decision, which is a
    /// pointer into `.rodata`, and `deinit` freed it beside a name that really
    /// was a copy. The names are the wire names of
    /// `chock_proto.event` decisions, because a person reading the message
    /// wants the word the log holds.
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

    /// A socket path and the bound it passed. **The bound is carried and not
    /// read at the reader**, so a person sees the number the build that
    /// refused really used.
    pub const SocketPathTooLong = struct {
        path: []const u8,
        bound: usize,
    };

    pub const ClientUidRefused = struct {
        uid: std.posix.uid_t,
        owner_uid: std.posix.uid_t,
    };

    /// A host and a port a sandboxed process asked to reach. `host` is owned:
    /// see the network broker's own group above.
    pub const NetHost = struct {
        host: []const u8,
        port: u16,
    };

    /// The same, and what the table answered. `host` is owned.
    pub const NetRefused = struct {
        host: []const u8,
        port: u16,
        decision: chock_policy.table.Decision,
    };

    /// A host the fetch tool was asked to read, and what the table answered.
    /// `host` is owned, and so is `action` when it is there.
    pub const FetchRefused = struct {
        host: []const u8,
        decision: chock_policy.table.Decision,
        /// The policy key the host builds, for example
        /// `net.fetch.org.ziglang`, or null for a host that builds none.
        ///
        /// **Carried so the sentence can name the rule to add.** A person who
        /// reads "the policy refused it" has learned nothing they can act on,
        /// and the one thing they can do is write a row of `chock.zon`. The
        /// key is built where the decision is made, because that is the one
        /// place that knows how a host becomes an action.
        action: ?[]const u8 = null,
    };

    /// A host and the path on it that `robots.txt` disallowed. Both are owned.
    pub const FetchPath = struct {
        host: []const u8,
        path: []const u8,
    };

    /// Release what the diagnostic owns, with the allocator that filled it.
    /// Safe on every variant, so a caller can call it without asking which
    /// one it holds.
    ///
    /// **Every variant is named here, and there is no `else`.** A variant
    /// added later must say whether it owns memory before this file compiles
    /// again. The `else` this had is what let `answer_claims_a_review` fold
    /// into the arm beside it and free a string literal.
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

            // Every one below owns nothing. A field of one of these is
            // borrowed from the `Ask`, which the caller of `actions.run`
            // holds for the whole call, or it is a number, or an
            // enumeration, or a literal of this build.
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
            // **Written to the person and not about them.** This is the one
            // sentence a reader can act on, so it names the rule to write, the
            // block it goes in, and the file. The agent is told a different
            // sentence for the same refusal: see
            // `chock_broker.fetch.Session.refusalForHost`, and
            // `chock_proto.event.ToolResult.note` for why the two are separate
            // and must stay so.
            .fetch_host_not_permitted => |about| {
                try writer.print("nothing was read from {s}. ", .{about.host});
                const action = about.action orelse {
                    return writer.writeAll("That is not a host name a policy key is built " ++
                        "from, so no rule of chock.zon can name it. Give a plain host name.");
                };
                // A host a rule already denies is a decision somebody made.
                // Telling them to add an `allow` row would be wrong: the row
                // that is there wins, and they have to find it first.
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

/// Fill `out` when the caller asked for one, and say whether it took `value`.
///
/// **The first fault is kept, not the last.** An act can only be carried out
/// after the approval flow permitted it, so a later fault overwriting an
/// earlier one would replace the fault that explains the run with the fault
/// it caused.
///
/// The answer matters because several variants own memory: a site that hands
/// one over must release it itself when the answer is false.
pub fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// Whether a diagnostic is wanted and still empty, which is the one case in
/// which a site should copy a string for it. A caller that passes null must
/// pay no allocation at all.
pub fn wants(out: ?*?Diagnostic) bool {
    const slot = out orelse return false;
    return slot.* == null;
}

const testing = std.testing;

test "the first fault is kept, and a caller that wants none pays nothing" {
    // **The first, not the last.** An act is only carried out after the
    // approval flow permitted it, so a later fault overwriting an earlier one
    // would replace the fault that explains the run with the fault it caused.
    var diag: ?Diagnostic = null;
    try testing.expect(note(&diag, .{ .no_reviewer = .{ .decision = .agent_review, .action = "git.push" } }));
    try testing.expect(!note(&diag, .{ .model_not_on_roster = "sonnet" }));
    try testing.expectEqualStrings("git.push", diag.?.no_reviewer.action);

    // A caller that asked for no diagnostic must reach no store at all. The
    // false answer is what tells an owning site to release its own copy
    // rather than leak it into a slot that does not exist.
    try testing.expect(!note(null, .{ .model_not_on_roster = "sonnet" }));
    try testing.expect(!wants(null));
    try testing.expect(!wants(&diag));
}

test "a message is released by the allocator that filled it, and by nothing else" {
    // The fault this test exists for: `answer_claims_a_review` held
    // `@tagName` of a decision, `deinit` folded it into the arm that frees a
    // copied name, and `gpa.free` reached a pointer into `.rodata`. The
    // process died on a `memset` of read only memory.
    //
    // Every variant goes through `deinit` here, filled the way its own site
    // fills it. A variant added later that borrows where its neighbours own
    // fails here rather than in a user's run. A dangling read alone often
    // does not fail, because a freed page still holds the text: **it is the
    // invalid free that never passes.**
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer testing.expect(debug.deinit() == .ok) catch @panic("a leak");
    const gpa = debug.allocator();

    for (everyVariant(gpa)) |built| {
        var one = built;
        one.deinit(gpa);
    }
}

/// One of every variant, each filled the way its own site fills it. Owned
/// strings are copies of `gpa`, and borrowed ones are literals.
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
        // The two that used to share one arm of `deinit`. The first owns
        // nothing at all now.
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
                // Owned as well, and released by the same arm.
                .action = gpa.dupe(u8, "net.fetch.h") catch @panic("no memory"),
            },
        },
        .{ .fetch_robots_disallow = .{
            .host = gpa.dupe(u8, "h") catch @panic("no memory"),
            .path = gpa.dupe(u8, "/p") catch @panic("no memory"),
        } },
        // One that owns nothing, so the arm with no work is walked too.
        .{ .path_read_failed = .{ .path = "/p", .err = error.AccessDenied } },
    };
}

test "every decision a review writes reads as itself" {
    // The enumeration replaced a `@tagName`. A member added later with no
    // text, or with the text of another, would make two different claims read
    // the same.
    var seen: [std.meta.fields(Diagnostic.ReviewDecision).len][]const u8 = undefined;
    inline for (std.meta.fields(Diagnostic.ReviewDecision), 0..) |field, i| {
        const text = (@field(Diagnostic.ReviewDecision, field.name)).text();
        try testing.expect(text.len > 0);
        for (seen[0..i]) |other| try testing.expect(!std.mem.eql(u8, text, other));
        seen[i] = text;
    }
}

test "no two faults of this module read the same" {
    // A reader has to be able to tell which one happened, and this module
    // has several pairs that would collapse into one phrase: the two git
    // refusals, the four socket directory faults, and the two answers that
    // name a decision.
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
        // The two the fetch tool fills. They must not read as the two above
        // them: one is a raw connection a sandboxed process asked for, and
        // this is a page the agent asked for.
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
    // **The fault the project owner reported on 2026-08-25.** He asked for a
    // page, the policy refused it correctly, and the only sentence he could
    // act on was the one written to the model: "which you cannot write and the
    // user can. Ask the user, or work without that page." He read a message
    // about himself in the third person, and reported a working refusal as a
    // broken feature.
    //
    // So this sentence, which is the one he reads, names the rule, the block
    // it goes in, and the file. The agent still reads its own, unchanged: see
    // `chock_broker.fetch.Session.refusalForHost`.
    //
    // Mutation check: drop `action` and the key is gone from the sentence;
    // fold the `.deny` arm into the one below it and the second half fails.
    var buffer: [512]u8 = undefined;

    const asked = Diagnostic{ .fetch_host_not_permitted = .{
        .host = "ziglang.org",
        .decision = .ask,
        .action = "net.fetch.org.ziglang",
    } };
    const said = try std.fmt.bufPrint(&buffer, "{f}", .{&asked});
    // The whole rule, in the syntax `chock.zon` really takes.
    try testing.expect(std.mem.indexOf(
        u8,
        said,
        ".{ .action = \"net.fetch.org.ziglang\", .decision = .allow }",
    ) != null);
    // The block, because a rule written beside `.agents` is a file that does
    // not parse and a session that does not start. See docs/configuration.md.
    try testing.expect(std.mem.indexOf(u8, said, ".policy.rules") != null);
    try testing.expect(std.mem.indexOf(u8, said, "chock.zon") != null);

    // **A host a rule already denies is a different instruction.** The row
    // that is there wins, so telling somebody to add an `allow` row would send
    // them to write a rule that changes nothing.
    var deny_buffer: [512]u8 = undefined;
    const denied = Diagnostic{ .fetch_host_not_permitted = .{
        .host = "ziglang.org",
        .decision = .deny,
        .action = "net.fetch.org.ziglang",
    } };
    const refused = try std.fmt.bufPrint(&deny_buffer, "{f}", .{&denied});
    try testing.expect(std.mem.indexOf(u8, refused, "denies that host") != null);
    try testing.expect(std.mem.indexOf(u8, refused, ".decision = .allow }") == null);

    // A host that builds no key promises no rule at all, rather than naming
    // one nobody can write.
    var none_buffer: [512]u8 = undefined;
    const unnamed = Diagnostic{ .fetch_host_not_permitted = .{
        .host = "..",
        .decision = .ask,
    } };
    const nothing = try std.fmt.bufPrint(&none_buffer, "{f}", .{&unnamed});
    try testing.expect(std.mem.indexOf(u8, nothing, "not a host name") != null);
}
