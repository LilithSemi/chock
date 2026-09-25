//! How the loop answers a `web_search` call for the agent.
//!
//! ## Why this is a seam and not a call
//!
//! No engine talks to the network here. `src/run.zig` fills this vtable in
//! with whatever engine a project's `config.zon` names, the same way
//! `lib/chock-core/fetch.zig` is filled in, and for the same reason:
//! `chock-core` imports no `chock-broker`, so the policy table stays in a
//! process the agent cannot reach.
//!
//! ## Why the loop answers this call and not the tool runner
//!
//! **A promise binds this**, and the promises live in the fold of the session
//! log, which only the loop holds. A tool runner is handed one call and knows
//! nothing about the session around it, the same reason `fetch_url` is
//! answered here rather than dispatched.
//!
//! ## `web.search` asks a live question
//!
//! `fetch_url` is answered by the loop before `gateToolCall` is reached, so
//! its `net.fetch` question is read early, with nobody waiting on the
//! answer, and `ask` there means refusal. `web_search` takes the ordinary
//! road: `gateToolCall` asks the arbiter under the action `web.search`, at
//! the moment the model is waiting on the result, so `ask` there is a real
//! question a person answers. This file decides nothing about that; it is
//! only reached once the gate has already let the call through.
//!
//! ## A result is written by a stranger
//!
//! A title, a URL, and a snippet in a search result are bytes an engine
//! handed back from somewhere on the web, the same kind of input a fetched
//! page is. Whatever implementation fills this seam must run its `Answer.text`
//! through the same cleaning `chock_core.fetch.textForModel` does, for the
//! same reasons stated there, before handing it back.

const std = @import("std");

const chock_policy = @import("chock-policy");

const ratchet = chock_policy.ratchet;

/// What the loop wants searched.
pub const Ask = struct {
    /// The query the model gave. Borrowed for the call.
    query: []const u8,
    /// What this session promised about itself, folded from its own
    /// `policy.self` events. Carried and never applied here: see this file's
    /// own top comment.
    self_policy: []const ratchet.Restriction = &.{},
    /// The tool the agent called, which is one of the four parts of a policy
    /// key.
    tool: []const u8,
};

/// What came back. `text` is what the agent reads, and it is allocated with
/// the `gpa` the call was given.
pub const Answer = struct {
    text: []u8,
    /// True when nothing was searched. The agent reads `text` either way, and
    /// a refusal names what would permit the search.
    is_error: bool,
    /// What the person watching is told, or empty for none. Allocated with the
    /// same `gpa` `text` is, and the loop frees it.
    note: []u8 = &.{},
};

pub const Error = std.mem.Allocator.Error;

/// The seam itself.
pub const Searcher = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Run one query. **A refusal is not an error**: it is an `Answer`
        /// the agent reads and acts on, the same rule every tool call in
        /// Chock follows. Only running out of memory reaches the caller.
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

/// What a `web_search` call gets when this session was started with no
/// search engine configured. A real case and not a stub: every test of the
/// loop drives one, and so does any caller that runs a session with no
/// engine named.
pub const has_no_searcher = "nothing was searched: this session was started with no search " ++
    "engine configured. One is set in the user's own config.zon; work from what is in the " ++
    "project, or ask the user for the content.";

const testing = std.testing;

test "the no-engine message names where an engine is set" {
    try testing.expect(std.mem.indexOf(u8, has_no_searcher, "config.zon") != null);
    try testing.expect(std.mem.indexOf(u8, has_no_searcher, "nothing was searched") != null);
}
