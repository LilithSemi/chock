//! The broker: the actor that does privileged work for an agent that cannot
//! do it itself. **The agent never gets the privilege.** Chock does the
//! operation outside the sandbox after the user approves it, and gives the
//! agent the result.
//!
//! That is why this is an actor and not a check. A check is a gate the caller
//! walks through, so a bug in the caller opens it. An actor holds the
//! capability itself, so a bug in the caller cannot reach it: the caller never
//! had the capability to lose.
//!
//! A later change puts the broker in its own process, with the credentials,
//! apart from the agent loop. That is the target and Chock does not build it
//! yet. This library has one entry point, `Broker.request`, and it is shaped
//! so that moving it into a process of its own changes no caller. See
//! `lib/chock-broker/Broker.zig`'s own top comment for the one seam that
//! changes when it moves.

/// Why the broker refused an act, or could not carry one out. One type for
/// the whole module: see its own top comment.
pub const Diagnostic = @import("chock-broker/diagnostic.zig").Diagnostic;

pub const Broker = @import("chock-broker/Broker.zig");

/// The eight acts the broker can carry out, and the one call that asks for
/// one and then does it. See `lib/chock-broker/actions.zig`'s own top comment for
/// why an action names its effect and never a command.
pub const actions = @import("chock-broker/actions.zig");

/// Carrying the session's work onto the branch the user has checked out, for
/// the `merge`, `rebase` and `squash` modes of `chock_policy.apply`. **No merge
/// and no rebase is ever run in the user's repository**: the result is built in
/// the session's own object store and the only write to the project is one fast
/// forward. See its own top comment for why that is the whole design.
pub const integrate = @import("chock-broker/integrate.zig");

/// The `git` shim. **It prevents a mistake and it does not
/// prevent an attack**, and its own top comment says so at length, with the
/// ways around it named one by one. The capability layers are the boundary.
pub const git_shim = @import("chock-broker/git_shim.zig");

/// The credentials. The broker holds them, the model never
/// sees a value, and every tool result is redacted **before** it enters the
/// log, because `chockd` serves the log to other clients.
pub const secrets = @import("chock-broker/secrets.zig");

/// The password helper: the half that runs beside the credentials and
/// answers a prompt `git` or `ssh` wrote. **It prevents a
/// mistake and it does not prevent an attack**, exactly as the git shim does
/// not, and its own top comment says so with the ways around it named one by
/// one. A prompt is untrusted text, a host is permitted by the policy table
/// or by nobody, and a prompt nobody can answer is refused.
pub const askpass = @import("chock-broker/askpass.zig");

/// The reviewer agent, for the two policy decisions that a subagent answers
/// before anybody else does. **The arbitrator is told why an
/// action is guarded and the agent that asked is not**, and that asymmetry is
/// the reason it is worth building rather than being a second opinion from an
/// identical model. See its own top comment.
pub const review = @import("chock-broker/review.zig");

/// The network broker: who answers when a `namespace.Network.filtered`
/// process asks to reach a host, and on what grounds. **The connect happens
/// here and never inside the sandbox**, so a sandboxed process cannot reach a
/// host merely by knowing its address, and a host rule is an ordinary action
/// in the policy table rather than a second policy system. See its own
/// top comment, especially on what a hostile name can and cannot make this
/// process look up.
pub const network = @import("chock-broker/network.zig");

/// Reading a URL for the agent: the policy row that authorises one host, the
/// redirect chain where **every hop is authorised in its own right**, and the
/// `robots.txt` that is honoured for convention parity and is not a boundary.
/// One layer above the `net.fetch` action, which still reads one URL on one
/// host and follows nothing. See its own top comment.
pub const fetch = @import("chock-broker/fetch.zig");

/// The approval socket: the second implementation of
/// `Broker.Waiter`, so an answer can arrive from a process other than the one
/// holding the session lock. **The broker does not own the log and does not
/// append to it over the wire**, and its own top comment says why that is the
/// right shape rather than a shortcut.
pub const socket = @import("chock-broker/socket.zig");

/// The handover socket: how one process asks a running session to stop at its
/// next turn boundary, so another process can take the session log's exclusive
/// lock and become the owner. **It carries a question and an answer and never a
/// log write**, which is the same rule the approval socket keeps, and its own
/// top comment says why the two are not one descriptor.
pub const handover = @import("chock-broker/handover.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
