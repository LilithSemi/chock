//! The public interface of chock-container: what a container image says, and
//! what a sandbox has to mount for it.
//!
//! This library is the sibling of `chock-nix`. It answers the same two
//! questions for a person who has no Nix. `chock-nix` reads a project's dev
//! shell and gives back an environment and a set of store paths.
//! `chock-container` reads a container image and gives back an environment and
//! a set of directories. `src/run.zig` turns either answer into a
//! `sandbox.Config.env` and a mount list.
//!
//! ## The central decision: a tool call does not run inside a container
//!
//! **The image is a source of files. Chock's own sandbox still applies on
//! top.** The container runtime is not part of the boundary at any point.
//!
//! Chock's boundary is a user namespace, a PID namespace, an IPC namespace, a
//! mount namespace, Landlock, seccomp, a network namespace, a throwaway
//! workspace, and cgroup limits. `src/doctor.zig` measures each one and tells
//! a person what this machine gives. If a tool call ran inside a container
//! instead, every one of those guarantees would become the container runtime's
//! guarantee. They would be weaker, they would differ between two runtimes,
//! and `chock doctor` could no longer speak for any of them. Chock would then
//! have two boundaries and one report, which is the shape that misleads.
//!
//! So this library does the same job a Nix closure does. It puts files on the
//! host disk, before a session starts, and it names them. Nothing more.
//!
//! ## The measurement behind that decision
//!
//! Measured on this machine on 2026-08-25, on Linux 6.18.42, aarch64, with
//! Docker 29.7.2 and no Podman:
//!
//! * `docker export` of a created container writes a plain tar of the image
//!   root filesystem. An unprivileged user extracts the whole of it with no
//!   error. Every file is owned by that user. There are no device nodes,
//!   because `export` writes `/dev/console` as an empty ordinary file.
//! * A musl program from that extracted tree runs inside an unprivileged user
//!   namespace. `/bin/busybox uname -a` answered. Its dynamic loader was found
//!   inside the tree.
//! * A network namespace over the same tree refuses a connection. The reply
//!   was "Network unreachable".
//!
//! **The user namespace question therefore does not arise.** A rootless
//! runtime uses a user namespace of its own while it builds and stores an
//! image. That work is over before a tool call starts. At tool-call time there
//! is no container, no runtime process, and no second user namespace. There is
//! a directory. Nothing nests, so nothing costs anything.
//!
//! ## What this arrangement may honestly claim
//!
//! **It adds no guarantee at all, and it must never appear to.** There is no
//! `Guarantees` value anywhere in this library, on purpose. A session that
//! gets its files from an image has exactly the guarantees
//! `chock_sandbox.guarantees` states, because the sandbox is unchanged.
//!
//! What this library does state is a different fact, on a different axis:
//! **which program put those files on the disk, and what privilege that
//! program holds.** See `Runtime.Trust`. A root daemon that unpacks an image
//! is a materially different trust position from a rootless runtime that
//! unpacks the same image. A person choosing between them is told, and
//! `Trust.isPrivileged` reads an unknown answer as the privileged one, so a
//! caller cannot get the good answer by failing to measure.
//!
//! ## No network at tool-call time
//!
//! Everything here spawns a host process, so it runs in `src/run.zig`'s phase
//! 1 and nowhere else. That is the same rule `chock-nix` carries.
//!
//! **An image is never pulled during a session.** `Image.Options.pull`
//! defaults to `.never`, and an image that is not on the disk is a plain
//! refusal that names the pull command to run first. The reason is the same
//! one the Nix half has: the sandbox has no network and no daemon socket.
//!
//! ## The image cache is shared, and one session at a time may change it
//!
//! Two terminals on one project is the ordinary case. The extracted tree lives
//! under one name per image so that the second session pays nothing, which
//! means two cold sessions would otherwise remove and rebuild what the other is
//! reading. `chock-container/lock.zig` is what stops that: one session extracts
//! and the others wait for it, with a bound, and a session that runs out of the
//! bound is refused with a sentence rather than left waiting.
//!
//! ## It imports no other Chock library
//!
//! An image is read before a session, a workspace, or a sandbox exists. So
//! nothing here may depend on any of them, which is the rule `chock-nix` and
//! `chock-auth` already follow. It hands back plain strings: `KEY=VALUE`
//! records for the environment, and source and target pairs for the mount set.

const std = @import("std");

const diagnostic = @import("chock-container/diagnostic.zig");

/// Why a container runtime call did not give an answer. One type for the whole
/// module: see `chock-container/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;

/// Where a fault goes, and **who owns what it points at**. Every entry point
/// of this library that can fill a diagnostic takes one of these rather than a
/// bare slot, because the working allocator inside the library can be an arena
/// that is gone before a caller reads the message.
pub const Sink = diagnostic.Sink;

/// Build a `Sink` from a caller's own allocator and its own slot. The same
/// allocator releases the message with `Diagnostic.deinit`.
pub const sinkOf = diagnostic.sinkOf;

/// What a project says about the image it wants. See
/// `chock-container/config.zig`.
pub const config = @import("chock-container/config.zig");
pub const Image = @import("chock-container/Image.zig");
pub const proc = @import("chock-container/proc.zig");
pub const reference = @import("chock-container/reference.zig");
pub const Runtime = @import("chock-container/Runtime.zig");

test {
    std.testing.refAllDecls(@This());
    _ = config;
    _ = Image;
    _ = proc;
    _ = reference;
    _ = Runtime;
}
