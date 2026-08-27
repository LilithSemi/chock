//! `chock memory`: read the knowledgebase, and clear it.
//!
//! **Memory a user cannot inspect is memory a user cannot trust.** A note
//! written in one session is read by every session after it, and it survives
//! the sandbox by construction, because outliving the sandbox is what memory
//! is for. So there has to be a way to look at what is there, and clearing it
//! has to be one obvious step.
//!
//! ```
//! chock memory            # one line per note
//! chock memory show <name>
//! chock memory forget <name>
//! chock memory clear
//! ```
//!
//! Nothing here starts a session, opens a sandbox, or touches the project. It
//! reads and writes one directory of Chock's own, the same one
//! `lib/chock-core/memory.zig` describes.

const std = @import("std");
const chock_core = @import("chock-core");

const session_paths = @import("session.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const memory = chock_core.memory;

const usage_text =
    \\Usage: chock memory [list|show <name>|forget <name>|clear] [options]
    \\
    \\With no subcommand, lists every note this project has.
    \\
    \\Options:
    \\  --project <dir>   The project. Defaults to the current directory.
    \\
++ tty.options_text;

const Options = struct {
    project: ?[]const u8 = null,
    action: Action = .list,
    name: []const u8 = "",
};

const Action = enum { list, show, forget, clear };

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = gpa;
    _ = exe_path;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env = try environ.createMap(arena);
    defer env.deinit();

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        else => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    const project_root = try resolveProject(arena, io, options.project);
    const dir = session_paths.memoryDir(arena, &env, project_root) catch |err| {
        tty.print(.err, "chock memory: the knowledgebase directory is unknown: {s}\n", .{@errorName(err)});
        return Exit.usage.code();
    };

    return switch (options.action) {
        .list => listNotes(arena, io, dir),
        .show => showNote(arena, io, dir, options.name),
        .forget => forgetNote(io, dir, options.name),
        .clear => clearNotes(arena, io, dir),
    };
}

fn listNotes(arena: std.mem.Allocator, io: std.Io, dir: []const u8) !u8 {
    const notes = try memory.list(arena, io, dir);
    if (notes.len == 0) {
        tty.print(.plain, "chock memory: this project has no notes ({s})\n", .{dir});
        return Exit.finished.code();
    }
    // A `--verbose` line. The notes are the answer; where they are kept is not
    // a question this command was asked, and every other subcommand here takes
    // a note name and no path.
    tty.detail("{s}\n\n", .{dir});
    for (notes) |note| {
        tty.out(.plain, "{s}  {t}  {s}\n    {s}\n", .{
            note.written_at,
            note.kind,
            note.name,
            note.description,
        });
        // **Shown here, and not only on request.** A note keeps every version
        // that was written under its name, and a user who cannot see that a
        // note has a history has no reason to ask for it. One extra line, and
        // only for the notes that have one. `chock memory show <name>` prints
        // the versions themselves, newest first.
        if (note.versions > 1) {
            tty.out(.plain, "    {d} versions, newest shown. \"chock memory show {s}\" for all\n", .{
                note.versions,
                note.name,
            });
        }
    }
    tty.out(.plain, "\n{d} of at most {d}\n", .{ notes.len, memory.max_entries });
    return Exit.finished.code();
}

fn showNote(arena: std.mem.Allocator, io: std.Io, dir: []const u8, name: []const u8) !u8 {
    if (name.len == 0) {
        tty.print(.err, "chock memory show: which note?\n", .{});
        return Exit.usage.code();
    }
    memory.checkName(name) catch {
        tty.print(.err, "chock memory show: \"{s}\" is not a note name\n", .{name});
        return Exit.usage.code();
    };

    // The whole file, which is every version of this note, newest first. That
    // is what `show` is for: the list above says a note has a history, and
    // this is where a user reads it.
    const file = try std.fmt.allocPrint(arena, "{s}/{s}" ++ memory.extension, .{ dir, name });
    const text = std.Io.Dir.cwd().readFileAlloc(io, file, arena, .limited(memory.max_entry_bytes)) catch {
        tty.print(.err, "chock memory show: there is no note named \"{s}\"\n", .{name});
        // Never `finished`: a command that did nothing must not report
        // success. See `src/main.zig`'s own top comment.
        return Exit.usage.code();
    };
    tty.out(.plain, "{s}", .{text});
    return Exit.finished.code();
}

fn forgetNote(io: std.Io, dir: []const u8, name: []const u8) !u8 {
    if (name.len == 0) {
        tty.print(.err, "chock memory forget: which note?\n", .{});
        return Exit.usage.code();
    }
    memory.forget(io, dir, name) catch {
        tty.print(.err, "chock memory forget: there is no note named \"{s}\"\n", .{name});
        return Exit.usage.code();
    };
    tty.print(.plain, "chock memory: forgot {s}\n", .{name});
    return Exit.finished.code();
}

fn clearNotes(arena: std.mem.Allocator, io: std.Io, dir: []const u8) !u8 {
    const removed = try memory.clear(arena, io, dir);
    tty.print(.plain, "chock memory: cleared {d} notes from {s}\n", .{ removed, dir });
    return Exit.finished.code();
}

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var index: usize = 0;
    var saw_action = false;

    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--project")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.project = args[index];
            continue;
        }
        if (argument.len != 0 and argument[0] == '-') return error.BadArguments;

        if (!saw_action) {
            options.action = std.meta.stringToEnum(Action, argument) orelse return error.BadArguments;
            saw_action = true;
            continue;
        }
        if (options.name.len != 0) return error.BadArguments;
        options.name = argument;
    }

    if ((options.action == .show or options.action == .forget) and options.name.len == 0) {
        return error.BadArguments;
    }
    return options;
}

/// The project this command is about, as an absolute path.
///
/// **The same two calls `chock run`'s own `resolveProject` makes**, and that
/// is not a style choice: a knowledgebase is keyed by the project's real
/// path, so a spelling this command resolved differently would read a
/// different directory from the one the session wrote. In particular the
/// current directory comes from `std.process.currentPathAlloc` and never
/// from `realPath` on the open working directory, which answers
/// `error.FileNotFound` on this platform.
fn resolveProject(arena: std.mem.Allocator, io: std.Io, given: ?[]const u8) ![]const u8 {
    if (given) |path| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return arena.dupe(u8, path);
        defer dir.close(io);
        const len = dir.realPath(io, &buffer) catch return arena.dupe(u8, path);
        return arena.dupe(u8, buffer[0..len]);
    }
    return std.process.currentPathAlloc(io, arena);
}

const testing = std.testing;

test "the command line names an action and at most one note" {
    try testing.expectEqual(Action.list, (try parseOptions(&.{})).action);
    try testing.expectEqual(Action.clear, (try parseOptions(&.{"clear"})).action);

    const shown = try parseOptions(&.{ "show", "mount-order" });
    try testing.expectEqual(Action.show, shown.action);
    try testing.expectEqualStrings("mount-order", shown.name);

    const with_project = try parseOptions(&.{ "--project", "/somewhere", "forget", "stale" });
    try testing.expectEqualStrings("/somewhere", with_project.project.?);
    try testing.expectEqualStrings("stale", with_project.name);

    // `show` and `forget` need a name, and a word this command does not know
    // is not silently read as one.
    try testing.expectError(error.BadArguments, parseOptions(&.{"show"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"forget"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"delete-everything"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}
