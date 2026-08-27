//! One `chock login` worth of store writing, as its own process.
//!
//! **Two `chock login` runs at once is the ordinary case**: a person who runs
//! the command twice, or once while a script does. Both write the same index
//! file, so the contention is through the filesystem and two `Store.put` calls
//! inside one test binary would say nothing about two commands. This program is
//! one of those commands, with everything a login does around the store taken
//! away: no prompt, no provider check, no configuration.
//!
//! **The start time is a command line argument**, because the section under
//! measurement is microseconds long. Processes started one after the other
//! would not overlap at all, and a race nobody entered measures nothing. Every
//! helper waits for the same wall clock instant and then goes.
//!
//! **Nothing here writes to standard error.** `test/proto/lock.zig` holds the
//! rule for the whole build. Every answer travels as an exit status.
//!
//! **The two shapes a login has, and they are not the same race.** A login that
//! was given `--name` replaces what that name held, and says so. A login that
//! was given none must refuse when the name is already there, so that a
//! second unnamed instance never silently replaces the first. This helper can
//! run either shape, and `<if-present>` chooses.
//!
//! **The refusing shape asks twice, exactly as `src/login.zig` does.** The early
//! `get` is the one that keeps a person from being asked for a credential that
//! cannot be kept, and it is outside every lock. The `replace_existing` field is
//! the one the store checks again with the lock held. A helper that made only
//! the second check would measure a command nobody runs.
//!
//! Command line:
//!   login-helper <data-dir> <name> <token> <stored-ms> <start-unix-ms> <if-present>
//!
//! `<if-present>` is `replace` for a login that was given `--name`, or `refuse`
//! for one that was not.
//!
//! Exit status:
//!   0   the credential was stored
//!   1   another login held the store and this one gave up
//!   2   the store refused for some other reason
//!   3   the command line was wrong
//!   4   this program itself failed
//!   5   the name was already stored and this login was not given one

const std = @import("std");
const chock_auth = @import("chock-auth");

pub const stored = 0;
pub const busy = 1;
pub const store_failed = 2;
pub const bad_usage = 3;
pub const helper_fault = 4;
pub const name_taken = 5;

pub fn main(init: std.process.Init) u8 {
    const arena = init.arena.allocator();

    const args = init.minimal.args.toSlice(arena) catch return helper_fault;
    if (args.len != 7) return bad_usage;
    const data_dir = args[1];
    const name = args[2];
    const token = args[3];
    const stored_ms = std.fmt.parseInt(i64, args[4], 10) catch return bad_usage;
    const start_ms = std.fmt.parseInt(i64, args[5], 10) catch return bad_usage;
    const replace = if (std.mem.eql(u8, args[6], "replace"))
        true
    else if (std.mem.eql(u8, args[6], "refuse"))
        false
    else
        return bad_usage;

    waitUntil(init.io, start_ms);

    const driver = chock_auth.store.Driver{ .data_dir = data_dir };
    const store = chock_auth.store.Store{ .data_dir = data_dir, .secrets = driver.secrets() };

    // The early look, which `src/login.zig` makes before it asks a person for
    // anything. It holds no lock, so two logins can both pass it.
    if (!replace) {
        const existing = store.get(init.gpa, init.io, name, null) catch return store_failed;
        if (existing) |found| {
            var value = found;
            value.deinit();
            return name_taken;
        }
    }

    var diag: ?chock_auth.store.Diagnostic = null;
    defer if (diag) |*d| d.deinit(init.gpa);
    store.put(init.gpa, init.io, .{
        .name = name,
        .kind = .aiand,
        .token = token,
        .stored_ms = stored_ms,
        .replace_existing = replace,
    }, &diag) catch {
        if (diag) |fault| {
            switch (std.meta.activeTag(fault)) {
                .store_is_busy => return busy,
                .name_already_stored => return name_taken,
                else => {},
            }
        }
        return store_failed;
    };
    return stored;
}

/// Spin until the wall clock reaches `start_ms`. Short sleeps rather than a
/// tight loop: eight helpers burning a core each would change what is being
/// measured.
fn waitUntil(io: std.Io, start_ms: i64) void {
    while (std.Io.Timestamp.now(io, .real).toMilliseconds() < start_ms) {
        std.Io.sleep(io, .fromNanoseconds(200 * std.time.ns_per_us), .awake) catch return;
    }
}
