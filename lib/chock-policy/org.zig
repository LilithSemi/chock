//! The org bundle: **the policy an organisation gives an installation, above
//! the policy a project writes for itself.** `chock.zon` may only narrow it.
//!
//! ## The rule, which is the ratchet one level up
//!
//! * A bundle holds `table.Rule`s. The same four key fields, the same dotted
//!   pattern language, the same rule that wins.
//! * `Table.evaluateChain` folds a bundle in as one more term of the minimum
//!   it already takes over the chain. See `Table.org`.
//! * A rule of `chock.zon` can therefore lower an answer and can never raise
//!   one. A project cannot widen what an org narrowed, and that is a property
//!   of a minimum rather than a check somebody has to remember to write.
//!
//! **A bundle is read as a ceiling and never as a decision.** An action no
//! bundle rule names answers `allow`, which is no ceiling at all, and not
//! `ask`, which is what `chock.zon` answers for an action nobody named. The two
//! defaults are different because the two questions are different, and
//! `ratchet.ceilingFor` already draws that line for the agent's own promises:
//! "may this happen" must be safe when nobody said, and "how far does this
//! layer let it go" must be silent when this layer said nothing. Reading a
//! bundle as a decision would cap every action in every project at `ask` the
//! moment an installation was given one.
//!
//! ## Identity is the credential, and Chock builds no identity system
//!
//! The organisation issues the credential, so the hub that issued it already
//! knows who the subject is. The bundle travels with the credential and states
//! that subject; Chock reads it and never checks it. There is no user
//! database here, no directory, no sign in, and no token this file verifies:
//! **a bundle is trusted exactly as far as the file it was written into**,
//! which is a file in the data directory `lib/chock-auth/paths.zig` names,
//! written by whatever installed Chock and beyond the reach of the project.
//!
//! ## An expired bundle: neither failing shut nor falling open
//!
//! A laptop is offline for a week. The bundle it holds says it expired on
//! Tuesday. Two answers suggest themselves and both are wrong:
//!
//! * **Fail shut**, and refuse to run. The organisation's control becomes an
//!   outage every time a network is missing, and the people it was written for
//!   go around it.
//! * **Fall open**, and ignore the bundle. Every narrowing the organisation
//!   made evaporates at exactly the moment nobody can be reached to say
//!   whether that is right, and a bundle could be retired by keeping a machine
//!   off a network for long enough.
//!
//! **The answer is neither, and it falls out of what a bundle is.** A bundle
//! only narrows. Every rule in it is one more term of the same minimum, so a
//! bundle can refuse an act and it can never permit one. Dropping an expired
//! bundle can therefore only widen, and keeping one can only hold a session to
//! more than it has to be held to. So Chock decides:
//!
//! 1. **An expired bundle keeps binding, in full and for ever.** The laptop
//!    keeps working, under the last policy its organisation gave it, which is
//!    the last policy that organisation said it wanted.
//! 2. **An expired bundle is said out loud, on every start**, with how long
//!    ago it expired. `src/run.zig` prints it as a warning. An expiry that
//!    changes nothing and says nothing would be decoration, and a reader who
//!    is under a stale policy has to be able to see that they are.
//! 3. **An expired bundle may not be installed.** `refusalForInstall` refuses
//!    a file that is already expired, so `chock run --org-bundle` will not take
//!    one. That is what the date is for: it is the day after which nobody may
//!    hand this file to Chock, and it is not the day the file stops binding a
//!    machine that already has it.
//!
//! ## A bundle this build cannot fully read is refused
//!
//! `version` is the one field that fails a whole bundle. A file that names a
//! version above `max_version` was written by a newer Chock, and this build
//! cannot know whether the part it does not understand narrows something. An
//! unknown *field* at a version this build knows is ignored, which is how a hub
//! adds a note or a display name without breaking older installations; an
//! unknown *version* is refused, because falling open on a bundle is the one
//! outcome this file exists to prevent. A hub that adds a field which changes
//! what is permitted raises the version.
//!
//! ## A required sink, which is a control and not an option
//!
//! Log export is `lib/chock-proto/ship.zig`, and until this field it was
//! command line only. That made the audit trail **opt in by the person being
//! observed**: a developer who left `--export-dir` off left no trail, and an
//! installation had no way to say *every session here exports to this place*.
//! That is the difference between a control and an option, and an organisation
//! buying observability is buying the control.
//!
//! **A sink is not a rule, so it is a field and not a row.** A rule answers
//! "may this act happen"; a sink is a place bytes go. `evaluateChain` takes a
//! minimum over rules, and a minimum is the wrong arithmetic for a place: two
//! sinks are both used, never the lesser of the two.
//!
//! **The ratchet reading still holds, in the shape a sink can take it.** A
//! project narrows a rule and may not widen one. A project may **add** a sink
//! of its own, because more of the record reaching more places narrows nothing,
//! and it may **never drop** one the installation named. Chock takes the union
//! of the required sinks and whatever `--export-dir` and `--export-syslog`
//! asked for, so removal is not a thing a command line can express rather than
//! a thing a check has to catch. There is no flag that turns export off.
//!
//! **A required sink inherits the expiry decision above, in full.** An expired
//! bundle keeps requiring its sinks for ever, for the same reason it keeps
//! binding its rules: dropping the requirement can only widen, at exactly the
//! moment nobody can be reached to say whether that is right.
//!
//! ### A session that cannot reach a required sink
//!
//! **Decided: the session runs, and the machine tells on itself.**
//!
//! `ship.zig` already decided that a sink being down is not fatal, because a
//! session that fails when an audit sink fails is an observability feature an
//! operator turns off, and that a trail which silently stops arriving is worse
//! than one that never started. A *required* sink is a stronger claim than an
//! optional one, so the two candidate answers were weighed again:
//!
//! * **Refuse to start.** This is the answer that sounds strict and is the
//!   weakest one in practice. The organisation's control becomes an outage
//!   every time a daemon restarts, and a developer who cannot work reaches for
//!   a tool that is not Chock. The organisation then gets **no** record of that
//!   work, rather than a late one, and it gets a reputation for stopping
//!   people. It is the same argument that made an expired bundle keep binding
//!   instead of failing shut, and it is the same answer.
//! * **Behave exactly like an optional sink.** Then "required" is a word in a
//!   file and nothing else, and the failure that matters is left in place: an
//!   organisation believing it holds a whole trail while a machine quietly
//!   holds the only copy.
//!
//! Neither, and for the reason that decides between them: **the party the
//! control serves is not the party at the keyboard.** The developer can already
//! see the warning; the organisation cannot see anything, because the thing
//! that would have told it is the sink that is down. So a required sink differs
//! from an optional one in three ways that are all about being seen:
//!
//! 1. **It is reached for before the first turn**, not found to be down when
//!    the first event fails to ship. `src/run.zig` pushes the header line at
//!    start, so an unreachable required sink is said while a person can still
//!    fix it and before a model has spent anything.
//! 2. **What it says names the installation and not the flag.** Nobody typed
//!    this sink, so a message about `--export-dir` would send a reader looking
//!    for a command line that does not hold it.
//! 3. **A gap that is still open when the session ends is in the exit status.**
//!    `Exit.audit_gap`. This is the part an organisation can act on without a
//!    person choosing to tell it, and it is deliberately narrow: a sink that
//!    was down and came back leaves no gap at all, because the log on disk is
//!    the queue and the shipper backfills every line it missed. Only a tail
//!    that is still on this machine and nowhere else when the session is over
//!    reaches the exit code. A transient outage therefore costs nothing, which
//!    is what stops this being the outage answer wearing a different hat.
//!
//! ### A required sink names an absolute path
//!
//! A relative path in an installation wide file resolves against whatever
//! directory a session was started in, which for `chock run` is the project.
//! An organisation writing `audit` would put the trail **inside the tree the
//! developer owns**, where the person being observed can delete it. Refused at
//! read time, with a message that says so.
//!
//! **This reader is looser about a field name than `chock.zon`'s reader is**,
//! and the two are looser in opposite directions on purpose. `table.parse` is
//! strict, because a misspelled key field there makes a rule match more than
//! its author wanted, and a rule that matches more permits more. Here a
//! misspelled key field makes a rule match more as well, and a rule that
//! matches more *narrows* more, because this layer is a ceiling. So the typo
//! that would be an escalation in a project file is an over-restriction in a
//! bundle, and the safe reading of an unknown name is opposite in the two.
//! `decision` still has no default, so a rule with no decision at all is
//! refused in both.

const std = @import("std");
const table = @import("table.zig");

/// The name of the bundle file. It lives in the data directory
/// `lib/chock-auth/paths.zig` names, beside the credential store, because the
/// organisation issues both and neither is the project's to write.
///
/// **The reader is here and the directory is chock-auth's.** `lib/chock-auth`
/// imports no other chock library, by a rule its own module comment states, so
/// a reader that needs `table.Rule` cannot live there. `src/run.zig` joins the
/// two.
pub const file_name = "org-policy.zon";

/// The largest bundle this reader accepts. A bundle is a small file, and it is
/// read before anything else a session does.
pub const max_file_bytes = 1 << 20;

/// The longest subject this reader accepts. A subject is a name an
/// organisation gave a person or a machine, not a document.
pub const max_subject_bytes = 256;

/// The longest issuer this reader accepts.
pub const max_issuer_bytes = 256;

/// The highest `version` this build reads. See this file's own top comment: a
/// file above this is refused whole, because this build cannot know whether
/// the part it does not understand narrows something.
pub const max_version: u32 = 1;

/// How many sinks one bundle may require.
///
/// **Small on purpose.** Every sink is written on the session's own single
/// threaded path, once per event, so a bundle that named a hundred of them
/// would slow every turn of every session in the installation. An organisation
/// needs its own collector and perhaps a second one it is migrating to.
pub const max_sinks: usize = 4;

/// The longest sink path this reader accepts.
pub const max_sink_path_bytes = 4096;

/// A place every session of this installation sends its log, whatever the
/// person at the keyboard asked for.
///
/// **This is the control the command line could not be.** See this file's own
/// top comment for what "required" means, for why a session that cannot reach
/// one still runs, and for what it does instead.
pub const RequiredSink = struct {
    /// Which of the two transports `lib/chock-proto/ship.zig` carries.
    kind: Kind,
    /// Where it goes. **Absolute, and the reader refuses anything else**: see
    /// this file's own top comment, where a relative path puts the trail inside
    /// the tree the observed person owns.
    path: []const u8,

    /// The two sinks that exist. The names are the two options a person types,
    /// so a bundle and a command line say the same thing the same way.
    ///
    /// **No network sink.** `chock run` is single threaded on the tool path, so
    /// a sink that could block on a network would block the session; the whole
    /// argument is in `lib/chock-proto/ship.zig`. A bundle cannot require what
    /// Chock cannot carry.
    pub const Kind = enum {
        /// A directory a collector watches. One file per session appears in it,
        /// byte for byte the log, so `chock sessions verify` reads it at the
        /// far end. The same thing `--export-dir` names.
        directory,
        /// A unix datagram socket the local syslog daemon reads. The same thing
        /// `--export-syslog` names.
        syslog,
    };
};

/// What a bundle file holds.
///
/// **`rules` is the whole of the policy, and there are no `agents`.** A
/// `table.Policy` also declares which kind spawns which, and that is the
/// project's own shape: an organisation does not know the spawn tree of a
/// repository it has never seen. The read time check `table.parse` runs over
/// declared parent links has nothing to run over here, and it is not needed:
/// `Table.evaluateChain` takes the intersection over the real chain at run
/// time, which is where a bundle binds.
pub const Bundle = struct {
    /// Whose credential this installation holds, in the organisation's own
    /// spelling. **A record, never a control**: see this file's top comment.
    /// Empty for a bundle that named nobody.
    subject: []const u8 = "",
    /// Who issued it, in the organisation's own spelling. Empty when the file
    /// named nobody. Read by nothing; written for the person reading a log.
    issuer: []const u8 = "",
    /// When the organisation issued this, in milliseconds since the epoch.
    /// Zero when the file said nothing, which is a bundle whose age cannot be
    /// reported.
    issued_ms: i64 = 0,
    /// When this stops being a file anybody may install, in milliseconds since
    /// the epoch. **Zero means it never expires**, which is the ordinary
    /// answer for an installation that is not managed by a hub.
    ///
    /// See this file's own top comment for what an expiry does and does not
    /// do. It does not stop the bundle binding.
    expires_ms: i64 = 0,
    /// The rules, in the same language `chock.zon` speaks. Read as a ceiling:
    /// an action no rule here names is one this layer says nothing about.
    rules: []const table.Rule = &.{},
    /// Where every session of this installation sends its log, whatever the
    /// person at the keyboard asked for. Empty for an installation that
    /// requires none, which is every installation that predates this field.
    ///
    /// **A field and not a rule**, and a union and not a minimum: see this
    /// file's own top comment. A project adds a sink of its own and can drop
    /// none of these.
    sinks: []const RequiredSink = &.{},
    /// The version of the bundle format. See `max_version`.
    version: u32 = 1,

    /// Whether `now_ms` is past `expires_ms`. False for a bundle with no
    /// expiry at all.
    ///
    /// **The time is a parameter and never a clock.** This module reads no
    /// clock, so a test can pin every answer here without a wall clock
    /// assertion, and `src/run.zig` reads the one clock the session already
    /// has.
    pub fn expiredAt(self: *const Bundle, now_ms: i64) bool {
        if (self.expires_ms == 0) return false;
        return now_ms > self.expires_ms;
    }

    /// How long ago this expired, in milliseconds, or null for a bundle that
    /// has not expired or that never expires. **For the line a person reads**,
    /// which is point 2 of this file's expiry decision.
    pub fn expiredForMs(self: *const Bundle, now_ms: i64) ?i64 {
        if (!self.expiredAt(now_ms)) return null;
        // Both are milliseconds since the epoch and the branch above proves
        // the difference is positive, so this cannot overflow for any pair of
        // times a machine can hold.
        return now_ms -| self.expires_ms;
    }
};

/// What can go wrong while reading a bundle out of bytes in memory.
pub const ParseError = error{
    OutOfMemory,
    /// The file is not valid ZON, or it does not match the schema. Pass a
    /// `Diagnostic` to learn which line, and why.
    InvalidBundle,
    /// A key pattern the language of `lib/chock-policy/table.zig` does not
    /// allow.
    InvalidPattern,
    /// The bundle holds more than `table.max_rules` rules.
    TooManyRules,
    /// The subject or the issuer is longer than this reader accepts.
    NameTooLong,
    /// The bundle names a version above `max_version`. See this file's own top
    /// comment: a bundle this build cannot fully read is refused whole.
    VersionTooNew,
    /// The bundle requires more than `max_sinks` sinks.
    TooManySinks,
    /// A required sink names a path this reader will not take: an empty one, a
    /// relative one, or one longer than `max_sink_path_bytes`.
    InvalidSinkPath,
};

/// What can go wrong while reading a bundle from a path.
pub const LoadError = ParseError || error{
    /// There is no bundle at that path. **The ordinary answer for an
    /// installation nobody gave a bundle**, and never a fault: see
    /// `src/run.zig`, which then runs exactly as it did before bundles
    /// existed.
    NoBundleFile,
    /// The file is larger than `max_file_bytes`.
    BundleTooLarge,
    /// The file exists and could not be read.
    ReadFailed,
};

/// Why a bundle was refused, in the words the person who installed it needs.
///
/// The ZON variant owns the syntax tree its message points into. A caller that
/// gives `parse` or `load` a slot must call `deinit` on whatever lands in it.
pub const Diagnostic = union(enum) {
    /// The file is not valid ZON, or it does not match the schema.
    not_valid: std.zon.parse.Diagnostics,
    /// The file exists and the read failed.
    read_failed: anyerror,
    /// More rules than `table.max_rules`.
    too_many_rules: usize,
    /// A key field holds `"*"`. The field name is a literal of this file.
    pattern_matches_everything: []const u8,
    /// A key field holds a pattern the language does not allow.
    pattern_malformed: []const u8,
    /// The subject or the issuer is too long. The field name is a literal of
    /// this file, and the numbers are the length it holds and the bound.
    name_too_long: NameTooLong,
    /// The bundle was written by a newer Chock.
    version_too_new: u32,
    /// More required sinks than `max_sinks`.
    too_many_sinks: usize,
    /// A required sink names no path at all. The number is which sink, counted
    /// from one.
    ///
    /// **A position and never the path itself.** A bundle that fails to
    /// validate is freed by `parse` before this reaches a caller, so a
    /// diagnostic that borrowed a string out of it would dangle. The position
    /// is a number and outlives everything.
    sink_path_empty: usize,
    /// A required sink names a path that is not absolute. The number is which
    /// sink, counted from one. See `sink_path_empty` for why it is a position.
    sink_path_relative: usize,
    /// A required sink names a path longer than `max_sink_path_bytes`. The
    /// number is which sink, counted from one.
    sink_path_too_long: usize,

    pub const NameTooLong = struct {
        field: []const u8,
        held: usize,
        bound: usize,
    };

    /// Release what the diagnostic owns, with the allocator that filled it.
    /// Safe on every variant.
    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .not_valid => |*zon_diag| zon_diag.deinit(gpa),
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .not_valid => |*zon_diag| try writer.print(
                "the org policy bundle is not valid:\n{f}",
                .{zon_diag},
            ),
            .read_failed => |err| try writer.print(
                "reading the org policy bundle failed: {s}",
                .{@errorName(err)},
            ),
            .too_many_rules => |held| try writer.print(
                "the org policy bundle holds {d} rules, and this reader accepts {d}",
                .{ held, table.max_rules },
            ),
            .pattern_matches_everything => |field| try writer.print(
                "the org policy bundle has a rule whose {s} holds \"*\". Leave the field out to match every value.",
                .{field},
            ),
            .pattern_malformed => |field| try writer.print(
                "the org policy bundle has a rule whose {s} holds an invalid name. A name matches itself, and a name that ends in \".*\" matches every name below it.",
                .{field},
            ),
            .name_too_long => |name| try writer.print(
                "the org policy bundle holds a {s} of {d} bytes, and this reader accepts {d}",
                .{ name.field, name.held, name.bound },
            ),
            .version_too_new => |held| try writer.print(
                "the org policy bundle names version {d}, and this Chock reads up to version {d}. " ++
                    "A bundle this build cannot fully read is refused rather than applied in part, " ++
                    "because the part it cannot read may be the part that narrows something. Update Chock.",
                .{ held, max_version },
            ),
            .too_many_sinks => |held| try writer.print(
                "the org policy bundle requires {d} audit sinks, and this reader accepts {d}. " ++
                    "Every sink is written on the session's own path, once per event.",
                .{ held, max_sinks },
            ),
            .sink_path_empty => |which| try writer.print(
                "audit sink {d} of the org policy bundle names no path.",
                .{which},
            ),
            .sink_path_relative => |which| try writer.print(
                "audit sink {d} of the org policy bundle names a path that is not absolute. " ++
                    "A relative path resolves against whatever directory a session started in, " ++
                    "which is the project the session works on, so the audit trail would land " ++
                    "inside the tree the person under audit owns. Name the path from the root.",
                .{which},
            ),
            .sink_path_too_long => |which| try writer.print(
                "audit sink {d} of the org policy bundle names a path longer than {d} bytes.",
                .{ which, max_sink_path_bytes },
            ),
        }
    }
};

/// Fill `out` when the caller asked for one. The first fault is kept, not the
/// last, the same rule `table.zig` keeps and for the same reason: a later
/// check can only fail because an earlier one did.
fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// Read a bundle out of `source`, which must be the whole content of a bundle
/// file. The returned bundle owns a copy of every name in it, so the caller is
/// free to release `source` at once. `destroy` releases it, with the same
/// allocator.
///
/// `diag` is optional. A caller that passes null pays nothing and learns only
/// the error. A caller that passes a slot must call `Diagnostic.deinit` on
/// whatever lands in it.
pub fn parse(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    diag: ?*?Diagnostic,
) ParseError!*const Bundle {
    var zon_diag: std.zon.parse.Diagnostics = .{};
    var diag_owned = true;
    defer if (diag_owned) zon_diag.deinit(gpa);

    const bundle = std.zon.parse.fromSliceAlloc(Bundle, gpa, source, &zon_diag, .{
        // A member this build has no field for is kept out rather than
        // refused. See this file's own top comment: a hub adds a note or a
        // display name without breaking an older installation, and a hub that
        // changes what is permitted raises `version` instead.
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            if (note(diag, .{ .not_valid = zon_diag })) diag_owned = false;
            return error.InvalidBundle;
        },
    };
    errdefer std.zon.parse.free(gpa, bundle);

    try validate(bundle, diag);

    const owned = try gpa.create(Bundle);
    owned.* = bundle;
    return owned;
}

/// Read a bundle from `path` and parse it.
///
/// `error.NoBundleFile` is the ordinary answer, not a fault. See
/// `LoadError.NoBundleFile`.
pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    diag: ?*?Diagnostic,
) LoadError!*const Bundle {
    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.BundleTooLarge,
        error.FileNotFound, error.NotDir => return error.NoBundleFile,
        else => {
            _ = note(diag, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

/// Release everything the bundle owns, with the allocator that built it.
/// `self` is not valid after this call.
///
/// The allocator is the first parameter, for the reason `table.Table.destroy`
/// gives: a `Bundle` holds nothing that says where it came from, so it holds
/// no allocator either.
pub fn destroy(gpa: std.mem.Allocator, self: *const Bundle) void {
    std.zon.parse.free(gpa, self.*);
    gpa.destroy(self);
}

/// Everything about a bundle that must be right before a session starts.
fn validate(bundle: Bundle, diag: ?*?Diagnostic) ParseError!void {
    // The version first, because every other check is a check of a schema this
    // build believes it understands.
    if (bundle.version > max_version) {
        _ = note(diag, .{ .version_too_new = bundle.version });
        return error.VersionTooNew;
    }
    if (bundle.rules.len > table.max_rules) {
        _ = note(diag, .{ .too_many_rules = bundle.rules.len });
        return error.TooManyRules;
    }
    if (bundle.subject.len > max_subject_bytes) {
        _ = note(diag, .{ .name_too_long = .{
            .field = "subject",
            .held = bundle.subject.len,
            .bound = max_subject_bytes,
        } });
        return error.NameTooLong;
    }
    if (bundle.issuer.len > max_issuer_bytes) {
        _ = note(diag, .{ .name_too_long = .{
            .field = "issuer",
            .held = bundle.issuer.len,
            .bound = max_issuer_bytes,
        } });
        return error.NameTooLong;
    }

    for (bundle.rules) |rule| {
        inline for (.{ "agent_kind", "model", "tool", "action" }) |field| {
            try validatePattern(field, @field(rule, field), diag);
        }
    }

    if (bundle.sinks.len > max_sinks) {
        _ = note(diag, .{ .too_many_sinks = bundle.sinks.len });
        return error.TooManySinks;
    }
    for (bundle.sinks, 1..) |sink, which| {
        if (sink.path.len == 0) {
            _ = note(diag, .{ .sink_path_empty = which });
            return error.InvalidSinkPath;
        }
        if (sink.path.len > max_sink_path_bytes) {
            _ = note(diag, .{ .sink_path_too_long = which });
            return error.InvalidSinkPath;
        }
        if (!std.fs.path.isAbsolute(sink.path)) {
            _ = note(diag, .{ .sink_path_relative = which });
            return error.InvalidSinkPath;
        }
    }
}

/// The same check `table.validatePattern` makes, with the message the person
/// who installed a bundle needs rather than the one the author of `chock.zon`
/// needs. `field` is always a literal of this file, so the diagnostic borrows
/// it and copies nothing.
fn validatePattern(field: []const u8, pattern: ?[]const u8, diag: ?*?Diagnostic) ParseError!void {
    const text = pattern orelse return;
    if (std.mem.eql(u8, text, "*")) {
        _ = note(diag, .{ .pattern_matches_everything = field });
        return error.InvalidPattern;
    }
    if (!table.patternIsWellFormed(text)) {
        _ = note(diag, .{ .pattern_malformed = field });
        return error.InvalidPattern;
    }
}

/// Why this bundle may not be installed, or null when it may.
///
/// **This is the whole of what an expiry acts on**, which is point 3 of this
/// file's own expiry decision. A bundle that is already past its date is not a
/// file anybody may hand to Chock; a bundle already on the machine keeps
/// binding whatever the date says.
///
/// The message is for the person who ran the command, so it says what to do.
pub fn refusalForInstall(bundle: *const Bundle, now_ms: i64) ?[]const u8 {
    if (bundle.expiredAt(now_ms)) {
        return "this org policy bundle expired before it was given to Chock. Ask whoever issued " ++
            "it for a current one. A bundle already installed on this machine keeps binding " ++
            "whatever its date says, so nothing is lost by refusing this file.";
    }
    return null;
}

// Every test below reads bytes and answers a question about them. What a
// bundle does to a decision is `lib/chock-policy/table.zig`'s own tests, over
// `Table.org`, because that is where the minimum is taken.

const testing = std.testing;

/// A bundle whose rules and dates the caller chose, as bytes. Written as a
/// helper so a test names the fact it pins and not the ZON around it.
fn bundleSource(
    gpa: std.mem.Allocator,
    body: []const u8,
) ![:0]u8 {
    return std.fmt.allocPrintSentinel(gpa, ".{{{s}}}", .{body}, 0);
}

test "a bundle states a subject, and reading it verifies nothing about that subject" {
    const gpa = testing.allocator;

    const source = try bundleSource(gpa,
        \\ .subject = "ross@example.org",
        \\ .issuer = "example.org",
        \\ .issued_ms = 1000,
        \\ .expires_ms = 5000,
        \\ .rules = .{ .{ .action = "git.push", .decision = .deny } },
    );
    defer gpa.free(source);

    const bundle = try parse(gpa, source, null);
    defer destroy(gpa, bundle);

    try testing.expectEqualStrings("ross@example.org", bundle.subject);
    try testing.expectEqualStrings("example.org", bundle.issuer);
    try testing.expectEqual(@as(i64, 1000), bundle.issued_ms);
    try testing.expectEqual(@as(i64, 5000), bundle.expires_ms);
    try testing.expectEqual(@as(usize, 1), bundle.rules.len);
    try testing.expectEqualStrings("git.push", bundle.rules[0].action.?);
    try testing.expectEqual(table.Decision.deny, bundle.rules[0].decision);
    // The three key fields the rule left out match every value, which is the
    // same reading `chock.zon` gets.
    try testing.expectEqual(@as(?[]const u8, null), bundle.rules[0].agent_kind);
    try testing.expectEqual(@as(?[]const u8, null), bundle.rules[0].model);
    try testing.expectEqual(@as(?[]const u8, null), bundle.rules[0].tool);

    // A bundle that names nobody is a bundle, not a fault. An installation
    // that is not managed by a hub still writes rules.
    const anonymous = try parse(gpa, ".{ .rules = .{ .{ .action = \"git.push\", .decision = .deny } } }", null);
    defer destroy(gpa, anonymous);
    try testing.expectEqualStrings("", anonymous.subject);
    try testing.expectEqualStrings("", anonymous.issuer);
    try testing.expectEqual(@as(i64, 0), anonymous.expires_ms);
}

test "an expired bundle keeps binding, says how long ago, and may not be installed" {
    // The three points of this file's expiry decision, one assertion each.
    // Neither failing shut nor falling open: the rules are still there, the
    // staleness is reportable, and the date stops an installation.
    const gpa = testing.allocator;

    const source = try bundleSource(gpa,
        \\ .subject = "ross@example.org",
        \\ .expires_ms = 5000,
        \\ .rules = .{ .{ .action = "provider.public.*", .decision = .deny } },
    );
    defer gpa.free(source);

    const bundle = try parse(gpa, source, null);
    defer destroy(gpa, bundle);

    // Point 1. The rules survive the date. Nothing here drops a rule, and
    // there is no expired reading of a bundle in which `rules` is empty.
    try testing.expect(bundle.expiredAt(9000));
    try testing.expectEqual(@as(usize, 1), bundle.rules.len);
    try testing.expectEqualStrings("provider.public.*", bundle.rules[0].action.?);

    // Point 2. How long ago, in the unit the caller prints. A stale policy a
    // reader cannot see is the failure this number exists to prevent.
    try testing.expectEqual(@as(?i64, 4000), bundle.expiredForMs(9000));
    try testing.expectEqual(@as(?i64, null), bundle.expiredForMs(4999));
    // The boundary is not expired. A bundle is current on the millisecond it
    // names, because a deadline is the last moment that counts.
    try testing.expect(!bundle.expiredAt(5000));
    try testing.expect(bundle.expiredAt(5001));

    // Point 3. The one thing the date acts on.
    try testing.expect(refusalForInstall(bundle, 9000) != null);
    try testing.expectEqual(@as(?[]const u8, null), refusalForInstall(bundle, 5000));
    try testing.expectEqual(@as(?[]const u8, null), refusalForInstall(bundle, 1));

    // A bundle with no expiry never expires and is always installable, which
    // is the ordinary answer for an installation no hub manages.
    const forever = try parse(gpa, ".{ .rules = .{} }", null);
    defer destroy(gpa, forever);
    try testing.expect(!forever.expiredAt(9000));
    try testing.expect(!forever.expiredAt(std.math.maxInt(i64)));
    try testing.expectEqual(@as(?i64, null), forever.expiredForMs(std.math.maxInt(i64)));
    try testing.expectEqual(@as(?[]const u8, null), refusalForInstall(forever, std.math.maxInt(i64)));
}

test "a bundle from a newer Chock is refused whole, and an unknown field is not" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.VersionTooNew,
        parse(gpa, ".{ .version = 2, .rules = .{} }", &diag),
    );
    try testing.expect(diag != null);

    const current = try parse(gpa, ".{ .version = 1, .rules = .{} }", null);
    defer destroy(gpa, current);
    try testing.expectEqual(@as(u32, 1), current.version);

    // An unknown member at a known version is kept out and the bundle still
    // reads. The rule beside it must survive, or "ignored" would mean "the
    // file was skipped".
    const with_extra = try parse(
        gpa,
        ".{ .display_name = \"Example Org\", .rules = .{ .{ .action = \"git.push\", .decision = .deny } } }",
        null,
    );
    defer destroy(gpa, with_extra);
    try testing.expectEqual(@as(usize, 1), with_extra.rules.len);
    try testing.expectEqual(table.Decision.deny, with_extra.rules[0].decision);
}

test "a bundle with a pattern the language does not allow is refused before it binds" {
    const gpa = testing.allocator;

    inline for (.{ "agent_kind", "model", "tool", "action" }) |field| {
        var diag: ?Diagnostic = null;
        defer if (diag) |*d| d.deinit(gpa);
        const source = ".{ .rules = .{ .{ ." ++ field ++ " = \"*\", .decision = .deny } } }";
        try testing.expectError(error.InvalidPattern, parse(gpa, source, &diag));
        try testing.expect(diag.? == .pattern_matches_everything);
        try testing.expectEqualStrings(field, diag.?.pattern_matches_everything);
    }

    var malformed: ?Diagnostic = null;
    defer if (malformed) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidPattern,
        parse(gpa, ".{ .rules = .{ .{ .action = \"a.*.b\", .decision = .deny } } }", &malformed),
    );
    try testing.expect(malformed.? == .pattern_malformed);

    const good = try parse(gpa, ".{ .rules = .{ .{ .action = \"provider.*\", .decision = .deny } } }", null);
    defer destroy(gpa, good);
    try testing.expectEqualStrings("provider.*", good.rules[0].action.?);
}

test "a bundle larger than the reader accepts is refused by count and by name length" {
    // The file is not the project's, and it is still bytes on a disk that can
    // be wrong. Every bound is checked one value each side of itself.
    const gpa = testing.allocator;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try body.appendSlice(gpa, " .rules = .{");
    for (0..table.max_rules + 1) |index| {
        try body.print(gpa, " .{{ .action = \"a{d}\", .decision = .deny }},", .{index});
    }
    try body.appendSlice(gpa, " },");

    const too_many = try bundleSource(gpa, body.items);
    defer gpa.free(too_many);
    var count_diag: ?Diagnostic = null;
    defer if (count_diag) |*d| d.deinit(gpa);
    try testing.expectError(error.TooManyRules, parse(gpa, too_many, &count_diag));
    try testing.expectEqual(@as(usize, table.max_rules + 1), count_diag.?.too_many_rules);

    const long_subject = "s" ** (max_subject_bytes + 1);
    var name_diag: ?Diagnostic = null;
    defer if (name_diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.NameTooLong,
        parse(gpa, ".{ .subject = \"" ++ long_subject ++ "\", .rules = .{} }", &name_diag),
    );
    try testing.expectEqualStrings("subject", name_diag.?.name_too_long.field);
    try testing.expectEqual(@as(usize, max_subject_bytes + 1), name_diag.?.name_too_long.held);

    // One byte shorter is read, so the bound is the bound and not an
    // approximation of one.
    const at_bound = "s" ** max_subject_bytes;
    const accepted = try parse(gpa, ".{ .subject = \"" ++ at_bound ++ "\", .rules = .{} }", null);
    defer destroy(gpa, accepted);
    try testing.expectEqual(@as(usize, max_subject_bytes), accepted.subject.len);
}

test "a file that is not there is not a fault, and one that is broken names its line" {
    const gpa = testing.allocator;

    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = tmp.dir.realPath(io, &path_buffer) catch return error.RealPathFailed;
    const dir_path = path_buffer[0..written];

    const missing = try std.fs.path.join(gpa, &.{ dir_path, file_name });
    defer gpa.free(missing);
    try testing.expectError(error.NoBundleFile, load(gpa, io, missing, null));

    // A file that is there and is not ZON names where it went wrong, and the
    // trees behind the message are released with the diagnostic.
    try tmp.dir.writeFile(io, .{ .sub_path = file_name, .data = ".{ .rules = " });
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidBundle, load(gpa, io, missing, &diag));
    try testing.expect(diag.? == .not_valid);

    try tmp.dir.writeFile(io, .{
        .sub_path = file_name,
        .data = ".{ .subject = \"ross\", .rules = .{ .{ .action = \"git.push\", .decision = .deny } } }",
    });
    const bundle = try load(gpa, io, missing, null);
    defer destroy(gpa, bundle);
    try testing.expectEqualStrings("ross", bundle.subject);
    try testing.expectEqual(@as(usize, 1), bundle.rules.len);
}

test "a bundle requires a sink, and an installation that requires none reads as empty" {
    // **The whole of what this field adds at the reading layer**: an
    // installation states where every session sends its log, and a bundle that
    // states nothing states nothing. The second half is what keeps every
    // installation that predates the field behaving as it did, because an empty
    // list is what `src/run.zig` unions with the command line.
    //
    // Mutation check: default `sinks` to anything other than empty and the
    // second half fails, which is every existing bundle gaining a sink nobody
    // asked for.
    const gpa = testing.allocator;

    const source = try bundleSource(gpa,
        \\ .subject = "ross@example.org",
        \\ .sinks = .{
        \\   .{ .kind = .directory, .path = "/var/audit/chock" },
        \\   .{ .kind = .syslog, .path = "/dev/log" },
        \\ },
        \\ .rules = .{},
    );
    defer gpa.free(source);

    const bundle = try parse(gpa, source, null);
    defer destroy(gpa, bundle);

    try testing.expectEqual(@as(usize, 2), bundle.sinks.len);
    try testing.expectEqual(RequiredSink.Kind.directory, bundle.sinks[0].kind);
    try testing.expectEqualStrings("/var/audit/chock", bundle.sinks[0].path);
    try testing.expectEqual(RequiredSink.Kind.syslog, bundle.sinks[1].kind);
    try testing.expectEqualStrings("/dev/log", bundle.sinks[1].path);

    // A bundle that requires none, and a bundle written before the field
    // existed, are the same bundle. Neither gains a sink.
    const none = try parse(gpa, ".{ .rules = .{ .{ .action = \"git.push\", .decision = .deny } } }", null);
    defer destroy(gpa, none);
    try testing.expectEqual(@as(usize, 0), none.sinks.len);
}

test "an expired bundle keeps requiring its sinks, the same way it keeps binding its rules" {
    // A required sink inherits the expiry decision in full. Dropping the
    // requirement can only widen what a session may do without being recorded,
    // and it would widen it at exactly the moment nobody can be reached.
    //
    // Mutation check: clear `sinks` for an expired bundle anywhere and this
    // fails, which is an organisation losing its trail by a laptop staying off
    // a network for a week.
    const gpa = testing.allocator;

    const source = try bundleSource(gpa,
        \\ .expires_ms = 5000,
        \\ .sinks = .{ .{ .kind = .directory, .path = "/var/audit/chock" } },
        \\ .rules = .{},
    );
    defer gpa.free(source);

    const bundle = try parse(gpa, source, null);
    defer destroy(gpa, bundle);

    try testing.expect(bundle.expiredAt(9000));
    // There is no expired reading of a bundle in which the sinks are gone.
    try testing.expectEqual(@as(usize, 1), bundle.sinks.len);
    try testing.expectEqualStrings("/var/audit/chock", bundle.sinks[0].path);
    // And the staleness is still reportable, so nobody is under a stale
    // requirement without being able to see it.
    try testing.expectEqual(@as(?i64, 4000), bundle.expiredForMs(9000));
}

test "a required sink that is not an absolute path is refused before it binds" {
    // A relative path in an installation wide file resolves against the
    // directory a session started in, which is the project. The trail would
    // land inside the tree the person under audit owns, where they can delete
    // it, and it would land in a different place for every project.
    //
    // Mutation check: drop the `isAbsolute` check and the first case below
    // parses, which is an organisation writing one word and getting a trail its
    // own subject can remove.
    const gpa = testing.allocator;

    var relative: ?Diagnostic = null;
    defer if (relative) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidSinkPath, parse(
        gpa,
        ".{ .sinks = .{ .{ .kind = .directory, .path = \"audit\" } }, .rules = .{} }",
        &relative,
    ));
    try testing.expectEqual(@as(usize, 1), relative.?.sink_path_relative);

    // The message says why, because "not absolute" alone reads as pedantry.
    const said = try std.fmt.allocPrint(gpa, "{f}", .{&relative.?});
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "the tree the person under audit owns") != null);

    // The position is which sink, counted from one, so a bundle with several
    // says which one is wrong.
    var second: ?Diagnostic = null;
    defer if (second) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidSinkPath, parse(
        gpa,
        ".{ .sinks = .{ .{ .kind = .syslog, .path = \"/dev/log\" }, " ++
            ".{ .kind = .directory, .path = \"./here\" } }, .rules = .{} }",
        &second,
    ));
    try testing.expectEqual(@as(usize, 2), second.?.sink_path_relative);

    // An empty path is its own fault, not a relative one, because "name a path"
    // and "name it from the root" are different things to do.
    var empty: ?Diagnostic = null;
    defer if (empty) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidSinkPath, parse(
        gpa,
        ".{ .sinks = .{ .{ .kind = .directory, .path = \"\" } }, .rules = .{} }",
        &empty,
    ));
    try testing.expectEqual(@as(usize, 1), empty.?.sink_path_empty);

    // And a path longer than the reader accepts, one byte each side of the
    // bound, so the bound is the bound.
    const long = "/" ++ "p" ** max_sink_path_bytes;
    var too_long: ?Diagnostic = null;
    defer if (too_long) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidSinkPath, parse(
        gpa,
        ".{ .sinks = .{ .{ .kind = .directory, .path = \"" ++ long ++ "\" } }, .rules = .{} }",
        &too_long,
    ));
    try testing.expectEqual(@as(usize, 1), too_long.?.sink_path_too_long);

    const at_bound = "/" ++ "p" ** (max_sink_path_bytes - 1);
    const accepted = try parse(
        gpa,
        ".{ .sinks = .{ .{ .kind = .directory, .path = \"" ++ at_bound ++ "\" } }, .rules = .{} }",
        null,
    );
    defer destroy(gpa, accepted);
    try testing.expectEqual(@as(usize, max_sink_path_bytes), accepted.sinks[0].path.len);
}

test "a bundle that requires more sinks than the reader accepts is refused" {
    const gpa = testing.allocator;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try body.appendSlice(gpa, " .rules = .{}, .sinks = .{");
    for (0..max_sinks + 1) |index| {
        try body.print(gpa, " .{{ .kind = .directory, .path = \"/var/audit/{d}\" }},", .{index});
    }
    try body.appendSlice(gpa, " },");

    const source = try bundleSource(gpa, body.items);
    defer gpa.free(source);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.TooManySinks, parse(gpa, source, &diag));
    try testing.expectEqual(@as(usize, max_sinks + 1), diag.?.too_many_sinks);
}

test "no two faults of this module read the same" {
    // The same check every diagnostic in this project keeps. Two faults that
    // print the same sentence are two faults a person cannot tell apart.
    const gpa = testing.allocator;

    const faults = [_]Diagnostic{
        .{ .read_failed = error.AccessDenied },
        .{ .too_many_rules = 900 },
        .{ .pattern_matches_everything = "action" },
        .{ .pattern_malformed = "model" },
        .{ .name_too_long = .{ .field = "subject", .held = 300, .bound = max_subject_bytes } },
        .{ .version_too_new = 7 },
        .{ .too_many_sinks = 9 },
        .{ .sink_path_empty = 1 },
        .{ .sink_path_relative = 1 },
        .{ .sink_path_too_long = 1 },
    };

    var rendered: [faults.len][]u8 = undefined;
    var written: usize = 0;
    defer for (rendered[0..written]) |one| gpa.free(one);
    for (&faults, &rendered) |*fault, *slot| {
        slot.* = try std.fmt.allocPrint(gpa, "{f}", .{fault});
        written += 1;
    }
    for (rendered, 0..) |left, index| {
        for (rendered[index + 1 ..]) |right| {
            try testing.expect(!std.mem.eql(u8, left, right));
        }
        try testing.expect(left.len > 0);
    }
}

test "a caller that wants no diagnostic allocates nothing extra for one" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, parse(failing.allocator(), ".{ .rules = .{} }", null));

    // And the parse of a broken file with no slot ends with nothing leaked,
    // which the testing allocator proves for the whole test.
    try testing.expectError(error.InvalidBundle, parse(testing.allocator, ".{ .rules = ", null));
    try testing.expectError(
        error.VersionTooNew,
        parse(testing.allocator, ".{ .version = 99, .rules = .{} }", null),
    );
}
