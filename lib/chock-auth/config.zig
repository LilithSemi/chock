//! The configuration file, and the separate token file beside it. Both live
//! in the configuration directory, and **Chock reads them and never writes
//! them**.
//!
//! `token` is allowed, and `paths.requirePrivate` is what makes it safe: see
//! `lib/chock-auth/lookup.zig`, which applies the mode rule to every source.

const std = @import("std");
const paths = @import("paths.zig");

pub const file_name = "config.zon";

/// The separate token file, source 2 of the lookup order, inside the same
/// configuration directory. **A person maintains this file and
/// Chock never rewrites it**, which is why it is not the file `chock login`
/// writes.
pub const token_file_name = "tokens.zon";

/// The largest configuration file this reader accepts. A roster of providers
/// is a small file. This bounds a mistake, such as a path that names a disk
/// image, rather than a hostile author: the configuration directory belongs
/// to the user already.
pub const max_file_bytes: usize = 256 * 1024;

/// The provider kinds Chock knows. An enum and not a free string: a reader
/// must act on this value, and a free string cannot be told apart from a
/// typo.
pub const Kind = enum {
    anthropic,
    aiand,
    openai_compat,

    /// The one spelling a user writes, in the configuration file and on the
    /// `chock login` command line alike. `openai_compat` cannot carry the
    /// hyphen a Zig enum field name forbids, so the two spellings are joined
    /// here, once, rather than in each reader.
    pub fn wireName(self: Kind) []const u8 {
        return switch (self) {
            .anthropic => "anthropic",
            .aiand => "aiand",
            .openai_compat => "openai-compat",
        };
    }

    pub fn fromWireName(text: []const u8) ?Kind {
        inline for (@typeInfo(Kind).@"enum".fields) |field| {
            const kind: Kind = @enumFromInt(field.value);
            if (std.mem.eql(u8, kind.wireName(), text)) return kind;
        }
        return null;
    }

    pub const all_wire_names = "anthropic, aiand, openai-compat";

    /// Where this kind talks, when the instance names no base URL of its
    /// own. Empty for `openai-compat`, which is the escape hatch for an
    /// endpoint Chock has never heard of and therefore has no default for.
    pub fn defaultBaseUrl(self: Kind) []const u8 {
        return switch (self) {
            .anthropic => "https://api.anthropic.com/v1",
            .aiand => "https://api.aiand.com/v1",
            .openai_compat => "",
        };
    }

    /// Whether the address `defaultBaseUrl` gives refuses every request that
    /// carries no credential.
    ///
    /// **This is a fact about that one address, and not about the kind.** Two
    /// of the three kinds have a commercial hosted API for their default, and
    /// a request to one of those without a key is a 401 every time.
    /// `openai-compat` has no address of its own at all, so it answers false:
    /// a local llama.cpp server is the case that kind exists for, and it needs
    /// nothing.
    ///
    /// See `chock_auth.lookup.credentialIsMissing`, which is the one caller
    /// and the place the rule is explained.
    pub fn hostedEndpointNeedsCredential(self: Kind) bool {
        return switch (self) {
            .anthropic, .aiand => true,
            .openai_compat => false,
        };
    }
};

/// What this provider instance can do, beyond answering with words. The second
/// of the two gates a tool passes before Chock offers it to a model: the first
/// is whether the adapter's own wire format can express the thing at all, and
/// that one lives in `chock_provider.Client.Adapter.carries`.
///
/// **Every field defaults to false, and absence is never permissive.** Two
/// instances of one kind are not alike here: ai& has a file endpoint and a
/// local llama.cpp server does not, and `glm4.7-flash:A3B` is text only. A
/// user who says nothing gets the smaller tool list, which costs a
/// capability, and a user who says yes wrongly gets a model that spends a
/// turn on a call that cannot work. The first mistake is the cheaper one.
///
/// Not an enum set or a free string: a boolean per named thing, so a file
/// written for a newer Chock that names a capability this one has never
/// heard of is refused by the strict parse of a provider entry, the same way
/// a typo in `.token` is. See `parse`.
pub const Capabilities = struct {
    /// The instance can take an image in a request. Nothing offers a tool
    /// that needs this yet: `chock_provider.message.ContentPart` has no image
    /// part, so no adapter carries one either, and the first gate refuses
    /// before this one is ever read. The field is here so the record exists
    /// and is tested before the tool that needs it is built.
    images: bool = false,
};

/// One provider instance, exactly as the file spells it. `parse` turns this
/// into an `Instance`, which is the checked shape every caller uses.
const FileInstance = struct {
    name: ?[]const u8 = null,
    kind: []const u8,
    base_url: ?[]const u8 = null,
    token: ?[]const u8 = null,
    token_file: ?[]const u8 = null,
    context_tokens: ?u64 = null,
    capabilities: ?Capabilities = null,
};

const FileDefaults = struct {
    provider: ?[]const u8 = null,
    model: ?[]const u8 = null,
};

/// One provider instance, checked. Every string is owned by the `Config` it
/// came from.
pub const Instance = struct {
    /// The user's chosen name, or the kind's own spelling when the file gave
    /// none. This is the key everything else selects by.
    name: []const u8,
    kind: Kind,
    /// Where this instance talks. Never empty: `parse` fills in the kind's
    /// own default when the file gave none, and refuses a kind that has no
    /// default and was given no URL.
    base_url: []const u8,
    /// The credential this instance names for itself, source 1 of section
    /// 11.4's lookup order. `.absent` is the common case.
    credential: Credential,
    /// How many tokens the model behind this instance can hold, request and
    /// reply together. **Null means nobody said, and null is never a guess**:
    /// a session against an instance that gives no number compacts only when
    /// the provider itself refuses a request as too large. See
    /// `chock_core.compaction.Policy`.
    ///
    /// It sits on the instance and not in `Capabilities`, because it is a
    /// number and every field there is a yes or no about a thing the endpoint
    /// can do. The local llama.cpp server this project develops against is
    /// started with a fixed context size, which is exactly the case this
    /// field is for.
    context_tokens: ?u64,
    /// What this instance can do beyond words. See `Capabilities`: an
    /// instance that names none gets the all-false record, never a guess
    /// from its kind. Two instances of one kind can differ here.
    capabilities: Capabilities,
};

/// How an instance names its credential.
pub const Credential = union(enum) {
    /// Look it up in the other two sources, and if nothing is there, send
    /// none.
    absent,
    /// The value, written in the configuration file itself.
    token: []const u8,
    /// A path to read at run time, which is how sops-nix and agenix work.
    token_file: []const u8,
};

/// One line of the separate token file, source 2.
pub const TokenEntry = struct {
    name: []const u8,
    token: []const u8,
};

pub const ParseError = std.mem.Allocator.Error || error{
    /// The file is not valid ZON, or a field has the wrong type. Pass a
    /// `Diagnostic` to learn which line, and why.
    InvalidConfig,
    /// An instance names a `kind` Chock does not know. The message names
    /// every kind that is valid.
    UnknownProviderKind,
    /// Two instances resolve to one name. The message says which name, and,
    /// when neither gave one, that a name is needed.
    DuplicateInstanceName,
    /// An instance gave both `token` and `token_file`, so which one Chock
    /// should read is not decided. Refused rather than guessed.
    TwoCredentialSpellings,
    /// A field that is present holds nothing: `.name = ""`, `.token = ""`,
    /// or `.token_file = ""`. Absence already means "look it up", so an
    /// empty value is a second spelling of a meaning that already has one.
    EmptyField,
    /// A kind with no default base URL, which is `openai-compat`, was given
    /// none.
    NoBaseUrl,
};

pub const LoadError = ParseError || error{
    /// There is no configuration file. The caller decides what to do: `chock
    /// login` names the file to create, and `chock run` reports that no
    /// provider is configured.
    NoConfigFile,
    /// The file is larger than `max_file_bytes`.
    ConfigTooLarge,
    /// The file exists and could not be read. Pass a `Diagnostic` to learn
    /// which fault the filesystem gave.
    ReadFailed,
};

/// Why a configuration file was refused, in the words its author needs.
///
/// **Some variants own memory, and `deinit` releases all of them.** The two
/// ZON variants hold the syntax tree their message points into, which is how
/// they can name a line and a column. The variants that name a provider hold
/// a copy of the name, because the `providers` block those names live in is
/// released the moment the parse fails.
pub const Diagnostic = union(enum) {
    file_not_zon: std.zon.parse.Diagnostics,
    /// One top level block does not match the schema. `field` names the
    /// block, and it is always a literal of this file.
    block_not_valid: BlockNotValid,
    not_a_struct_literal,
    /// The separate token file does not match its schema.
    token_file_not_valid: std.zon.parse.Diagnostics,
    /// The separate token file can be read by somebody other than its
    /// owner. A wrong mode is a fault, never a warning.
    token_file_readable_by_others: ReadableByOthers,
    /// A field of `.defaults` is present and holds nothing. `field` is a
    /// literal of this file.
    empty_default: []const u8,
    /// A provider names a kind Chock does not know. The kind is owned.
    unknown_provider_kind: []const u8,
    empty_provider_name,
    /// A provider gives both `.token` and `.token_file`. The name is owned.
    two_credential_spellings: []const u8,
    /// A provider gives a field that is present and holds nothing. The name
    /// is owned, and `field` is a literal of this file.
    empty_provider_field: EmptyProviderField,
    /// A provider is of a kind with no address of its own and gives no
    /// `.base_url`. Both names are owned.
    no_base_url: NoBaseUrl,
    /// Two providers resolve to one name. The name is owned, and `kind` is
    /// set when both are of the same kind, which needs the other message.
    duplicate_instance_name: DuplicateInstanceName,
    /// A file exists and the read failed. The path is owned.
    read_failed: ReadFailed,

    pub const BlockNotValid = struct {
        field: []const u8,
        zon: std.zon.parse.Diagnostics,
    };

    pub const EmptyProviderField = struct {
        name: []const u8,
        field: []const u8,
    };

    pub const NoBaseUrl = struct {
        name: []const u8,
        kind: []const u8,
    };

    pub const DuplicateInstanceName = struct {
        name: []const u8,
        /// The wire name of the kind both providers hold, or null when the
        /// two are of different kinds.
        shared_kind: ?[]const u8,
    };

    pub const ReadFailed = struct {
        path: []const u8,
        err: anyerror,
    };

    pub const ReadableByOthers = struct {
        path: []const u8,
        mode: u32,
    };

    /// Release what the diagnostic owns, with the allocator that filled it.
    /// Safe on every variant, so a caller can call it without asking which
    /// one it holds.
    ///
    /// **Every variant is named here, and there is no `else`.** A variant
    /// added later must say whether it owns memory before this file compiles
    /// again. An `else` took that question away, and a borrowed path that
    /// slipped through one in `lookup.zig` reached a person as a `chmod` over
    /// freed memory.
    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .file_not_zon, .token_file_not_valid => |*zon_diag| zon_diag.deinit(gpa),
            .block_not_valid => |*block| block.zon.deinit(gpa),
            .unknown_provider_kind, .two_credential_spellings => |name| gpa.free(name),
            .empty_provider_field => |field| gpa.free(field.name),
            .no_base_url => |names| gpa.free(names.name),
            .duplicate_instance_name => |names| gpa.free(names.name),
            .read_failed => |failure| gpa.free(failure.path),
            .token_file_readable_by_others => |failure| gpa.free(failure.path),
            // These three carry nothing, or carry a literal of this file.
            .not_a_struct_literal, .empty_provider_name, .empty_default => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .file_not_zon => |*zon_diag| try writer.print(
                "{s} is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .block_not_valid => |*block| try writer.print(
                "{s}: .{s} is not valid:\n{f}",
                .{ file_name, block.field, &block.zon },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{file_name},
            ),
            .token_file_not_valid => |*zon_diag| try writer.print(
                "{s}: the token file is not valid:\n{f}",
                .{ token_file_name, zon_diag },
            ),
            .empty_default => |field| try writer.print(
                "{s}: .defaults.{s} holds nothing. Leave the field out instead.",
                .{ file_name, field },
            ),
            .unknown_provider_kind => |kind| try writer.print(
                "{s}: the provider kind \"{s}\" is not one Chock knows. The kinds are: {s}",
                .{ file_name, kind, Kind.all_wire_names },
            ),
            .empty_provider_name => try writer.print(
                "{s}: a provider names itself \"\". Leave .name out to take the kind as the name.",
                .{file_name},
            ),
            .two_credential_spellings => |name| try writer.print(
                "{s}: the provider {s} gives both .token and .token_file, so which one to read is not decided. " ++
                    "Name one of them.",
                .{ file_name, name },
            ),
            .empty_provider_field => |field| try writer.print(
                "{s}: the provider {s} gives .{s} = \"\".{s}",
                .{ file_name, field.name, field.field, emptyFieldAdvice(field.field) },
            ),
            .no_base_url => |names| try writer.print(
                "{s}: the provider {s} is of kind {s}, which has no address of its own, so it needs " ++
                    ".base_url.",
                .{ file_name, names.name, names.kind },
            ),
            .duplicate_instance_name => |names| {
                if (names.shared_kind) |kind| {
                    try writer.print(
                        "{s}: two providers of kind {s} are both named {s}. Give each one its own .name.",
                        .{ file_name, kind, names.name },
                    );
                } else {
                    try writer.print(
                        "{s}: two providers are both named {s}. A name selects one provider, so each " ++
                            "one needs its own.",
                        .{ file_name, names.name },
                    );
                }
            },
            .read_failed => |failure| try writer.print(
                "reading {s} failed: {s}",
                .{ failure.path, @errorName(failure.err) },
            ),
            .token_file_readable_by_others => |failure| try writer.print(
                "the credential file {s} has mode {o:0>4}, and a credential must be readable by its owner only. " ++
                    "Run: chmod 600 {s}",
                .{ failure.path, failure.mode, failure.path },
            ),
        }
    }
};

/// The sentence that follows an empty provider field. Only `.token` earns
/// one, because absence of a token already has a meaning and an empty string
/// is a second spelling of it.
fn emptyFieldAdvice(field: []const u8) []const u8 {
    if (std.mem.eql(u8, field, "token")) {
        return " Leave the field out: absence already means look the credential up, " ++
            "and send none if there is none.";
    }
    if (std.mem.eql(u8, field, "token_file")) return " Leave the field out instead.";
    return "";
}

/// Fill `out` when the caller asked for one, and say whether it took `value`.
///
/// **The first fault is kept, not the last.** A provider can only be checked
/// after the file parsed, so the first fault is the one that explains the
/// rest.
///
/// The answer matters because several variants own memory: a site that hands
/// one over must release it itself when the answer is false.
fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// Whether a diagnostic is wanted and still empty, which is the one case in
/// which a site should copy a name for it. A caller that passes null must pay
/// no allocation at all.
fn wantsDiagnostic(out: ?*?Diagnostic) bool {
    const slot = out orelse return false;
    return slot.* == null;
}

/// The parsed configuration. `deinit` releases everything it owns.
pub const Config = struct {
    gpa: std.mem.Allocator,
    /// The `providers` block exactly as the file spelled it, which owns every
    /// string the instances below point into.
    providers: []const FileInstance,
    /// The `defaults` block, which owns its own two strings.
    defaults: FileDefaults,
    instances: []Instance,
    /// The instance a session uses when the command line names none. Null
    /// when the file names none, and then a caller with exactly one instance
    /// may use that one.
    default_provider: ?[]const u8,
    /// The model a session uses when the command line names none.
    default_model: ?[]const u8,

    pub fn deinit(self: *Config) void {
        self.gpa.free(self.instances);
        std.zon.parse.free(self.gpa, self.providers);
        std.zon.parse.free(self.gpa, self.defaults);
        self.* = undefined;
    }

    pub fn find(self: *const Config, name: []const u8) ?Instance {
        for (self.instances) |instance| {
            if (std.mem.eql(u8, instance.name, name)) return instance;
        }
        return null;
    }

    /// The instance a caller that named none should use: the file's own
    /// default when it names one, or the only instance when there is exactly
    /// one. Null when neither holds, because guessing between two providers
    /// is guessing which account the user is billed on.
    pub fn defaultInstance(self: *const Config) ?Instance {
        if (self.default_provider) |name| return self.find(name);
        if (self.instances.len == 1) return self.instances[0];
        return null;
    }
};

/// Read `source`, which must be the whole content of a configuration file.
/// The result owns a copy of every string in it, so the caller may release
/// `source` at once.
///
/// `diag` is optional. A caller that passes null pays nothing, allocates
/// nothing extra, and learns only the error. A caller that passes a slot must
/// call `Diagnostic.deinit` on whatever lands in it.
pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Config {
    // Each top level block is parsed on its own, and **strictly**: a field
    // name with a typo inside a provider must never quietly become an
    // instance that means something the author did not write, which is the
    // same rule `lib/chock-policy/table.zig` keeps for a policy rule. A top
    // level field this build does not know is ignored instead, because a
    // later milestone writes the model roster and the cost caps into this
    // same file and an older Chock must still read the providers out of it.
    //
    // `std.zon.parse`'s own `ignore_unknown_fields` cannot express that: it
    // is one setting for the whole tree. Reading one named block at a time is
    // what keeps the two answers apart.
    const providers = try parseBlock([]const FileInstance, gpa, source, "providers", diag) orelse &.{};
    errdefer std.zon.parse.free(gpa, providers);
    const defaults = try parseBlock(FileDefaults, gpa, source, "defaults", diag) orelse FileDefaults{};
    errdefer std.zon.parse.free(gpa, defaults);

    const instances = try gpa.alloc(Instance, providers.len);
    errdefer gpa.free(instances);

    for (providers, instances) |entry, *slot| slot.* = try checkInstance(gpa, entry, diag);
    try refuseDuplicateNames(gpa, instances, diag);

    if (defaults.provider) |name| {
        if (name.len == 0) {
            _ = note(diag, .{ .empty_default = "provider" });
            return error.EmptyField;
        }
    }
    if (defaults.model) |model| {
        if (model.len == 0) {
            _ = note(diag, .{ .empty_default = "model" });
            return error.EmptyField;
        }
    }

    return .{
        .gpa = gpa,
        .providers = providers,
        .defaults = defaults,
        .instances = instances,
        .default_provider = defaults.provider,
        .default_model = defaults.model,
    };
}

/// The top level field `field_name`, parsed strictly into `T`, or null when
/// the file has no such field. Each call reads `source` again: a
/// configuration file is small, and two reads of it cost less than the
/// bookkeeping of sharing one parse tree across two calls that each want to
/// take ownership of it.
fn parseBlock(
    comptime T: type,
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    field_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?T {
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    var ast_owned = true;
    defer if (ast_owned) ast.deinit(gpa);

    // `parse_str_lits = false` matches what `std.zon.parse.fromSliceAlloc`
    // itself does: the parse call below reads the string literals off the
    // `Ast`, and this function only reads field names, which are always
    // there.
    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

    // A syntax error arrives here too: `ZonGen.generate` lowers the `Ast`'s
    // own errors into its own, and leaves a `Zoir` with no nodes, so nothing
    // may walk it.
    if (zoir.hasCompileErrors()) {
        if (note(diag, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidConfig;
    }

    const node = try findField(zoir, field_name, diag) orelse return null;

    // From here the diagnostics own both trees, the same handover
    // `lib/chock-policy/table.zig`'s own `Trees` type manages.
    var diagnostics: std.zon.parse.Diagnostics = .{};
    ast_owned = false;
    zoir_owned = false;
    var diagnostics_owned = true;
    defer if (diagnostics_owned) diagnostics.deinit(gpa);

    return std.zon.parse.fromZoirNodeAlloc(T, gpa, ast, zoir, node, &diagnostics, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            if (note(diag, .{ .block_not_valid = .{ .field = field_name, .zon = diagnostics } })) {
                diagnostics_owned = false;
            }
            return error.InvalidConfig;
        },
    };
}

/// The node of one top level field, or null when the file has no such field.
fn findField(
    zoir: std.zig.Zoir,
    field_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), field_name)) return fields.vals.at(@intCast(index));
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidConfig;
        },
    }
}

/// Every name a fault here carries is copied. `parse` releases the
/// `providers` block those names point into the moment this returns an error.
fn checkInstance(gpa: std.mem.Allocator, entry: FileInstance, diag: ?*?Diagnostic) ParseError!Instance {
    const kind = Kind.fromWireName(entry.kind) orelse {
        if (wantsDiagnostic(diag)) {
            _ = note(diag, .{ .unknown_provider_kind = try gpa.dupe(u8, entry.kind) });
        }
        return error.UnknownProviderKind;
    };

    const name = name: {
        const given = entry.name orelse break :name kind.wireName();
        if (given.len == 0) {
            _ = note(diag, .empty_provider_name);
            return error.EmptyField;
        }
        break :name given;
    };

    if (entry.token != null and entry.token_file != null) {
        if (wantsDiagnostic(diag)) {
            _ = note(diag, .{ .two_credential_spellings = try gpa.dupe(u8, name) });
        }
        return error.TwoCredentialSpellings;
    }

    const credential: Credential = credential: {
        if (entry.token) |token| {
            if (token.len == 0) {
                try noteEmptyProviderField(gpa, diag, name, "token");
                return error.EmptyField;
            }
            break :credential .{ .token = token };
        }
        if (entry.token_file) |path| {
            if (path.len == 0) {
                try noteEmptyProviderField(gpa, diag, name, "token_file");
                return error.EmptyField;
            }
            break :credential .{ .token_file = path };
        }
        break :credential .absent;
    };

    const base_url = base: {
        const given = entry.base_url orelse break :base kind.defaultBaseUrl();
        if (given.len == 0) {
            try noteEmptyProviderField(gpa, diag, name, "base_url");
            return error.EmptyField;
        }
        break :base given;
    };
    if (base_url.len == 0) {
        if (wantsDiagnostic(diag)) {
            _ = note(diag, .{ .no_base_url = .{
                .name = try gpa.dupe(u8, name),
                .kind = kind.wireName(),
            } });
        }
        return error.NoBaseUrl;
    }

    return .{
        .name = name,
        .kind = kind,
        .base_url = base_url,
        .credential = credential,
        .context_tokens = entry.context_tokens,
        .capabilities = entry.capabilities orelse .{},
    };
}

/// Refuse two instances that resolve to one name. A store keyed on the kind
/// cannot hold the second instance of a kind, and
/// that fault only appears after somebody has already stored it. This is the
/// same fault one step earlier, in the file.
fn refuseDuplicateNames(
    gpa: std.mem.Allocator,
    instances: []const Instance,
    diag: ?*?Diagnostic,
) ParseError!void {
    for (instances, 0..) |instance, index| {
        for (instances[index + 1 ..]) |other| {
            if (!std.mem.eql(u8, instance.name, other.name)) continue;
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .duplicate_instance_name = .{
                    .name = try gpa.dupe(u8, instance.name),
                    .shared_kind = if (instance.kind == other.kind)
                        instance.kind.wireName()
                    else
                        null,
                } });
            }
            return error.DuplicateInstanceName;
        }
    }
}

/// Note a provider field that is present and holds nothing. `field` is always
/// a literal of this file; the provider's own name is copied, for the reason
/// `checkInstance` gives.
fn noteEmptyProviderField(
    gpa: std.mem.Allocator,
    diag: ?*?Diagnostic,
    name: []const u8,
    comptime field: []const u8,
) std.mem.Allocator.Error!void {
    if (!wantsDiagnostic(diag)) return;
    _ = note(diag, .{ .empty_provider_field = .{
        .name = try gpa.dupe(u8, name),
        .field = field,
    } });
}

/// Read the configuration file out of `config_dir` and parse it.
pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    config_dir: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Config {
    const path = try std.fs.path.join(gpa, &.{ config_dir, file_name });
    defer gpa.free(path);
    const source = try readWholeFile(gpa, io, path, diag);
    defer gpa.free(source);
    return parse(gpa, source, diag);
}

/// The separate token file, source 2. `deinit` releases it.
pub const Tokens = struct {
    gpa: std.mem.Allocator,
    entries: []const TokenEntry,

    pub fn deinit(self: *Tokens) void {
        std.zon.parse.free(self.gpa, self.entries);
        self.* = undefined;
    }

    pub fn find(self: *const Tokens, name: []const u8) ?[]const u8 {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.token;
        }
        return null;
    }
};

/// Read and parse the separate token file out of `config_dir`. The file is a
/// plain list, so a person can read and edit it:
///
/// ```zon
/// .{
///     .{ .name = "work", .token = "sk-..." },
/// }
/// ```
pub fn loadTokens(
    gpa: std.mem.Allocator,
    io: std.Io,
    config_dir: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Tokens {
    const path = try std.fs.path.join(gpa, &.{ config_dir, token_file_name });
    defer gpa.free(path);

    // The mode rule covers every source, not only the store Chock writes: a
    // token file others can read is a leaked credential whoever wrote it.
    var mode_fault: ?paths.Diagnostic = null;
    paths.requirePrivate(io, path, &mode_fault) catch |err| switch (err) {
        // A missing file is not a fault here. `readWholeFile` below reports
        // it as `NoConfigFile`, which is the caller's own "there is nothing
        // in this source" answer.
        error.CredentialFileMissing => {},
        error.StatFailed => {
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .read_failed = .{
                    .path = try gpa.dupe(u8, path),
                    .err = mode_fault.?.stat_failed.err,
                } });
            }
            return error.ReadFailed;
        },
        error.CredentialFileIsReadable => {
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .token_file_readable_by_others = .{
                    .path = try gpa.dupe(u8, path),
                    .mode = mode_fault.?.readable_by_others.mode,
                } });
            }
            return error.InvalidConfig;
        },
    };

    const source = try readWholeFile(gpa, io, path, diag);
    defer gpa.free(source);

    var diagnostics: std.zon.parse.Diagnostics = .{};
    var diagnostics_owned = true;
    defer if (diagnostics_owned) diagnostics.deinit(gpa);
    const entries = std.zon.parse.fromSliceAlloc([]const TokenEntry, gpa, source, &diagnostics, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            if (note(diag, .{ .token_file_not_valid = diagnostics })) diagnostics_owned = false;
            return error.InvalidConfig;
        },
    };
    return .{ .gpa = gpa, .entries = entries };
}

fn readWholeFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    diag: ?*?Diagnostic,
) LoadError![:0]u8 {
    return std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.ConfigTooLarge,
        error.FileNotFound, error.NotDir => return error.NoConfigFile,
        else => {
            // The path is joined into a buffer this function releases, so
            // the diagnostic keeps its own copy of it.
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .read_failed = .{
                    .path = try gpa.dupe(u8, path),
                    .err = err,
                } });
            }
            return error.ReadFailed;
        },
    };
}

const testing = std.testing;

test "an instance with no name takes its kind as the name, and a named one keeps its own" {
    const gpa = testing.allocator;
    var config = try parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .kind = "aiand" },
        \\        .{ .name = "personal", .kind = "aiand" },
        \\    },
        \\}
    , null);
    defer config.deinit();

    try testing.expectEqual(@as(usize, 2), config.instances.len);
    try testing.expectEqualStrings("aiand", config.instances[0].name);
    try testing.expectEqualStrings("personal", config.instances[1].name);
    try testing.expectEqual(Kind.aiand, config.instances[0].kind);
    try testing.expectEqual(Kind.aiand, config.instances[1].kind);
    try testing.expectEqualStrings("personal", config.find("personal").?.name);
    try testing.expect(config.find("work") == null);
}

test "a second instance of a kind with no name is refused, never silently replacing the first" {
    const gpa = testing.allocator;
    try testing.expectError(error.DuplicateInstanceName, parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .kind = "aiand" },
        \\        .{ .kind = "aiand" },
        \\    },
        \\}
    , null));

    // Two different kinds under one name is the same fault: a name selects
    // one provider.
    try testing.expectError(error.DuplicateInstanceName, parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "work", .kind = "aiand" },
        \\        .{ .name = "work", .kind = "anthropic" },
        \\    },
        \\}
    , null));
}

test "both credential spellings parse, and an instance with neither says absent" {
    const gpa = testing.allocator;
    var config = try parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "local", .kind = "openai-compat", .base_url = "http://127.0.0.1:5000/v1" },
        \\        .{ .name = "work", .kind = "aiand", .token_file = "/run/secrets/aiand" },
        \\        .{ .name = "personal", .kind = "aiand", .token = "sk-written-in-place" },
        \\    },
        \\}
    , null);
    defer config.deinit();

    try testing.expectEqual(Credential.absent, std.meta.activeTag(config.find("local").?.credential));
    try testing.expectEqualStrings("/run/secrets/aiand", config.find("work").?.credential.token_file);
    try testing.expectEqualStrings("sk-written-in-place", config.find("personal").?.credential.token);
}

test "an instance that gives both spellings is refused rather than one of them guessed" {
    const gpa = testing.allocator;
    try testing.expectError(error.TwoCredentialSpellings, parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .kind = "aiand", .token = "sk-one", .token_file = "/run/secrets/two" },
        \\    },
        \\}
    , null));
}

test "a field that is present and holds nothing is refused, because absence already has a meaning" {
    const gpa = testing.allocator;
    try testing.expectError(error.EmptyField, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "aiand", .token = "" } } }
    , null));
    try testing.expectError(error.EmptyField, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "aiand", .token_file = "" } } }
    , null));
    try testing.expectError(error.EmptyField, parse(gpa,
        \\.{ .providers = .{ .{ .name = "", .kind = "aiand" } } }
    , null));
}

test "a kind Chock does not know is refused, and a kind with no address of its own needs one" {
    const gpa = testing.allocator;
    try testing.expectError(error.UnknownProviderKind, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "openai" } } }
    , null));
    try testing.expectError(error.NoBaseUrl, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "openai-compat" } } }
    , null));

    var config = try parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .kind = "aiand" },
        \\        .{ .name = "mirror", .kind = "aiand", .base_url = "https://mirror.example.invalid/v1" },
        \\    },
        \\}
    , null);
    defer config.deinit();
    try testing.expectEqualStrings(Kind.aiand.defaultBaseUrl(), config.find("aiand").?.base_url);
    try testing.expectEqualStrings("https://mirror.example.invalid/v1", config.find("mirror").?.base_url);
}

test "an instance can say how many tokens its model holds, and one that says nothing reads null" {
    const gpa = testing.allocator;
    var config = try parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "local", .kind = "openai-compat", .base_url = "http://127.0.0.1:5000/v1", .context_tokens = 65536 },
        \\        .{ .kind = "aiand" },
        \\    },
        \\}
    , null);
    defer config.deinit();
    try testing.expectEqual(@as(?u64, 65536), config.find("local").?.context_tokens);
    try testing.expect(config.find("aiand").?.context_tokens == null);
}

test "a field name with a typo inside a provider is refused, and a whole section from a newer Chock is not" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidConfig, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "aiand", .tokn = "sk-typo" } } }
    , null));

    var config = try parse(gpa,
        \\.{
        \\    .providers = .{ .{ .kind = "aiand" } },
        \\    .roster = .{ .main = "aiand" },
        \\}
    , null);
    defer config.deinit();
    try testing.expectEqual(@as(usize, 1), config.instances.len);
}

test "the default instance is the one the file names, or the only one, and never a guess between two" {
    const gpa = testing.allocator;
    {
        var config = try parse(gpa,
            \\.{ .providers = .{ .{ .kind = "aiand" } } }
        , null);
        defer config.deinit();
        try testing.expectEqualStrings("aiand", config.defaultInstance().?.name);
    }
    {
        var config = try parse(gpa,
            \\.{
            \\    .providers = .{ .{ .kind = "aiand" }, .{ .name = "personal", .kind = "aiand" } },
            \\}
        , null);
        defer config.deinit();
        try testing.expect(config.defaultInstance() == null);
    }
    {
        var config = try parse(gpa,
            \\.{
            \\    .providers = .{ .{ .kind = "aiand" }, .{ .name = "personal", .kind = "aiand" } },
            \\    .defaults = .{ .provider = "personal", .model = "a-model" },
            \\}
        , null);
        defer config.deinit();
        try testing.expectEqualStrings("personal", config.defaultInstance().?.name);
        try testing.expectEqualStrings("a-model", config.default_model.?);
    }
}

test "the separate token file is read, and one that others can read is refused" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ dir, token_file_name });

    {
        var file = try std.Io.Dir.createFileAbsolute(testing.io, path, .{ .truncate = true });
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io,
            \\.{
            \\    .{ .name = "work", .token = "sk-from-the-token-file" },
            \\}
        );
        try file.setPermissions(testing.io, .fromMode(0o600));
    }

    {
        var tokens = try loadTokens(gpa, testing.io, dir, null);
        defer tokens.deinit();
        try testing.expectEqualStrings("sk-from-the-token-file", tokens.find("work").?);
        try testing.expect(tokens.find("personal") == null);
    }

    // The same file, widened. The mode rule covers this source too.
    {
        var file = try std.Io.Dir.openFileAbsolute(testing.io, path, .{});
        defer file.close(testing.io);
        try file.setPermissions(testing.io, .fromMode(0o644));
    }
    try testing.expectError(error.InvalidConfig, loadTokens(gpa, testing.io, dir, null));
}

test "a missing configuration file and a missing token file are both reported, never taken as empty" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];

    try testing.expectError(error.NoConfigFile, load(gpa, testing.io, dir, null));
    try testing.expectError(error.NoConfigFile, loadTokens(gpa, testing.io, dir, null));
}

test "an instance says what it can do, and an instance that says nothing gets no capability" {
    const gpa = testing.allocator;
    var config = try parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "work", .kind = "aiand", .capabilities = .{ .images = true } },
        \\        .{ .name = "personal", .kind = "aiand" },
        \\    },
        \\}
    , null);
    defer config.deinit();

    try testing.expect(config.find("work").?.capabilities.images);
    try testing.expect(!config.find("personal").?.capabilities.images);
}

test "a capability this build has never heard of is refused, never taken as a yes" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidConfig, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "aiand", .capabilities = .{ .telepathy = true } } } }
    , null));
}

test "the provider a refused entry names reaches the caller, and no longer only a terminal" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.UnknownProviderKind, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "openai" } } }
    , &diag));
    try testing.expectEqualStrings("openai", diag.?.unknown_provider_kind);

    var buffer: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "config.zon: the provider kind \"openai\" is not one Chock knows. " ++
            "The kinds are: anthropic, aiand, openai-compat",
        try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?}),
    );
}

test "a name in a refused entry is a copy, because the providers block is released" {
    // `parse` frees the `providers` block on every error path, so a
    // diagnostic that borrowed a name from it would dangle. The testing
    // allocator fails this test if `deinit` misses the copy.
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.DuplicateInstanceName, parse(gpa,
        \\.{ .providers = .{
        \\    .{ .name = "work", .kind = "aiand" },
        \\    .{ .name = "work", .kind = "anthropic" },
        \\} }
    , &diag));
    try testing.expectEqualStrings("work", diag.?.duplicate_instance_name.name);
    try testing.expectEqual(@as(?[]const u8, null), diag.?.duplicate_instance_name.shared_kind);

    var buffer: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "config.zon: two providers are both named work. " ++
            "A name selects one provider, so each one needs its own.",
        try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?}),
    );
}

test "a typo inside a provider names its block, its line and its column" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidConfig, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "aiand", .tokn = "sk-typo" } } }
    , &diag));

    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.startsWith(u8, line, "config.zon: .providers is not valid:\n"));
    try testing.expect(std.mem.indexOf(u8, line, "1:41: error:") != null);
    try testing.expect(std.mem.indexOf(u8, line, "tokn") != null);
}

test "a caller that wants no diagnostic allocates nothing extra for one" {
    // The outer optional is what lets a caller opt out. The testing allocator
    // fails this test if a refused parse leaks the copy it would have made
    // for a diagnostic that nobody asked for.
    const gpa = testing.allocator;
    try testing.expectError(error.UnknownProviderKind, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "openai" } } }
    , null));
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    try testing.expect(note(&diag, .not_a_struct_literal));
    try testing.expect(!note(&diag, .empty_provider_name));
    try testing.expectEqual(Diagnostic.not_a_struct_literal, diag.?);

    try testing.expect(!note(null, .not_a_struct_literal));
    try testing.expect(!wantsDiagnostic(null));
    try testing.expect(!wantsDiagnostic(&diag));
}

test "no two faults of this module read the same" {
    // A reader has to be able to tell which one happened. The three ZON
    // variants are left out, because each renders a syntax tree that no
    // literal here can build; the test above pins one of them.
    const cases: []const Diagnostic = &.{
        .not_a_struct_literal,
        .empty_provider_name,
        .{ .empty_default = "provider" },
        .{ .empty_default = "model" },
        .{ .unknown_provider_kind = "openai" },
        .{ .two_credential_spellings = "work" },
        .{ .empty_provider_field = .{ .name = "work", .field = "token" } },
        .{ .empty_provider_field = .{ .name = "work", .field = "token_file" } },
        .{ .empty_provider_field = .{ .name = "work", .field = "base_url" } },
        .{ .no_base_url = .{ .name = "work", .kind = "openai-compat" } },
        .{ .duplicate_instance_name = .{ .name = "work", .shared_kind = null } },
        .{ .duplicate_instance_name = .{ .name = "work", .shared_kind = "aiand" } },
        .{ .read_failed = .{ .path = "/x", .err = error.AccessDenied } },
        .{ .token_file_readable_by_others = .{ .path = "/x", .mode = 0o644 } },
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
