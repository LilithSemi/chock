//! The price table, and the arithmetic that turns token counts into money.
//!
//! **This is data, not code, and it goes stale.** Every number below is a
//! published list price on the day `version` names. A model whose price
//! changed, or whose name never appeared here, is `unknown`, and unknown is
//! not zero. Every computed `Cost` is written into
//! the log beside `Usage.price_table_version`, so a wrong price later becomes
//! a fact somebody can find rather than a number nobody can explain.
//!
//! **A model with no entry is unknown, and the session says so.** Silently
//! counting it as free is how a cap is passed with nobody noticing, and it is
//! the same class of fault as a policy resolving an unnamed action to allow.

const std = @import("std");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;

/// The day the numbers below were read off the providers' own published
/// prices. Written into every `usage` event whose cost this file computed.
/// **Bump this in the same commit as any number below**, or a reader cannot
/// tell which table produced a total.
pub const version = "2026-08-21";

/// What one million tokens of each class costs. Providers publish per million
/// token prices, so the table holds them in the unit it was read in and the
/// division happens once, in `costFor`, rather than being baked into fifteen
/// literals where a slipped decimal point would hide.
pub const Price = struct {
    input_per_million: f64,
    output_per_million: f64,
    /// Writing a prompt into the cache costs more than an ordinary input
    /// token; reading it back costs far less. A table that folded these into
    /// `input_per_million` would over charge every cached turn, which is
    /// most turns of a long session.
    cache_write_per_million: f64,
    cache_read_per_million: f64,
    /// ISO 4217.
    currency: []const u8 = "USD",
};

/// One row of the table. `model` matches the model name as it goes on the
/// wire.
pub const Entry = struct {
    model: []const u8,
    price: Price,
};

/// The table itself. Ordered longest name first is not required: `lookup`
/// prefers an exact match and only then takes the longest prefix, so the
/// order here is for a reader's eyes and nothing else.
pub const table = [_]Entry{
    .{ .model = "claude-opus-5", .price = .{
        .input_per_million = 5.00,
        .output_per_million = 25.00,
        .cache_write_per_million = 6.25,
        .cache_read_per_million = 0.50,
    } },
    .{ .model = "claude-opus-4-8", .price = .{
        .input_per_million = 5.00,
        .output_per_million = 25.00,
        .cache_write_per_million = 6.25,
        .cache_read_per_million = 0.50,
    } },
    .{ .model = "claude-opus-4-7", .price = .{
        .input_per_million = 5.00,
        .output_per_million = 25.00,
        .cache_write_per_million = 6.25,
        .cache_read_per_million = 0.50,
    } },
    .{ .model = "claude-opus-4-6", .price = .{
        .input_per_million = 5.00,
        .output_per_million = 25.00,
        .cache_write_per_million = 6.25,
        .cache_read_per_million = 0.50,
    } },
    .{ .model = "claude-fable-5", .price = .{
        .input_per_million = 10.00,
        .output_per_million = 50.00,
        .cache_write_per_million = 12.50,
        .cache_read_per_million = 1.00,
    } },
    .{ .model = "claude-mythos-5", .price = .{
        .input_per_million = 10.00,
        .output_per_million = 50.00,
        .cache_write_per_million = 12.50,
        .cache_read_per_million = 1.00,
    } },
    .{ .model = "claude-sonnet-5", .price = .{
        .input_per_million = 3.00,
        .output_per_million = 15.00,
        .cache_write_per_million = 3.75,
        .cache_read_per_million = 0.30,
    } },
    .{ .model = "claude-sonnet-4-6", .price = .{
        .input_per_million = 3.00,
        .output_per_million = 15.00,
        .cache_write_per_million = 3.75,
        .cache_read_per_million = 0.30,
    } },
    .{ .model = "claude-haiku-4-5", .price = .{
        .input_per_million = 1.00,
        .output_per_million = 5.00,
        .cache_write_per_million = 1.25,
        .cache_read_per_million = 0.10,
    } },
};

/// Whether the endpoint this session talks to bills anybody at all. **This is
/// a property of the provider instance, not of the model**: the same model
/// name is free on a machine under the user's desk and billed on somebody
/// else's. See `isLoopback`.
pub const Billing = enum {
    /// Somebody is charged for this. Whether Chock can say how much depends
    /// on the price table.
    billed,
    /// Nothing is charged, whatever the token counts say. A fact, not an
    /// absence: a session against a local server runs under a cap without
    /// trouble.
    free,
};

/// The price for `model`, or null when the table does not name it.
///
/// An exact match first. Failing that, the longest entry whose name is a
/// prefix of `model`, which is what catches a dated snapshot such as
/// `claude-opus-4-5-20251101` and a provider prefixed id such as
/// `anthropic.claude-opus-5` once the prefix before the last dot is dropped.
/// A prefix match never invents a price for a model the table has never heard
/// of: `glm4.7-flash:A3B` matches nothing here and stays unknown.
pub fn lookup(model: []const u8) ?Price {
    for (table) |entry| {
        if (std.mem.eql(u8, entry.model, model)) return entry.price;
    }

    const bare = if (std.mem.lastIndexOfScalar(u8, model, '.')) |dot| model[dot + 1 ..] else model;
    var best: ?Price = null;
    var best_len: usize = 0;
    for (table) |entry| {
        if (!std.mem.startsWith(u8, bare, entry.model)) continue;
        if (entry.model.len <= best_len) continue;
        best = entry.price;
        best_len = entry.model.len;
    }
    return best;
}

/// What `usage` cost on `model`, given whether the endpoint bills at all.
///
/// * `billing == .free` gives `free`, whatever the counts are.
/// * A model the table names gives `known`, computed from the counts.
/// * Anything else gives `unknown`. **Never zero.**
///
/// A usage that reports no tokens at all on a billed endpoint is still
/// `unknown` rather than a `known` zero, because a provider that counted
/// nothing has told Chock nothing, and reading its silence as a free turn is
/// the exact mistake this table must not make.
pub fn costFor(model: []const u8, usage: event.Usage, billing: Billing) event.Cost {
    // The provider's own number wins. A number from the provider is the truth
    // and Chock never recomputes it.
    if (usage.cost != .unknown) return usage.cost;

    if (billing == .free) return .free;
    if (usage.totalTokens() == 0) return .unknown;
    const price = lookup(model) orelse return .unknown;

    const per_million = 1_000_000.0;
    const total =
        @as(f64, @floatFromInt(usage.input_tokens)) * price.input_per_million / per_million +
        @as(f64, @floatFromInt(usage.output_tokens)) * price.output_per_million / per_million +
        @as(f64, @floatFromInt(usage.cache_creation_input_tokens)) * price.cache_write_per_million / per_million +
        @as(f64, @floatFromInt(usage.cache_read_input_tokens)) * price.cache_read_per_million / per_million;
    return .{ .known = .{ .value = total, .currency = price.currency } };
}

/// Whether `base_url` names a loopback address, which is what makes a local
/// llama.cpp server free: **nothing bills anybody for localhost.**
///
/// This is the only place Chock decides an endpoint is free, and it decides
/// it from a fact rather than a guess. A remote `openai-compat` endpoint is
/// somebody's server and is billed, whether or not the price table can say
/// how much.
pub fn isLoopback(base_url: []const u8) bool {
    const after_scheme = if (std.mem.indexOf(u8, base_url, "://")) |index|
        base_url[index + 3 ..]
    else
        base_url;
    // A bracketed IPv6 literal ends at its own `]`, not at the first colon:
    // `[::1]:5000` is full of colons that are part of the address.
    const host_end = if (after_scheme.len != 0 and after_scheme[0] == '[')
        (std.mem.indexOfScalar(u8, after_scheme, ']') orelse after_scheme.len -| 1) + 1
    else
        std.mem.indexOfAny(u8, after_scheme, ":/") orelse after_scheme.len;
    const host = after_scheme[0..@min(host_end, after_scheme.len)];

    if (std.mem.eql(u8, host, "localhost")) return true;
    if (std.mem.eql(u8, host, "127.0.0.1")) return true;
    if (std.mem.eql(u8, host, "0.0.0.0")) return true;
    if (std.mem.eql(u8, host, "[::1]")) return true;
    // The whole 127.0.0.0/8 block, which a user pointing at 127.0.0.2 is
    // just as entitled to use.
    if (std.mem.startsWith(u8, host, "127.")) return true;
    return false;
}

/// The billing a provider instance has, from its base URL. A caller that
/// knows better, for example one whose configuration says a remote endpoint
/// is on a flat rate, passes its own `Billing` instead.
pub fn billingFor(base_url: []const u8) Billing {
    return if (isLoopback(base_url)) .free else .billed;
}

const testing = std.testing;

test "a model the table names is priced from its own counts, class by class" {
    const usage = event.Usage{
        .input_tokens = 1_000_000,
        .output_tokens = 1_000_000,
        .cache_creation_input_tokens = 1_000_000,
        .cache_read_input_tokens = 1_000_000,
    };
    const cost = costFor("claude-opus-5", usage, .billed);
    try testing.expectEqual(event.Cost.known, std.meta.activeTag(cost));
    // 5.00 + 25.00 + 6.25 + 0.50. A table that folded the cache classes into
    // the input price would say 40.00 here, and a table that ignored them
    // would say 30.00.
    try testing.expectApproxEqAbs(@as(f64, 36.75), cost.known.value, 1e-9);
    try testing.expectEqualStrings("USD", cost.known.currency);
}

test "a model with no price entry is unknown, and unknown is not zero" {
    // The fault this whole three state type exists to stop: a session against
    // a model nobody priced must not read as a free session.
    const usage = event.Usage{ .input_tokens = 1200, .output_tokens = 150 };
    const cost = costFor("a-model-nobody-priced", usage, .billed);
    try testing.expectEqual(event.Cost.unknown, std.meta.activeTag(cost));
    try testing.expect(cost != .free);
    try testing.expect(cost != .known);
}

test "a loopback endpoint is free, and a remote one is not" {
    try testing.expectEqual(Billing.free, billingFor("http://127.0.0.1:5000/v1"));
    try testing.expectEqual(Billing.free, billingFor("http://localhost:8080/v1"));
    try testing.expectEqual(Billing.free, billingFor("http://127.0.0.2:5000/v1"));
    try testing.expectEqual(Billing.free, billingFor("http://[::1]:5000/v1"));
    try testing.expectEqual(Billing.billed, billingFor("https://api.aiand.com/v1"));
    try testing.expectEqual(Billing.billed, billingFor("https://api.anthropic.com/v1"));
    // Not a substring match: a host that merely mentions localhost is not
    // localhost, and reading it as free would make somebody's bill free too.
    try testing.expectEqual(Billing.billed, billingFor("https://localhost.example.com/v1"));
}

test "a free endpoint costs nothing even for a model the table prices" {
    const usage = event.Usage{ .input_tokens = 1_000_000, .output_tokens = 1_000_000 };
    try testing.expectEqual(event.Cost.free, std.meta.activeTag(costFor("claude-opus-5", usage, .free)));
    try testing.expectEqual(event.Cost.known, std.meta.activeTag(costFor("claude-opus-5", usage, .billed)));
}

test "a cost the provider itself reported is kept and never recomputed" {
    const usage = event.Usage{
        .input_tokens = 1_000_000,
        .output_tokens = 1_000_000,
        .cost = .{ .known = .{ .value = 0.0042, .currency = "EUR" } },
    };
    const cost = costFor("claude-opus-5", usage, .billed);
    try testing.expectApproxEqAbs(@as(f64, 0.0042), cost.known.value, 1e-12);
    try testing.expectEqualStrings("EUR", cost.known.currency);
}

test "a billed turn that reported no tokens at all is unknown, not a free turn" {
    const cost = costFor("claude-opus-5", .{}, .billed);
    try testing.expectEqual(event.Cost.unknown, std.meta.activeTag(cost));
}

test "a dated or provider prefixed model name still finds its price" {
    try testing.expect(lookup("claude-opus-4-5-20251101") == null);
    try testing.expect(lookup("anthropic.claude-opus-5") != null);
    try testing.expectApproxEqAbs(
        @as(f64, 5.00),
        lookup("anthropic.claude-opus-5").?.input_per_million,
        1e-9,
    );
    try testing.expect(lookup("glm4.7-flash:A3B") == null);
    // And the longest prefix wins, so a name that starts with a shorter
    // entry does not take the shorter entry's price.
    try testing.expectApproxEqAbs(
        @as(f64, 3.00),
        lookup("claude-sonnet-5-some-later-variant").?.input_per_million,
        1e-9,
    );
}

test "every entry in the table has a currency and a price above zero" {
    // A row added with a field left at zero would price every turn on that
    // model at nothing, which reads as free and is not.
    for (table) |entry| {
        try testing.expect(entry.model.len != 0);
        try testing.expect(entry.price.currency.len != 0);
        try testing.expect(entry.price.input_per_million > 0);
        try testing.expect(entry.price.output_per_million > 0);
        try testing.expect(entry.price.cache_write_per_million > 0);
        try testing.expect(entry.price.cache_read_per_million > 0);
    }
    try testing.expect(version.len != 0);
}
