//! The price table, and the arithmetic that turns token counts into money.
//! A model missing from the table reads as `unknown`, never free.

const std = @import("std");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;

/// Bump this in the same commit as any number below.
pub const version = "2026-08-21";

pub const Price = struct {
    input_per_million: f64,
    output_per_million: f64,
    cache_write_per_million: f64,
    cache_read_per_million: f64,
    currency: []const u8 = "USD",
};

pub const Entry = struct {
    model: []const u8,
    price: Price,
};

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

/// A property of the provider instance, not of the model.
pub const Billing = enum {
    billed,
    /// Not an absence: a cap still applies.
    free,
};

/// Never invents a price for a model the table has never heard of.
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

pub fn costFor(model: []const u8, usage: event.Usage, billing: Billing) event.Cost {
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

pub fn isLoopback(base_url: []const u8) bool {
    const after_scheme = if (std.mem.indexOf(u8, base_url, "://")) |index|
        base_url[index + 3 ..]
    else
        base_url;
    // A bracketed IPv6 literal ends at its own `]`, not at the first colon.
    const host_end = if (after_scheme.len != 0 and after_scheme[0] == '[')
        (std.mem.indexOfScalar(u8, after_scheme, ']') orelse after_scheme.len -| 1) + 1
    else
        std.mem.indexOfAny(u8, after_scheme, ":/") orelse after_scheme.len;
    const host = after_scheme[0..@min(host_end, after_scheme.len)];

    if (std.mem.eql(u8, host, "localhost")) return true;
    if (std.mem.eql(u8, host, "127.0.0.1")) return true;
    if (std.mem.eql(u8, host, "0.0.0.0")) return true;
    if (std.mem.eql(u8, host, "[::1]")) return true;
    // The whole 127.0.0.0/8 block is loopback too.
    if (std.mem.startsWith(u8, host, "127.")) return true;
    return false;
}

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
    try testing.expectApproxEqAbs(@as(f64, 36.75), cost.known.value, 1e-9);
    try testing.expectEqualStrings("USD", cost.known.currency);
}

test "a model with no price entry is unknown, and unknown is not zero" {
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
    // Not a substring match.
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
    try testing.expectApproxEqAbs(
        @as(f64, 3.00),
        lookup("claude-sonnet-5-some-later-variant").?.input_per_million,
        1e-9,
    );
}

test "every entry in the table has a currency and a price above zero" {
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
