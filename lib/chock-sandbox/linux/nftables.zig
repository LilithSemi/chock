//! The kernel half of the network router: one fixed nftables ruleset, and one
//! dynamic allow set the resolver writes into.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const namespace = @import("namespace.zig");

pub const table_name = "chock";
pub const set4_name = "allowed4";
pub const set6_name = "allowed6";
pub const guard_chain_name = "guard";
pub const relay_chain_name = "relay";

pub const relay_port: u16 = 18080;

pub const default_timeout_ms: u64 = 30_000;

const hook_output: u32 = 3;
const guard_priority: i32 = -150;
const relay_priority: i32 = -100;
const guard_policy: u32 = 0;

pub const Address = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,

    fn setName(self: Address) []const u8 {
        return switch (self) {
            .ipv4 => set4_name,
            .ipv6 => set6_name,
        };
    }

    fn key(self: *const Address) []const u8 {
        return switch (self.*) {
            .ipv4 => |*bytes| bytes,
            .ipv6 => |*bytes| bytes,
        };
    }
};

pub const Element = struct {
    timeout_ms: u64,
    expiration_ms: u64,
    has_comment: bool,
};

pub const Step = enum {
    open_socket,
    bind_socket,
    send,
    receive,
    batch_begin,
    table,
    guard_chain,
    relay_chain,
    set4,
    set6,
    conntrack_rule,
    loopback_rule,
    allowed4_rule,
    allowed6_rule,
    reject_rule,
    relay_rule,
    batch_end,
    element_add,
    element_read,
    chain_read,
    set_read,
    rule_read,

    fn ofInstallSequence(seq: u32) Step {
        return switch (seq) {
            0 => .batch_begin,
            1 => .table,
            2 => .guard_chain,
            3 => .relay_chain,
            4 => .set4,
            5 => .set6,
            6 => .conntrack_rule,
            7 => .loopback_rule,
            8 => .allowed4_rule,
            9 => .allowed6_rule,
            10 => .reject_rule,
            11 => .relay_rule,
            else => .batch_end,
        };
    }
};

pub const Diagnostic = struct {
    step: Step,
    errno: i32,

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const name = std.enums.fromInt(linux.E, self.errno);
        if (name) |e| {
            try writer.print("{t} at the {t} step", .{ e, self.step });
        } else {
            try writer.print("errno {d} at the {t} step", .{ self.errno, self.step });
        }
    }
};

pub const Error = error{
    KernelModuleMissing,
    NotPermitted,
    Refused,
    ExchangeFailed,
};

fn note(diag: ?*?Diagnostic, step: Step, errno: i32) void {
    if (diag) |slot| slot.* = .{ .step = step, .errno = errno };
}

fn classify(step: Step, errno: i32) Error {
    if (errno == @intFromEnum(linux.E.PERM) or errno == @intFromEnum(linux.E.ACCES)) return error.NotPermitted;
    if (errno == @intFromEnum(linux.E.OPNOTSUPP) or errno == @intFromEnum(linux.E.PROTONOSUPPORT)) return error.KernelModuleMissing;
    if (errno == @intFromEnum(linux.E.NOENT)) {
        return switch (step) {
            .guard_chain, .relay_chain, .conntrack_rule, .loopback_rule, .allowed4_rule, .allowed6_rule, .reject_rule, .relay_rule => error.KernelModuleMissing,
            else => error.Refused,
        };
    }
    return error.Refused;
}

pub const Session = struct {
    fd: i32,

    pub fn open(diag: ?*?Diagnostic) Error!Session {
        const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.NETFILTER);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |e| {
                note(diag, .open_socket, @intFromEnum(e));
                return classify(.open_socket, @intFromEnum(e));
            },
        }
        const fd: i32 = @intCast(rc);
        const me: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        switch (linux.errno(linux.bind(fd, @ptrCast(&me), @sizeOf(linux.sockaddr.nl)))) {
            .SUCCESS => {},
            else => |e| {
                _ = linux.close(fd);
                note(diag, .bind_socket, @intFromEnum(e));
                return classify(.bind_socket, @intFromEnum(e));
            },
        }
        return .{ .fd = fd };
    }

    pub fn close(self: Session) void {
        _ = linux.close(self.fd);
    }

    pub fn install(self: Session, diag: ?*?Diagnostic) Error!void {
        try self.send(&install_batch, .send, diag);
        try self.acknowledge(Step.ofInstallSequence, diag);
    }

    pub fn allow(self: Session, address: Address, timeout_ms: u64, diag: ?*?Diagnostic) Error!void {
        std.debug.assert(timeout_ms > 0);

        var buffer: [max_element_message]u8 = undefined;
        const length = buildElementBatch(&buffer, address, timeout_ms);
        try self.send(buffer[0..length], .element_add, diag);
        try self.acknowledge(elementAddStep, diag);
    }

    pub fn element(self: Session, address: Address, diag: ?*?Diagnostic) Error!?Element {
        var buffer: [max_element_message]u8 = undefined;
        const length = buildElementQuery(&buffer, address);
        try self.send(buffer[0..length], .element_read, diag);

        var reply: [reply_capacity]u8 = undefined;
        const filled = try self.receive(&reply, .element_read, diag);
        var messages = Messages{ .bytes = reply[0..filled] };
        while (messages.next()) |message| {
            if (message.kind == nlmsg_error) {
                const code = errorCode(message.body);
                if (code == @intFromEnum(linux.E.NOENT)) return null;
                if (code == 0) continue;
                note(diag, .element_read, code);
                return classify(.element_read, code);
            }
            if (message.kind != (subsys_nftables << 8) | msg_newsetelem) continue;
            var attributes = Attributes{ .bytes = message.payload() };
            while (attributes.next()) |attribute| {
                if (attribute.kind != nfta_set_elem_list_elements) continue;
                var list = Attributes{ .bytes = attribute.payload };
                while (list.next()) |entry| return readElement(entry.payload);
            }
        }
        return null;
    }

    fn send(self: Session, bytes: []const u8, step: Step, diag: ?*?Diagnostic) Error!void {
        const rc = linux.sendto(self.fd, bytes.ptr, bytes.len, 0, null, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |e| {
                note(diag, step, @intFromEnum(e));
                return error.ExchangeFailed;
            },
        }
        if (rc != bytes.len) {
            note(diag, step, 0);
            return error.ExchangeFailed;
        }
    }

    fn receive(self: Session, into: []u8, step: Step, diag: ?*?Diagnostic) Error!usize {
        const rc = linux.recvfrom(self.fd, into.ptr, into.len, 0, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => return rc,
            else => |e| {
                note(diag, step, @intFromEnum(e));
                return error.ExchangeFailed;
            },
        }
    }

    fn acknowledge(self: Session, stepOf: *const fn (u32) Step, diag: ?*?Diagnostic) Error!void {
        var reply: [reply_capacity]u8 = undefined;
        while (true) {
            const rc = linux.recvfrom(self.fd, &reply, reply.len, linux.MSG.DONTWAIT, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .AGAIN => return,
                else => |e| {
                    note(diag, .receive, @intFromEnum(e));
                    return error.ExchangeFailed;
                },
            }
            var messages = Messages{ .bytes = reply[0..rc] };
            while (messages.next()) |message| {
                if (message.kind != nlmsg_error) continue;
                const code = errorCode(message.body);
                if (code == 0) continue;
                const step = stepOf(message.sequence);
                note(diag, step, code);
                return classify(step, code);
            }
        }
    }
};

fn elementAddStep(sequence: u32) Step {
    return if (sequence == 0) .batch_begin else .element_add;
}

fn readElement(bytes: []const u8) Element {
    var found: Element = .{ .timeout_ms = 0, .expiration_ms = 0, .has_comment = false };
    var attributes = Attributes{ .bytes = bytes };
    while (attributes.next()) |attribute| {
        switch (attribute.kind) {
            nfta_set_elem_timeout => found.timeout_ms = readBe64(attribute.payload),
            nfta_set_elem_expiration => found.expiration_ms = readBe64(attribute.payload),
            nfta_set_elem_userdata => found.has_comment = true,
            else => {},
        }
    }
    return found;
}

const subsys_nftables: u16 = 10;
const nfnl_msg_batch_begin: u16 = 16;
const nfnl_msg_batch_end: u16 = 17;

const msg_newtable: u16 = 0;
const msg_newchain: u16 = 3;
const msg_getchain: u16 = 4;
const msg_newrule: u16 = 6;
const msg_getrule: u16 = 7;
const msg_newset: u16 = 9;
const msg_getset: u16 = 10;
const msg_newsetelem: u16 = 12;
const msg_getsetelem: u16 = 13;

const nlmsg_error: u16 = 2;
const nlmsg_done: u16 = 3;

const f_request: u16 = 0x001;
const f_ack: u16 = 0x004;
const f_create: u16 = 0x400;
const f_append: u16 = 0x800;
const f_dump: u16 = 0x300;

const nla_nested: u16 = 0x8000;
const nla_type_mask: u16 = 0x3fff;

const nfta_set_elem_list_table: u16 = 1;
const nfta_set_elem_list_set: u16 = 2;
const nfta_set_elem_list_elements: u16 = 3;
const nfta_list_elem: u16 = 1;

const nfta_set_elem_key: u16 = 1;
const nfta_set_elem_timeout: u16 = 4;
const nfta_set_elem_expiration: u16 = 5;
const nfta_set_elem_userdata: u16 = 6;
const nfta_data_value: u16 = 1;

const nfproto_inet: u8 = 1;
const nfproto_ipv4: u8 = 2;
const nfproto_ipv6: u8 = 10;
const ipproto_tcp: u8 = 6;

const Builder = struct {
    buf: []u8,
    len: usize = 0,

    fn put(b: *Builder, bytes: []const u8) void {
        @memcpy(b.buf[b.len..][0..bytes.len], bytes);
        b.len += bytes.len;
    }

    fn pad(b: *Builder) void {
        while (b.len % 4 != 0) : (b.len += 1) b.buf[b.len] = 0;
    }

    fn attribute(b: *Builder, kind: u16, payload: []const u8) void {
        const at = b.len;
        b.put(&[_]u8{0} ** 4);
        b.put(payload);
        std.mem.writeInt(u16, b.buf[at..][0..2], @intCast(4 + payload.len), .little);
        std.mem.writeInt(u16, b.buf[at + 2 ..][0..2], kind, .little);
        b.pad();
    }

    fn be32(b: *Builder, kind: u16, value: u32) void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        b.attribute(kind, &bytes);
    }

    fn be64(b: *Builder, kind: u16, value: u64) void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .big);
        b.attribute(kind, &bytes);
    }

    fn string(b: *Builder, kind: u16, text: []const u8) void {
        const at = b.len;
        b.put(&[_]u8{0} ** 4);
        b.put(text);
        b.put(&[_]u8{0});
        std.mem.writeInt(u16, b.buf[at..][0..2], @intCast(5 + text.len), .little);
        std.mem.writeInt(u16, b.buf[at + 2 ..][0..2], kind, .little);
        b.pad();
    }

    fn openNested(b: *Builder, kind: u16) usize {
        const at = b.len;
        b.put(&[_]u8{0} ** 4);
        std.mem.writeInt(u16, b.buf[at + 2 ..][0..2], kind | nla_nested, .little);
        return at;
    }

    fn closeNested(b: *Builder, at: usize) void {
        std.mem.writeInt(u16, b.buf[at..][0..2], @intCast(b.len - at), .little);
    }

    fn openMessage(b: *Builder, kind: u16, flags: u16, sequence: u32, family: u8, res_id: u16) usize {
        const at = b.len;
        b.put(&[_]u8{0} ** 16);
        std.mem.writeInt(u16, b.buf[at + 4 ..][0..2], kind, .little);
        std.mem.writeInt(u16, b.buf[at + 6 ..][0..2], flags, .little);
        std.mem.writeInt(u32, b.buf[at + 8 ..][0..4], sequence, .little);
        b.put(&[_]u8{ family, 0, 0, 0 });
        std.mem.writeInt(u16, b.buf[b.len - 2 ..][0..2], res_id, .big);
        return at;
    }

    fn closeMessage(b: *Builder, at: usize) void {
        std.mem.writeInt(u32, b.buf[at..][0..4], @intCast(b.len - at), .little);
    }

    fn batchBegin(b: *Builder, sequence: u32) void {
        const at = b.openMessage(nfnl_msg_batch_begin, f_request, sequence, 0, subsys_nftables);
        b.closeMessage(at);
    }

    fn batchEnd(b: *Builder, sequence: u32) void {
        const at = b.openMessage(nfnl_msg_batch_end, f_request, sequence, 0, subsys_nftables);
        b.closeMessage(at);
    }

    fn openChange(b: *Builder, message: u16, flags: u16, sequence: u32) usize {
        return b.openMessage((subsys_nftables << 8) | message, f_request | f_ack | flags, sequence, nfproto_inet, 0);
    }
};

fn openExpression(b: *Builder, name: []const u8) struct { usize, usize } {
    const entry = b.openNested(nfta_list_elem);
    b.string(1, name);
    const data = b.openNested(2);
    return .{ entry, data };
}

fn closeExpression(b: *Builder, marks: struct { usize, usize }) void {
    b.closeNested(marks[1]);
    b.closeNested(marks[0]);
}

fn metaLoad(b: *Builder, key: u32) void {
    const marks = openExpression(b, "meta");
    b.be32(2, key); // NFTA_META_KEY
    b.be32(1, 1); // NFTA_META_DREG, NFT_REG_1
    closeExpression(b, marks);
}

fn compare(b: *Builder, op: u32, value: []const u8) void {
    const marks = openExpression(b, "cmp");
    b.be32(1, 1); // NFTA_CMP_SREG
    b.be32(2, op); // NFTA_CMP_OP
    const data = b.openNested(3); // NFTA_CMP_DATA
    b.attribute(nfta_data_value, value);
    b.closeNested(data);
    closeExpression(b, marks);
}

fn immediateAccept(b: *Builder) void {
    const marks = openExpression(b, "immediate");
    b.be32(1, 0); // NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT
    const data = b.openNested(2); // NFTA_IMMEDIATE_DATA
    const verdict = b.openNested(2); // NFTA_DATA_VERDICT
    b.be32(1, 1); // NFTA_VERDICT_CODE, NF_ACCEPT
    b.closeNested(verdict);
    b.closeNested(data);
    closeExpression(b, marks);
}

fn payloadLoad(b: *Builder, offset: u32, length: u32) void {
    const marks = openExpression(b, "payload");
    b.be32(1, 1); // NFTA_PAYLOAD_DREG
    b.be32(2, 1); // NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER
    b.be32(3, offset);
    b.be32(4, length);
    closeExpression(b, marks);
}

fn setLookup(b: *Builder, name: []const u8, id: u32) void {
    const marks = openExpression(b, "lookup");
    b.be32(2, 1); // NFTA_LOOKUP_SREG
    b.string(1, name); // NFTA_LOOKUP_SET
    b.be32(4, id); // NFTA_LOOKUP_SET_ID, which names a set made in this batch
    closeExpression(b, marks);
}

fn openRule(b: *Builder, sequence: u32, chain: []const u8) struct { usize, usize } {
    const at = b.openChange(msg_newrule, f_create | f_append, sequence);
    b.string(1, table_name); // NFTA_RULE_TABLE
    b.string(2, chain); // NFTA_RULE_CHAIN
    const expressions = b.openNested(4); // NFTA_RULE_EXPRESSIONS
    return .{ at, expressions };
}

fn closeRule(b: *Builder, marks: struct { usize, usize }) void {
    b.closeNested(marks[1]);
    b.closeMessage(marks[0]);
}

const set4_id: u32 = 1;
const set6_id: u32 = 2;

fn buildInstall(buf: []u8) usize {
    var b = Builder{ .buf = buf };
    b.batchBegin(0);

    var at = b.openChange(msg_newtable, f_create, 1);
    b.string(1, table_name); // NFTA_TABLE_NAME
    b.be32(2, 0); // NFTA_TABLE_FLAGS
    b.closeMessage(at);

    at = b.openChange(msg_newchain, f_create, 2);
    b.string(1, table_name); // NFTA_CHAIN_TABLE
    b.string(3, guard_chain_name); // NFTA_CHAIN_NAME
    b.be32(5, guard_policy); // NFTA_CHAIN_POLICY
    b.string(7, "filter"); // NFTA_CHAIN_TYPE
    var hook = b.openNested(4); // NFTA_CHAIN_HOOK
    b.be32(1, hook_output);
    b.be32(2, @bitCast(guard_priority));
    b.closeNested(hook);
    b.closeMessage(at);

    at = b.openChange(msg_newchain, f_create, 3);
    b.string(1, table_name);
    b.string(3, relay_chain_name);
    b.string(7, "nat");
    hook = b.openNested(4);
    b.be32(1, hook_output);
    b.be32(2, @bitCast(relay_priority));
    b.closeNested(hook);
    b.closeMessage(at);

    at = b.openChange(msg_newset, f_create, 4);
    b.string(1, table_name); // NFTA_SET_TABLE
    b.string(2, set4_name); // NFTA_SET_NAME
    b.be32(3, 0x10); // NFTA_SET_FLAGS, NFT_SET_TIMEOUT
    b.be32(4, 7); // NFTA_SET_KEY_TYPE, which nft reads back as ipv4_addr
    b.be32(5, 4); // NFTA_SET_KEY_LEN
    b.be32(10, set4_id); // NFTA_SET_ID
    b.be64(11, default_timeout_ms); // NFTA_SET_TIMEOUT
    b.closeMessage(at);

    at = b.openChange(msg_newset, f_create, 5);
    b.string(1, table_name);
    b.string(2, set6_name);
    b.be32(3, 0x10);
    b.be32(4, 8); // ipv6_addr
    b.be32(5, 16);
    b.be32(10, set6_id);
    b.be64(11, default_timeout_ms);
    b.closeMessage(at);

    var rule = openRule(&b, 6, guard_chain_name);
    {
        const marks = openExpression(&b, "ct");
        b.be32(2, 0); // NFTA_CT_KEY, NFT_CT_STATE
        b.be32(1, 1); // NFTA_CT_DREG
        closeExpression(&b, marks);
    }
    {
        const marks = openExpression(&b, "bitwise");
        b.be32(1, 1); // NFTA_BITWISE_SREG
        b.be32(2, 1); // NFTA_BITWISE_DREG
        b.be32(3, 4); // NFTA_BITWISE_LEN
        const mask = b.openNested(4);
        b.attribute(nfta_data_value, &[_]u8{ 6, 0, 0, 0 }); // ESTABLISHED | RELATED
        b.closeNested(mask);
        const xor = b.openNested(5);
        b.attribute(nfta_data_value, &[_]u8{ 0, 0, 0, 0 });
        b.closeNested(xor);
        closeExpression(&b, marks);
    }
    compare(&b, 1, &[_]u8{ 0, 0, 0, 0 }); // NFT_CMP_NEQ
    immediateAccept(&b);
    closeRule(&b, rule);

    rule = openRule(&b, 7, guard_chain_name);
    metaLoad(&b, 5); // NFT_META_OIF
    compare(&b, 0, &[_]u8{ 1, 0, 0, 0 });
    immediateAccept(&b);
    closeRule(&b, rule);

    rule = openRule(&b, 8, guard_chain_name);
    metaLoad(&b, 15); // NFT_META_NFPROTO
    compare(&b, 0, &[_]u8{nfproto_ipv4});
    payloadLoad(&b, 16, 4); // the destination in an IPv4 header
    setLookup(&b, set4_name, set4_id);
    immediateAccept(&b);
    closeRule(&b, rule);

    rule = openRule(&b, 9, guard_chain_name);
    metaLoad(&b, 15);
    compare(&b, 0, &[_]u8{nfproto_ipv6});
    payloadLoad(&b, 24, 16); // the destination in an IPv6 header
    setLookup(&b, set6_name, set6_id);
    immediateAccept(&b);
    closeRule(&b, rule);

    rule = openRule(&b, 10, guard_chain_name);
    {
        const marks = openExpression(&b, "reject");
        b.be32(1, 2); // NFTA_REJECT_TYPE, NFT_REJECT_ICMPX_UNREACH
        b.attribute(2, &[_]u8{1}); // NFT_REJECT_ICMPX_PORT_UNREACH
        closeExpression(&b, marks);
    }
    closeRule(&b, rule);

    rule = openRule(&b, 11, relay_chain_name);
    metaLoad(&b, 16); // NFT_META_L4PROTO
    compare(&b, 0, &[_]u8{ipproto_tcp});
    {
        const marks = openExpression(&b, "immediate");
        b.be32(1, 1); // NFTA_IMMEDIATE_DREG, NFT_REG_1
        const data = b.openNested(2);
        var port: [2]u8 = undefined;
        std.mem.writeInt(u16, &port, relay_port, .big);
        b.attribute(nfta_data_value, &port);
        b.closeNested(data);
        closeExpression(&b, marks);
    }
    {
        const marks = openExpression(&b, "redir");
        b.be32(1, 1); // NFTA_REDIR_REG_PROTO_MIN, the register holding the port
        b.be32(3, 2); // NF_NAT_RANGE_PROTO_SPECIFIED
        closeExpression(&b, marks);
    }
    closeRule(&b, rule);

    b.batchEnd(12);
    return b.len;
}

const install_batch = build: {
    @setEvalBranchQuota(100_000);
    var buffer: [4096]u8 = @splat(0);
    const length = buildInstall(&buffer);
    const bytes: [length]u8 = buffer[0..length].*;
    break :build bytes;
};

const max_element_message = 256;
const reply_capacity = 8192;

fn buildElementBatch(buf: []u8, address: Address, timeout_ms: u64) usize {
    var b = Builder{ .buf = buf };
    b.batchBegin(0);
    const at = b.openChange(msg_newsetelem, f_create, 1);
    b.string(nfta_set_elem_list_table, table_name);
    b.string(nfta_set_elem_list_set, address.setName());
    const elements = b.openNested(nfta_set_elem_list_elements);
    const entry = b.openNested(nfta_list_elem);
    const key = b.openNested(nfta_set_elem_key);
    b.attribute(nfta_data_value, address.key());
    b.closeNested(key);
    b.be64(nfta_set_elem_timeout, timeout_ms);
    b.closeNested(entry);
    b.closeNested(elements);
    b.closeMessage(at);
    b.batchEnd(2);
    return b.len;
}

fn buildElementQuery(buf: []u8, address: Address) usize {
    var b = Builder{ .buf = buf };
    const at = b.openMessage((subsys_nftables << 8) | msg_getsetelem, f_request, 0, nfproto_inet, 0);
    b.string(nfta_set_elem_list_table, table_name);
    b.string(nfta_set_elem_list_set, address.setName());
    const elements = b.openNested(nfta_set_elem_list_elements);
    const entry = b.openNested(nfta_list_elem);
    const key = b.openNested(nfta_set_elem_key);
    b.attribute(nfta_data_value, address.key());
    b.closeNested(key);
    b.closeNested(entry);
    b.closeNested(elements);
    b.closeMessage(at);
    return b.len;
}

const Message = struct {
    kind: u16,
    sequence: u32,
    body: []const u8,

    fn payload(self: Message) []const u8 {
        if (self.body.len < 4) return self.body[0..0];
        return self.body[4..];
    }
};

const Messages = struct {
    bytes: []const u8,
    at: usize = 0,

    fn next(self: *Messages) ?Message {
        if (self.at + 16 > self.bytes.len) return null;
        const length = std.mem.readInt(u32, self.bytes[self.at..][0..4], .little);
        if (length < 16 or self.at + length > self.bytes.len) return null;
        const message = Message{
            .kind = std.mem.readInt(u16, self.bytes[self.at + 4 ..][0..2], .little),
            .sequence = std.mem.readInt(u32, self.bytes[self.at + 8 ..][0..4], .little),
            .body = self.bytes[self.at + 16 .. self.at + length],
        };
        self.at += (length + 3) & ~@as(usize, 3);
        return message;
    }
};

const Attribute = struct {
    kind: u16,
    payload: []const u8,
};

const Attributes = struct {
    bytes: []const u8,
    at: usize = 0,

    fn next(self: *Attributes) ?Attribute {
        if (self.at + 4 > self.bytes.len) return null;
        const length = std.mem.readInt(u16, self.bytes[self.at..][0..2], .little);
        const kind = std.mem.readInt(u16, self.bytes[self.at + 2 ..][0..2], .little);
        if (length < 4 or self.at + length > self.bytes.len) return null;
        const found = Attribute{
            .kind = kind & nla_type_mask,
            .payload = self.bytes[self.at + 4 .. self.at + length],
        };
        self.at += (length + 3) & ~@as(usize, 3);
        return found;
    }

    fn find(self: Attributes, kind: u16) ?[]const u8 {
        var walk = self;
        while (walk.next()) |attribute| {
            if (attribute.kind == kind) return attribute.payload;
        }
        return null;
    }
};

fn errorCode(body: []const u8) i32 {
    if (body.len < 4) return 0;
    const signed = std.mem.readInt(i32, body[0..4], .little);
    return if (signed < 0) -signed else signed;
}

fn readBe32(bytes: []const u8) u32 {
    if (bytes.len < 4) return 0;
    return std.mem.readInt(u32, bytes[0..4], .big);
}

fn readBe64(bytes: []const u8) u64 {
    if (bytes.len < 8) return 0;
    return std.mem.readInt(u64, bytes[0..8], .big);
}

const ChainFacts = struct {
    hook: u32,
    priority: i32,
    policy: u32,
    type_name: [8]u8,
};

fn chainFacts(session: Session, name: []const u8, diag: ?*?Diagnostic) Error!?ChainFacts {
    var buffer: [max_element_message]u8 = undefined;
    var b = Builder{ .buf = &buffer };
    const at = b.openMessage((subsys_nftables << 8) | msg_getchain, f_request, 0, nfproto_inet, 0);
    b.string(1, table_name); // NFTA_CHAIN_TABLE
    b.string(3, name); // NFTA_CHAIN_NAME
    b.closeMessage(at);
    try session.send(b.buf[0..b.len], .chain_read, diag);

    var reply: [reply_capacity]u8 = undefined;
    const filled = try session.receive(&reply, .chain_read, diag);
    var messages = Messages{ .bytes = reply[0..filled] };
    while (messages.next()) |message| {
        if (message.kind == nlmsg_error) {
            const code = errorCode(message.body);
            if (code == 0) continue;
            note(diag, .chain_read, code);
            return classify(.chain_read, code);
        }
        const attributes = Attributes{ .bytes = message.payload() };
        var found = ChainFacts{ .hook = 0, .priority = 0, .policy = 0, .type_name = @splat(0) };
        if (attributes.find(4)) |hook| { // NFTA_CHAIN_HOOK
            const inside = Attributes{ .bytes = hook };
            if (inside.find(1)) |number| found.hook = readBe32(number);
            if (inside.find(2)) |priority| found.priority = @bitCast(readBe32(priority));
        }
        if (attributes.find(5)) |policy| found.policy = readBe32(policy);
        if (attributes.find(7)) |text| {
            const wanted = @min(text.len, found.type_name.len);
            @memcpy(found.type_name[0..wanted], text[0..wanted]);
        }
        return found;
    }
    return null;
}

const SetFacts = struct {
    flags: u32,
    key_len: u32,
    timeout_ms: u64,
};

fn setFacts(session: Session, name: []const u8, diag: ?*?Diagnostic) Error!?SetFacts {
    var buffer: [max_element_message]u8 = undefined;
    var b = Builder{ .buf = &buffer };
    const at = b.openMessage((subsys_nftables << 8) | msg_getset, f_request, 0, nfproto_inet, 0);
    b.string(1, table_name); // NFTA_SET_TABLE
    b.string(2, name); // NFTA_SET_NAME
    b.closeMessage(at);
    try session.send(b.buf[0..b.len], .set_read, diag);

    var reply: [reply_capacity]u8 = undefined;
    const filled = try session.receive(&reply, .set_read, diag);
    var messages = Messages{ .bytes = reply[0..filled] };
    while (messages.next()) |message| {
        if (message.kind == nlmsg_error) {
            const code = errorCode(message.body);
            if (code == 0) continue;
            note(diag, .set_read, code);
            return classify(.set_read, code);
        }
        const attributes = Attributes{ .bytes = message.payload() };
        return .{
            .flags = if (attributes.find(3)) |bytes| readBe32(bytes) else 0,
            .key_len = if (attributes.find(5)) |bytes| readBe32(bytes) else 0,
            .timeout_ms = if (attributes.find(11)) |bytes| readBe64(bytes) else 0,
        };
    }
    return null;
}

fn ruleShape(session: Session, chain: []const u8, into: []u8, diag: ?*?Diagnostic) Error!usize {
    var buffer: [max_element_message]u8 = undefined;
    var b = Builder{ .buf = &buffer };
    const at = b.openMessage((subsys_nftables << 8) | msg_getrule, f_request | f_dump, 0, nfproto_inet, 0);
    b.string(1, table_name); // NFTA_RULE_TABLE
    b.string(2, chain); // NFTA_RULE_CHAIN
    b.closeMessage(at);
    try session.send(b.buf[0..b.len], .rule_read, diag);

    var written: usize = 0;
    var rules: usize = 0;
    var reply: [reply_capacity]u8 = undefined;
    var datagrams: usize = 0;
    while (datagrams < 64) : (datagrams += 1) {
        const filled = try session.receive(&reply, .rule_read, diag);
        var messages = Messages{ .bytes = reply[0..filled] };
        while (messages.next()) |message| {
            if (message.kind == nlmsg_done) return written;
            if (message.kind == nlmsg_error) {
                const code = errorCode(message.body);
                if (code == 0) continue;
                note(diag, .rule_read, code);
                return classify(.rule_read, code);
            }
            const attributes = Attributes{ .bytes = message.payload() };
            const expressions = attributes.find(4) orelse continue; // NFTA_RULE_EXPRESSIONS
            if (rules > 0) written += append(into[written..], ";");
            rules += 1;
            var list = Attributes{ .bytes = expressions };
            var first = true;
            while (list.next()) |entry| {
                const inside = Attributes{ .bytes = entry.payload };
                const name = inside.find(1) orelse continue; // NFTA_EXPR_NAME
                if (!first) written += append(into[written..], ",");
                first = false;
                written += append(into[written..], std.mem.sliceTo(name, 0));
            }
        }
    }
    note(diag, .rule_read, 0);
    return error.ExchangeFailed;
}

fn append(into: []u8, text: []const u8) usize {
    const wanted = @min(into.len, text.len);
    @memcpy(into[0..wanted], text[0..wanted]);
    return wanted;
}

const testing = std.testing;

const Measurement = extern struct {
    failed_step: u32,
    failed_errno: i32,

    guard_hook: u32,
    guard_priority: i32,
    guard_policy: u32,
    guard_type: [8]u8,

    relay_hook: u32,
    relay_priority: i32,
    relay_policy: u32,
    relay_type: [8]u8,

    set4_flags: u32,
    set4_key_len: u32,
    set4_timeout_ms: u64,
    set6_flags: u32,
    set6_key_len: u32,
    set6_timeout_ms: u64,

    element_found: u32,
    element_has_comment: u32,
    element_timeout_ms: u64,
    element_expiration_ms: u64,

    shape_len: u32,
    shape: [384]u8,

    const no_failure: u32 = 0xffff_ffff;
};

const probe_address = Address{ .ipv4 = .{ 10, 1, 2, 3 } };
const probe_timeout_ms: u64 = 45_000;

const expected_shape =
    "ct,bitwise,cmp,immediate" ++
    ";meta,cmp,immediate" ++
    ";meta,cmp,payload,lookup,immediate" ++
    ";meta,cmp,payload,lookup,immediate" ++
    ";reject" ++
    "|meta,cmp,immediate,redir";

fn measureInChild(record: *Measurement) void {
    record.* = std.mem.zeroes(Measurement);
    record.failed_step = Measurement.no_failure;

    var diag: ?Diagnostic = null;
    const session = Session.open(&diag) catch {
        recordFailure(record, diag);
        return;
    };
    defer session.close();

    session.install(&diag) catch {
        recordFailure(record, diag);
        return;
    };
    session.allow(probe_address, probe_timeout_ms, &diag) catch {
        recordFailure(record, diag);
        return;
    };

    if (session.element(probe_address, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |found| {
        record.element_found = 1;
        record.element_has_comment = @intFromBool(found.has_comment);
        record.element_timeout_ms = found.timeout_ms;
        record.element_expiration_ms = found.expiration_ms;
    }

    if (chainFacts(session, guard_chain_name, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.guard_hook = facts.hook;
        record.guard_priority = facts.priority;
        record.guard_policy = facts.policy;
        record.guard_type = facts.type_name;
    }
    if (chainFacts(session, relay_chain_name, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.relay_hook = facts.hook;
        record.relay_priority = facts.priority;
        record.relay_policy = facts.policy;
        record.relay_type = facts.type_name;
    }

    if (setFacts(session, set4_name, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.set4_flags = facts.flags;
        record.set4_key_len = facts.key_len;
        record.set4_timeout_ms = facts.timeout_ms;
    }
    if (setFacts(session, set6_name, &diag) catch {
        recordFailure(record, diag);
        return;
    }) |facts| {
        record.set6_flags = facts.flags;
        record.set6_key_len = facts.key_len;
        record.set6_timeout_ms = facts.timeout_ms;
    }

    var used = ruleShape(session, guard_chain_name, &record.shape, &diag) catch {
        recordFailure(record, diag);
        return;
    };
    used += append(record.shape[used..], "|");
    used += ruleShape(session, relay_chain_name, record.shape[used..], &diag) catch {
        recordFailure(record, diag);
        return;
    };
    record.shape_len = @intCast(used);
}

fn recordFailure(record: *Measurement, diag: ?Diagnostic) void {
    if (diag) |d| {
        record.failed_step = @intFromEnum(d.step);
        record.failed_errno = d.errno;
    } else {
        record.failed_step = @intFromEnum(Step.send);
    }
}

fn measure() error{ChildCrashed}!?Measurement {
    if (builtin.os.tag != .linux) return null;
    if (!namespace.probeAvailability().available()) return null;

    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) return null;

    const child = linux.fork();
    if (linux.errno(child) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return null;
    }

    if (child == 0) {
        _ = linux.close(fds[0]);
        var record: Measurement = undefined;
        if (namespace.enter(.{}, null)) |_| {
            measureInChild(&record);
            const bytes = std.mem.asBytes(&record);
            _ = linux.write(fds[1], bytes.ptr, bytes.len);
        } else |_| {}
        std.process.exit(0);
    }

    _ = linux.close(fds[1]);
    var record: Measurement = undefined;
    const bytes = std.mem.asBytes(&record);
    var filled: usize = 0;
    while (filled < bytes.len) {
        const rc = linux.read(fds[0], bytes.ptr + filled, bytes.len - filled);
        if (linux.errno(rc) != .SUCCESS) break;
        if (rc == 0) break;
        filled += rc;
    }
    _ = linux.close(fds[0]);
    var status: u32 = 0;
    _ = linux.waitpid(@intCast(child), &status, 0);

    if (status != 0) return error.ChildCrashed;
    if (filled != bytes.len) return null;
    return record;
}

fn measuredNothing(record: Measurement) bool {
    if (record.failed_step == Measurement.no_failure) return false;
    const step = std.enums.fromInt(Step, record.failed_step) orelse return false;
    return switch (step) {
        .open_socket, .batch_begin => true,
        else => false,
    };
}

fn shapeOf(record: *const Measurement) []const u8 {
    return record.shape[0..@min(record.shape_len, record.shape.len)];
}

test "the install batch is the pinned byte sequence" {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&install_batch, &digest, .{});

    try testing.expectEqual(@as(usize, 1688), install_batch.len);
    try testing.expectEqualSlices(
        u8,
        &@as([32]u8, .{
            0x98, 0xca, 0x40, 0x85, 0x32, 0xc5, 0x86, 0x15,
            0xb0, 0x05, 0x9f, 0x0c, 0xcc, 0xdb, 0x44, 0xd9,
            0xa8, 0xd2, 0xff, 0x25, 0x2c, 0x8b, 0xc3, 0x6c,
            0xc7, 0x4d, 0xbc, 0x40, 0x7b, 0xed, 0x14, 0x4c,
        }),
        &digest,
    );
}

test "the batch opens and closes exactly one nfnetlink transaction" {
    var messages = Messages{ .bytes = &install_batch };
    var first: ?u16 = null;
    var last: ?u16 = null;
    var count: usize = 0;
    while (messages.next()) |message| {
        if (first == null) first = message.kind;
        last = message.kind;
        try testing.expectEqual(@as(u32, @intCast(count)), message.sequence);
        count += 1;
    }
    try testing.expectEqual(@as(?u16, nfnl_msg_batch_begin), first);
    try testing.expectEqual(@as(?u16, nfnl_msg_batch_end), last);
    try testing.expectEqual(@as(usize, 13), count);
}

test "every change in the batch asks for an acknowledgement" {
    var messages = Messages{ .bytes = &install_batch };
    var acknowledged: usize = 0;
    var at: usize = 0;
    while (messages.next()) |message| {
        const flags = std.mem.readInt(u16, install_batch[at + 6 ..][0..2], .little);
        at = messages.at;
        if (message.kind == nfnl_msg_batch_begin or message.kind == nfnl_msg_batch_end) {
            try testing.expectEqual(@as(u16, 0), flags & f_ack);
            continue;
        }
        try testing.expectEqual(f_ack, flags & f_ack);
        acknowledged += 1;
    }
    try testing.expectEqual(@as(usize, 11), acknowledged);
}

test "a set element carries its timeout in attribute 4 and never in 6" {
    try testing.expectEqual(@as(u16, 4), nfta_set_elem_timeout);
    try testing.expectEqual(@as(u16, 6), nfta_set_elem_userdata);

    var buffer: [max_element_message]u8 = undefined;
    const length = buildElementBatch(&buffer, probe_address, probe_timeout_ms);
    var messages = Messages{ .bytes = buffer[0..length] };
    _ = messages.next(); // the batch begin
    const change = messages.next() orelse return error.TestUnexpectedResult;
    const attributes = Attributes{ .bytes = change.payload() };
    const elements = attributes.find(nfta_set_elem_list_elements) orelse return error.TestUnexpectedResult;
    var list = Attributes{ .bytes = elements };
    const entry = list.next() orelse return error.TestUnexpectedResult;
    const inside = Attributes{ .bytes = entry.payload };

    const timeout = inside.find(nfta_set_elem_timeout) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(probe_timeout_ms, readBe64(timeout));
    try testing.expectEqual(@as(?[]const u8, null), inside.find(nfta_set_elem_userdata));
}

test "install reads back the ruleset it wrote" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.failed_step);

    try testing.expectEqualStrings("filter", std.mem.sliceTo(&record.guard_type, 0));
    try testing.expectEqualStrings("nat", std.mem.sliceTo(&record.relay_type, 0));
    try testing.expectEqual(@as(u32, 0), record.guard_policy);
    try testing.expectEqual(@as(u32, 1), record.relay_policy);

    try testing.expectEqual(@as(u32, 0x10), record.set4_flags);
    try testing.expectEqual(@as(u32, 4), record.set4_key_len);
    try testing.expectEqual(default_timeout_ms, record.set4_timeout_ms);
    try testing.expectEqual(@as(u32, 0x10), record.set6_flags);
    try testing.expectEqual(@as(u32, 16), record.set6_key_len);
    try testing.expectEqual(default_timeout_ms, record.set6_timeout_ms);

    try testing.expectEqualStrings(expected_shape, shapeOf(&record));
}

test "the two chains keep the priorities the ordering depends on" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.failed_step);

    try testing.expectEqual(hook_output, record.guard_hook);
    try testing.expectEqual(hook_output, record.relay_hook);

    try testing.expectEqual(@as(i32, -150), record.guard_priority);
    try testing.expectEqual(@as(i32, -100), record.relay_priority);
    try testing.expect(record.guard_priority < record.relay_priority);
}

test "allow stores a timeout the kernel gives back as a timeout" {
    const record = try measure() orelse return error.SkipZigTest;
    if (measuredNothing(record)) return error.SkipZigTest;
    try testing.expectEqual(Measurement.no_failure, record.failed_step);

    try testing.expectEqual(@as(u32, 1), record.element_found);
    try testing.expectEqual(probe_timeout_ms, record.element_timeout_ms);
    try testing.expect(record.element_timeout_ms != default_timeout_ms);
    try testing.expectEqual(@as(u32, 0), record.element_has_comment);
    try testing.expect(record.element_expiration_ms <= probe_timeout_ms);
    try testing.expect(record.element_expiration_ms > probe_timeout_ms / 2);
}

test "an address that was never allowed is absent rather than an error" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var buffer: [max_element_message]u8 = undefined;
    const length = buildElementQuery(&buffer, .{ .ipv6 = .{0xff} ** 16 });
    var messages = Messages{ .bytes = buffer[0..length] };
    const query = messages.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqual((subsys_nftables << 8) | msg_getsetelem, query.kind);
    const attributes = Attributes{ .bytes = query.payload() };
    const set = attributes.find(nfta_set_elem_list_set) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings(set6_name, std.mem.sliceTo(set, 0));
}

test "an absent kernel module is told apart from a refusal and from a bug" {
    try testing.expectEqual(error.KernelModuleMissing, classify(.batch_begin, @intFromEnum(linux.E.OPNOTSUPP)));
    try testing.expectEqual(error.KernelModuleMissing, classify(.open_socket, @intFromEnum(linux.E.PROTONOSUPPORT)));
    try testing.expectEqual(error.KernelModuleMissing, classify(.relay_rule, @intFromEnum(linux.E.NOENT)));
    try testing.expectEqual(error.KernelModuleMissing, classify(.relay_chain, @intFromEnum(linux.E.NOENT)));

    try testing.expectEqual(error.NotPermitted, classify(.batch_begin, @intFromEnum(linux.E.PERM)));

    try testing.expectEqual(error.Refused, classify(.table, @intFromEnum(linux.E.NOENT)));
    try testing.expectEqual(error.Refused, classify(.element_add, @intFromEnum(linux.E.NOENT)));
    try testing.expectEqual(error.Refused, classify(.set4, @intFromEnum(linux.E.INVAL)));
}

test "a refusal names the message the kernel would not take" {
    try testing.expectEqual(Step.batch_begin, Step.ofInstallSequence(0));
    try testing.expectEqual(Step.table, Step.ofInstallSequence(1));
    try testing.expectEqual(Step.guard_chain, Step.ofInstallSequence(2));
    try testing.expectEqual(Step.relay_chain, Step.ofInstallSequence(3));
    try testing.expectEqual(Step.set4, Step.ofInstallSequence(4));
    try testing.expectEqual(Step.set6, Step.ofInstallSequence(5));
    try testing.expectEqual(Step.reject_rule, Step.ofInstallSequence(10));
    try testing.expectEqual(Step.relay_rule, Step.ofInstallSequence(11));
    try testing.expectEqual(Step.batch_end, Step.ofInstallSequence(12));
}

test "an address picks its own set and carries its own key width" {
    const four = Address{ .ipv4 = .{ 192, 0, 2, 1 } };
    const six = Address{ .ipv6 = .{0x20} ++ .{0} ** 15 };
    try testing.expectEqualStrings(set4_name, four.setName());
    try testing.expectEqualStrings(set6_name, six.setName());
    try testing.expectEqual(@as(usize, 4), four.key().len);
    try testing.expectEqual(@as(usize, 16), six.key().len);
}
