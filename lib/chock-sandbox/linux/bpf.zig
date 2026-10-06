const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

pub const Insn = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

/// The header that `seccomp(SET_MODE_FILTER, ...)` takes.
pub const Prog = extern struct {
    len: u16,
    filter: [*]const Insn,

    pub fn init(insns: []const Insn) Prog {
        // Classic BPF has a hard limit of 4096 instructions.
        std.debug.assert(insns.len > 0);
        std.debug.assert(insns.len <= 4096);
        return .{ .len = @intCast(insns.len), .filter = insns.ptr };
    }
};

pub const LD_W_ABS: u16 = 0x00 | 0x00 | 0x20;
pub const JMP_JEQ_K: u16 = 0x05 | 0x10 | 0x00;
pub const JMP_JGE_K: u16 = 0x05 | 0x30 | 0x00;
pub const JMP_JA: u16 = 0x05 | 0x00;
pub const ALU_AND_K: u16 = 0x04 | 0x50 | 0x00;
pub const RET_K: u16 = 0x06 | 0x00;

pub fn stmt(code: u16, k: u32) Insn {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

/// `jt` and `jf` are jump offsets, counted from the instruction after this one.
pub fn jump(code: u16, k: u32, jt: u8, jf: u8) Insn {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

// struct seccomp_data: nr at 0, arch at 4, args start at 16.
pub const offset_of_nr: u32 = 0;
pub const offset_of_arch: u32 = 4;

// A 64 bit argument is two 32 bit loads; the low half's position depends on endianness.
pub fn offsetOfArgLow(index: u32) u32 {
    std.debug.assert(index < 6);
    const base = 16 + index * 8;
    return switch (native_endian) {
        .little => base,
        .big => base + 4,
    };
}

test "an Insn is the eight byte layout the kernel expects" {
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(Insn));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(Insn, "code"));
    try std.testing.expectEqual(@as(usize, 2), @offsetOf(Insn, "jt"));
    try std.testing.expectEqual(@as(usize, 3), @offsetOf(Insn, "jf"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(Insn, "k"));
}

test "stmt sets the jump fields to zero and jump keeps them" {
    const s = stmt(LD_W_ABS, 4);
    try std.testing.expectEqual(@as(u8, 0), s.jt);
    try std.testing.expectEqual(@as(u8, 0), s.jf);
    try std.testing.expectEqual(@as(u32, 4), s.k);

    const j = jump(JMP_JEQ_K, 117, 2, 5);
    try std.testing.expectEqual(@as(u8, 2), j.jt);
    try std.testing.expectEqual(@as(u8, 5), j.jf);
    try std.testing.expectEqual(@as(u32, 117), j.k);
}

test "the argument offsets follow the seccomp_data layout" {
    try std.testing.expectEqual(@as(u32, 0), offset_of_nr);
    try std.testing.expectEqual(@as(u32, 4), offset_of_arch);
    try std.testing.expectEqual(@as(u32, 16), offsetOfArgLow(0));
    try std.testing.expectEqual(@as(u32, 32), offsetOfArgLow(2));
}

test "a Prog reports the instruction count that the kernel needs" {
    var insns = [_]Insn{
        stmt(LD_W_ABS, offset_of_nr),
        stmt(RET_K, 0x7fff0000),
    };
    const prog = Prog.init(&insns);
    try std.testing.expectEqual(@as(u16, 2), prog.len);
}
