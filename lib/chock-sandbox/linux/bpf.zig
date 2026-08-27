const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

/// One classic BPF instruction. The kernel reads this layout directly.
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
        // A classic BPF program has a hard limit of 4096 instructions.
        std.debug.assert(insns.len > 0);
        std.debug.assert(insns.len <= 4096);
        return .{ .len = @intCast(insns.len), .filter = insns.ptr };
    }
};

// The instruction classes and modes that this filter needs.
// BPF_LD | BPF_W | BPF_ABS
pub const LD_W_ABS: u16 = 0x00 | 0x00 | 0x20;
// BPF_JMP | BPF_JEQ | BPF_K
pub const JMP_JEQ_K: u16 = 0x05 | 0x10 | 0x00;
// BPF_JMP | BPF_JGE | BPF_K
pub const JMP_JGE_K: u16 = 0x05 | 0x30 | 0x00;
// BPF_JMP | BPF_JA
pub const JMP_JA: u16 = 0x05 | 0x00;
// BPF_ALU | BPF_AND | BPF_K
pub const ALU_AND_K: u16 = 0x04 | 0x50 | 0x00;
// BPF_RET | BPF_K
pub const RET_K: u16 = 0x06 | 0x00;

/// An instruction with no jump.
pub fn stmt(code: u16, k: u32) Insn {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

/// A comparison. `jt` is the offset to take when true. `jf` is the offset when false.
/// Both offsets count instructions from the one after this instruction.
pub fn jump(code: u16, k: u32, jt: u8, jf: u8) Insn {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

// The layout of `struct seccomp_data`:
//   int   nr;                       offset 0
//   __u32 arch;                     offset 4
//   __u64 instruction_pointer;      offset 8
//   __u64 args[6];                  offset 16
pub const offset_of_nr: u32 = 0;
pub const offset_of_arch: u32 = 4;

/// The offset of the low 32 bits of one argument.
/// A classic BPF program loads 32 bits at a time, so a 64 bit argument is two loads.
/// The low half is first on a little endian machine and second on a big endian machine.
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
    // seccomp_data is nr, arch, instruction_pointer, then six arguments of eight bytes.
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
