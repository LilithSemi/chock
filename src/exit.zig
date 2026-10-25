pub const Exit = enum(u8) {
    finished = 0,
    usage = 1,
    faulted = 2,
    refused = 3,
    turn_limit = 4,
    not_implemented = 5,
    no_progress = 6,
    budget = 7,
    handed_over = 8,
    audit_gap = 9,
    empty_response = 10,
    model_refused = 11,
    rate_limited = 12,

    pub fn code(self: Exit) u8 {
        return @backingInt(self);
    }
};
