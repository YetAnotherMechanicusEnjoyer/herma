const std = @import("std");
const StringError = @import("string").StringError;

const ProcessError = error{
    BadUsage,
};

const InputError = error{
    EmptyInput,
};

pub const HermaError = ProcessError || StringError || InputError;
