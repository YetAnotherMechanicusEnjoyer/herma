const std = @import("std");
const StringError = @import("string").StringError;

const ProcessError = error{
    BadUsage,
};

const InputError = error{
    EmptyInput,
};

const VaultError = error{
    InvalidFormat,
    UnsupportedVersion,
};

pub const HermaError = ProcessError || StringError || InputError || VaultError;
