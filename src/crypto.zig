const std = @import("std");

pub const KEY_SIZE = 32;
pub const SALT_SIZE = 16;
pub const NONCE_SIZE = 24;
pub const MAC_SIZE = 16;

const Cipher = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

const argon2_params = std.crypto.pwhash.argon2.Params.interactive_2i;

pub fn deriveKey(io: std.Io, password: []const u8, salt: [SALT_SIZE]u8) ![KEY_SIZE]u8 {
    var key: [KEY_SIZE]u8 = undefined;
    const allocator = std.heap.page_allocator;

    try std.crypto.pwhash.argon2.kdf(allocator, &key, password, &salt, argon2_params, .argon2i, io);

    return key;
}

pub fn generateRandomBytes(io: std.Io, comptime size: usize) [size]u8 {
    var buffer: [size]u8 = undefined;

    const rand_source: std.Random.IoSource = .{ .io = io };
    const rand = rand_source.interface();
    for (&buffer) |*c| c.* = rand.int(u8);

    return buffer;
}
