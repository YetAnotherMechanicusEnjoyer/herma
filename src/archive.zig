const std = @import("std");

const crypto = @import("crypto.zig");
const HermaError = @import("error.zig").HermaError;
const vault = @import("vault.zig");

const CHUNK_SIZE = 64 * 1024;
const Cipher = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const VaultWriter = struct {
    io: std.Io,
    file: std.Io.File,
    key: [crypto.KEY_SIZE]u8,
    base_nonce: [crypto.NONCE_SIZE]u8,
    chunk_counter: u64 = 0,

    buffer: [CHUNK_SIZE]u8 = undefined,
    buffer_pos: usize = 0,

    pub fn init(io: std.Io, file: std.Io.File, key: [crypto.KEY_SIZE]u8, nonce: [crypto.NONCE_SIZE]u8) VaultWriter {
        return .{
            .io = io,
            .file = file,
            .key = key,
            .base_nonce = nonce,
        };
    }

    pub fn write(self: *VaultWriter, bytes: []const u8) !void {
        var index: usize = 0;

        while (index < bytes.len) {
            const available = CHUNK_SIZE - self.buffer_pos;
            const n = @min(available, bytes.len - index);

            @memcpy(self.buffer[self.buffer_pos .. self.buffer_pos + n], bytes[index .. index + n]);

            self.buffer_pos += n;
            index += n;

            if (self.buffer_pos == CHUNK_SIZE) {
                try self.flush();
            }
        }
    }

    pub fn flush(self: *VaultWriter) !void {
        if (self.buffer_pos == 0) return;

        var nonce = self.base_nonce;
        const counter = std.mem.toBytes(self.chunk_counter);

        for (counter, 0..) |b, i| nonce[i] ^= b;

        var ciphertext: [CHUNK_SIZE]u8 = undefined;
        var tag: [crypto.MAC_SIZE]u8 = undefined;

        Cipher.encrypt(ciphertext[0..self.buffer_pos], &tag, self.buffer[0..self.buffer_pos], &.{}, nonce, self.key);

        var header: [4]u8 = undefined;
        std.mem.writeInt(u32, &header, @intCast(self.buffer_pos), .little);

        try self.file.writeStreamingAll(self.io, &header);
        try self.file.writeStreamingAll(self.io, ciphertext[0..self.buffer_pos]);
        try self.file.writeStreamingAll(self.io, &tag);

        self.chunk_counter += 1;
        self.buffer_pos = 0;
    }
};

pub fn pack_and_lock(io: std.Io, input_path: []const u8, mut_file: std.Io.File, key: [crypto.KEY_SIZE]u8, nonce: [crypto.NONCE_SIZE]u8) !void {
    const input_file = try std.Io.Dir.cwd().openFile(io, input_path, .{});
    defer input_file.close(io);

    var vault_writer = VaultWriter.init(io, mut_file, key, nonce);

    var buffer: [CHUNK_SIZE]u8 = undefined;

    while (true) {
        const iovecs = [_][]u8{buffer[0..]};

        const bytes_read = input_file.readStreaming(io, &iovecs) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };

        if (bytes_read == 0) break;

        try vault_writer.write(buffer[0..bytes_read]);
    }

    try vault_writer.flush();
}

pub fn unpack_and_unlock(io: std.Io, input_file: std.Io.File, output_file: std.Io.File, key: [crypto.KEY_SIZE]u8, base_nonce: [crypto.NONCE_SIZE]u8) !void {
    var chunk_counter: u64 = 0;

    var ciphertext: [CHUNK_SIZE]u8 = undefined;
    var plaintext: [CHUNK_SIZE]u8 = undefined;

    while (true) {
        var size_buf: [4]u8 = undefined;
        if (!(try vault.read_exact(input_file, io, &size_buf))) {
            break;
        }

        const chunk_size = std.mem.readInt(u32, &size_buf, .little);
        if (chunk_size == 0 or chunk_size > CHUNK_SIZE) return HermaError.CorruptedFile;

        if (!(try vault.read_exact(input_file, io, ciphertext[0..chunk_size]))) {
            return HermaError.UnexpectedEndOfFile;
        }

        var tag: [crypto.MAC_SIZE]u8 = undefined;
        if (!(try vault.read_exact(input_file, io, &tag))) {
            return HermaError.UnexpectedEndOfFile;
        }

        var nonce = base_nonce;
        const counter_bytes = std.mem.toBytes(chunk_counter);
        for (counter_bytes, 0..) |b, i| nonce[i] ^= b;

        Cipher.decrypt(plaintext[0..chunk_size], ciphertext[0..chunk_size], tag, &.{}, nonce, key) catch return HermaError.DecryptionFailed;

        try output_file.writeStreamingAll(io, plaintext[0..chunk_size]);

        chunk_counter += 1;
    }
}
