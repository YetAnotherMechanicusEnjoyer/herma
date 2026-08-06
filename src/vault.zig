const std = @import("std");

const crypto = @import("crypto.zig");
const HermaError = @import("error.zig").HermaError;

const MAGIC = [4]u8{ 'M', 'O', 'R', 'A' };
const VERSION: u8 = 1;

pub const Header = struct {
    salt: [crypto.SALT_SIZE]u8,
    nonce: [crypto.NONCE_SIZE]u8,
};

pub fn read_exact(file: std.Io.File, io: std.Io, buffer: []u8) !bool {
    var total_read: usize = 0;
    while (total_read < buffer.len) {
        const iovecs = [_][]u8{buffer[total_read..]};
        const n = file.readStreaming(io, &iovecs) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };

        if (n == 0) break;
        total_read += n;
    }

    if (total_read == 0) return false;
    if (total_read < buffer.len) return HermaError.UnexpectedEndOfFile;

    return true;
}

pub fn init_vault_file(io: std.Io, path: []const u8, header: Header) !std.Io.File {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    errdefer file.close(io);

    try file.writeStreamingAll(io, &MAGIC);
    try file.writeStreamingAll(io, &[_]u8{VERSION});
    try file.writeStreamingAll(io, &header.salt);
    try file.writeStreamingAll(io, &header.nonce);

    return file;
}

pub fn open_vault_file(io: std.Io, path: []const u8) !struct { file: std.Io.File, header: Header } {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    errdefer file.close(io);

    var magic: [4]u8 = undefined;
    if (!(try read_exact(file, io, &magic)) or !std.mem.eql(u8, &magic, &MAGIC)) {
        return HermaError.InvalidFormat;
    }

    var version_buf: [1]u8 = undefined;
    if (!(try read_exact(file, io, &version_buf)) or version_buf[0] != VERSION) {
        return HermaError.UnsupportedVersion;
    }

    var header: Header = undefined;
    if (!(try read_exact(file, io, &header.salt))) return HermaError.InvalidFormat;
    if (!(try read_exact(file, io, &header.nonce))) return HermaError.InvalidFormat;

    return .{ .file = file, .header = header };
}
