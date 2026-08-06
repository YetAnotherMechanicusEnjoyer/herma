const std = @import("std");

const crypto = @import("crypto.zig");
const HermaError = @import("error.zig").HermaError;

const MAGIC = [4]u8{ 'M', 'O', 'R', 'A' };
const VERSION: u8 = 1;

pub const Header = struct {
    salt: [crypto.SALT_SIZE]u8,
    nonce: [crypto.NONCE_SIZE]u8,
};

pub fn init_vault_file(io: std.Io, path: []const u8, header: Header) !std.Io.File {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    errdefer file.close(io);

    const magic = MAGIC;
    const version = [1]u8{VERSION};

    try file.writeStreamingAll(io, &magic);
    try file.writeStreamingAll(io, &version);
    try file.writeStreamingAll(io, &header.salt);
    try file.writeStreamingAll(io, &header.nonce);

    return file;
}

pub fn open_vault_file(io: std.Io, path: []const u8) !struct { file: std.Io.File, header: Header } {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    errdefer file.close(io);

    var buffer: [1024]u8 = undefined;
    var reader = @constCast(&file.reader(io, &buffer).interface);

    var magic: [4]u8 = undefined;
    const bytes_read = try reader.readSliceShort(&magic);
    if (bytes_read != 4 or !std.mem.eql(u8, &magic, &MAGIC)) {
        return HermaError.InvalidFormat;
    }

    const version = try reader.takeByte();
    if (version != VERSION) {
        return HermaError.UnsupportedVersion;
    }

    var header: Header = undefined;
    const salt_read = try reader.readSliceShort(&header.salt);
    const nonce_read = try reader.readSliceShort(&header.nonce);
    if (salt_read != crypto.SALT_SIZE or nonce_read != crypto.NONCE_SIZE) {
        return HermaError.InvalidFormat;
    }

    return .{ .file = file, .header = header };
}
