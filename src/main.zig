const std = @import("std");

const crypto = @import("crypto.zig");
const HermaError = @import("error.zig").HermaError;
const utils = @import("utils.zig");
const vault = @import("vault.zig");

const APP_NAME = "herma";
const FILE_EXTENSION = "herma";

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();

    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);

    parse_arguments(init.io, allocator, args) catch |err| switch (err) {
        HermaError.BadUsage => print_usage(),
        else => {},
    };
}

fn parse_arguments(io: std.Io, allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    if (args.len < 4) {
        std.log.err("Error: Bad Usage: too many arguments. Found: {}", .{args.len});
        return HermaError.BadUsage;
    }

    const cmd = args[1];
    const input_path = args[2];
    const output_path = args[3];

    if (std.mem.eql(u8, cmd, "lock")) {
        try lock(io, allocator, input_path, output_path);
    } else if (std.mem.eql(u8, cmd, "unlock")) {
        try unlock(io, allocator, input_path, output_path);
    } else {
        std.log.err("Error: Bad Usage: Unknown command '{s}'", .{cmd});
        return HermaError.BadUsage;
    }
}

fn print_usage() void {
    std.debug.print(
        \\usage: {s} <command> /path/to/input /path/to/output
        \\
        \\command:
        \\  lock    Package, compress, and encrypt a folder/file into a .{s} file.
        \\  unlock  Decrypts and extracts a .{s} file to its original form.
        \\
        \\e.g.:
        \\  {s} lock ./secret_documents ./secret.{s}
        \\  {s} unlock ./secret.{s} ./restored_documents
        \\
    , .{ APP_NAME, FILE_EXTENSION, FILE_EXTENSION, APP_NAME, FILE_EXTENSION, APP_NAME, FILE_EXTENSION });
}

fn lock(io: std.Io, allocator: std.mem.Allocator, input_path: []const u8, output_path: []const u8) !void {
    std.debug.print("Locking '{s}' to '{s}'...\n", .{ input_path, output_path });

    var password_entered = false;
    var password: []u8 = undefined;
    defer if (password.len > 0) {
        std.crypto.secureZero(u8, password);
        allocator.free(password);
    };

    while (!password_entered) {
        password = utils.get_line(io, allocator, "Enter your password: ") catch |err| switch (err) {
            HermaError.EmptyInput => {
                std.log.err("Error reading input: Input cannot be empty.", .{});
                continue;
            },
            else => return err,
        };

        password_entered = true;
    }

    std.debug.print("Password entered: {s}\n", .{password});

    const salt = crypto.generate_random_bytes(io, crypto.SALT_SIZE);
    const secret_key = try crypto.derive_key(io, password, salt);
    defer std.crypto.secureZero(u8, @constCast(&secret_key));

    std.debug.print("Secret key generated: {x}\n", .{secret_key});

    const header = vault.Header{
        .salt = crypto.generate_random_bytes(io, crypto.SALT_SIZE),
        .nonce = crypto.generate_random_bytes(io, crypto.NONCE_SIZE),
    };

    var file = try vault.init_vault_file(io, output_path, header);
    defer file.close(io);

    std.debug.print("Successfully locked '{s}' to '{s}'\n", .{ input_path, output_path });
}

fn unlock(io: std.Io, allocator: std.mem.Allocator, input_path: []const u8, output_path: []const u8) !void {
    std.debug.print("Unlocking '{s}' to '{s}'...\n", .{ input_path, output_path });

    var vault_data = vault.open_vault_file(io, input_path) catch |err| {
        switch (err) {
            HermaError.InvalidFormat => std.log.err("Error reading input file: Invalid format.", .{}),
            HermaError.UnsupportedVersion => std.log.err("Error reading input file: Unsupported version.", .{}),
            else => {},
        }
        return err;
    };
    defer vault_data.file.close(io);

    var password_entered = false;
    var password: []u8 = undefined;
    defer if (password.len > 0) {
        std.crypto.secureZero(u8, password);
        allocator.free(password);
    };

    while (!password_entered) {
        password = utils.get_line(io, allocator, "Enter your password: ") catch |err| switch (err) {
            HermaError.EmptyInput => {
                std.log.err("Error reading input: Input cannot be empty.", .{});
                continue;
            },
            else => return err,
        };

        password_entered = true;
    }

    std.debug.print("Password entered: {s}\n", .{password});

    const secret_key = try crypto.derive_key(io, password, vault_data.header.salt);
    defer std.crypto.secureZero(u8, @constCast(&secret_key));

    std.debug.print("Successfully unlocked '{s}' to '{s}'\n", .{ input_path, output_path });
}
