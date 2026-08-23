const std = @import("std");
const builtin = @import("builtin");

const HermaError = @import("error.zig").HermaError;

const HANDLE = *anyopaque;
const DWORD = u32;
const BOOL = i32;

extern "kernel32" fn GetStdHandle(nStdHandle: DWORD) callconv(.winapi) ?HANDLE;
extern "kernel32" fn GetConsoleMode(hConsoleHandle: ?HANDLE, lpMode: *DWORD) callconv(.winapi) BOOL;
extern "kernel32" fn SetConsoleMode(hConsoleHandle: ?HANDLE, dwMode: DWORD) callconv(.winapi) BOOL;

fn set_echo_win(enable: bool) !void {
    const STDIN_HANDLE: DWORD = @bitCast(@as(i32, -10));
    const ENABLE_ECHO_INPUT: DWORD = 0x0004;

    const handle = GetStdHandle(STDIN_HANDLE) orelse return error.StdHandleFailed;

    const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(std.math.maxInt(usize));
    if (handle == INVALID_HANDLE_VALUE) {
        return error.StdHandleFailed;
    }

    var mode: DWORD = 0;
    if (GetConsoleMode(handle, &mode) == 0) {
        return error.GetConsoleModeFailed;
    }

    const new_mode = if (enable)
        mode | ENABLE_ECHO_INPUT
    else
        mode & ENABLE_ECHO_INPUT;

    if (SetConsoleMode(handle, new_mode) == 0) {
        return error.SetConsoleModeFailed;
    }
}

fn set_echo_posix(enable: bool) !void {
    const fd = std.posix.STDIN_FILENO;

    var termios = try std.posix.tcgetattr(fd);

    termios.lflag.ECHO = enable;

    try std.posix.tcsetattr(fd, .NOW, termios);
}

fn set_echo(enable: bool) void {
    switch (builtin.os.tag) {
        .windows => set_echo_win(enable) catch {},
        else => set_echo_posix(enable) catch {},
    }
}

pub fn get_secret_line(io: std.Io, allocator: std.mem.Allocator, prompt_text: []const u8) ![]u8 {
    set_echo(false);
    defer set_echo(true);
    return try get_line(io, allocator, prompt_text);
}

pub fn get_line(io: std.Io, allocator: std.mem.Allocator, prompt_text: []const u8) ![]u8 {
    var stdin_buffer: [1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buffer);
    const stdin = &stdin_reader.interface;

    const stdout = std.Io.File.stdout();
    try stdout.writeStreamingAll(io, prompt_text);

    const line = try stdin.takeDelimiterExclusive('\n');

    if (line.len > 0) {
        const trimmed_line = std.mem.trimEnd(u8, line, "\r");

        return try allocator.dupe(u8, trimmed_line);
    } else {
        return HermaError.EmptyInput;
    }
}
