const std = @import("std");

const HermaError = @import("error.zig").HermaError;

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
