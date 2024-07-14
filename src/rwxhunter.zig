const std = @import("std");
const windows = std.os.windows;
const DWORD = windows.DWORD;
const HANDLE = windows.HANDLE;
const HMODULE = windows.HMODULE;
const BOOL = windows.BOOL;
const LPCWSTR = windows.LPCWSTR;
const LPWSTR = windows.LPWSTR;
const LPVOID = windows.LPVOID;
const MEMORY_BASIC_INFORMATION = windows.MEMORY_BASIC_INFORMATION;

const MAX_PATH = 260;
const PROCESS_QUERY_INFORMATION = 0x0400;
const PROCESS_VM_READ = 0x0010;
const PAGE_EXECUTE_READWRITE = 0x40;
const PROCESS_ALL_ACCESS = 0x001F0FFF;

extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) HANDLE;
extern "psapi" fn EnumProcessModules(hProcess: HANDLE, lphModule: [*]HMODULE, cb: DWORD, lpcbNeeded: *DWORD) BOOL;
extern "psapi" fn GetModuleBaseNameW(hProcess: HANDLE, hModule: ?HMODULE, lpBaseName: LPWSTR, nSize: DWORD) DWORD;
extern "kernel32" fn VirtualQueryEx(hProcess: HANDLE, lpAddress: ?*const anyopaque, lpBuffer: *MEMORY_BASIC_INFORMATION, dwLength: usize) usize;
extern "kernel32" fn GetLastError() DWORD;
extern "kernel32" fn CloseHandle(hObject: HANDLE) BOOL;
extern "psapi" fn EnumProcesses(lpidProcess: [*]DWORD, cb: DWORD, lpcbNeeded: *DWORD) windows.BOOL;

const PROCESS_BASIC_INFORMATION = extern struct {
    Reserved1: ?*anyopaque,
    PebBaseAddress: ?*anyopaque,
    Reserved2: [2]?*anyopaque,
    UniqueProcessId: usize,
    Reserved3: ?*anyopaque,
};

extern "ntdll" fn NtQueryInformationProcess(
    ProcessHandle: HANDLE,
    ProcessInformationClass: c_int,
    ProcessInformation: *anyopaque,
    ProcessInformationLength: DWORD,
    ReturnLength: ?*DWORD,
) c_long;

extern "kernel32" fn WriteProcessMemory(
    hProcess: HANDLE,
    lpBaseAddress: LPVOID,
    lpBuffer: [*]const u8,
    nSize: usize,
    lpNumberOfBytesWritten: ?*usize,
) BOOL;

pub const MemoryRegion = struct {
    base_address: usize,
    size: usize,
};

pub fn enumProcs() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pids = try allocator.alloc(DWORD, 1024);
    defer allocator.free(pids);

    var cbNeeded: DWORD = 0;
    const result = EnumProcesses(pids.ptr, @intCast(pids.len * @sizeOf(DWORD)), &cbNeeded);

    if (result == 0) {
        return error.EnumProcessesFailed;
    }

    const processCount = cbNeeded / @sizeOf(DWORD);
    for (pids[0..processCount]) |pid| {
        try getRWXRegionInfo(pid);
    }
}

pub fn searchMem(pid: u32, allocator: std.mem.Allocator) ![]MemoryRegion {
    var regions = std.ArrayList(MemoryRegion).init(allocator);
    defer regions.deinit();

    var hmod: [1]HMODULE = undefined;
    var cbNeeded: DWORD = 0;
    var szProcessName: [MAX_PATH:0]u16 = [_:0]u16{0} ** MAX_PATH;

    const process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
    if (process == windows.INVALID_HANDLE_VALUE) {
        return error.FailedToOpenProcess;
    }
    defer _ = CloseHandle(process);

    const result = EnumProcessModules(process, &hmod, @sizeOf(HMODULE), &cbNeeded);
    if (result == 0) {
        return error.FailedToEnumerateModules;
    }

    const nameLen = GetModuleBaseNameW(process, hmod[0], &szProcessName, MAX_PATH);
    if (nameLen == 0) {
        return error.FailedToGetModuleName;
    }

    const processName = std.unicode.fmtUtf16Le(szProcessName[0..nameLen]);
    std.debug.print("[+] searching in {s} [pid: {}] for RWX memory\n", .{ processName, pid });

    const maxAddr: usize = 0x7fffffff;
    var addr: usize = 0;
    var m: MEMORY_BASIC_INFORMATION = undefined;

    while (addr < maxAddr) {
        const res = VirtualQueryEx(process, @ptrFromInt(addr), &m, @sizeOf(MEMORY_BASIC_INFORMATION));
        if (res == 0) {
            break;
        }

        if (m.AllocationProtect == PAGE_EXECUTE_READWRITE) {
            try regions.append(MemoryRegion{
                .base_address = @intFromPtr(m.BaseAddress),
                .size = m.RegionSize,
            });
        }

        if (addr == @intFromPtr(m.BaseAddress) + m.RegionSize) {
            break;
        }
        addr = @intFromPtr(m.BaseAddress) + m.RegionSize;
    }

    return regions.toOwnedSlice();
}

pub fn getRWXRegionInfo(pid: u32) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const regions = searchMem(pid, allocator) catch |err| {
        std.debug.print("[!] error searching memory for pid {}: {}\n", .{ pid, err });
        return;
    };
    defer allocator.free(regions);

    if (regions.len > 0) {
        std.debug.print("[!] found {} RWX memory regions for pid {}:\n", .{ regions.len, pid });
        for (regions, 0..) |region, i| {
            std.debug.print("Region {}:\n", .{i + 1});
            std.debug.print("  Base Address: 0x{X}\n", .{region.base_address});
            std.debug.print("  Size: {} bytes\n", .{region.size});

            const process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if (process == windows.INVALID_HANDLE_VALUE) {
                std.debug.print("[!] failed to open process. Error: {}\n", .{GetLastError()});
                continue;
            }
            defer _ = CloseHandle(process);

            var mbi: MEMORY_BASIC_INFORMATION = undefined;
            const res = VirtualQueryEx(process, @ptrFromInt(region.base_address), &mbi, @sizeOf(MEMORY_BASIC_INFORMATION));
            if (res == 0) {
                std.debug.print("[!] failed to query memory information. Error: {}\n", .{GetLastError()});
                continue;
            }

            std.debug.print("  State: 0x{X}\n", .{mbi.State});
            std.debug.print("  Type: 0x{X}\n", .{mbi.Type});
            std.debug.print("  Protect: 0x{X}\n", .{mbi.Protect});
        }
    } else {
        std.debug.print("[!] no RWX memory regions found for process with PID: {}\n", .{pid});
    }
}

pub fn main() !void {
    std.debug.print("[+] starting rwxhunter :)\n", .{});
    try enumProcs();
}
