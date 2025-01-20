const std = @import("std");
const windows = std.os.windows;

pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: windows.WORD, // magic number (0x4D5A)
    e_cblp: windows.WORD, // bytes of last page of file
    e_cp: windows.WORD, // pages in file
    e_crlc: windows.WORD, // relocations
    e_cparhdr: windows.WORD, // size of header in paragraphs
    e_minalloc: windows.WORD, // min extra paragraphs needed
    e_maxalloc: windows.WORD, // max extra paragraphs needed
    e_ss: windows.WORD, // initial (relative) ss value
    e_sp: windows.WORD, // initial sp value
    e_csum: windows.WORD, // checksum
    e_ip: windows.WORD, // initial instruction pointer
    e_cs: windows.WORD, // initial (relative) CS value
    e_lfarlc: windows.WORD, // file address of relocation table
    e_ovno: windows.WORD, // overlay number
    e_res: [4]windows.WORD, // reserved words (padding)
    e_oemid: windows.WORD, // oem identifier
    e_oeminfo: windows.WORD, // oem information
    e_res2: [10]windows.WORD, // reserved words (padding)
    e_lfanew: windows.DWORD, // file address of new exe header
};

pub const IMAGE_NT_HEADERS = extern struct {
    Signature: windows.DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

pub const IMAGE_FILE_HEADER = extern struct {
    Machine: windows.WORD,
    NumberOfSections: windows.WORD,
    TimeDateStamp: windows.DWORD,
    PointerToSymbolTable: windows.DWORD,
    NumberOfSymbols: windows.DWORD,
    SizeOfOptionalHeader: windows.DWORD,
    Characteristics: windows.DWORD,
};

pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: windows.WORD,
    MajorLinkerVersion: windows.BYTE,
    MinorLinkerVersion: windows.BYTE,
    SizeOfCode: windows.DWORD,
    SizeOfInitializedData: windows.DWORD,
    SizeOfUninitializedData: windows.DWORD,
    AddressOfEntryPoint: windows.DWORD,
    BaseOfCode: windows.DWORD,
    ImageBase: windows.ULONGLONG,
    SectionAlignment: windows.DWORD,
    FileAlignment: windows.DWORD,
    MajorOperatingSystemVersion: windows.WORD,
    MinorOperatingSystemVersion: windows.WORD,
    MajorImageVersion: windows.WORD,
    MinorImageVersion: windows.WORD,
    MajorSubsystemVersion: windows.WORD,
    MinorSubsystemVersion: windows.WORD,
    Win32VersionValue: windows.DWORD,
    SizeOfImage: windows.DWORD,
    SizeOfHeader: windows.DWORD,
    CheckSum: windows.DWORD,
    Subsystem: windows.WORD,
    DllCharacteristics: windows.WORD,
    SizeOfStackReserve: windows.ULONGLONG,
    SizeOfStackCommit: windows.ULONGLONG,
    SizeOfHeapReserve: windows.ULONGLONG,
    SizeOfHeapCommit: windows.ULONGLONG,
    LoaderFlags: windows.DWORD,
    NumberOfRvaAndSize: windows.DWORD,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: windows.DWORD,
    TimeDataStamp: windows.DWORD,
    MajorVersion: windows.WORD,
    MinorVersion: windows.WORD,
    Name: windows.DWORD,
    Base: windows.DWORD,
    NumberOfFunctions: windows.DWORD,
    NumberOfNames: windows.DWORD,
    AddressOfFunctions: windows.DWORD,
    AddressOfNames: windows.DWORD,
    AddressOfNameOrdinals: windows.DWORD,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: windows.DWORD,
    Size: windows.DWORD,
};

pub fn getKernel32Base() ?*anyopaque {
    const peb = windows.peb();
    var list_entry = peb.Ldr.InMemoryOrderModuleList.Flink;

    while (true) {
        const module: *const windows.LDR_DATA_TABLE_ENTRY = @fieldParentPtr("InMemoryOrderLinks", list_entry);

        if (module.FullDllName.Buffer) |buffer| {
            var dll_name: [256]u8 = undefined;
            var i: u8 = 0;
            while (i < module.FullDllName.Length / @sizeOf(windows.WORD) and i < 255) {
                dll_name[i] = @truncate(buffer[i]);
                i += 1;
            }
            dll_name[i] = 0;

            if (std.ascii.eqlIgnoreCase(dll_name[0..i], "c:\\windows\\system32\\kernel32.dll")) {
                std.debug.print("kernel32.dll found\n", .{});
                std.debug.print("   base address: 0x{x}\n", .{@intFromPtr(module.DllBase)});
                std.debug.print("   size: 0x{x}\n", .{module.SizeOfImage});
                std.debug.print("   entry: 0x{x}\n", .{@intFromPtr(module.EntryPoint)});

                return module.DllBase;
            }
        }

        list_entry = list_entry.Flink;
        if (list_entry == &peb.Ldr.InMemoryOrderModuleList) break;
    }

    return null;
}

pub fn getProcAddress(base_address: [*]const u8, proc_ordinal: u16, comptime T: type) ?T {
    const dos_header: *const IMAGE_DOS_HEADER = @alignCast(@ptrCast(base_address));

    const e_lfanew: usize = @intCast(dos_header.e_lfanew);
    const nt_header_addr = base_address + e_lfanew;
    const nt_header: *const IMAGE_NT_HEADERS = @alignCast(@ptrCast(nt_header_addr));

    const export_directory_rva = nt_header.OptionalHeader.DataDirectory[0].VirtualAddress;
    const export_directory_addr = base_address + export_directory_rva;
    const export_directory: *const IMAGE_EXPORT_DIRECTORY = @alignCast(@ptrCast(export_directory_addr));

    const names = export_directory.NumberOfNames;
    if (names == 0) {
        std.debug.print("functions are likely exported via ordinal. checking now\n", .{});
        const function_address_array: [*]const u32 = @alignCast(@ptrCast(base_address + @as(usize, @intCast(export_directory.AddressOfFunctions))));
        const function_ordinal_array: [*]const u16 = @alignCast(@ptrCast(base_address + @as(usize, @intCast(export_directory.AddressOfNameOrdinals))));

        for (0..export_directory.NumberOfFunctions) |i| {
            const function_ordinal = function_ordinal_array[i];
            const function_address = base_address + function_address_array[function_ordinal];

            if (proc_ordinal == function_ordinal) {
                std.debug.print("ordinal match found!\n", .{});

                return @alignCast(@constCast(@ptrCast(function_address)));
            }
        }
    }

    // std.debug.print("export dir: {any}\n", .{export_directory});

    return null;
}

const LoadLibraryAFn = *const fn (
    lpLibFileName: [*:0]const u8,
) callconv(windows.WINAPI) ?windows.HMODULE;

const MessageBoxAFn = *const fn (
    hWnd: windows.HWND,
    lpText: windows.LPCSTR,
    lpCaption: windows.LPCSTR,
    uType: windows.UINT,
) callconv(windows.WINAPI) void;

pub fn main() !void {
    const kernel32_base = getKernel32Base();
    if (getProcAddress(@ptrCast(kernel32_base), 43, LoadLibraryAFn)) |loadLibraryPtr| {
        std.debug.print("loadlibrary found @ 0x{x}\n", .{@intFromPtr(loadLibraryPtr)});

        const loadLibrary = @as(LoadLibraryAFn, @ptrCast(loadLibraryPtr));

        if (loadLibrary("user32.dll")) |hModule| {
            std.debug.print("user32.dll loaded successfully. Module handle: 0x{x}\n", .{@intFromPtr(hModule)});

            _ = windows.FreeLibrary(hModule);
        } else {
            std.debug.print("Failed to load user32.dll\n", .{});
        }
    } else {
        std.debug.print("LoadLibraryA function not found\n", .{});
        return error.FunctionNotFound;
    }
}
