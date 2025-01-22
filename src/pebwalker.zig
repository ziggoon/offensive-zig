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

pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]u8, // 8 byte name - null padded if shorter
    PhysicalAddress: u32, // aka VirtualSize
    VirtualAddress: u32, // RVA of section start
    SizeOfRawData: u32, // size of section in file
    PointerToRawData: u32, // file offset to section data
    PointerToRelocations: u32, // offset to relocation entries
    PointerToLinenumbers: u32, // offset to line number entries
    NumberOfRelocations: u16, // number of relocations
    NumberOfLinenumbers: u16, // number of line numbers
    Characteristics: u32, // section flags
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
    TimeDateStamp: windows.DWORD,
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

pub const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderLinks: windows.LIST_ENTRY,
    InMemoryOrderLinks: windows.LIST_ENTRY,
    Reserved2: [2]?*anyopaque,
    DllBase: ?*anyopaque,
    EntryPoint: ?*anyopaque,
    SizeOfImage: windows.ULONG,
    FullDllName: windows.UNICODE_STRING,
    Reserved4: [8]u8,
    Reserved5: [3]?*anyopaque,
    CheckSum_Reserved6: extern union {
        CheckSum: u32,
        Reserved6: ?*anyopaque,
    },
    TimeDateStamp: u32,
};

pub fn getKernel32Base() ?*anyopaque {
    const peb = windows.peb();
    var list_entry = peb.Ldr.InLoadOrderModuleList.Flink;

    while (true) {
        const module: *const LDR_DATA_TABLE_ENTRY = @fieldParentPtr(
            "InLoadOrderLinks",
            list_entry,
        );

        if (module.FullDllName.Buffer) |buffer| {
            var dll_name: [256]u16 = undefined; // Use u16 for wide chars
            const len = @min(module.FullDllName.Length / 2, 255);

            for (0..len) |i| {
                dll_name[i] = buffer[i];
            }
            dll_name[len] = 0;

            var utf8_buf: [512]u8 = undefined;
            const utf8_len = std.unicode.utf16LeToUtf8(&utf8_buf, dll_name[0..len]) catch continue;

            if (std.ascii.eqlIgnoreCase(utf8_buf[0..utf8_len], "c:\\windows\\system32\\kernel32.dll")) {
                std.debug.print("kernel32.dll found\n", .{});
                std.debug.print("   base address: 0x{x}\n", .{@intFromPtr(module.DllBase)});
                std.debug.print("   size: 0x{x}\n", .{module.SizeOfImage});
                std.debug.print("   entry: 0x{x}\n", .{@intFromPtr(module.EntryPoint)});
                return module.DllBase;
            }
        }

        list_entry = list_entry.Flink;
        if (list_entry == &peb.Ldr.InLoadOrderModuleList) break;
    }

    return null;
}

pub fn getProcAddress(base_address: [*]const u8, proc_name: []const u8, comptime T: type) ?T {
    _ = proc_name;
    const dos_header: *const IMAGE_DOS_HEADER = @ptrCast(@alignCast(base_address));
    if (dos_header.e_magic != 0x5A4D) return null;

    const e_lfanew: usize = @intCast(dos_header.e_lfanew);
    const nt_header_addr = base_address + e_lfanew;
    const nt_header: *const IMAGE_NT_HEADERS = @ptrCast(@alignCast(nt_header_addr));
    if (nt_header.Signature != 0x4550) return null;

    const export_dir_rva = nt_header.OptionalHeader.DataDirectory[0].VirtualAddress;
    const export_dir_ptr = base_address + export_dir_rva;

    const export_bytes: [*]const u32 = @ptrCast(@alignCast(export_dir_ptr));

    const name_rva = export_bytes[3];
    const name_ptr: [*:0]const u8 = @ptrCast(base_address + name_rva);
    const dll_name = std.mem.span(name_ptr);
    std.debug.print("\n[*] DLL Name: {s}\n", .{dll_name});

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
    if (getProcAddress(@ptrCast(kernel32_base), "LoadLibraryA", LoadLibraryAFn)) |loadLibraryPtr| {
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
