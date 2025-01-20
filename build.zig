const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const local = b.addExecutable(.{
        .name = "local",
        .root_source_file = b.path("src/local.zig"),
        .target = target,
        .optimize = optimize,
    });

    const remote = b.addExecutable(.{
        .name = "remote",
        .root_source_file = b.path("src/remote.zig"),
        .target = target,
        .optimize = optimize,
    });

    const rwxhunter = b.addExecutable(.{
        .name = "rwxhunter",
        .root_source_file = b.path("src/rwxhunter.zig"),
        .target = target,
        .optimize = optimize,
    });

    const pebwalker = b.addExecutable(.{
        .name = "pebwalker",
        .root_source_file = b.path("src/pebwalker.zig"),
        .target = target,
        .optimize = optimize,
    });

    const host = b.option([]const u8, "host", "remote host") orelse "127.0.0.1";
    const port = b.option(u16, "port", "remote port") orelse 80;
    const size = b.option(u32, "size", "shellcode size") orelse 4096;

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "host", host);
    build_options.addOption(u16, "port", port);
    build_options.addOption(u32, "size", size);

    local.root_module.addOptions("build_options", build_options);
    remote.root_module.addOptions("build_options", build_options);

    const rc = std.Build.LazyPath{ .src_path = .{ .owner = b, .sub_path = "metadata.rc" } };

    local.addWin32ResourceFile(.{ .file = rc });
    remote.addWin32ResourceFile(.{ .file = rc });
    rwxhunter.addWin32ResourceFile(.{ .file = rc });
    pebwalker.addWin32ResourceFile(.{ .file = rc });

    b.installArtifact(local);
    b.installArtifact(remote);
    b.installArtifact(rwxhunter);
    b.installArtifact(pebwalker);
}
