const std = @import("std");

pub fn linkTo(exe: *std.build.LibExeObjStep, pkg_name: []const u8) void {
    const sodium = exe.builder.addStaticLibrary("sodium", src() ++ "/src/sodium.zig");
    sodium.setTarget(exe.target);
    sodium.setBuildMode(exe.build_mode);
    if (exe.target.os_tag) |os| {
        if (os == .windows) {
            sodium.linkSystemLibrary("advapi32");
        }
    }

    exe.linkLibrary(sodium);
    exe.linkLibC();
    exe.addCSourceFile(src() ++ "/lib/netcode/netcode.c", &.{});
    exe.addIncludePath(src() ++ "/src");
    exe.addPackage(.{
        .name = pkg_name,
        .source = .{ .path = src() ++ "/src/main.zig" },
    });
}

inline fn src() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
