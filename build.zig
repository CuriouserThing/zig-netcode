const std = @import("std");

pub fn linkTo(exe: *std.build.LibExeObjStep) !void {
    const sodium = exe.builder.addStaticLibrary("sodium", src() ++ "/src/sodium.zig");
    sodium.setTarget(exe.target);
    sodium.setBuildMode(exe.build_mode);

    const target_info = try std.zig.system.NativeTargetInfo.detect(exe.target);
    if (target_info.target.os.tag == .windows) {
        sodium.linkSystemLibrary("advapi32");
        exe.linkSystemLibrary("ws2_32");
    }

    exe.linkLibrary(sodium);
    exe.linkLibC();
    exe.addCSourceFile(src() ++ "/lib/netcode/netcode.c", &.{"-U__MINGW32__"});
    exe.addIncludePath(src() ++ "/src");
}

pub fn package(name: []const u8) std.build.Pkg {
    return .{
        .name = name,
        .source = .{ .path = src() ++ "/src/main.zig" },
    };
}

inline fn src() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
