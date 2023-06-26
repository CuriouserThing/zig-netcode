const std = @import("std");

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}

pub const Package = struct {
    module: *std.Build.Module,
    sodium: *std.Build.CompileStep,

    pub fn build(b: *std.Build, target: std.zig.CrossTarget, optimize: std.builtin.Mode) !Package {
        return Package{
            .module = b.createModule(.{
                .source_file = .{ .path = thisDir() ++ "/src/main.zig" },
                .dependencies = &.{},
            }),
            .sodium = try buildSodium(b, target, optimize),
        };
    }

    pub fn linkTo(package: Package, exe: *std.Build.CompileStep) !void {
        exe.addIncludePath(thisDir() ++ "/src");
        exe.linkLibC();
        exe.linkLibrary(package.sodium);

        const target_info = try std.zig.system.NativeTargetInfo.detect(exe.target);
        if (target_info.target.os.tag == .windows) {}
        switch (target_info.target.os.tag) {
            .windows => {
                exe.linkSystemLibrary("ws2_32");
                exe.addCSourceFile(thisDir() ++ "/lib/netcode/netcode.c", &.{"-U__MINGW32__"});
            },

            // TODO: examine linux support for netcode.io
            .linux => {
                exe.addCSourceFile(thisDir() ++ "/lib/netcode/netcode.c", &.{});
            },

            // TODO: examine macos support for netcode.io
            .macos => {
                exe.addCSourceFile(thisDir() ++ "/lib/netcode/netcode.c", &.{});
            },

            else => unreachable,
        }
    }
};

fn buildSodium(b: *std.Build, target: std.zig.CrossTarget, optimize: std.builtin.Mode) !*std.Build.CompileStep {
    const sodium = b.addStaticLibrary(.{
        .name = "sodium",
        .root_source_file = .{ .path = thisDir() ++ "/src/sodium.zig" },
        .target = target,
        .optimize = optimize,
    });

    const target_info = try std.zig.system.NativeTargetInfo.detect(target);
    switch (target_info.target.os.tag) {
        .windows => {
            sodium.linkSystemLibrary("advapi32");
        },

        // TODO: examine linux support for netcode.io
        .linux => {},

        // TODO: examine macos support for netcode.io
        .macos => {},

        else => unreachable,
    }

    return sodium;
}
