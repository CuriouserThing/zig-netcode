const std = @import("std");

pub const Package = struct {
    module: *std.Build.Module,
    sodium: *std.Build.CompileStep,

    pub fn build(b: *std.Build, target: std.zig.CrossTarget, optimize: std.builtin.Mode) !Package {
        const module = b.createModule(.{
            .source_file = .{ .path = src() ++ "/src/main.zig" },
            .dependencies = &.{},
        });

        const sodium = b.addStaticLibrary(.{
            .name = "sodium",
            .root_source_file = .{ .path = src() ++ "/src/sodium.zig" },
            .target = target,
            .optimize = optimize,
        });
        const target_info = try std.zig.system.NativeTargetInfo.detect(target);
        if (target_info.target.os.tag == .windows) {
            sodium.linkSystemLibrary("advapi32");
        }

        return Package{
            .module = module,
            .sodium = sodium,
        };
    }

    pub fn linkTo(package: Package, exe: *std.Build.CompileStep) !void {
        const target_info = try std.zig.system.NativeTargetInfo.detect(exe.target);
        if (target_info.target.os.tag == .windows) {
            exe.linkSystemLibrary("ws2_32");
        }
        exe.linkLibrary(package.sodium);
        exe.linkLibC();
        exe.addCSourceFile(src() ++ "/lib/netcode/netcode.c", &.{"-U__MINGW32__"});
        exe.addIncludePath(src() ++ "/src");
    }
};

inline fn src() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
