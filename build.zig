const std = @import("std");
const log = std.log.scoped(.build);

pub fn build(b: *std.build.Builder) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    const native_target = (std.zig.system.NativeTargetInfo.detect(target) catch unreachable).target;

    // TODO: Git parsing
    const git_commit_hash = "abcdef0";
    const version = std.SemanticVersion{
        .major = 0,
        .minor = 0,
        .patch = 0,
    };

    const lib = b.addSharedLibrary(.{
        .name = "duckdb",
        .target = target,
        .optimize = optimize,
        .version = version,
    });

    // Build CXXFLAGS
    var cxx_flags = std.ArrayList([]const u8).init(b.allocator);
    cxx_flags.appendSlice(&[_][]const u8{
        "-std=c++11",
        "-ffunction-sections",
        "-fdata-sections",
        std.fmt.allocPrint(b.allocator, "-DDUCKDB_VERSION=\"v{}.{}.{}-dev{}\"", .{
            version.major, version.minor, version.patch, 0,
        }) catch unreachable,
        std.fmt.allocPrint(b.allocator, "-DDUCKDB_SOURCE_ID=\"{s}\"", .{
            git_commit_hash,
        }) catch unreachable,
    }) catch unreachable;

    if (optimize == .Debug) {
        cxx_flags.appendSlice(&[_][]const u8{
            "-g",
            "-Wall",
            "-Werror=vla",
            "-Wunused",
            "-Wnarrowing",
            "-pedantic",
        }) catch unreachable;
    }

    const force_assert = b.option(bool, "FORCE_ASSERT", "Enable checking of assertions, even in release mode") orelse (optimize == .ReleaseSafe);
    if (force_assert) {
        cxx_flags.append("-DDUCKDB_FORCE_ASSERT") catch unreachable;
    }

    // Sanitizer flags.
    // TODO: error: cannot make section .ASAN$GL associative with sectionless symbol
    // AddresSanitizer is disabled by default for now.
    var enable_asan = b.option(bool, "ENABLE_SANITIZER", "Enable address sanitizer.") orelse false;
    var enable_tsan = b.option(bool, "ENABLE_THREAD_SANITIZER", "Enable thread sanitizer.") orelse false;
    var enable_ubsan = b.option(bool, "ENABLE_UBSAN", "Enable undefined behavior sanitizer.") orelse false;
    const disable_vptr = b.option(bool, "DISABLE_VPTR_SANITIZER", "Disable vptr sanitizer; work-around for sanitizer false positive on Macbook M1") orelse false;

    if (enable_tsan) {
        inline for (.{ .{ "address", &enable_asan }, .{ "undefined", &enable_ubsan } }) |sanitizer| {
            if (sanitizer[1].*) {
                log.warn(
                    "Both thread and {s} sanitizers are enabled. This is not supported." ++ "The {s} sanitizer will be disabled, and we will run with only the thread sanitizer.",
                    .{ sanitizer[0], sanitizer[0] },
                );
                sanitizer[1].* = false;
            }
        }

        if (force_assert or optimize == .Debug) {
            cxx_flags.appendSlice(&[_][]const u8{
                "-fsanitize=thread",
                "-DDUCKDB_THREAD_SANITIZER",
            }) catch unreachable;
        }
    }

    if (enable_asan and (force_assert or optimize == .Debug)) {
        cxx_flags.append("-fsanitize=address") catch unreachable;
    }

    if (enable_ubsan and (force_assert or optimize == .Debug)) {
        cxx_flags.appendSlice(&[_][]const u8{
            "-fsanitize=undefined",
            "-fno-sanitize-recover=all",
        }) catch unreachable;

        if (disable_vptr or (native_target.os.tag.isDarwin() and native_target.cpu.arch.isAARCH64())) {
            cxx_flags.append("-fno-sanitize=vptr") catch unreachable;
        }
    }

    // Other configurations
    if (b.option(bool, "ASSERT_EXCEPTION", "Throw an exception on an assert failing, instead of triggering a sigabort") orelse true) {
        cxx_flags.append("-DDUCKDB_CRASH_ON_ASSERT") catch unreachable;
    }
    if (b.option(bool, "DISABLE_STR_INLINE", "Debug setting: disable inlining of strings") orelse false) {
        cxx_flags.append("-DDUCKDB_DEBUG_NO_INLINE") catch unreachable;
    }
    if (b.option(bool, "DISABLE_MEMORY_SAFETY", "Debug setting: disable memory access checks at runtime") orelse false) {
        cxx_flags.append("-DDUCKDB_DEBUG_NO_SAFETY") catch unreachable;
    }
    if (b.option(bool, "DISABLE_ASSERTIONS", "Debug setting: disable assertions") orelse (optimize == .ReleaseFast or optimize == .ReleaseSmall)) {
        cxx_flags.append("-DDISABLE_ASSERTIONS") catch unreachable;
    }
    if (b.option(bool, "DESTROY_UNPINNED_BLOCKS", "Debug setting: destroy unpinned buffer-managed blocks") orelse false) {
        cxx_flags.append("-DDUCKDB_DEBUG_DESTROY_BLOCKS") catch unreachable;
    }
    if (b.option(bool, "FORCE_ASYNC_SINK_SOURCE", "Debug setting: forces sinks/sources to block the first 2 times they're called") orelse false) {
        cxx_flags.append("-DDUCKDB_DEBUG_ASYNC_SINK_SOURCE") catch unreachable;
    }
    if (b.option(bool, "ALTERNATIVE_VERIFY", "Debug setting: use alternative verify mode") orelse false) {
        cxx_flags.append("-DDUCKDB_ALTERNATIVE_VERIFY") catch unreachable;
    }
    if (b.option(bool, "DEBUG_STACKTRACE", "Debug setting: print a stracktrace on asserts and when testing crashes") orelse false) {
        cxx_flags.append("-DDUCKDB_DEBUG_STACKTRACE") catch unreachable;
    }
    if (b.option(bool, "DEBUG_MOVE", "Debug setting: Ensure std::move is being used") orelse false) {
        cxx_flags.append("-DDUCKDB_DEBUG_MOVE") catch unreachable;
    }
    if (b.option(bool, "CLANG_TIDY", "Enable build for clang-tidy, this disables all source files excluding the core database. This does not produce a working build.") orelse false) {
        cxx_flags.append("-DDUCKDB_CLANG_TIDY") catch unreachable;
    }
    if (b.option(bool, "FORCE_WARN_UNUSED", "Unused code objects lead to compiler warnings.") orelse false) {
        cxx_flags.append("-Wunused") catch unreachable;
    }
    if (b.option(bool, "TREAT_WARNINGS_AS_ERRORS", "Treat warnings as errors") orelse false) {
        log.warn("Treating warnings as errors.", .{});
        cxx_flags.append("-Werror") catch unreachable;
    }

    // Collect include paths usable by all (TODO: detect via dir walk)
    var include_paths = std.ArrayList([]const u8).init(b.allocator);
    include_paths.appendSlice(&[_][]const u8{
        "./src/include",
        "./third_party/fsst",
        "./third_party/fmt/include",
        "./third_party/hyperloglog",
        "./third_party/fastpforlib",
        "./third_party/fast_float",
        "./third_party/re2",
        "./third_party/miniz",
        "./third_party/utf8proc/include",
        "./third_party/miniparquet",
        "./third_party/concurrentqueue",
        "./third_party/pcg",
        "./third_party/tdigest",
        "./third_party/mbedtls/include",
        "./third_party/jaro_winkler",
        "./third_party/libpg_query/include",
        "./third_party/httplib",
        "./third_party/tpce-tool/include",
    }) catch unreachable;

    // Generate compile steps by parsing CMakeLists.txt files in src/
    for (find_cmake_files(b, "src")) |path| {
        const data = std.fs.cwd().readFileAlloc(b.allocator, path, 4 * 1024 * 1024) catch unreachable;
        const args = parse_cmake_call(b, data, "add_library_unity(") orelse continue;
        const dep = b.addStaticLibrary(.{
            .name = args[0],
            .target = target,
            .optimize = optimize,
        });

        const dirname = std.fs.path.dirname(path) orelse unreachable;
        dep.addIncludePath(dirname);

        for (include_paths.items) |include| {
            dep.addIncludePath(include);
        }

        for (args[2..]) |source| {
            const src_path = std.fs.path.join(b.allocator, &[_][]const u8{ dirname, source }) catch unreachable;
            dep.addCSourceFile(src_path, cxx_flags.items);
        }

        dep.linkLibCpp();
        lib.linkLibrary(dep);
    }

    for (find_cmake_files(b, "third_party")) |path| {
        const dirname = std.fs.path.dirname(path) orelse unreachable;
        if (std.mem.endsWith(u8, dirname, "imdb")) continue; // only compiled under BUILD_UNITTESTS
        if (std.mem.endsWith(u8, dirname, "sqlite")) continue; // only compiled under BUILD_UNITTESTS
        if (std.mem.indexOf(u8, dirname, "tpce-tool") != null) continue; // only compiled under BUILD_UNITTESTS and BUILD_TPCE
        if (std.mem.indexOf(u8, dirname, "snowball") != null) continue; // only referenced by an extension.

        const data = std.fs.cwd().readFileAlloc(b.allocator, path, 4 * 1024 * 1024) catch unreachable;
        const args = parse_cmake_call(b, data, "add_library(") orelse continue;
        const dep = b.addStaticLibrary(.{
            .name = args[0],
            .target = target,
            .optimize = optimize,
        });

        const include_path = std.fs.path.join(b.allocator, &[_][]const u8{ dirname, "include" }) catch unreachable;
        dep.addIncludePath(include_path);
        dep.addIncludePath(dirname);

        for (include_paths.items) |include| {
            dep.addIncludePath(include);
        }

        var sources = std.ArrayList([]const u8).init(b.allocator);
        for (args[2..]) |source| {
            if (std.mem.startsWith(u8, source, "${")) {
                const end = std.mem.indexOf(u8, source, "}") orelse unreachable;
                const name = source[2..end];
                if (std.mem.eql(u8, name, "RE2_SOURCES")) {
                    for (parse_cmake_call(b, data, "set(RE2_SOURCES") orelse unreachable) |re2_src| {
                        sources.append(re2_src) catch unreachable;
                    }
                } else {
                    std.debug.panic("unhandled cmake var: {s}", .{source});
                }
            } else {
                sources.append(source) catch unreachable;
            }
        }

        for (sources.items) |source| {
            if (std.mem.endsWith(u8, source, ".inc")) continue; // TODO: handle .inc files
            const src_path = std.fs.path.join(b.allocator, &[_][]const u8{ dirname, source }) catch unreachable;
            const cstd = if (std.mem.endsWith(u8, src_path, ".c")) "" else "-std=c++11";
            dep.addCSourceFile(src_path, &[_][]const u8{cstd});
        }

        dep.linkLibCpp();
        lib.linkLibrary(dep);
    }

    lib.strip = true;
    lib.link_gc_sections = true;
    lib.dead_strip_dylibs = true;

    b.installArtifact(lib);
}

fn find_cmake_files(b: *std.build.Builder, folder: []const u8) []const []const u8 {
    var dir = std.fs.cwd().openIterableDir(folder, .{}) catch unreachable;
    defer dir.close();

    var walker = dir.walk(b.allocator) catch unreachable;
    defer walker.deinit();

    var files = std.ArrayList([]const u8).init(b.allocator);
    while (walker.next() catch unreachable) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.eql(u8, entry.basename, "CMakeLists.txt")) continue;
        if (std.mem.eql(u8, entry.basename, entry.path)) continue; // skip root level CMakeLists.txt

        const path = std.fs.path.join(b.allocator, &[_][]const u8{ folder, entry.path }) catch unreachable;
        files.append(path) catch unreachable;
    }

    return files.toOwnedSlice() catch unreachable;
}

fn parse_cmake_call(b: *std.build.Builder, data: []u8, prefix: []const u8) ?[][]const u8 {
    const start = std.mem.indexOf(u8, data, prefix) orelse return null;
    const end = std.mem.indexOf(u8, data[start + prefix.len ..], ")") orelse return null;
    const raw_args = data[start + prefix.len ..][0..end];

    // Replace newlines with spaces so they can be split on.
    for (raw_args) |*c| {
        if (c.* == '\r') c.* = ' ';
        if (c.* == '\n') c.* = ' ';
    }

    var args = std.ArrayList([]const u8).init(b.allocator);
    var it = std.mem.tokenizeAny(u8, raw_args, " ");
    while (it.next()) |arg| {
        const item = std.mem.trim(u8, arg, " ");
        if (item.len == 0) continue; // skip empty line entries.
        args.append(item) catch unreachable;
    }

    return args.toOwnedSlice() catch unreachable;
}
