// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Zig build script for hpm-crypto-rsr.
// Tested against Zig 0.15.x. Other versions may need adjustment to the
// build-graph API.
//
// Outputs:
//   zig-out/lib/libhpm_crypto.so   (dynamic, for Idris2 / AffineScript / Rust consumers)
//   zig-out/lib/libhpm_crypto.a    (static, optional)
//
// Tests:
//   zig build test    runs the Zig-side test suite in src/main.zig

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ------------------------------------------------------------------
    // Module
    // ------------------------------------------------------------------

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ------------------------------------------------------------------
    // Shared library — the production artefact
    // ------------------------------------------------------------------

    const shared = b.addLibrary(.{
        .name = "hpm_crypto",
        .root_module = root_mod,
        .linkage = .dynamic,
    });
    b.installArtifact(shared);

    // ------------------------------------------------------------------
    // Static library — convenience for bundling consumers
    // ------------------------------------------------------------------

    const static = b.addLibrary(.{
        .name = "hpm_crypto",
        .root_module = root_mod,
        .linkage = .static,
    });
    b.installArtifact(static);

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    const tests = b.addTest(.{
        .root_module = root_mod,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
