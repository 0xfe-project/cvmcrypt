// scripts/lib/flags.mjs
//
// Compiler flag sets for cvmcrypt.
//
//   freestanding  src/ — no libc at all, references cvm's rt/ headers
//   hosted        tests/ — ordinary userland, libc allowed
//
// The platform boundary is cvm's rt/ (submodule at vendor/cvm): cvmcrypt
// calls rt_mem_alloc and friends, which live on the hosted side and are
// resolved at link time. The freestanding audit allows rt_ as a prefix
// for exactly that reason.

import path from "node:path";
import { freestandingInclude } from "./toolchain.mjs";

export const STD = "-std=c11";

const COMMON = [STD, "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-fno-common"];

export const DEBUG_FLAGS = ["-g", "-O0", "-fno-omit-frame-pointer", "-DCVM_DEBUG"];
export const RELEASE_FLAGS = ["-O2", "-DNDEBUG"];

export function sanitizerFlags({ asan, tsan }) {
    if (asan) return ["-fsanitize=address"];
    if (tsan) return ["-fsanitize=thread"];
    return [];
}

/**
 * The platform's feature-test macro, where one is needed. Same reasoning
 * as cvm's: -std=c11 turns on __STRICT_ANSI__, which hides the BSD jump
 * API on glibc.
 */
function featureTestFlags() {
    return process.platform === "linux" ? ["-D_GNU_SOURCE"] : [];
}

function commonFor(opts) {
    return [...COMMON, ...featureTestFlags()];
}

/**
 * Include paths.
 *
 *   vendor/cvm/rt   so `#include "base/types.h"` and `#include "rt.h"` resolve
 *   include/        public API: `#include "cvmcrypt/cvmcrypt.h"`
 *   src/            internal headers
 *   tests/          hosted only — the test framework lives there
 */
export function includeFlags(root, flavor) {
    const dirs = [
        path.join(root, "vendor", "cvm", "rt"),
        path.join(root, "include"),
        path.join(root, "src"),
    ];
    if (flavor === "hosted") dirs.push(path.join(root, "tests"));
    return dirs.flatMap((d) => ["-I", d]);
}

export function flagsFor({ flavor, opts, toolchain, root, extra = [] }) {
    const base =
        flavor === "freestanding"
            ? [
                  ...commonFor(opts),
                  "-ffreestanding",
                  "-nostdinc",
                  "-fno-stack-protector",
                  ...freestandingInclude(toolchain.cc, toolchain.isClang),
              ]
            : commonFor(opts);

    return [
        ...base,
        ...(opts.release ? RELEASE_FLAGS : DEBUG_FLAGS),
        ...sanitizerFlags(opts),
        ...includeFlags(root, flavor),
        ...extra,
    ];
}
