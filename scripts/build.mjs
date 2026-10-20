// scripts/build.mjs
//
// Orchestration for cvmcrypt.
//
//   src/   freestanding — no libc, references vendor/cvm/rt for types
//   tests/ hosted — ordinary userland, links the library objects
//
// The freestanding audit runs on every build, in every configuration.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseArgs, help } from "./lib/args.mjs";
import { logger, mkdirp, rmrf, collect } from "./lib/util.mjs";
import { discover } from "./lib/toolchain.mjs";
import { flagsFor, sanitizerFlags } from "./lib/flags.mjs";
import { compile, link, objectPath } from "./lib/cc.mjs";
import { checkFreestanding } from "./lib/verify.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BUILD = path.join(ROOT, "build");

const ui = logger("build");
const opts = parseArgs(process.argv.slice(2));

if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(help.usage);
    for (const o of help.options) console.log(`  ${o}`);
    process.exit(0);
}

function clean() {
    rmrf(BUILD);
    ui.log("cleaned build/");
}

function compileTree({ dir, flavor, toolchain, verbose }) {
    /*
     * Assembly is per-architecture and must not be assembled for the wrong
     * one: `gcm_arm64.S` fails outright on an x86_64 assembler, and the other
     * way round would silently produce nothing for the fast path. The file
     * name is the contract — `_arm64` and `_amd64` are the only suffixes a
     * file in this tree may carry.
     */
    const arch = process.arch;
    const srcs = collect(dir, [".c", ".S"]).filter((f) => {
        if (!f.endsWith(".S")) return true;
        if (f.endsWith("_arm64.S")) return arch === "arm64";
        if (f.endsWith("_amd64.S") || f.endsWith("_x86_64.S")) return arch === "x64";
        return true;
    });
    const objs = [];

    for (const src of srcs) {
        const obj = objectPath({
            root: ROOT,
            buildDir: BUILD,
            config: opts.config,
            flavor,
            src,
        });
        objs.push(
            compile({
                src,
                obj,
                flags: flagsFor({ flavor, opts, toolchain, root: ROOT }),
                toolchain,
                verbose,
                ui,
            }),
        );
    }

    return { srcs, objs };
}

function buildLibrary(toolchain) {
    const lib = compileTree({
        dir: path.join(ROOT, "src"),
        flavor: "freestanding",
        toolchain,
        verbose: opts.verbose,
    });

    if (lib.objs.length === 0) {
        ui.log("library: no sources yet (headers only)");
        return { objs: [] };
    }

    ui.log(`library: ${lib.objs.length} object(s) (freestanding)`);
    return { objs: lib.objs };
}

function buildTests(toolchain, libObjs) {
    const binDir = path.join(BUILD, "bin");
    rmrf(binDir);
    mkdirp(binDir);

    /* The platform stub: cvmcrypt calls rt_mem_alloc and friends, resolved
     * by cvm's rt/ when linked into cvm, and by tests/support/rt_stub.c
     * when linked into a test binary. Compiled hosted, linked into every
     * test, never reachable from src/. */
    const stubObj = compile({
        src: path.join(ROOT, "tests", "support", "rt_stub.c"),
        obj: objectPath({
            root: ROOT,
            buildDir: BUILD,
            config: opts.config,
            flavor: "hosted",
            src: path.join("tests", "support", "rt_stub.c"),
        }),
        flags: flagsFor({ flavor: "hosted", opts, toolchain, root: ROOT }),
        toolchain,
        verbose: opts.verbose,
        ui,
    });

    const srcs = collect(path.join(ROOT, "tests"), [".c"]).filter(
        (f) =>
            !f.includes(path.join("tests", "support")) &&
            !f.includes(path.join("tests", "integration")),
    );
    if (srcs.length === 0) {
        ui.log("tests: none found");
        return [];
    }

    const bins = [];
    for (const src of srcs) {
        const obj = compile({
            src,
            obj: objectPath({
                root: ROOT,
                buildDir: BUILD,
                config: opts.config,
                flavor: "hosted",
                src,
            }),
            flags: flagsFor({ flavor: "hosted", opts, toolchain, root: ROOT }),
            toolchain,
            verbose: opts.verbose,
            ui,
        });

        const bin = path.join(BUILD, "bin", path.basename(src, ".c"));
        link({
            objs: [obj, ...libObjs, stubObj],
            out: bin,
            toolchain,
            flags: sanitizerFlags(opts),
            verbose: opts.verbose,
            ui,
        });
        bins.push(bin);
    }

    ui.log(`tests: ${bins.length} binaries`);
    return bins;
}

function main() {
    if (opts.clean) return clean();

    const toolchain = discover();

    ui.log(
        `toolchain: ${toolchain.cc}${toolchain.isClang ? " (clang)" : ""}` +
            `${toolchain.ccache ? " + ccache" : ""}` +
            `${toolchain.mold ? " + mold" : ""}` +
            ` · config=${opts.config}` +
            `${opts.asan ? " · asan" : ""}${opts.tsan ? " · tsan" : ""}`,
    );

    mkdirp(BUILD);

    fs.writeFileSync(
        path.join(BUILD, "config.json"),
        JSON.stringify({ sanitizer: opts.sanitizer, config: opts.config }) + "\n",
    );

    const lib = buildLibrary(toolchain);

    if (opts.test) buildTests(toolchain, lib.objs);

    checkFreestanding({
        root: ROOT,
        buildDir: BUILD,
        opts,
        toolchain,
        verbose: opts.verbose,
        ui,
        runtimeObjs: lib.objs,
    });

    ui.log("done");
}

main();
