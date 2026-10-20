// scripts/lib/verify.mjs
//
// The "no libc leaked" check, adapted from cvm.
//
// cvmcrypt is freestanding. Every compiled object under src/ is scanned for
// undefined symbols; anything outside our own prefixes is a libc (or other
// foreign) dependency and fails the build.
//
// Allowed prefixes:
//   cvmcrypt_   our own cross-object references
//   rt_         cvm's platform layer — resolved at link time, not here

import fs from "node:fs";
import path from "node:path";
import { run, which } from "./exec.mjs";
import { mkdirp } from "./util.mjs";
import { compile } from "./cc.mjs";
import { flagsFor } from "./flags.mjs";

function allowedPrefixes(opts) {
    /*
     * cvmcrypt_ is our own cross-object references. rt_ is cvm's platform
     * layer, resolved at link time on the hosted side.
     *
     * Sanitizer instrumentation injects calls into the sanitizer runtime.
     * Those are compiler-injected, not a libc dependency, so they are
     * allowed only when the corresponding flag is on — same reasoning as
     * cvm's verify.mjs.
     */
    const base = ["cvmcrypt_", "rt_"];
    if (opts && opts.asan) {
        base.push("asan_", "sanitizer_");
    }
    if (opts && opts.tsan) {
        base.push("tsan_", "sanitizer_");
    }
    return base;
}

const PLATFORM_EXCEPTIONS = {
    darwin: [
        {
            symbol: "tlv_bootstrap",
            why:
                "Darwin implements thread-local variable access inside a " +
                "dylib through dyld's TLS bootstrap.",
        },
    ],
};

function wrap(text, width) {
    const words = text.split(/\s+/);
    const lines = [];
    let line = "";
    for (const w of words) {
        if (line.length + w.length + 1 > width) {
            lines.push(line);
            line = w;
        } else {
            line = line ? line + " " + w : w;
        }
    }
    if (line) lines.push(line);
    return lines;
}

function stripMachOSymbolNoise(sym) {
    return sym.replace(/^_+/, "");
}

function symbolsOf(nm, obj) {
    const r = run(nm, ["-u", obj], { allowFail: true });
    const undef = r.stdout
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0)
        /* `nm -u` prints a bare name on macOS but "<addr> U <name>" on Linux,
         * so the type letter stays glued to the symbol unless it is split off.
         * With it attached no allowlist prefix ever matched and every
         * legitimate cross-object reference was reported as a libc call. */
        .map((l) => l.split(/\s+/).pop())
        .map(stripMachOSymbolNoise);
    return { undef };
}

function foreignSymbols(nm, obj, runtimeDefines, report, opts) {
    const allowed = allowedPrefixes(opts);
    const exceptions = PLATFORM_EXCEPTIONS[process.platform] ?? [];
    const { undef } = symbolsOf(nm, obj);
    const foreign = [];

    for (const name of undef) {
        if (runtimeDefines.has(name)) continue;
        if (exceptions.some((e) => name.includes(e.symbol))) {
            report(exceptions.find((e) => name.includes(e.symbol)));
            continue;
        }
        if (allowed.some((p) => name.startsWith(p))) continue;
        foreign.push(name);
    }
    return foreign;
}

const PROBE_HEADERS = ["cvmcrypt/cvmcrypt.h", "base/mem.h", "base/secure.h"];

export function checkFreestanding({
    root,
    buildDir,
    opts,
    toolchain,
    verbose,
    ui,
    runtimeObjs = [],
}) {
    const tmp = path.join(buildDir, "tmp");
    mkdirp(tmp);

    const probe = path.join(tmp, "freestanding_probe.c");
    fs.writeFileSync(
        probe,
        [
            ...PROBE_HEADERS.map((h) => `#include "${h}"`),
            "",
            "/* Declares nothing, calls nothing: a clean probe has zero",
            " * undefined symbols. */",
            "void cvmcrypt_build_probe(void) {}",
            "",
        ].join("\n"),
    );

    const probeObj = compile({
        src: probe,
        obj: path.join(tmp, "freestanding_probe.o"),
        flags: flagsFor({ flavor: "freestanding", opts, toolchain, root }),
        toolchain,
        verbose,
        ui,
    });

    const nm = which("nm") || which("llvm-nm");
    if (!nm) {
        ui.log("verify: nm not found, symbol scan skipped");
        return true;
    }

    const applied = new Map();
    const report = (exception) => applied.set(exception.symbol, exception);

    const objects = [probeObj, ...runtimeObjs];

    const runtimeDefines = new Set();
    for (const obj of objects) {
        const r = run(nm, ["--defined-only", obj], { allowFail: true });
        for (const line of r.stdout.split("\n")) {
            const m = line.match(/^\S*\s*[A-Za-z]\s+(\S+)$/);
            if (m) runtimeDefines.add(stripMachOSymbolNoise(m[1]));
        }
    }

    const violations = [];
    for (const obj of objects) {
        const foreign = foreignSymbols(nm, obj, runtimeDefines, report, opts);
        if (foreign.length > 0) violations.push({ obj, foreign });
    }

    for (const exception of applied.values()) {
        ui.log(`verify: platform exception ${exception.symbol}`);
        for (const line of wrap(exception.why, 72)) ui.log(`        ${line}`);
    }

    if (violations.length > 0) {
        console.error("[verify] freestanding violation: foreign symbols");
        for (const v of violations) {
            console.error(`         ${path.relative(root, v.obj)}`);
            for (const s of v.foreign) console.error(`           ${s}`);
        }
        ui.fatal("src/ must not depend on libc");
    }

    const scanned = 1 + runtimeObjs.length;
    ui.log(`verify: freestanding ok (${scanned} object(s) scanned, 0 foreign)`);
    return true;
}
