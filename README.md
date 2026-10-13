# cvmcrypt

A freestanding, zero-libc cryptography library for [cvm](../cvm).

See [PLAN.md](PLAN.md) for the design and roadmap.

## Build

```
node scripts/build.mjs              # build src/
node scripts/build.mjs --test       # build src/ + tests/
node scripts/run-tests.mjs          # run all test binaries
```

## Conventions

cvmcrypt follows cvm's coding rules (`../cvm/rt/base/types.h`):
`u8`/`u16`/`u32`/`u64`, no `char`, no NUL-terminated strings,
`const` by default, fixed-width only, zero libc.

The library references cvm's `rt/` for platform primitives
(`rt_mem_alloc`, `rt_mem_zero`, `rt_time_nanos`, `cvm_rqsort`).
