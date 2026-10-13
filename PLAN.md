# cvmcrypt — 计划

一个可移植、freestanding、零 libc 依赖的密码学库。给 cvm 提供 TLS 1.3 与 X.509 能力。

## 0. 原则

**没有基座。** 不 fork libtomcrypt，不 vendor mbedtls。cvmcrypt 是我们自己的树，
文件一个一个搬进来，搬进来就按我们的规矩改写。

搬运 ≠ 拷贝。每个搬进来的文件都要过一遍下面的规矩，过完才算数。

### 代码规矩（来自 `cvm/rt/base/types.h`，全文强制）

1. **不用裸 C 标量** —— 只有 `i8..i64` / `u8..u64` / `f32` / `f64` / `usize` / `isize`。
   没有 `int` / `long` / `unsigned char` / `char`。
2. **没有 C 字符串** —— `char` 不存在。文本是 `(u8 const *ptr, usize len)`，永不假设 NUL 结尾。
3. **const 纪律** —— 指针参数默认 `T const *` 或 `T const * const`；可变指针是显式例外。
4. **只有定宽** —— `usize` / `isize` 只用于指针算术和尺寸。
5. **零 libc** —— 编译时 `-ffreestanding -nostdinc`，每个目标文件扫未定义符号，
   白名单只有 `cvm_` / `rt_` 前缀。
6. **没有间接层** —— 见 §0.1。

### 0.1 没有 ltc 的可移植性间接层

libtomcrypt 用一层宏做可移植性：`XMALLOC` / `XMEMCPY` / `XSTRLEN` / … 共 14 个
（全库 820 个调用点），加 `LTC_ARGCHK`（1890 个调用点），加 `tomcrypt_custom.h`
的配置块。这一层存在的理由是「让 ltc 能靠 `#define` 移植到没有 libc 的平台」。

**我们不是移植 ltc，我们是拿 ltc 的算法当源材料写 cvmcrypt。** 所以这一层整个不要：

| ltc 的写法 | cvmcrypt 的写法 | 说明 |
|---|---|---|
| `XMALLOC(n)` | `rt_mem_alloc(n)` | **rt/ 已有**，直接调 |
| `XREALLOC(p, n)` | `rt_mem_realloc(p, n)` | **rt/ 已有** |
| `XCALLOC(n, s)` | `rt_mem_alloc` + `rt_mem_zero` | **rt/ 已有**，两个已有函数组合 |
| `XFREE(p)` | `rt_mem_free(p)`，密钥材料走 `cvmcrypt_secure_free` | rt_mem_free 已有；secure_free 新写 |
| `XMEMSET(p, 0, n)` | `rt_mem_zero(p, n)` | **rt/ 已有** |
| `XMEMCPY` / `XMEMMOVE` / `XMEMCMP` | `src/base/mem.c` | rt/ 没有暴露；freestanding 必须自有（同 `vm/mem.c`） |
| `XMEM_NEQ` | `cvmcrypt_ct_eq` | 常数时间，新写 |
| `XSTRLEN` / `XSTRCMP` / `XSTRNCPY` | **不存在** | cvm 没有 `char`；这些函数不搬、不替代、调用点消失 |
| `XCLOCK()` | `rt_time_nanos()` | **rt/ 已有** |
| `XQSORT` | `cvm_rqsort`（`rt/base/sort.h`） | **rt/ 已有** |
| `LTC_ARGCHK(x)` | cvmcrypt 自己的错误返回 | 随文件改写

`tomcrypt_custom.h` 整个文件不搬。

**一个安全后果要写明**：`XFREE` 换成 `rt_mem_free` 就丢了清零。密钥材料
（私钥、会话密钥、bignum 中间值）必须走 `cvmcrypt_secure_free`，它先
`rt_mem_zero` 再 `rt_mem_free`。这是新写的一块，不能省。

### 依赖规矩

- 库引用走 `rt/`，不直接碰平台。
- **运行时 CPU 检测**（决定走哪条 SIMD 路径）是平台相关代码，放 `rt/` PAL，
  不放在密码学文件里。
- 时间从 `rt_time_*` 来，不用 `clock()`。
- **分配走 `rt_mem_alloc`，不走 GC 堆。** `rt/` 的注释写得很清楚：这是给运行时
  簿记用的通用分配器，不是收集器的堆。密码学材料放在 GC 堆上会被收集器搬动、
  被非确定性地回收，而且无法可靠清零。

## 1. 目录

```
cvmcrypt/
  PLAN.md               本文件
  README.md
  LICENSE               Unlicense（ltc 来源部分）
  LICENSE-APACHE        Apache-2.0（mbedtls 来源部分）
  NOTICE                来源与修改说明
  include/cvmcrypt/     公开头文件
  src/
    base/               类型、字节序、清零、常数时间工具
    math/               bignum 与 ltc math descriptor 适配层
    cipher/             AES、ChaCha20
    aead/               GCM、ChaCha20-Poly1305
    hash/               SHA-256/384/512、HMAC、HKDF
    kx/                 X25519、ECDHE
    pk/                 RSA、ECDSA（验签侧）
    asn1/               DER 解码
    x509/               证书解析与链验证
    simd/               vector 扩展与各平台 intrinsic
    registry/           算法描述符表
  tests/                KAT + 差分测试
  bench/                吞吐与握手
```

`src/` 下没有第三方代码的目录结构，只有我们自己的组织方式。

## 2. 搬运清单

行数是**原始文件的实测值**（不是改完之后的）。改写成 cvm 风格后通常 ±20%，
因为去掉 NUL 字符串假设和 `unsigned long` 会让签名变长、样板变短。

### 2.1 从 libtomcrypt develop 搬（Unlicense）

| 模块 | 来源 | 行数 |
|---|---|---|
| AEAD（AES + GCM） | `ciphers/aes/{aes,aes_tab,aes_desc}.c`、`encauth/gcm/*.c` | 3655 |
| ChaCha20 + Poly1305 | `stream/chacha/*.c`、`encauth/chachapoly/*.c`、`mac/poly1305/*.c` | 1556 |
| SHA-2 | `hashes/sha2/{sha256,sha512,*_desc}.c` | 1190 |
| HMAC | `mac/hmac/*.c` | 1133 |
| X25519 | `pk/x25519/*.c` | 276 |
| RSA（仅验签） | `pk/rsa/` 8 个 + `pk/pkcs1/` 5 个 | 1625 |
| ECC（仅验签） | `pk/ecc/` 16 个 | 2295 |
| DER（仅解码） | `pk/asn1/der/der_decode*.c` 等 | 3003 |
| x509 提取 + OID + PKCS8 | `pk/asn1/{x509,oid,pkcs8}/` | 1002 |
| 算法注册表 | `misc/crypt/` 11 个 | 904 |
| 支撑 | `misc/{zeromem,burn_stack,mem_neq,copy_or_zeromem}.c`、`misc/hkdf/` | 568 |
| **小计** | | **17207** |

**不搬**：全部编码器（`der_encode*` / `der_length*`）、`crypt_constants.c`、`crypt_sizes.c`、
`pem_ssh.c`、SSH 相关、SM4/SM3、以及 TLS 1.3 用不到的分组密码与模式。
（ltc 全库 557 个 .c / 91K 行，这里只要 17K。）

### 2.2 从 mbedtls 3.6.7 搬（Apache-2.0）

| 模块 | 来源 | 行数 |
|---|---|---|
| bignum | `library/{bignum,bignum_core,bignum_mod,bignum_mod_raw}.c` | 4493 |
| x509 解析与验证 | `library/{x509_crt,x509,x509_crl}.c` | 5795 |
| ASN.1 + OID | `library/{asn1parse,oid}.c` | 1634 |
| 平台工具 | `library/platform_util.c` | 258 |
| 内部头 | `library/{common,x509_internal}.h` | 588 |
| 公开头（重写） | `x509.h`、`x509_crt.h`、`x509_crl.h`、`oid.h`、`asn1.h` | 3261 |
| **小计** | | **16029** |

**不搬**：`error.c`（用自己的错误串）、`threading.c`、`pem.c`、`platform.c`、
`x509_csr.c`、`x509_create.c`、`x509write*.c`、`pkcs7.c`、`md.c`、以及 mbedtls 自己的
AES/SHA/bignum 以外的 crypto。

### 2.3 新写

| 模块 | 说明 | 预估 |
|---|---|---|
| `src/base/mem.c` | `memcpy` / `memmove` / `memset` / `memcmp`，freestanding 必须自有（rt/ 不暴露这些） | 150 |
| `src/base/secure.c` | `cvmcrypt_secure_free`（清零+释放）、`cvmcrypt_ct_eq`（常数时间比较） | 80 |
| SIMD — ChaCha20 | 编译器 vector 扩展，**一份源码双平台**，4 车道 16 字节 | 200 |
| SIMD — arm64 AES | `vaeseq` / `vaesmcq` intrinsic | 90 |
| SIMD — arm64 SHA-256 | `sha256h` / `sha256h2` / `sha256su0/1` | 100 |
| SIMD — arm64 SHA-384/512 | `sha512h` / `sha512h2` / `sha512su0/1` | 120 |
| SIMD — amd64 批量 AES-CTR | VAES / AVX2 intrinsic | 250 |
| SIMD — 运行时派发 | 走 `rt/` PAL | 80 |
| ltc math descriptor 适配层 | mbedtls bignum → `ltc_mp` 的 40+ 个槽 | 600 |
| mbedtls pk 层（ltc 版） | `mbedtls_pk_info_t` vtable 的 ltc 实现 | 400 |
| x509 补丁 | SPKI 导入 / `verify_ext` 的 PSS 分支 / `get_ec_group_id` | 150 |
| picotls 后端 | 算法表 + `verify_certificate` 回调 | 1300 |
| 公开 API | `cvmcrypt_*` 面 | 500 |
| **小计** | | **3790** |

### 2.4 总量

| | 行数 |
|---|---|
| 搬运（ltc） | 17207 |
| 搬运（mbedtls） | 16029 |
| 新写 | 4130 |
| **合计** | **~37300** |

范围：**33000 – 42000 行**。区间来自两点不确定：改写后的膨胀率（±20%），
以及 x509 里有多少 mbedtls 特有的东西要拆掉。

**不含测试。** KAT 语料和差分 harness 另算，预计 +2000。

### 2.5 与现有第三方库的对比

| | 行数 | 说明 |
|---|---|---|
| libtomcrypt 全库 | 91K | 我们只要其中 17K |
| mbedtls 3.6.7 全库 | ~180K | 我们只要其中 16K |
| **cvmcrypt** | **~37K** | 是两者的**并集**，但都裁到最小 |

注意 37K ≈ 17K + 16K + 4K，**不比单用 mbedtls 小多少**。换来的东西是：
零 libc、零 malloc、cvm 类型系统、以及可控的 SIMD。

## 3. 搬运方法

**每个文件走完整个流水线才碰下一个。** 不是先搬完所有文件再加 SIMD，
是每个文件一次性做到位：

```
搬运一个文件
  ↓ 类型改写（u8/u16、const 默认、定宽、零 libc、无 X* 宏、无 LTC_ARGCHK）
  ↓ SIMD（编译器 vector 扩展 + 各平台 intrinsic，运行时派发）
  ↓ 单测（KAT 向量从 ltc 的 *_test.c 一起搬）
  ↓ 全绿 → 下一个文件
```

### 每个文件的验收标准

1. **不比现在慢** —— 不慢于原 ltc 标量实现；SIMD 版至少打平
2. **代码符合规范** —— u8/u16、const 默认、定宽、零 libc、无 X* 宏、无 LTC_ARGCHK
3. **单测全过** —— KAT 向量全绿，freestanding audit 全绿

三条都过才碰下一个文件。不满足就修到满足。

### 文件顺序（从最独立、KAT 最标准、SIMD 路径最清晰的开始）

| 序 | 文件 | 来源 | 行数 | SIMD |
|---|---|---|---|---|
| 1 | sha256 | `hashes/sha2/sha256.c` + `sha256_desc.c` | 313+199 | arm64 `sha256h` intrinsic；amd64 SHA-NI |
| 2 | sha512/384 | `hashes/sha2/sha512.c` + desc | 287+263 | arm64 `sha512h`；amd64 AVX2 |
| 3 | hmac | `mac/hmac/*.c` | 1133 | — |
| 4 | aes | `ciphers/aes/{aes,aes_desc}.c` | 742+287 | arm64 `vaeseq`；amd64 AES-NI |
| 5 | gcm | `encauth/gcm/*.c` | 1197 | arm64 PMULL（ltc 已有）；amd64 PCLMUL（ltc 已有） |
| 6 | chacha20 | `stream/chacha/*.c` | 500 | **编译器 vector 扩展，一份双平台** |
| 7 | poly1305 | `mac/poly1305/*.c` | 258+ | — |
| 8 | chachapoly | `encauth/chachapoly/*.c` | 381 | — |
| 9 | x25519 | `pk/x25519/*.c` | 276 | — |
| 10 | hkdf | `misc/hkdf/*.c` | 568-1133 | — |
| 11 | rsa verify | `pk/rsa/` 8 个 + `pk/pkcs1/` 5 个 | 1625 | — |
| 12 | ecc | `pk/ecc/` 16 个 | 2295 | — |
| 13 | der decode | `pk/asn1/der/der_decode*.c` | 3003 | — |
| 14 | x509 extract | `pk/asn1/{x509,oid,pkcs8}/` | 1002 | — |
| 15 | registry | `misc/crypt/` 11 个 | 904 | — |
| 16+ | mbedtls bignum + x509 | 见 §2.2 | 16029 | — |

## 4. 验收总则

- **KAT 是唯一的标准。** 每个算法搬进来时，它自带的测试向量一起搬。
- **性能改动要有对照。** 同 session 交替跑，低于 3% 视为噪声；给与 bdwgc/go 的对比。
- **落改动前跑 debug / release / asan / tsan / bench。**
- **x509 用差分测试**：同一批语料喂 cvmcrypt 和 mbedtls，逐条比判决。

## 5. 待定

1. **AES 的 S-box**：查表（快，有 cache-timing 泄漏）vs bitslice（常数时间，慢一个数量级）。
   两条路都记在案，等 SIMD 期再定。
2. **RSA 是否要私钥侧**（签名/解密）：现在只搬验签。若要 TLS 服务端，要补
   `rsa_make_key` / `rsa_sign_hash` / CRT / 盲化，约 +400 行。
3. **CRL 是否要**：`x509_crl.c` 708 行已在清单里，但撤销检查是可选功能。
4. **曲线范围**：只 P-256/384/521，还是保留 ltc 的全套（secp256k1、brainpool）。
   ltc 的 ECC 是通用的，砍曲线省不了多少行。

## 6. 已知风险

- **x509 策略正确性**：RFC 5280 合规 ≠ 现实兼容。差分测试是唯一的保险。
- **常数时间**：搬运时不得把常数时间实现"优化"成变量时间。
- **改写膨胀**：cvm 风格比 C 风格冗长（显式类型、显式长度），37K 可能变大。
- **清零**：丢掉 `XFREE` 的间接层后，没有任何机制强制密钥材料走
  `cvmcrypt_secure_free`。这是个纪律问题，不是编译器能查的 —— 需要在
  代码审阅里盯。
- **集成**：cvmcrypt 是 freestanding，但 `scripts/lib/flags.mjs` 现在只把 `vm/`
  划入 freestanding flavor。cvmcrypt 需要一个自己的 flavor，或者被加进那一组。
  另外它的 `src/base/mem.c` 和 `vm/mem.c` 会各有一份 memcpy —— 要么接受重复，
  要么把这一层提到 `rt/`。未定。
