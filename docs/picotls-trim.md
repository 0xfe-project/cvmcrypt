# picotls 裁剪清单（TLS 1.3 only）

## 源码分析结果

picotls.c 共 **7353 行**，约 208 个函数。

## 要砍掉的

| 类别 | 行数 | 原因 |
|---|---|---|
| TLS 1.2 专属 | ~244 | handle_input_tls12, tls12_phash, export/import_tls12, build_tls12_aad |
| ECH (Encrypted Client Hello) | ~325 | 8 个函数，Cloudflare 扩展，非 RFC 8446 核心 |
| 日志系统 | ~308 | ptls_log__ 系列全部，走 cvm 自己的日志 |
| import/export 状态 | ~200 | ptls_import/ptls_export（进程间传 TLS 状态，不用） |
| QUICLB | ~40 | CDN 负载均衡加密，跟 TLS 无关 |
| **合计砍掉** | **~1117** | |

## 保留的 QUIC 支持

- `ptls_encode/decode_quicint` + `adjust_quic_blocksize`（~40 行）— varint 工具
- `ptls_handle_message` / `ptls_client_handle_message` / `ptls_server_handle_message` + `raw_message_emitter`（~80 行）— 让 QUIC 栈跳过 record layer，直接拿握手明文（未来 HTTP/3 需要）

## 保留的（按搬迁顺序）

| 类别 | 行数 | 函数数 | 说明 |
|---|---|---|---|
| decode 工具 | ~90 | 8 | ptls_decode8/16/24/32/64, quicint |
| buffer 工具 | ~125 | 8 | reserve/pushv/adjust, ASN.1 push |
| record AEAD | ~345 | 15 | parse_record, encrypt/decrypt, build_iv |
| HKDF/HMAC | ~119 | 7 | hkdf_extract/expand/expand_label, hmac |
| key schedule | ~234 | 16 | derive_secret, traffic_protection, extract |
| handshake 消息 decode | ~460 | — | decode_client_hello(300), decode_server_hello(161) |
| client handshake | ~1212 | 12 | send_client_hello(243), encode_client_hello(191), handle_* |
| server handshake | ~1003 | 12 | server_handle_hello(606), server_finish, decode_sh |
| session ticket | ~223 | 4 | send/decode_ticket, client_handle_new_session_ticket |
| API 入口 | ~238 | 10 | ptls_handshake, ptls_send, ptls_receive |
| 杂项（PSK、HRR、extensions） | ~1148 | 50 | try_psk, hello_retry, extension_bitmap |
| **保留合计** | **~5197** | **~144** | |

## 砍掉后的估算

- picotls.h: 2262 → ~1200 行（砍 TLS 1.2 类型、ECH、日志、QUIC）
- picotls.c: 7353 → ~5200 行（改写成 cvm 规范后可能膨胀 20% ≈ 6200 行）
- crypto 回调层: ~500 行（新写）
- **TLS 模块总计: ~7900 行**

## TLS 1.2-only 的具体函数（直接不搬）

```
build_tls12_aad          L753   10 行
export_tls12_params      L5296  23 行
ptls_build_tls12_export  L5320  39 行
import_tls12_traffic     L5394  26 行
handle_input_tls12       L6031  64 行
ptls_tls12_phash         L6480  40 行
```

## ECH 的具体函数（直接不搬）

```
clear_ech                    L997   18 行
decode_one_ech_config        L1020  92 行
client_decode_ech_config_list L1113 37 行
client_setup_ech             L1151  31 行
client_setup_ech_grease      L1183  43 行
ech_calc_confirmation        L1229  31 行
client_ech_select_hello      L2842  36 行
ptls_ech_encode_config       L6780  24 行
```

## 日志函数（直接不搬）

```
所有 ptls_log__ 开头的 15 个函数
expand_logbuf_or_invalidate
close_log_fd
duplicate_stringlist / is_in_stringlist / is_in_addresslist
byte_to_hex
```

## struct st_ptls_t 内要砍的字段

```
struct st_ptls_ech_t *ech;         // ECH 状态
// 日志相关不需要（走 cvm 自己的）
```

## picotls.h 要砍的类型

```
ptls_hpke_kem_t / ptls_hpke_cipher_suite_t / ptls_hpke_suite_t   // ECH 用
ptls_log_* 全部                                                    // 日志
ptls_build_tls12_export_params                                     // TLS 1.2
```
