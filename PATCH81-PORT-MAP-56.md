---
name: patch81_port_map_56
title: 官方 8.1 回补补丁在 PHP 5.6 上的移植对照
description: 逐个文件对照官方 8.1 安全回补（20 个文件 +287/-72）在 PHP 5.6.40 上的可移植性，分「可照搬 / 需改造 / 改不动」三类，给出每一项的依据与代价
summary: 5 个文件可照搬、5 处需改造、8 处改不动；改不动的核心原因是 5.6 没有 zend_string、ZVAL_UNDEF、ZEND_ASSERT、CS cache 这些 7.0+ 才有的基础设施
keywords:
  - PHP5.6
  - 8.1回补
  - 补丁移植
  - '109618'
  - '109619'
  - zend_alloc
category: 安全研究/PHP
---

# 官方 8.1 回补补丁在 PHP 5.6 上的移植对照

## 一、这份对照在回答什么

我先前做了一份 5.6 的最小补丁（`php2shell-56-109618.patch`），只改 `Zend/zend_alloc.c`，实测把 OOM 退出码从 255 改成了 1，证明 `longjmp` 被从 OOM 出口摘掉了。

但官方 8.1 的回补是 **20 个文件、+287/-72**。差这么多，到底差在哪、能不能补齐、补齐要付什么代价，就是这份文档要回答的。

**数据来源**：`p81.patch`（官方 8.1 分支安全回补）、`php-5.6.40.tar.xz` 原始源码（未打补丁，校验 `zend_mm_safe_error_ex` 命中 0 处）。

（说明：文件清单里共有 23 个条目，其中 3 个是 `.phpt` 测试文件，实际改动落在 20 个文件上。）

## 二、先看 5.6 和 8.1 的四道结构性鸿沟

这不是「改几个函数名」的问题。5.6 缺少 7.0 之后才有的四样基础设施，导致官方的很多改动在 5.6 上**没有落点**。

| 基础设施 | 8.1 有 | 5.6 有 | 后果 |
|---|---|---|---|
| `zend_string` 类型 | 有（7.0 引入） | **没有**（`zend_types.h` 中 0 处） | 官方新版 `zend_mm_safe_error_ex` 签名用 `zend_string *script_filename`，5.6 只能用 `const char *` |
| `zend_get_executed_filename_ex()` | 有 | **没有**（只有无 `_ex` 的 `zend_get_executed_filename()`，还带 `TSRMLS_D`） | 取文件名的方式不同，需改写 |
| `ZVAL_UNDEF` / 统一 zval | 有 | **没有**（5.6 是 `zval` 结构体 + `IS_NULL`） | 官方用 `ZVAL_UNDEF(&PG(http_globals)[i])` 做的「安全空值初始化」，5.6 得换成别的写法 |
| `ZEND_ASSERT` | 有（7.x 引入） | **没有**（`zend_types.h` 中 0 处） | opcache 那批代码大量依赖 `ZEND_ASSERT`，5.6 上要么去掉、要么换成自定义宏 |

另外两处不是鸿沟但同样致命：

- **`zend_new_array_singleton()`**：8.1 新增的函数，5.6 完全没有（`grep` 无任何命中）。官方的 `array_init_singleton` 宏、`php_variables.c` 里 4 处 `array_init` 改写，全都建立在它之上。
- **opcache 的 CE cache 机制**：5.6 的 opcache 里 `get_class_name_map_ptr`、`CE_CACHE`、`map_ptr_last` **一个都没有**。8.1 补丁给 opcache 加的 4 个文件共 +63 行，全部围绕这套 8.x 才有的机制。

## 三、逐文件对照

### A 类：可照搬（5.6 有语义等价位置，改动直接套用）

| 文件 | 官方改动 | 5.6 情况 | 移植说明 |
|---|---|---|---|
| `Zend/zend_alloc.h` | +1：声明 `zend_mm_safe_error_ex` | 文件存在 | 直接加一行声明 |
| `Zend/zend_strtod.c` | +2/-2：`Balloc()` 失败改走 `zend_mm_safe_error_ex` | 有 `Balloc()`（第 476 行），当前用 `zend_error(E_ERROR, "Balloc() failed to allocate memory")`（第 493 行） | 把 `zend_error` 换成新的 safe_error_ex 即可，逻辑等价 |
| `main/SAPI.c` | +5：请求开始时把 `SG(request_info)` 的 `auth_user`/`auth_password`/`auth_digest`/`content_type_dup`/`current_user` 显式置 NULL | 结构体字段同名同义 | 直接照搬，属防御性初始化 |
| `ext/session/session.c` | +1/-1：把 upload_progress 的判断改成恒不进入（等价于整段禁用） | 第 822 行 `STD_PHP_INI_BOOLEAN("session.upload_progress.enabled", ...)` | **代价最小、收益最直接的一项**，一行改动就能切断 109619 的 session 路径 |
| `main/rfc1867.c`（后半段） | `substring_conf()` 的 `int len` → `size_t len`，去 3 处 int 强转 | 有 `substring_conf` | 纯整数宽度修正，直接套用 |

### B 类：需改造（有对应位置，但形态不同，得重写）

| 文件 | 官方改动 | 5.6 情况 | 改造要点 |
|---|---|---|---|
| `Zend/zend_alloc.c` | +40/-20：新增 `zend_mm_safe_error_ex`，用 `zend_string *` + `zend_is_executing()` + `zend_get_executed_filename_ex()` | 已在我的补丁里做了**简化版**：用 `const char *` + `TSRMLS_FETCH()` + `zend_get_compiled_filename()` / `EG(active_op_array)->filename` | 已可用（退出码实测 255→1）。与官方版的差距在「取文件名/行号」的完整度，不影响 `_exit(1)` 这个核心行为 |
| `Zend/zend_execute_API.c` | +14：`EG(user_error_handler)`/`EG(user_exception_handler)` 改 `ZVAL_UNDEF`，其余用 `memset` 清零；补 `EG(record_errors)`/`EG(errors)`/`EG(error_handling)`/`EG(exception)`/`EG(objects_store)` 初始化 | 5.6 已有这些初始化（153 行 `EG(error_handling) = EH_NORMAL;`、168 行 `EG(user_error_handler) = NULL;`），但用的是**直接赋 NULL** | 5.6 原本就有等价初始化，属于「8.x 重构后丢过一次、官方补回来」。**5.6 这条路径基本不需要动**，只需确认 `EG(objects_store).top` 在 bailout 后被正确重置 |
| `main/main.c` | +5：`ZVAL_UNDEF(&PG(http_globals)[i])` + `clear_last_error()` + `PG(modules_activated) = 0` | 有 `PG(http_globals)`（1785 行），但无 `ZVAL_UNDEF`、无 `modules_activated` | 前两项可用 5.6 等价写法替代（`ZVAL_NULL` / 手动清 `PG(last_error_*)`）；**`modules_activated` 在 5.6 不存在**，这条要放弃 |
| `main/php_variables.c` | 4 处 `array_init` → `array_init_singleton` | 用的是 `array_init` | 依赖 `zend_new_array_singleton`（5.6 无）。**可以跳过**——singleton 是性能优化 + 空数组共享，不是安全修复的必要条件 |
| `main/rfc1867.c`（前半段，头白名单） | +19/-7：新增 `php_mime_should_save_hdr()`，只保留 `Content-Disposition`/`Content-Type`，丢弃重复头 | 已有 `php_mime_get_hdr_value()`（第 465 行，可直接复用），**没有** `php_mime_should_save_hdr` | **这是 109618 的关键一环**（对应「52x 内存放大」那条）。需新写一个 10 行的 `should_save_hdr`，并在解析处插入去重逻辑。**改造成本低、收益高** |
| `Zend/zend_multiply.h` | +2/-2 | 5.6 该文件只有 `ZEND_SIGNED_MULTIPLY_LONG` 宏，**没有** `safe_address` | 官方的溢出检查在 8.x 的 `zend_multiply.h`，5.6 的 `safe_address` 在 `zend_alloc.c` 里（已在我的补丁中处理）。**这条在 5.6 上无对应位置，归到 A 类的等价工作已完成** |

### C 类：改不动 / 不适用（5.6 无对应结构）

| 文件 | 官方改动 | 为什么改不动 |
|---|---|---|
| `Zend/zend_API.h` | +1：`array_init_singleton` 宏 | 依赖 `zend_new_array_singleton()`，5.6 无此函数 |
| `Zend/zend_hash.h` | +1：声明 `zend_new_array_singleton` | 同上，须先实现一个 5.6 版的 singleton 数组，属重构而非修复 |
| `Zend/zend_hash.c` | +9/-3：`zend_new_array_singleton` 实现 + 溢出检查改 safe_error_ex | singleton 部分改不动；**溢出检查部分可做**（5.6 的 `zend_hash.c` 里 `zend_error_noreturn` 命中 0 处，说明 5.6 本就没有这些检查点，属 7.x+ 新增的分配路径） |
| `Zend/zend_types.h` | +15/-11：`ZEND_ASSERT` 相关 | 5.6 无 `ZEND_ASSERT` 基础设施，要补就得先移植整个断言框架，代价远超收益 |
| `Zend/zend_vm_def.h` | +10/-1：VM 里的整数溢出检查改 safe_error_ex | 5.6 的 VM 里**没有任何**对应检查点（`grep` 命中 0），无落点 |
| `Zend/zend_vm_execute.h` | +86/-8：VM 生成文件同步（22 处 safe_error_ex） | 同上，5.6 的 VM 无这些检查点。且该文件是**生成产物**，手改会被 `make` 覆盖 |
| `ext/opcache/ZendAccelerator.c` | +4：pending_ce_cache begin/commit/discard | 5.6 opcache 无 CE cache 机制 |
| `ext/opcache/ZendAccelerator.h` | +9/-1：`HashTable *pending_ce_cache` 字段 + 3 个函数声明 | 同上 |
| `ext/opcache/zend_file_cache.c` | +8：失败路径里的 discard | **5.6 根本没这个文件** |
| `ext/opcache/zend_persist.c` | +51/-7：三个 pending_ce_cache 函数实现，用 `zend_string`/`ZSTR_HAS_CE_CACHE`/`GC_ADD_FLAGS`/`ZEND_HASH_FOREACH_NUM_KEY_VAL` | 5.6 的 opcache 持久化模型完全不同，没有共享类名映射表这套东西。**这是 8.x 独有的「持久化窗口」问题**，5.6 架构上不存在 |

## 四、移植代价汇总

| 类别 | 文件数 | 说明 |
|---|---|---|
| 可照搬 | 5 | 直接套用，半小时内可完成 |
| 需改造 | 6（含 1 项已完成的等价工作） | 其中 `main/rfc1867.c` 的头白名单改造性价比最高 |
| 改不动 | 10 | 集中在 VM 检查点、singleton 数组、opcache 持久化三块，都是 7.0/8.x 新增的基础设施 |

**净效果**按实际投入产出分层，而不是简单相加：

| 优先级 | 项 | 说明 |
|---|---|---|
| 已完成 | `Zend/zend_alloc.c` | 退出码 255→1 已实测 |
| 高性价比（2 项） | `ext/session/session.c`（1 行）、`main/rfc1867.c` 头白名单（约 10 行） | 分别切断 109619 的 session 路径与 109618 的内存放大路径 |
| 可选补齐（3 项） | `zend_strtod.c`、`main/SAPI.c`、`main/main.c` 中可用 5.6 等价写法替代的部分 | 防御性加固，不改也能跑 |
| 不必做（3 项） | `php_variables.c`（singleton 是性能优化，非安全修复）、`zend_execute_API.c`（5.6 本就有等价初始化）、`zend_multiply.h`（5.6 无 `safe_address` 落点，等价工作已随 `zend_alloc.c` 完成） | 做了没有安全收益 |

剩下 10 个改不动的，不是「偷懒」，而是 5.6 的代码库里压根没有那些位置。

## 五、一个反直觉的结论

官方的 opcache 那 4 个文件（+63 行）看着量最大，但在 5.6 上**完全无意义**——它修的是 8.x 的「CE cache 持久化窗口在 bailout 时未发布槽位」问题，5.6 的 opcache 没有这套机制，所以也不会有这个 bug。

反过来，官方 `ext/session/session.c` 只改 **+1/-1**，却是**收益最大的一行**：它直接切断 109619 的 session 路径。这也是为什么官方在缓解建议里把 `session.upload_progress.enabled=0` 放在第一位。

**换句话说：8.1 补丁里行数最多的部分（VM 86 行、opcache 63 行）在 5.6 上全是空转，而行数最少的 session.c（1 行）才是真正该抄的。**

## 六、如果要真补齐，建议的顺序

1. `ext/session/session.c` +1 —— 切断 109619 session 路径，成本最低
2. `main/rfc1867.c` 头白名单 —— 切断内存放大，成本低
3. `Zend/zend_strtod.c`、`main/SAPI.c` —— 防御性补齐
4. `Zend/zend_alloc.c` —— 已完成（退出码 255→1 已实测）
5. `Zend/zend_execute_API.c` —— 核对即可，5.6 原本已有等价初始化

做完 1–4 后，能覆盖 109618 的 OOM 出口与 rfc1867 放大路径，以及 109619 的 session 路径。但这仍**不等于安全**——109619 还有 `EG(last_fatal_error_backtrace)`、`BG(unserialize)`、`PS(id)`、OPcache frontier 四条子路径，其中 `PS(id)` 那条正是我在 8.5.11 上实际打通成 `uid=33(www-data)` 的那条。

## 相关文档

- `SELF-PATCH-5.6-7.3.md` —— 自制 5.6 最小补丁与「为什么不等于安全」的分析
- `REPRODUCED-109619.md` —— 109619 在 8.5.11 上的完整 RCE 复现
