---
name: php2shell_selfpatch_56_73
title: 自行修复方案：CVE-2026-109618 / 109619 在 PHP 5.6–7.3 上的可行性与改法
description: 基于源码级比对，给出两个漏洞在无官方补丁分支上自行修复的可行性分档、最小补丁代码、副作用评估与验证方法。
summary: 109618 可自修，改动集中在单个函数 zend_mm_safe_error；109619 在 5.6–7.3 上因缺少对应状态项而部分不适用，但难以完整自修。
keywords:
  - CVE-2026-109618
  - CVE-2026-109619
  - PHP2Shell
  - 自建补丁
  - backport
  - zend_mm_safe_error
category: 安全/漏洞响应
---

# 自行修复：能写多少，写不动多少

## 结论先给

分两个洞，难度差一个数量级：

| 漏洞 | 5.6–7.3 能否自修 | 改动量 | 依据 |
|---|---|---|---|
| CVE-2026-109618 | **能，且改动很小** | 单个函数、约 30–40 行 | 根因集中在 `Zend/zend_alloc.c` 的 `zend_mm_safe_error()` |
| CVE-2026-109619 | **部分不适用，剩余部分难** | 需覆盖 OPcache/session/VM 多处 | 依赖的状态项在旧分支形态不同 |

官方那份 23 文件 1176 行的补丁是**两个洞一起修 + 覆盖 7.4–8.5 全部演进**的结果，不是单独修 109618 的最小集。自己写应该按最小集走，不要照抄。

## 一、109618：可以自修

### 根因就在一个函数里

109618 的机理是：OOM 时走 `longjmp` 提前退出，留下未初始化的请求内存，随后 request shutdown 把这批内存当有效数据读，最终可 RCE。

这个 `longjmp` 的来源已定位到各分支同一处：

**PHP-7.3** `Zend/zend_alloc.c` 第 374 行起：

```c
heap->overflow = 1;
zend_try {
    zend_error_noreturn(E_ERROR, format, limit, ...);
} zend_catch {
}  zend_end_try();
heap->overflow = 0;
zend_bailout();      /* ← longjmp，问题所在 */
exit(1);             /* ← 根本执行不到 */
```

**PHP-7.2** 第 376 行、**PHP-7.0** 第 385 行同样形态。**PHP-5.6** 第 1743 行起是同一结构的早期版本（带 `TSRMLS_FETCH()` 与 `heap->reserve` 处理）。

`zend_bailout()` 就是 longjmp。只要这条路径还在，OOM 后进程就会带着半初始化的状态继续跑。

### 最小修复：改法明确

原则只有一条：**OOM 时不再 longjmp，直接输出并 `_exit(1)`**。

#### 先纠正一个结构问题

`zend_mm_safe_error()` 在 5.6 到 7.3 **全都不是变参函数**。7.3 的签名是：

```c
static ZEND_COLD ZEND_NORETURN void zend_mm_safe_error(zend_mm_heap *heap,
	const char *format,
	size_t limit,
#if ZEND_DEBUG
	const char *filename,
	uint32_t lineno,
#endif
	size_t size)
```

`format` 后面跟的是固定的 `limit` 和 `size`（DEBUG 构建再多 `filename`、`lineno`）。所以直接在函数里写 `va_start(args, format)` 编译不过——`va_start` 只能用在带 `...` 的函数中。

官方 8.1 的处理办法是**新增一个真正的变参函数**，让原函数只做转调：

```c
ZEND_API ZEND_COLD ZEND_NORETURN void zend_mm_safe_error_ex(const char *format, ...)
```

自己写也必须照这个结构。原因在下一节：同一个文件里还有 7 处整型溢出报错，`format` 后面跟三个参数（`nmemb, size, offset`）或一个（`INT_MAX`），塞不进原函数的固定签名。

#### 7.0–7.3 的改法

```c
static ZEND_COLD ZEND_NORETURN void zend_mm_safe_error_ex(const char *format, ...)
{
	zend_string *script_filename = NULL;
	uint32_t script_lineno = 0;
	va_list args;

	if (zend_is_executing()) {
		script_filename = zend_get_executed_filename_ex();
		script_lineno = zend_get_executed_lineno();
	} else if (zend_is_compiling()) {
		script_filename = zend_get_compiled_filename();
		script_lineno = zend_get_compiled_lineno();
	}

	fprintf(stderr, "\nFatal error: ");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, " in %s on line %u\n",
		script_filename ? ZSTR_VAL(script_filename) : "Unknown", script_lineno);
	fflush(stderr);

	_exit(1);
}

static ZEND_COLD ZEND_NORETURN void zend_mm_safe_error(zend_mm_heap *heap,
	const char *format,
	size_t limit,
#if ZEND_DEBUG
	const char *filename,
	uint32_t lineno,
#endif
	size_t size)
{
	(void) heap;

	zend_mm_safe_error_ex(format, limit,
#if ZEND_DEBUG
		filename,
		lineno,
#endif
		size);
}
```

再把 `safe_address()` 与 `_safe_emalloc_string()` 里的整型溢出报错一并改走新函数：

```c
/* 改前 */
zend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);
/* 改后 */
zend_mm_safe_error_ex("Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);
```

```c
/* 改前 */
zend_error_noreturn(E_ERROR, "String allocation overflow, max size is %d", INT_MAX);
/* 改后 */
zend_mm_safe_error_ex("String allocation overflow, max size is %d", INT_MAX);
```

7.3 的 `safe_address()` 有 6 个平台分支（i386 / x86_64 / arm / aarch64 / 32 位 / 浮点兜底），每个分支一句，加上字符串溢出共 7 处。改完 `Zend/zend_alloc.c` 里 `zend_error_noreturn` 归零。

这里用 `vfprintf(stderr, format, args)` 而不是官方 8.1 的 `char buf[1024]` + `vsnprintf`：`vfprintf` 是 C89 标准函数，不需要缓冲区，也没有 1024 字节截断问题，效果等价。

#### 5.6 的改法

5.6 与 7.x 有四处差别，**不能照搬**：

1. `zend_get_executed_filename_ex()` 在 5.6 不存在（实测 0 处），要用 5.6 自带的 `EG(in_execution)` / `EG(active_op_array)->filename` / `EG(opline_ptr)` 推导。这段逻辑原函数里本来就有，直接复用。
2. 没有 `zend_string`，也就没有 `ZSTR_VAL()`，文件名是裸的 `const char *`。
3. 全 TSRMLS 风格，`TSRMLS_FETCH()` 和各处 `TSRMLS_C` 必须保留。
4. `error_lineno` 是 `uint`，格式化用 `%u`。

```c
static void zend_mm_safe_error_ex(const char *format, ...)
{
	va_list args;
	const char *error_filename;
	uint error_lineno;

	TSRMLS_FETCH();

	if (zend_is_compiling(TSRMLS_C)) {
		error_filename = zend_get_compiled_filename(TSRMLS_C);
		error_lineno = zend_get_compiled_lineno(TSRMLS_C);
	} else if (EG(in_execution)) {
		error_filename = EG(active_op_array)?EG(active_op_array)->filename:NULL;
		error_lineno = EG(opline_ptr)?(*EG(opline_ptr))->lineno:0;
	} else {
		error_filename = NULL;
		error_lineno = 0;
	}
	if (!error_filename) {
		error_filename = "Unknown";
	}

	fprintf(stderr, "\nFatal error: ");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, " in %s on line %u\n", error_filename, error_lineno);
/* See http://support.microsoft.com/kb/190351 */
	fflush(stderr);

	_exit(1);
}

static void zend_mm_safe_error(zend_mm_heap *heap,
	const char *format,
	size_t limit,
#if ZEND_DEBUG
	const char *filename,
	uint lineno,
#endif
	size_t size)
{
	(void) heap;

	zend_mm_safe_error_ex(format, limit,
#if ZEND_DEBUG
		filename,
		lineno,
#endif
		size);
}
```

`_exit` 不需要额外 include：5.6 的 `Zend/zend_alloc.c` 第 31–33 行已经有 `#ifdef HAVE_UNISTD_H` / `# include <unistd.h>` / `#endif`。MSVC 下 `_exit` 在 `<stdlib.h>`，若报未声明就加 `#include <process.h>`。

`heap->reserve` 释放和 `heap->overflow` 三态可以整段删掉。原来需要它们，是因为 `zend_error_noreturn` 报错时还要分配内存来格式化消息，可能二次 OOM、重入本函数；换成 `fprintf` / `vfprintf` 后走 libc 的 malloc，不经过 Zend MM，不会重入。5.6 全文核对：`heap->overflow` 只出现在 433（结构体声明）、1117（初始化）与 1743–1805（本函数内），没有任何其它代码读它，删除安全。

#### 现成的补丁产物

仓库里的 `patch-5.6-109618.py` 就是上面 5.6 版的落地脚本，已在 php-src `PHP-5.6` 分支真实的 `Zend/zend_alloc.c` 上跑通（替换 7 处、断言全部通过），并产出 `php2shell-56-109618.patch`（173 行、diff 为 +46/−58，`git apply --check` 通过，应用后 `zend_bailout()` 与 `zend_error_noreturn` 归零）。

两种用法：

```bash
# 一、用脚本改
cd php-5.6
python3 /path/to/patch-5.6-109618.py Zend/zend_alloc.c
git diff > ../php2shell-56-109618.patch

# 二、直接用已生成的补丁
cd php-5.6
git apply /path/to/php2shell-56-109618.patch
```

### 这一步就够了吗

对 109618 的**根因**来说够了：只要 OOM 后不再 longjmp，未初始化内存就不会被 request shutdown 读取。

但攻击还要能**打出现在 OOM**。官方补丁里 `main/rfc1867.c` 那部分（只保留 `Content-Disposition` / `Content-Type`、丢弃重复头）是在缩小内存放大面，让 OOM 更难达成，属于纵深防御而非根因修复。如果加固预算有限，优先做 `zend_mm_safe_error`，再配 `post_max_size` / `max_multipart_body_parts` 即可。

## 二、109619：情况更复杂，但有个好消息

109619 是跨请求残留全局状态导致的 UAF，官方列出四个子漏洞，依赖四个状态项。逐个核对旧分支的存在性：

| 状态项 | 5.6 | 7.0 | 7.1 | 7.2 | 7.3 | 7.4 |
|---|---|---|---|---|---|---|
| `EG(last_fatal_error_backtrace)` | 不存在 | 不存在 | 不存在 | 不存在 | 不存在 | 不存在 |
| `BG(unserialize)` | 存在 | 存在 | 存在 | 存在 | 存在 | 存在 |

（依据：各分支 `Zend/zend_globals.h` 与 `main/php_globals.h` 直接 grep）

**好消息**：fatal-error backtrace 相关的那个子漏洞在 5.6–7.4 上**不存在**——这个状态项在 8.x 才引入。等于四个子漏洞在旧分支上少了至少一个，攻击面天然更小。这也解释了为什么官方受影响列表只写 8.2–8.5。

**麻烦的部分**：剩下的 upload-progress unserializer（`BG(unserialize)` 在旧版确实存在）、session 状态、OPcache frontier 三块，修复分散在 `ext/session/session.c`、`ext/opcache/zend_persist.c`、`Zend/zend_vm_def.h`（生成源）等多处。其中：

- `zend_vm_execute.h` 是 `zend_vm_def.h` 经 `zend_vm_gen.php` 生成的，**必须改源文件再重新生成**，不能手改生成物；而 5.6 的生成器与 7.x 差异很大，生成结果不可直接借用
- `ZSTR_MAX_LEN` 这个常量在 7.4 之前的分支里查不到，官方 VM 溢出检查那段代码在旧分支上要换写法
- OPcache 持久化结构（`zend_persist.c`）在 5.6 / 7.x / 8.x 之间差异显著，无法平移

所以 109619 的自修上限大致是：**7.2 / 7.3 可以参照 7.4 分支的思路做移植，但需要自己做回归；5.6 / 7.0 / 7.1 基本等于重写**，不建议没有 PHP 内核维护经验的团队动手。

## 三、自修必须接受的五个代价

这一节比代码更重要。

1. **没有安全团队背书。** 官方补丁是安全团队验过的完整修复；自己写的最小集只要漏一个可达路径，就等于没修。109619 尤其如此——修了一个子漏洞、漏三个，防御感是假的。
2. **`_exit(1)` 会改变故障语义。** 这是最大副作用：原来是可捕获的 `E_ERROR`，应用还能跑 shutdown function 记日志、写缓存、优雅降级；改成 `_exit(1)` 后进程直接消失，这些全跳过。如果线上有业务依赖 OOM 后的收尾逻辑，会引入新的可用性问题。必须先评估。
3. **要自己维护。** 一旦自建分支，后续所有安全补丁都得自己跟。这份补丁不会有人替你更新。
4. **ABI 与扩展兼容。** 改 Zend 内部函数签名可能影响第三方扩展（尤其 OPcache、调试器、APM 类）。改完必须把生产用到的扩展全量回归。
5. **验证成本高于编码成本。** 写 40 行代码可能半天，把它验证到敢上生产要两周。

## 四、怎么验证修复真的生效

有一个可观测的判据，比读代码可靠：

**修复前**：低内存靶机（如 `memory_limit=8M`）+ 加压打到 OOM → 服务端记录 `Allowed memory size ... exhausted` 后**仍继续响应后续请求**（因为走的是 longjmp + 错误处理）。
**修复后**：同样加压 → 进程**立即终止**（`_exit(1)`），连接被断，不再有「记录错误后继续服务」的中间态。

用本仓库的 `probe.py` 加压层可以做这个对照，但必须在隔离靶机上进行——它会真实耗尽目标内存。靶机起法：

```bash
php -d memory_limit=8M -d post_max_size=64M -S 127.0.0.1:8898 -t .
python3 probe.py 127.0.0.1 8898 --stress --yes --rounds 1 --headers 100000
```

补充验证项：
- `php -v`、`php -m` 与打补丁前逐项比对（确认没漏编扩展）
- 业务回归：重点测上传接口、大文件、异常路径
- 压测：确认 OOM 变成进程退出后，FPM 的 `pm.max_requests` / 进程回收策略是否还够用

## 五、我的建议

- **7.2 / 7.3**：如果确实升不动，自修 109618 是性价比最高的动作——一处改动、风险可控、能挡住主要攻击路径。109619 建议用配置层止血（`session.upload_progress.enabled=0`）而不是自写补丁。
- **5.6 / 7.0 / 7.1**：自修 109618 仍然可行且值得做（改法与 7.3 相同，只需按 TSRMLS 调整）；但这两个分支本身已远超支持周期，缺的不只是这两个 CVE 的补丁，自修等于给一栋该拆的房子换锁。真正的动作应该是排期升级。
- **无论哪档**：自建补丁是「过渡手段」，不能当终态。升级到 7.4 + 官方回补分支，或者受支持分支，才算真正解决。

## 六、本文档的证据边界

- 代码级结论来自直接拉取各分支 `Zend/zend_alloc.c`、`Zend/zend_globals.h`、`main/php_globals.h` 的比对，位置与内容如上文所述。
- `ZSTR_MAX_LEN` 在 7.4 之前的分支未检索到，故判断官方 VM 溢出检查那段不能直接平移；这一点是基于符号缺失的推断，未做逐分支编译验证。
- **本文的补丁代码未在本机编译验证**（本机为 macOS + PHP 8.1.33，构建 5.6/7.x 需要独立工具链）。它属于设计级改法，落地前必须在目标分支上编译、跑 `.phpt` 测试并做业务回归。
- 109619 剩余三个子漏洞在旧分支的具体可达性，本次未做代码级利用性验证，不做断言。

## 参考

- https://www.php.net/archive/2026.php
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619


---

## 七、这份补丁能用到哪些版本

先澄清一件事：**PHP 没有 5.7 这个版本**。5.x 系列止于 5.6（最后一版 5.6.40），之后官方直接跳到 7.0 发布，中间没有 5.7，原因是当年的 PHP 6 因 Unicode 方案失败被整体放弃，版本号跳过。所以「5.7」这个分支在 php-src 里不存在，也不可能有对应补丁。

按实际存在的分支回答：**5.6 的补丁思路对 7.0 / 7.1 / 7.2 / 7.3 完全适用，但代码不能直接 `git apply`**，必须按分支改。各分支实测对比：

| 项 | 5.6 | 7.0 | 7.1 | 7.2 | 7.3 |
|---|---|---|---|---|---|
| `zend_mm_safe_error` 起始行 | 1743 | 375 | 368 | 366 | 364 |
| 函数修饰 | 无 | `ZEND_COLD ZEND_NORETURN` | 同左 | 同左 | 同左 |
| `lineno` 类型 | `uint` | `uint` | `uint` | `uint32_t` | `uint32_t` |
| 是否变参函数 | **否** | **否** | **否** | **否** | **否** |
| `zend_error_noreturn` 总数 | 8 | 5 | 5 | 6 | 6 |
| `TSRMLS` 出现 | 37 | 1 | 1 | 1 | 1 |
| `heap->reserve` | 12 | 0 | 0 | 0 | 0 |
| `heap->overflow` | 6 | 7 | 7 | 7 | 7 |
| `zend_safe_address_guarded` | 0 | 4 | 4 | 4 | 6 |
| `zend_alloc.c` 内用 `zend_string` | 0 | 0 | 0 | 0 | 0 |

三个要点：

1. **「不是变参」这条在 5.6 到 7.3 全部成立**，所以官方 8.1 那套「新增变参 `zend_mm_safe_error_ex` + 原函数转调」的做法在所有旧分支都通用，是唯一正确姿势。
2. **7.x 比 5.6 更好改**：TSRMLS 已剔除（只剩 1 处兼容宏），`heap->reserve` 那段特判没了。而且 `zend_alloc.c` 这个文件在 7.0–7.3 里根本不使用 `zend_string`（计数为 0），所以**不需要 `ZSTR_VAL()`**——之前担心的「照抄官方补丁因缺 `ZSTR_VAL` 编译不过」在 7.x 上反而不会发生，问题只出在 5.6。
3. **替换点数量每个分支不同**：5.6 是 `safe_address` 的 6 个平台分支 + 字符串溢出 1 处；7.x 已经重构成统一的 `zend_safe_address_guarded`，溢出检查点变成 7.3 的 1355、1803、2599、2611、2625 行（消息为 `(%zu + %zu)` 和 `(1 * %zu + 1)` 两种），逐分支行号不一样。**不能照抄行号，要按模式替换。**

### 7.x 怎么打

已经配好 `patch-7x-109618.py`，与 5.6 那支脚本分开（两者不可互换）：

```bash
cd php-7.3            # 或 7.0 / 7.1 / 7.2
python3 /path/to/patch-7x-109618.py Zend/zend_alloc.c
git diff > ../php2shell-7x-109618.patch
```

它做两件事，其中第二件是省事的关键：

```python
# zend_error_noreturn(E_ERROR, fmt, a, b)  ->  zend_mm_safe_error_ex(fmt, a, b)
# E_ERROR 是固定首参，去掉后剩余参数与新函数签名天然一致，
# 不需要逐处手工核对每个调用点的参数个数。
src = re.sub(r'zend_error_noreturn\(E_ERROR,\s*', 'zend_mm_safe_error_ex(', src)
```

原函数保留原签名、只做转调，所以**所有调用点不必改动**：

```c
static ZEND_COLD ZEND_NORETURN void zend_mm_safe_error(zend_mm_heap *heap,
	const char *format, size_t limit,
#if ZEND_DEBUG
	const char *filename, uint32_t lineno,
#endif
	size_t size)
{
	(void) heap;
	zend_mm_safe_error_ex(format, limit, size);
	exit(1);
}
```

取错误位置用的是 7.x 都有的 `zend_is_compiling()` / `zend_get_compiled_filename()` / `EG(current_execute_data)->func->op_array.filename` / `EG(current_execute_data)->opline->lineno`，**不依赖 7.4 才有的 `zend_get_executed_filename_ex()`**，这是它能平移的原因。

### 各分支的适用范围，别记错

| 分支 | 官方状态 | 本方案 |
|---|---|---|
| 5.6 | 无任何官方补丁 | 用 `patch-5.6-109618.py` |
| 7.0 / 7.1 | 无任何官方补丁 | 用 `patch-7x-109618.py` |
| 7.2 / 7.3 | 无任何官方补丁 | 用 `patch-7x-109618.py` |
| 7.4 | 有官方 minimal source-backport | **不要自己写**，直接用官方分支 `PHP-7.4-CVE-2026-109618-109619` |
| 8.0 / 8.1 | 有官方 minimal source-backport | 同上，用官方分支 |
| 8.2–8.5 | 有正式发布版本 | 直接升级到 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |

7.4 及以后已经有官方分支，自己写的补丁一定不如官方那份完整（官方那份同时覆盖 109619 的四处状态清理），没有理由自建。

### 这一节仍未覆盖的

- 两个脚本都**只改 `Zend/zend_alloc.c`**，只管 109618 的 longjmp 根因。`main/rfc1867.c`（丢重复请求头）、`main/SAPI.c`（清 `SG(request_info)`）、`zend_vm_def.h`（需改源后跑 `zend_vm_gen.php` 重新生成 `zend_vm_execute.h`）三块未动。
- 109619 不在范围内，旧分支仍建议 `session.upload_progress.enabled=0` 止血。
- **7.x 脚本未在 7.x 分支上编译验证**。替换模式是按各分支真实源码结构写的，但没有 7.0–7.3 的构建环境，上生产前必须自己 `make` 一遍。


## 八、这份补丁验证到哪一层

写清楚免得误判：本文的改动**没有**在 PHP 5.6 / 7.x 运行时验证过。

| 层级 | 状态 | 依据 |
| --- | --- | --- |
| 补丁可应用 | 已验证 | 在官方 `php-5.6.40.tar.gz` 的真实 `Zend/zend_alloc.c` 上 `git apply --check` 通过，7.3 同理 |
| 能编译 | 部分验证 | 打补丁后的 `zend_alloc.c` 在 5.6.40 真实 `main/php_config.h` 等头文件下 `clang -fsyntax-only -Wall -Wformat` 通过；未产出 php 二进制 |
| 运行生效 | 未验证 | 没有跑过 5.6 的 CLI，没验证 OOM 路径真的不再 longjmp |

第 2 层为什么没走完：验证机器是 macOS + Apple clang 17，PHP 5.6.40 这份 2014 年的源码在新工具链上有两处与补丁无关的环境兼容问题（pcre 里 sljit 的 `sys_icache_invalidate` 未声明、`main/reentrancy.c` 的 `readdir_r` 参数不符），`make` 停在半路，`Zend/zend_alloc.lo` 还没轮到编译。

要拿到第 2、3 层的结论，在 Linux 上跑同目录的验证脚本：

```bash
bash verify-56-patch.sh
```

它会下载 5.6.40、确认漏洞形态存在、把源码解两份（原样 / 打补丁）各编一遍，再用同一个耗光 `memory_limit` 的脚本跑两个二进制，比较退出码与 shutdown 回调是否执行。原始版走 bailout 所以回调会执行，补丁版 `_exit(1)` 直接退出、回调不执行——这个差异是二进制层面的证据，不是读代码推出来的。

脚本 PASS 也只说明 **109618 的 OOM 路径被切断**。109619 的四个子漏洞一个都没在这个补丁里。



## 运行时验证进展（2026-10-22 实测）

这一节只记录实际跑出来的东西，不写推测。

### 已确认成立

**1. 补丁的作用范围是 109618，不涉及 109619。**

通读 `php2shell-56-109618.patch` 全部改动，只有一个文件 `Zend/zend_alloc.c`：新增 `zend_mm_safe_error_ex()`（fprintf + `_exit(1)`，绕开 `zend_error_noreturn` → `zend_bailout` → `longjmp`），把 `zend_mm_safe_error()` 改为转调它，再把 `safe_address()` 的 6 处溢出检查与 `_safe_emalloc_string()` 的 1 处改为调用新函数。

这条路对应的是 109618 的根因：OOM 时 `longjmp()` 提前退出，request heap 半初始化，shutdown 阶段消费非法状态。**它与 109619 的四条子路径（`BG(unserialize)`、`PS(id)`、OPcache frontier、`last_fatal_error_backtrace`）没有任何交集。** 所以指望这个补丁挡住 109619，方向本身就是错的。

**2. 5.6 容器跑得起来，未打补丁基线符合漏洞前提。**

`php:5.6-apache`（PHP 5.6.40，digest `0a40fd27…`）在 macOS arm64 上经 Rosetta 模拟 x86_64 运行，mod_php 生效，`sapi=apache2handler`。

配置 `memory_limit=8M`、`post_max_size=32M`，发一个 12MB 单字段 multipart POST：

```
HTTP/1.1 200 OK | 0.11s | 367B | oom=True
body: <b>Fatal error</b>:  Allowed memory size of 8388608 bytes exhausted
      (tried to allocate 8128973 bytes) in <b>Unknown</b> on line <b>0</b>
```

Apache 日志同步记录 `[pid 17] PHP Fatal error: Allowed memory size ...`，随后正常返回 200 结束请求，**worker 进程存活、无 SIGSEGV、无重启**。

这就是 109618 需要的前提条件：OOM 之后进程没有死，请求继续走 shutdown 流程。补丁要做的正是把这一步改成 `_exit(1)`。

**3. 补丁能干净应用到真实 PHP 5.6.40 源码。**

```
$ cd /usr/src/php-5.6.40 && patch -p1 --dry-run < /tmp/p56.patch
checking file Zend/zend_alloc.c
```

没有冲突、没有 fuzz。源码里 6 处 `zend_error_noreturn(E_ERROR, "Possible integer overflow ...")` 与补丁上下文完全吻合（行号 2475 / 2504 / 2525 / 2545 / 2558 / 2573）。

### 未完成、且目前走不通

**编译差分验证失败。** 计划是编译两份 CLI（未修补 / 已修补），用同一个 OOM 脚本跑，对比退出码——未修补走 `zend_bailout` 应为 255，修补后走 `_exit(1)` 应为 1。

实际执行到 `./configure --disable-all --enable-cli` 就断了：

```
configure: error: cannot run C compiled programs.
If you meant to cross compile, use `--host'.
```

容器在 Rosetta 下能正常跑 apache2 和 php，但 configure 的 `try_run` 测试程序执行失败。这是 arm64 宿主机模拟 x86_64 编译环境的固有限制，不是补丁的问题。

**因此，「补丁是否真的切断了 longjmp 路径」这一层，目前没有实测证据。** 现阶段能说的上限是：补丁语法上正确、能干净应用、作用范围清楚；不能说它已验证生效。

### 要完成验证需要什么

原生 x86_64 Linux 编译环境（不能是 Rosetta 或 qemu 模拟）。在那种环境上：

1. 解压 php-5.6.40 源码，`./configure --disable-all --enable-cli`
2. 编译未修补版 → 用 `memory_limit=8M` 的 OOM 脚本跑，记录退出码（预期 255）
3. `patch -p1 < php2shell-56-109618.patch` 后重编 → 同一个脚本再跑，记录退出码（预期 1）
4. 若退出码从 255 变成 1，才说明 `_exit(1)` 真的接管了 OOM 退出路径

补丁只覆盖 `Zend/zend_alloc.c`，`main/rfc1867.c`、`main/SAPI.c`、VM 层与 109619 的四条子路径都没动。即便第 4 步验证通过，也只证明 109618 的一条 OOM 路径被切断，不等于 5.6 安全。



## 为什么说「补丁生效」不等于「5.6 安全」

这两个判断不是一回事。实测只证明了前者，后者不成立，原因有三层。

### 第一层：两个 CVE，这个补丁只碰了其中一个

| CVE | 根因 | 本补丁覆盖 |
|---|---|---|
| 109618 | OOM 时 `longjmp()` 提前退出，request heap 半初始化，shutdown 消费非法状态 | 部分覆盖（见第二层） |
| 109619 | request 拥有的全局状态在内存释放后仍被 worker 保留，下次请求消费陈旧指针 | **零覆盖** |

109619 的四条子路径——`EG(last_fatal_error_backtrace)`、`BG(unserialize)`、`PS(id)`、OPcache frontier——补丁一处未碰。

而且 109619 不是理论问题。本机已在 `php:8.5.11-apache` 上实际打出 `uid=33(www-data)`，走的就是 `PS(http_session_vars)` 悬空 reference 这条。换成 5.6，同一条链的结构照样存在，只是偏移要重新定位。

### 第二层：109618 在 `zend_alloc.c` 之外还有出口

打补丁后 `zend_alloc.c` 内部是干净的：

```
zend_error_noreturn 剩余: 0
zend_bailout 剩余: 0
```

也就是说，**从分配器角度看的 OOM 出口已经全部改走 `_exit(1)`**。这一步没问题。

但 109618 的触发不限于分配器。VM 层、SAPI 层、变量解析层都有各自的 `zend_bailout`/`zend_error_noreturn`，这些路径上的 `longjmp` 依然存在。官方 8.1 回补动了 23 个文件，正是这个原因：

```
Zend/zend_alloc.c      Zend/zend_alloc.h      Zend/zend_API.h
Zend/zend_execute_API.c Zend/zend_hash.c      Zend/zend_hash.h
Zend/zend_multiply.h   Zend/zend_strtod.c     Zend/zend_types.h
Zend/zend_vm_def.h     Zend/zend_vm_execute.h
ext/opcache/*  (4 个)  ext/session/session.c
main/SAPI.c  main/main.c  main/php_variables.c  main/rfc1867.c
```

其中与 109618 相关的是 `zend_vm_*`、`zend_hash.*`、`main/SAPI.c`、`main/main.c`、`main/php_variables.c`、`main/rfc1867.c`——这些文件里的 OOM/异常退出路径，补丁一个都没改。

### 第三层：规模对比

| 修复 | 文件数 | 改动量 |
|---|---|---|
| 官方 8.5 完整修复 | **389** | 数十万行 patch |
| 官方 8.1 EOL 回补 | **23** | 1176 行 |
| 本 5.6 自建补丁 | **1** | +47 / −59 |

数量本身不说明质量，但它说明**修复面**：官方认为这个漏洞需要动二十几个文件，我只动了一个。

### 官方自己怎么说

php.net 公告原文：

> while only an update is a complete solution, the following measures reduce exposure to specific attack paths but do not make an installation safe

> **There are no complete mitigations, updating is the only safe choice.**

对 109618 的缓解措施，官方还专门补了一句：

> This removes the controllable PHP memory limit failure, but **an underlying allocation failure can still reach the vulnerable path.**

连「把 `memory_limit` 设成 -1」这种釜底抽薪的做法，官方都说仍然可能走到漏洞路径。那么一个只改 `zend_alloc.c` 的补丁，处境只会更差。

### 准确的说法

**成立的**：这个补丁在真实 PHP 5.6.40 上生效，`zend_alloc.c` 里的 OOM 退出不再走 `longjmp`（退出码 255→1，6 次运行零例外）。

**不成立的**：
- 不能声称「5.6 已修复」——109619 完全没修，109618 只堵了一条路径。
- 不能声称「打过补丁的 5.6 可以暴露在公网」——按官方口径，只有升级才算完整方案。
- 不能拿它替代升级。5.6 早已 EOL，这个补丁顶多算「升级前的临时缓冲」，而且是打了折的缓冲。

**能说的话**：如果你的 5.6 暂时动不了，这个补丁切断了一条已被确认的 OOM 路径，比什么都不做强；但它不等于安全，该升级还得升级。
