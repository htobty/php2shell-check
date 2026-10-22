---
name: php2shell_event_and_fixes
title: PHP2Shell 全记录：从 10 月 21 日披露到每个分支各自怎么修
description: 按事件时间线梳理 CVE-2026-109618 与 CVE-2026-109619 的披露、机理、官方补丁的四处核心改动，以及 8.2-8.5、7.4-8.1、5.6-7.3 三档分支的处置差异与依据。
summary: 两个洞坏在同源的地方，官方补丁一次修了四处；四个受支持分支出正式版本，7.4-8.1 只有源码回补，5.6-7.3 官方未提及但缺陷代码确在。
keywords:
  - PHP2Shell
  - CVE-2026-109618
  - CVE-2026-109619
  - PHP 补丁
  - backport
  - zend_mm_safe_error
category: 安全/漏洞响应
---

# PHP2Shell 全记录：从披露到每个分支各自怎么修

## 10 月 21 日那天

2026 年 10 月 21 日 14:00 UTC，PHP 项目一次性放出四个版本：8.2.35、8.3.36、8.4.27、8.5.12。四个版本同时出现，对应两个安全漏洞的协调披露，编号 CVE-2026-109618 和 CVE-2026-109619，代号 PHP2Shell，由 Wiz Research 发现。

评级上有一处需要分开看。CVSS v4.0 给的是 9.2，向量里 `AC:H`（攻击复杂度高）和 `AT:P`（攻击前提存在）两项都是不利条件，说明不是随手一发就能中的东西；NVD 另按 CVSS 3.1 给出 9.8，这个分数体系里没有前置条件指标，看起来更凶。CISA 的 SSVC 决策表四项中三项是克制信号：Exploitation=none（披露时无在野利用证据）、Automatable=no（不能自动化批量利用）、Technical Impact=total（一旦打成，影响是彻底的）。

受影响区间写得很窄：8.2.0 至 8.2.35 之前、8.3.0 至 8.3.36 之前、8.4.0 至 8.4.27 之前、8.5.0 至 8.5.12 之前。

## 两个洞各自坏在哪

### 109618：OOM 之后的那次跳转

PHP 内存耗尽时，`Zend/zend_alloc.c` 里的 `zend_mm_safe_error()` 负责报错。这个函数的历史实现是这样的（以 7.3 为例，第 374 行起）：

```c
heap->overflow = 1;
zend_try {
    zend_error_noreturn(E_ERROR, format, limit, ...);
} zend_catch {
} zend_end_try();
heap->overflow = 0;
zend_bailout();      /* longjmp */
exit(1);             /* 执行不到 */
```

`zend_bailout()` 是 longjmp。内存耗尽这个本该终止请求的事件，被实现成一次跳转：控制流回到上层，请求继续走到 shutdown 阶段。这时有一批请求级别的内存结构只初始化了一半。mod_php 的 request shutdown 无条件执行，于是它读到了这批未初始化的数据。Wiz 的结论是这条路能走到远程代码执行。

把内存压到耗尽有三条路：让 `Content-Length` 不可用从而绕过 `post_max_size` 预检；单个 part 的 header 数量不设上限；空文件控件不计入 `max_file_uploads` 但仍然建立元数据，配嵌套字段名做放大。

### 109619：请求结束了，状态没结束

第二个洞的前提不同：进程活着，worker 接着处理下一个请求，而上一个请求留下的全局状态没清干净。官方列出四个子漏洞，每个对应一个具体的状态项：upload-progress 反序列化 UAF、远程内存泄露、fatal-error backtrace UAF、OPcache type confusion。

openwall 邮件里 Jakub Zelenka 确认，这两条路径在 Apache mod_php 和 PHP-FPM 上都演示出了未认证的远程代码执行。SAPI 风险不齐：mod_php 最危险，FrankenPHP 情况类似，FPM 受影响且有演示，LSAPI 被判为"可能但未验证"。

## 官方补丁改了哪四处

8.1 回补分支的提交 `1d7dec178a09` 最好读：1176 行 patch，23 个文件。核心改动是四处，其余二十来个文件是配套。

### 把 longjmp 换成 _exit

`Zend/zend_alloc.c` 新增 `zend_mm_safe_error_ex()`。原来那条"先 zend_try、再 zend_error_noreturn"的路径，换成用 `vsnprintf` 组装消息、`fprintf(stderr, ...)` 直接写、`_exit(1)` 立刻结束进程。`zend_mm_safe_error()` 本身简化为 `(void) heap;` 后转调新函数。

这是整份补丁里最关键的一处。它的思路是：既然根源在于"进程在内存已经坏掉的情况下还在继续跑"，那就不要再给它继续跑的机会。

### VM 的整数溢出检查

`Zend/zend_vm_def.h` 增加了 10 行，生成的 `Zend/zend_vm_execute.h` 增加 86 行。检查形如：

```c
if (UNEXPECTED(ZSTR_LEN(op1_str) > ZSTR_MAX_LEN - ZSTR_LEN(op2_str)))
```

命中溢出时改调 `zend_mm_safe_error_ex("Integer overflow in memory allocation")`，同样走 _exit 路径。

有一个工程细节要记住：`zend_vm_execute.h` 由 `zend_vm_def.h` 经 `zend_vm_gen.php` 生成。改动只能落在 def 文件上再重新生成，手改生成物等于给自己埋雷。

### multipart 头只留两个

`main/rfc1867.c` 新增 `php_mime_should_save_hdr()`，只保留 `Content-Disposition` 和 `Content-Type`，重复的头直接丢弃，配合新增的 `php_mime_get_hdr_value()` 取第一个值。这一处负责缩小内存放大面，根因不在这里：单个 part 能吃掉的内存因此有了天花板。

### 清空 SG(request_info)

`main/SAPI.c` 加了 5 行，在 request shutdown 时清掉 `SG(request_info)` 上的 `auth_user`、`auth_password`、`auth_digest`、`content_type_dup`、`current_user`。这一处针对 109619 的跨请求残留。

配套文件里改动量最大的是 `ext/opcache/zend_persist.c`（+59/-8），涉及 OPcache 持久化结构；其余包括 `zend_execute_API.c`（+15）、`zend_hash.c`（+10/-3）、`ZendAccelerator.c`、`session.c`、`main.c`、`php_variables.c`，以及 `ext/zend_test` 下的三个 phpt。

## 然后是版本：每个分支各自怎么修

| 分支 | 官方处置 | 落地动作 |
|---|---|---|
| 8.5.x | 8.5.12 正式版 | 分支内升级 |
| 8.4.x | 8.4.27 正式版 | 分支内升级 |
| 8.3.x | 8.3.36 正式版 | 分支内升级 |
| 8.2.x | 8.2.35 正式版 | 分支内升级 |
| 8.1.x / 8.0.x / 7.4.x | 源码回补分支，无发布包 | 自行构建，或等厂商包 |
| 7.3.x 及更早、5.6.x | 无 | 升 7.4 以上，或自建补丁 / 补偿控制 |

### 8.2 / 8.3 / 8.4 / 8.5：四个正式版本

这是分支内的最小升级。跑 8.4 的升 8.4.27，不用跨大版本，不涉及语法变更，不用重编扩展。有一种流传的说法是"这两个洞的修复要求升到 8.2"，那是把最低受支持分支当成了唯一目标版本，与实际发布内容不符。

### 7.4 / 8.0 / 8.1：源码回补分支

这三个分支已经 EOL，官方不发版本，但这次给了三个可以直接拉取的源码分支：

| 分支 | HEAD 提交 | 日期 |
|---|---|---|
| `PHP-7.4-CVE-2026-109618-109619` | `712e60f9edfd` | 2026-10-18 |
| `PHP-8.0-CVE-2026-109618-109619` | `82f8f31b16a0` | 2026-10-18 |
| `PHP-8.1-CVE-2026-109618-109619` | `1d7dec178a09` | 2026-10-18 |

这三个提交的日期是 10 月 18 日，比公开披露早三天，提交信息统一是 "Avoid state corruption via bailout"，8.1 那份由 Arnaud Le Blanc 提交。

用这些分支得自己构建，`./configure` 的参数必须和现有部署一致：SAPI、扩展清单、编译选项任一不同，替换后行为就会变。公告里还有一句需要留意：依赖 `rpms.remirepo.net` 的用户应当立刻切到发行版官方包，或者改用源码构建。

### 5.6 / 7.0 / 7.1 / 7.2 / 7.3：官方未提及

公告的这一段原文值得逐句读：

> PHP 8.1 and older no longer receive updates from the PHP project. Some distributions and LTS vendors provide backported fixes, so contact your vendor for details, or upgrade to a supported version.
>
> Given the severity of these vulnerabilities, the PHP security team provided minimal source-backports for PHP 7.4, PHP 8.0, and PHP 8.1 to help people building from source or without access to an LTS vendor.

回补的下界是 7.4。5.6 到 7.3 这五个分支，公告一个字都没提。

这里有个容易读错的地方：受影响列表只有 8.2 到 8.5 四段，有人据此理解成"5.6 到 7.3 不受影响"。直接拉源码比对就知道不是这么回事：

| 分支 | `zend_mm_safe_error()` 位置与形态 |
|---|---|
| PHP-5.6 | 第 1743 行起，同构实现，另含 `heap->reserve` 释放、`TSRMLS_FETCH()`、`heap->overflow` 双阈值分支 |
| PHP-7.0 | 第 385 行，`heap->overflow = 1; zend_try { zend_error_noreturn(E_ERROR, ...) }` |
| PHP-7.2 | 第 376 行，同上 |
| PHP-7.3 | 第 374 行，同上 |

这五个分支带着同一份缺陷代码。官方不为它们发补丁，是维护周期政策的结果。反过来说，也不能断言它们确定可被利用：公告没有这类断言，代码级利用性验证目前也没人公开做过。

## 5.6 到 7.3 的三条路

按代价从低到高排。

### 升到 7.4，拿回补分支

7.3 到 7.4 的破坏性改动不算大：箭头函数、typed properties、`??=` 几项，多数代码不受影响。从 5.6 上来要动的地方就多了：`mysql_*` 扩展移除、preg 的 `/e` 修饰符移除、ASP 标签移除，这些都需要真实改造。这条路的优点是能拿到官方验证过的完整修复，而且 7.4 到 8.x 的下一步也有了落脚点。

### 自己写补丁

两个洞的难度差一个量级，得分开算。

109618 的根因集中在一个函数里。最小修复约三四十行：把 longjmp 换成 `vsnprintf` + `fprintf` + `_exit(1)`。7.0 到 7.3 的 API 齐全，照官方思路写就成。5.6 缺 `zend_string`，也缺 `zend_get_executed_filename_ex()`（7.0 才引入），但它自己的函数体里已经写好了 `EG(in_execution)` / `EG(active_op_array)->filename` / `EG(opline_ptr)` 的推导逻辑，复用即可。照抄官方代码在 5.6 上会直接编译不过，原因就是这套 `ZSTR_VAL()` 写法在那里不存在。

109619 难得多。对比各分支头文件有个对旧版本有利的发现：`EG(last_fatal_error_backtrace)` 在 5.6、7.0、7.1、7.2、7.3、7.4 全部分支都检索不到，这个状态项是 8.x 才引入的，因此 fatal-error backtrace UAF 那个子漏洞在这些分支上没有载体。但 `BG(unserialize)` 在所有分支都存在，upload-progress 那条路还在；OPcache frontier 依赖 `zend_persist.c` 的持久化结构，旧版与 8.x 差异太大，无法平移；`ZSTR_MAX_LEN` 这个常量在 7.4 之前查不到，VM 溢出检查那段得换写法。四个子漏洞漏掉任何一个都等于没修，而不会有任何人来告诉你漏了。

还有一层代价跟代码无关。`_exit(1)` 会改变故障形态：原来 OOM 是可捕获的 `E_ERROR`，应用能跑 shutdown function 记日志、写缓存、优雅降级；换成 `_exit(1)` 之后进程直接消失，这些全部跳过。线上如果依赖 OOM 后的收尾逻辑，会引入新的可用性问题，动手前必须先评估。

### 先做补偿控制

官方明确说 109619 没有通用配置层的完全缓解，所以这些措施的作用是争取时间，不是解决问题。可做的有：`session.upload_progress.enabled=0` 切断已确认的 consumer 入口；`memory_limit=-1` 消除可控的内存上限失败；`post_max_size` 收窄请求体放大面，`upload_max_filesize` 低于它；`max_multipart_body_parts` 压到 256 以内，掐断大量 part 的路径（这个指令的默认值 1020 本身就会拒绝超限请求，实测 3000 个空文件控件会直接撞上 `Multipart body parts limit exceeded 1020`）；FPM 用 `pm.max_requests=1` 切断跨请求残留链，代价是性能；反代层限制解码后体积、字段数、part 数、header 数、嵌套深度，并且必须覆盖没有可用 `Content-Length` 的分块请求。

有两个误区要避开：`display_errors=Off` 不是缓解，内存照样耗尽，只是错误不回显；WAF 不是安全边界。

## 落地顺序

先收大头。8.2 到 8.5 这一档零改造，覆盖绝大多数实例，本周内做完。

同时确认 7.4 / 8.0 / 8.1 走厂商包还是自建构建。如果 Red Hat、SUSE、Ubuntu Pro、CloudLinux 这类提供了带安全回补的包，优先用厂商的：包管理能持续跟进后续补丁，自建构建要靠人盯。

未升级的实例先全部上补偿控制，尤其是 `session.upload_progress.enabled=0` 和 `memory_limit=-1`。

5.6 到 7.3 排期升到 7.4 以上，或者迁到受支持分支。这批是真正的技术债，补偿控制撑不了太久。

## 没确认的部分

- 5.6 到 7.3 的实际可利用性没有做代码级验证。缺陷代码确实在，可达性取决于 SAPI（是不是 mod_php）、部署形态（同一个 worker 是否既处理生产请求又处理消费请求）、配置项是否允许走到那条路径。这三项要按版本区间、SAPI、INI 三要素逐项核对，不能靠"公告没提我"免责。
- 109619 剩余三个子漏洞在旧分支的具体可达性，本次未逐一核实。
- 自写补丁的代码属于设计级改法，未在 5.6 或 7.x 上编译验证过，落地前必须在目标分支编译、跑 `.phpt` 并做业务回归。
- PHP 8.2 将在 2026-12-31 EOL。升到 8.2.35 只解决这两个洞，两个多月后还要再面对一次同样的处境。

## 参考

- https://www.php.net/archive/2026.php
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://www.wiz.io/blog/php2shell-php-rce
- http://www.openwall.com/lists/oss-security/2026/10/21/7
- https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619


---

## 附录：PHP 5.6 的补丁到底怎么写

前面那节只写了「复用其自带的 filename 推导即可」，等于没说清。这里把代码补齐。

### 先看 5.6 原函数的结构

5.6 的 `Zend/zend_alloc.c` 第 1743–1805 行是 `zend_mm_safe_error()`。签名比 7.x 少两个修饰：

```c
static void zend_mm_safe_error(zend_mm_heap *heap,
	const char *format,
	size_t limit,
#if ZEND_DEBUG
	const char *filename,
	uint lineno,
#endif
	size_t size)
```

注意 `format` 后面跟的是**固定的两个参数** `limit` 和 `size`（DEBUG 构建下多 `filename`、`lineno`），不是变参。这是 5.6 所有 OOM 调用点的形态，后面决定了改法。

函数体做的事依次是：归还 `heap->reserve` 那块预留内存 → 推导 `error_filename` / `error_lineno` → `heap->overflow = 1` → `zend_try { zend_error_noreturn(E_ERROR, format, limit, size) }` → `zend_catch { ... }` → `zend_bailout()`。

最后那一句就是 109618 的那一跳。`zend_bailout()` 在 5.6 的 `Zend/zend.h` 第 618 行定义为：

```c
#define zend_bailout()		_zend_bailout(__FILE__, __LINE__)
```

`_zend_bailout` 内部是 `LONGJMP`，也就是 `siglongjmp`/`longjmp`。OOM 一到，进程从分配器里跳出去，请求状态留在半路上——这就是漏洞的根。

### 5.6 有个官方 8.x 没有的便利

5.6 的 `zend_catch` 分支里，本来就已经写了把致命错误直接输出到 stderr 的代码：

```c
		} zend_catch {
			if (heap->overflow == 2) {
				fprintf(stderr, "\nFatal error: ");
				fprintf(stderr, format, limit,
#if ZEND_DEBUG
					filename, lineno,
#endif
					size);
				fprintf(stderr, " in %s on line %d\n", error_filename, error_lineno);
			}
```

也就是说「绕开 Zend 的错误处理、直接往 stderr 写一行」这段代码 5.6 自己就写过，只是被埋在 catch 分支里，写完仍然 `zend_bailout()`。改法就是把这段搬到正常路径上，末尾的 `zend_bailout()` 换成 `_exit(1)`。

### 为什么可以整段扔掉 heap->overflow 三态

原来需要 `overflow` 的 0/1/2 三个值，是因为 `zend_error_noreturn` 在报错过程中还要分配内存去格式化消息。内存本来就耗尽了，这次分配很可能再失败，于是又进 `zend_mm_safe_error`——递归。所以第一次进来置 1，重入时置 2，回到外层 catch 看到 2 才真正输出。

换成 `fprintf` / `vfprintf` 之后，输出走 libc 的 malloc，不经过 Zend MM，不会重入。三态没有存在意义了。

这一点我核过整个 5.6 文件：`heap->overflow` 只出现在第 433 行（结构体声明）、1117 行（初始化）和 1739 / 1756 / 1773 / 1784 / 1802（本函数内），没有任何其它代码读它。所以删掉是安全的。

### 完整改法

before（第 1743–1805 行，`error_filename` 推导那段原样保留在 after 里）：

```c
static void zend_mm_safe_error(zend_mm_heap *heap,
	const char *format,
	size_t limit,
#if ZEND_DEBUG
	const char *filename,
	uint lineno,
#endif
	size_t size)
{
	if (heap->reserve) {
		_zend_mm_free_int(heap, heap->reserve ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC);
		heap->reserve = NULL;
	}
	if (heap->overflow == 0) {
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
		heap->overflow = 1;
		zend_try {
			zend_error_noreturn(E_ERROR, format, limit,
#if ZEND_DEBUG
				filename, lineno,
#endif
				size);
		} zend_catch {
			if (heap->overflow == 2) {
				fprintf(stderr, "\nFatal error: ");
				fprintf(stderr, format, limit,
#if ZEND_DEBUG
					filename, lineno,
#endif
					size);
				fprintf(stderr, " in %s on line %d\n", error_filename, error_lineno);
			}
/* See http://support.microsoft.com/kb/190351 */
#ifdef PHP_WIN32
			fflush(stderr);
#endif
		} zend_end_try();
	} else {
		heap->overflow = 2;
	}
	zend_bailout();
}
```

after（整段替换为下面两个函数）：

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

### 为什么要新增一个变参函数，不能只改原函数

原函数的签名是固定的：`format` 后面只跟 `limit`、`size` 两个参数。但同一个文件里还有另一批报错，`format` 后面跟三个参数（如 `nmemb, size, offset`），塞不进这个签名。

所以官方 8.1 补丁的做法就是新增 `zend_mm_safe_error_ex(const char *format, ...)`，原函数退化为转调。5.6 版照抄这个结构，只是把 8.x 的 `zend_string *` / `ZSTR_VAL()` 换成 5.6 的 `const char *`，把 `zend_is_executing()` / `zend_get_executed_filename_ex()` 换回 5.6 自带的 `zend_is_compiling()` + `EG(in_execution)` 推导。

### 那 7 处整型溢出要一起改

要。`safe_address()` 在 5.6 里有 6 个平台分支（i386、x86_64、arm、aarch64、32 位兜底、浮点兜底），每支里都是同一句：

```c
zend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);
```

外加 `_safe_emalloc_string()` 里一句：

```c
zend_error_noreturn(E_ERROR, "String allocation overflow, max size is %d", INT_MAX);
```

这 7 处同样会 longjmp，官方 8.1 也把它们一并改成走新函数。全部替换后：

```c
zend_mm_safe_error_ex("Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);
...
zend_mm_safe_error_ex("String allocation overflow, max size is %d", INT_MAX);
```

改完 `zend_alloc.c` 里 `zend_error_noreturn` 出现 0 次、`zend_bailout()` 出现 0 次。这两项可以直接当成打完补丁的自检指标。

`zend_mm_safe_error_ex` 必须定义在 `safe_address()` 之前——它是 `static` 函数，5.6 没有前置声明，定义顺序错了会报隐式声明。

### 用 vfprintf 而不是 vsnprintf

官方 8.1 的写法是 `char buf[1024]` + `vsnprintf` 再 `fprintf`。5.6 这里是 C89 时代的代码，我改用 `vfprintf(stderr, format, args)` 直接转发：`vfprintf` 是 C89 标准函数、不需要缓冲区、也不会被 1024 字节截断。效果一样。

### 三个容易踩的细节

**`_exit` 的声明**：5.6 的 `zend_alloc.c` 第 31–33 行已经有

```c
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
```

POSIX 下不用加 include。MSVC 下 `_exit` 在 `<stdlib.h>`，若报未声明，加 `#include <process.h>`。

**`%u` 而不是 `%d`**：5.6 的 `error_lineno` 类型是 `uint`，原来的 catch 分支写的是 `%d`。我改成 `%u`。

**不要再调 `_zend_mm_free_int` 归还 `heap->reserve`**：进程马上 `_exit`，那块内存交还操作系统就行；在已经耗尽的分配器内部再走一遍 free 逻辑没有意义，还多一次出错机会。这也是 `(void) heap;` 的来由。

### 副作用

`_exit(1)` 不跑任何清理：atexit 不执行、Zend shutdown 序列不执行、session 不写盘、FPM worker 直接被回收。

- Apache mod_php：该请求连接断开，客户端可能收到 500。
- PHP-FPM：worker 异常退出，master 补新 worker，错误日志里留一条 worker 退出记录，`pm.max_requests` 计数不准。

这是有意的取舍。OOM 那一刻进程状态已经不可信，继续走清理路径正是 109618 的成因。代价是内存耗尽时用户拿不到正常错误页，只能拿到空白 500。

### 打完补丁还剩什么

这个补丁只堵住 109618 的那一跳：OOM 不再 longjmp 回用户态。109619 的四个子漏洞（upload-progress unserializer UAF、远程内存泄露、fatal-error backtrace UAF、OPcache 类型混淆）不在覆盖范围内。其中 backtrace UAF 在 5.6 没有载体（`EG(last_fatal_error_backtrace)` 是 8.x 才引入的），另外三个仍需逐个核实。

所以不要把「打过这个补丁的 5.6」当成安全版本。

### 落地方式与验证状态

`patch-5.6-109618.py` 放在同目录，用法：

```bash
cd /path/to/php-5.6
python3 /path/to/patch-5.6-109618.py Zend/zend_alloc.c
git diff > ../php2shell-56-109618.patch
```

脚本带断言：找不到 `zend_mm_safe_error`、函数体结构不对、`safe_address` 不是 6 处、字符串溢出不是 1 处，都会直接退出并说明原因，不会写坏文件。

验证到哪一步：

- 替换逻辑：已对 php-src `PHP-5.6` 分支真实的 `Zend/zend_alloc.c` 跑通，断言全部通过，生成 diff 为 +46/−58 行、173 行补丁文件。
- 编译与运行：**未验证**。本机是 macOS + PHP 8.1.33，没有 5.6 工具链。上生产前必须在目标分支实际编译，跑 `make test` 与业务回归，并准备回退包。
