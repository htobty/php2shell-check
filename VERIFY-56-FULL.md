---
name: verify_56_full_patch
title: PHP 5.6 三补丁组合包：设计与实测结果
description: 把 zend_alloc.c OOM 出口、rfc1867.c 头白名单、session.c 禁用 upload progress 三处改动合并为一个补丁，在 x86_64 Linux 上编译并做行为差分
summary: zend_alloc 退出码 255→1 已验证；rfc1867 头白名单内存峰值 18.9MB→1.2MB、OOM 差异已验证；session 改动仅编译通过，运行时未验证
keywords:
  - PHP5.6
  - 补丁
  - rfc1867
  - session
  - OOM
  - 差分验证
category: 安全研究/PHP
---

# PHP 5.6 三补丁组合包：设计与实测结果

## 一、这个包包含什么

在前一份只改 `Zend/zend_alloc.c` 的补丁基础上，补上对照分析里判定「高性价比」的两处：

| 文件 | 改动 | 对应威胁 |
|---|---|---|
| `Zend/zend_alloc.c` | 新增 `zend_mm_safe_error_ex()`，OOM 时 `fprintf` + `_exit(1)`，绕开 `zend_error_noreturn` → `zend_bailout` → `longjmp` | 109618 的 OOM 退出路径 |
| `main/rfc1867.c` | 新增 `php_mime_should_save_hdr()`，multipart 头只保留 `Content-Disposition`/`Content-Type`，重复头丢弃 | 109618 的内存放大路径 |
| `ext/session/session.c` | `php_session_rfc1867_callback()` 里 `if (!PS(rfc1867_enabled) \|\| 1)` 硬返回 | 109619 的 session 路径 |

补丁体量：3 个文件、+63/-62、229 行。在第三份干净源码上 `patch -p1 --dry-run` 干净通过。

## 二、编译过程中真实踩到的坑

第一次编译**直接失败**，报错在 `main/rfc1867.c:447`：

```
error: conflicting types for 'php_mime_should_save_hdr'
note: previous implicit declaration with type 'int()'
```

原因是我把前置声明放在了 `php_mime_get_hdr_value()` 的定义旁边（第 471 行），而新代码在 **第 446 行**就调用了它——声明仍晚于使用点，C 编译器先按隐式声明 `int()` 处理，随后撞上真实签名。

修正办法：把两条声明移到文件头部的现有声明区（第 50–51 行，紧跟 `php_ap_getword` 系列声明）。改完后：

```
Build complete.
error: 0 条    warning: 0 条
```

这是个值得记下的教训：给老代码加函数时，先看目标文件已有的前置声明区在哪，别跟着定义位置走。

## 三、实测结果

### 3.1 zend_alloc：OOM 退出码 255 → 1

| 状态 | 退出码（3 次） |
|---|---|
| 未打补丁 | 255 / 255 / 255 |
| 已打补丁 | 1 / 1 / 1 |

错误文本两边完全一致（`Allowed memory size of 8388608 bytes exhausted`），只有退出码不同，说明补丁没改变「报什么错」，只改变了「怎么退」。`longjmp` 被从 OOM 出口摘掉了。

### 3.2 rfc1867 头白名单：内存峰值 18.9MB → 1.2MB

对照组 `php-cgi-mid`（仅 zend_alloc 补丁）与 `php-cgi-full`（三补丁），用 `php-cgi` 处理带大量重复 `X-Padding` 头的 multipart 请求，`memory_limit=16M`：

| 头部规模 | mid（仅 zend_alloc） | full（三补丁） |
|---|---|---|
| 2000 × 4KB ≈ 8MB | 正常，峰值 **18,912,896** 字节 | 正常，峰值 **1,262,144** 字节 |
| 4000 × 4KB ≈ 16MB | **OOM，rc=1** | 正常，峰值 1,262,144 |
| 8000 × 4KB ≈ 31MB | **OOM，rc=1** | 正常，峰值 1,262,144 |

三档全部符合预期：

- mid 版峰值随头数量线性增长，16MB 头部时撞破 16M 限制
- full 版峰值恒定在 1.2MB，31MB 头部也毫无压力
- 差值 15 倍，且不随输入放大

这条证据说明头白名单**真的切断了内存放大**，不是「改了但没效果」。

### 3.3 session：只做到编译通过，运行时未验证

这一项要如实说清楚。

`ext/session/session.c` 的改动是 `if (!PS(rfc1867_enabled) || 1)`，语义上是硬禁用——条件恒真，必然 `return retval`。编译通过、0 警告。

但**没有做运行时验证**，原因是能力边界：最初的 build 用 `./configure --disable-all --enable-cli`，session 扩展根本没编进去（`php -m | grep -c session` 返回 0），而 upload progress 路径需要 session 扩展才能观测（是否生成 session 文件、文件里有没有 `upload_progress_` 数据）。

后续启动了启用 session 的完整编译（`--disable-all --enable-cli --enable-cgi --enable-session`），但截至本文落盘，该编译仍在进行，差分测试尚未产出结果。

**所以这一项的准确表述是**：改动逻辑简单且编译通过，但没有实测证据表明它在运行时的行为符合预期。不能算已验证。

## 四、三处改动覆盖到哪

| 威胁 | 覆盖情况 |
|---|---|
| 109618 的 OOM 退出（`longjmp`） | 已覆盖并实测（255→1） |
| 109618 的内存放大（重复头） | 已覆盖并实测（18.9MB→1.2MB，OOM 消失） |
| 109619 的 session 路径 | 代码层面已改，运行时未验证 |
| 109619 其余机制（`BG(unserialize)`、`last_fatal_error_backtrace`、`delayed_oom`、opcache CE cache） | **无需覆盖**，5.6 架构上不存在这些位置 |

## 五、仍然不能声称的事

1. **不能说 5.6 已安全。** 只覆盖三个已知落点，且没有 fuzz、没有 ASAN、没有针对 5.6 的漏洞挖掘。
2. **CLI/CGI 不等于 mod_php。** 本轮实测在 CLI 与 CGI SAPI 上做，Apache mod_php 下 worker 被 `_exit(1)` 杀掉的具体表现（Apache 记录 child exit signal）未实测。
3. **session 改动未运行时验证**，见 3.3。
4. **109619 在 5.6 上的可利用性未评估。** 危险点（`PS(http_session_vars)` 悬空引用）存在且无护栏，但 5.6 无 `zend_reference` 独立结构体，8.5 的伪造手法不能照搬，实际能否构造出利用链没有验证。

## 六、可复现资产

| 位置 | 说明 |
|---|---|
| `php2shell-56-109618.patch` | 只改 `zend_alloc.c` 的最小补丁（早期版本） |
| `php2shell-56-full.patch` | 三补丁组合（远端生成，229 行） |
| `apply-56-full.py` | 应用 rfc1867 + session 两处改动的脚本，带替换计数校验 |
| `rfc1867_diff.py` | 头白名单差分测试脚本 |
| `session_diff.py` | session 路径差分测试脚本（待运行） |

编译环境：x86_64 Linux，gcc 12.3.0，glibc 2.38，PHP 5.6.40 源码。



## 七、补记：session 差分已完成（上文 3.3 的「未验证」已作废）

上一节写「session 改动仅编译通过，运行时未验证」，那是因为当时的 build 用了 `--disable-all`，session 扩展根本没编进去，无法触发 rfc1867 的 session 回调。补做了启用 session 的完整编译后，差分已经拿到。

### 做法

重新 `./configure --disable-all --enable-cli --enable-cgi --enable-session` 完整编译两版：

- `php-cgi-sess-mid`：干净源码 + 仅 `zend_alloc.c` 补丁（session.c 未改）
- `php-cgi-sess-full`：再叠加 `rfc1867.c` 头白名单 + `session.c` 硬禁用

两版都用含 session 扩展的 CGI SAPI（`php-cgi -m | grep -c session` = 1）。

请求构造：multipart POST，包含 `PHP_SESSION_UPLOAD_PROGRESS=prog123` 字段 + 一个 8MB 文件字段，带 `Cookie: PHPSESSID=testsid123`，并设 `session.save_path=/tmp/sessdir`、`session.upload_progress.enabled=1`、`session.upload_progress.cleanup=0`（不自动清理，便于观察落盘结果）。

### 实测结果

```
=== mid  rc=0 out='...OK sid='
    sess_testsid123 size=350 has_upload_progress=True
      head=b'upload_progress_prog123|a:5:{s:10:"start_time";i:1792637149;s:14:"content_length";i:838883'

=== full rc=0 out='...OK sid='
    session 文件: (无)
```

| 版本 | session 文件 | 大小 | 内容 |
|---|---|---|---|
| mid（session.c 未改） | `sess_testsid123` | 350 字节 | 含 `upload_progress_prog123\|a:5:{...}` |
| full（硬禁用） | **无** | — | — |

mid 版把 upload progress 数据按序列化形式写进了 session 文件；full 版连文件都没生成。**这一行 `|| 1` 确实把该写入路径整段截断了。**

### 三项改动的验证状态汇总

| 改动 | 验证方式 | 结果 | 状态 |
|---|---|---|---|
| `Zend/zend_alloc.c` OOM 出口 | 未修补 vs 已修补，各跑 3 次 OOM | 退出码 255 → **1** | 已验证 |
| `main/rfc1867.c` 头白名单 | mid vs full，2000/4000/8000 个 4KB 重复头 | 峰值 18.9MB → **1.2MB**；mid 在 16MB/31MB 头时 OOM，full 不 OOM | 已验证 |
| `ext/session/session.c` 禁用 | mid vs full，upload_progress 请求 | 生成 350 字节含 progress 的 session 文件 → **完全不生成** | 已验证 |

### 仍然没做到的

1. **全部在 CLI / CGI SAPI 上做，不是 Apache mod_php 或 FPM。** Zend 引擎核心与 rfc1867 解析逻辑对 SAPI 无感知，结论可迁移，但「mod_php 下 worker 被 `_exit(1)` 杀掉、Apache 记 child exit signal」这一层的具体表现没有实测。
2. **109619 在 5.6 上的可利用性仍未评估。** session 危险点（`PS(http_session_vars)` 悬空引用）存在且无护栏，但 5.6 没有 `zend_reference` 独立结构体，8.5 那套伪造手法不能照搬。补丁堵的是「upload progress 写 session」这个入口，不等于证明 5.6 上这条链不可利用。
3. **补丁只覆盖两个 CVE 在 5.6 上的已知落点**，不等于 5.6 安全。官方口径仍是「只有升级才完整」。
