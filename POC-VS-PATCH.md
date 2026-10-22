---
name: poc_vs_patch
title: 公开 PoC 与官方补丁逐条对照
description: 把 GitHub 上公开的 php2shell PoC 与 PHP 官方修复补丁逐条比对，判断哪些打的是同一个漏洞点、哪些是搭便车的夸大，以及 8.1 回补与 8.5 完整修复的强度差异。
summary: 核对 6 份公开 PoC 与 8.1 backport、8.5 完整修复两个补丁的对应关系；结论是两个 PoC 与内存损坏无关、一个需要本地代码执行、一个判定标准不可信、一个机理扎实但依赖外部地址泄漏；同时发现 EOL 分支拿到的是「整段禁用」而非同等修复。
keywords:
  - CVE-2026-109618
  - CVE-2026-109619
  - php2shell
  - PoC
  - 补丁对照
category: 技术/安全研究
---

# 公开 PoC 与官方补丁逐条对照

核查时间：2026-10-22。方法：从 GitHub 拉取 PoC 源码全文，与 `PHP-8.1-CVE-2026-109618-109619` 分支提交 `1d7dec178a09`（下称 8.1 回补）和 `PHP-8.5` 分支提交 `3584a98bda0f`（下称 8.5 完整修复）逐处比对。

**所有 PoC 都没有实际执行。** 以下判定基于源码阅读与补丁比对，不代表已验证其可用性。

## 先说一个关键差异：两个补丁不是同一件事

这是本次核对最重要的发现，也是判断 PoC 的前提。

| | 8.1 回补（EOL 分支） | 8.5 完整修复 |
| --- | --- | --- |
| 改动文件数 | 23 | 300 |
| `ext/session/session.c` | **+1/-1** | **+56/-11** |
| `Zend/zend_alloc.c` | +48/-20 | +527/-122 |

8.1 的 `session.c` 只有一行实质改动：

```c
-	if (!PS(rfc1867_enabled)) {
+	if (!PS(rfc1867_enabled) || true) {
```

这是无条件 return，整段禁用 upload progress 后续处理。它不修机理，只是把功能关掉。

8.5 则在同一文件里加了这些：

- 新增 `PS(in_rfc1867_update)` 标志位，在 `php_session_rfc1867_update()` 与 `php_session_rfc1867_cleanup()` 里置位/复位。
- 新增 `php_session_unserialize_init()` / `php_session_serialize_init()`，当该标志为真时调用 `php_var_unserialize_set_incomplete_classes_only()` 与对应的 serialize 版本。注释写明原因：

  > The upload progress handler decodes and re-encodes the session during request startup, before RINIT, when no user code may run. Objects are then kept as `__PHP_Incomplete_Class`: no autoloading, no `unserialize_callback_func`, no `__wakeup()` or `__unserialize()`, and they are written back unchanged.

- `MULTIPART_EVENT_START` 里提前调用 `php_rinit_session_globals()`，注释是 “This runs before RINIT, so we need to clear these early”。
- 新增 `PG(modules_activated)` 判断，`request_parse_body()` 场景直接返回，注释是 “Do not run here as it corrupts the session”。
- `php_session_initialize()` 返回 `FAILURE` 时直接 return，不再继续写 session。
- MULTIPART 结束时用 `zend_delete_global_variable()` 删掉 `_SESSION`，注释是 “`$_SESSION` was populated in incomplete_classes_only mode”。

**结论：EOL 分支（7.4 / 8.0 / 8.1）拿到的是功能阉割式免疫，不是与 8.2–8.5 同等的修复。** 这个区别对下面每一条判定都有影响。

## 逐条判定

### 1. `ikow/verify_session_injection.py` —— 与这两个 CVE 无关

它做三件事：在 POST body 里塞 `PHPSESSID` 字段、把 `<?php system('id');?>` 写进 filename、把 `x|O:8:"stdClass":0:{}` 也写进 filename。判定方式是提示你去目标机 `cat /tmp/sessions/sess_xxx` 看内容。

全程没有触发 OOM，没有触发 UAF，没有触发跨请求状态残留。它测的是：

- session fixation（body 里的 `PHPSESSID` 能否覆盖 Cookie）——这取决于 `use_only_cookies` / `use_strict_mode` 配置，是配置问题，不是漏洞；
- filename 原样写进 session 文件——这是 session 序列化的正常行为。

文件名挂着两个 CVE，但打的位置与内存损坏无关。**属于夸大。**

顺带一提：8.1 的 `rfc1867.c` 改动只保留 `Content-Disposition` 与 `Content-Type` 两个头，而 filename 就在 `Content-Disposition` 里，所以这条路径**即使打完补丁也依然存在**。它根本不是这两个 CVE 的修复目标。

### 2. `ikow/chain_a_session_lfi.py` —— 作者自己承认不是内存损坏

该文件开头的说明写得很清楚：

> This does NOT require a memory corruption exploit — the PHP session serializer stores raw filenames from multipart uploads, allowing PHP code injection into session files. Combined with any local file inclusion, this gives pre-auth RCE.

条件是：`session.upload_progress.enabled=On`（默认）+ 应用存在 LFI sink + session 路径可知或可猜。

这是「session 文件注入 + LFI」这条老链，借用 upload progress 作为写文件的跳板。同样与 109618/109619 的内存损坏机制无关。**属于夸大**，虽然作者在正文里算是诚实的。

### 3. `ikow/chain_b_uaf_rce.php` —— 机理对，但不是远程链

这份对应 109619 的 unserialize UAF，机理描述具体：`var_destroy()` 在 `var_unserializer.c:245` 释放回引扩展块，`i_zval_ptr_dtor`（:310）在未持有 `BG(serialize_lock)` 时触发 `__destruct`，内层 `unserialize('R:1500;')` 复用已释放的 `var_hash`，读落在 `php_var_unserialize`（:851）。

行号与机制能对上 109619 的 upload-progress unserialize UAF。

但它是个 PHP 脚本，自己 `fopen('/proc/self/mem','r+b')` 去覆写 `var_dump` 的 handler。**前提是攻击者已经能在目标上执行 PHP 代码**。php2shell 的卖点是未认证远程，而这份 PoC 站在"已有代码执行"的位置上验证「UAF 之后能不能走到 RCE」这个原语。

不是远程链。**方向成立，标题暗示的 RCE 需要打折扣。**

### 4. `ikow/chain_c_mismatch_rce.py` —— 条件苛刻，归因不准

它靠三步：命中某端点让应用自己 `ini_set('session.serialize_handler','php_serialize')` 污染 FPM 持久 worker → 用 filename 注入 `x|O:CLASS:N:{...}` → 干净的 worker 用 `php` handler 读、在 `|` 处切开、反序列化出对象、解码失败但 `__destruct` 已触发。

前提是：目标用 php-fpm、存在调用 `ini_set('session.serialize_handler','php_serialize')` 的端点、有一个带可利用 `__destruct` 的类被 autoload。

这里的跨请求污染是**应用自己调 `ini_set` 造成的**，不是 PHP 内部状态残留。虽然 8.5 的 `set_incomplete_classes_only` 恰好能阻断 rfc1867 update 期间的对象实例化，但这条链的根因在应用侧。**条件性成立，归因不准。**

### 5. `ikow/verify_oom_trigger.py` —— 方向对，判定不可信

这份确实打 109618，三种策略：

| 策略 | 对应补丁 | 覆盖情况 |
| --- | --- | --- |
| `headers`（5000 条 × 500 字节） | 8.1 `rfc1867.c` 头白名单 | **同一处**，重复头被丢弃后放大倍数被削 |
| `nested`（空文件控件 + 嵌套字段） | 8.1 补丁**未触及** `max_file_uploads` | 未被该补丁覆盖 |
| `no_length`（chunked 无 `Content-Length`） | 与 `post_max_size` 预检相关 | 我实测 chunked 可行 |

`headers` 这条与官方修复点一致。但它的判定逻辑不可信：只要响应码里出现 `500` 就打印 `[+] Server returned 500 — OOM likely triggered`。500 可能是任何错误，也可能是应用自己抛的。**结论需要服务端日志佐证，不能只看响应码。**

### 6. `eness/poc_109618.py` —— 机理最扎实，但不开箱即用

六份里质量最高的一份。它描述的机制是：外层 `zval*` 通过 `session.c` 里 `zend_hash_str_find` 缓存 `data["bytes_processed"]` 后不刷新，第二次 update 时 `zend_hash_update` 通过 `HashTable.pDestructor = zval_ptr_dtor` 析构旧 progress 树，造成外层指针悬垂；再用 149 个 `t[]` packed 自然表（`nTableSize` 256、320 字节 bin）回收该内存；伪造 `zend_fcall_info`（`+0` size、`+8` handler、`+48` param_count、`+88` internal handler），把 handler 指向 `zend_call_function`，尾部植入 `system\0cmd`。

几个必须说清的限制：

- **需要外部提供地址。** 靠 `--dtor` 传入泄漏到的 `zval_ptr_dtor`，再算 `call = dtor - 0x43EF0`。ASLR 绕过不在 PoC 内完成。
- **偏移不通用。** 注释自己写了 `Profile ubuntu php 8.5.4`，随后一行是 `Not this host's lsphp`——作者本人在别的环境上试过且没对上。
- **打的是修复前的 8.5.4。** 8.5.12 的修复核心是 `set_incomplete_classes_only` 与 initialize 失败即返回。而两份补丁（8.1 与 8.5）的 `grep` 都没有改动 `post_bytes_processed` 字段本身。

第三点值得单独说明：`set_incomplete_classes_only` 管的是对象实例化，而这份 PoC 伪造的是 `zend_fcall_info` 直调内部函数。**它是否被 8.5.12 覆盖，我无法从补丁文本判断**——需要跑起来才知道。这是本次核对留下的最大未知。

## 汇总

| PoC | 打的是同一个点吗 | 是否夸大 |
| --- | --- | --- |
| `verify_session_injection.py` | 否，与内存损坏无关 | 是 |
| `chain_a_session_lfi.py` | 否，session 注入 + LFI | 是 |
| `chain_b_uaf_rce.php` | 是（109619 unserialize UAF） | 是，需本地代码执行 |
| `chain_c_mismatch_rce.py` | 部分，根因在应用侧 | 是 |
| `verify_oom_trigger.py` | 是（109618，`headers` 策略） | 判定标准不可信 |
| `eness/poc_109618.py` | 是（109618，机理具体） | 否，但需外部地址泄漏 |

六份里，两份与这两个 CVE 无关，三份有条件或夸大，一份质量扎实但依赖外部信息。**"252 个仓库"这个数字不能当作"有 252 份可用武器"来读。**

## 对 5.6–7.3 自建补丁的影响

有个意外收获。8.1 对 `session.c` 的处理是 `|| true`——整段禁用。这意味着**照抄这一行就能在旧分支上把 upload progress 这条路径关掉**，不需要理解 109619 的四个子漏洞。

这对 `SELF-PATCH-5.6-7.3.md` 里"109619 不建议自修"的判断是个补充：四个子漏洞确实修不全，但如果目的是消除已确认的 session 路径，`|| true` 是官方对 EOL 分支自己采用的做法，成本极低、行为明确。代价是 upload progress 功能失效。

仍然不建议把它称作"修好了 109619"。它和 8.5 的机理修复不是一回事，剩下的 `SG(request_info)` 悬垂指针、OPcache CE cache 竞争、fatal backtrace 三条路径一条都没动。

## 没确认的部分

- 任何 PoC 都未执行，可用性未知。
- `eness/poc_109618.py` 描述的路径是否被 8.5.12 覆盖，未确认。
- `verify_oom_trigger.py` 的 `nested` 策略在打补丁后是否仍有效，未验证。
- 8.1 补丁未触及 `max_file_uploads`，空文件控件这条路在 8.1 上是否靠 `zend_alloc.c` 的 `_exit(1)` 兜底，未确认。


---

# 实测记录（2026-10-22）

上面那部分全部是读代码得出的判断。以下是真正跑起来的结果。

## 环境

| 项 | 值 |
| --- | --- |
| 系统 | macOS (darwin) |
| PHP | 8.1.33 (cli) NTS —— 未修复分支 |
| session.upload_progress.enabled | 1 |
| session.upload_progress.cleanup | 1 |
| memory_limit | 128M |
| post_max_size | 8M |
| max_file_uploads | 20 |
| /proc | 不存在（macOS 无 procfs） |

靶机是自己写的 `lab/index.php`（最简 upload progress 页面），用 `php -S 127.0.0.1:8899` 起，只绑回环。

## 实测一：verify_session_injection.py

跑通了，退出码 0。但看输出就知道这个 0 没有意义：

```
[1] Testing normal filename...
    → Session file should contain: s:10:"normal.txt"
[2] Testing PHP code in filename: <?php system('id');echo 'RCE';?>
    → Session file should contain PHP code as raw string
[3] Testing pipe + serialized object in filename
    → Session file should contain |O:8: in the filename field

[*] Verification complete. Check session files on the target:
    cat /tmp/sessions/sess_verifysession00000000000000a
```

**脚本自己不做任何判定。** 它发完三个请求，把结论责任推给用户自己去 `cat` 文件。退出码 0 只代表"三个请求发出去了"。

那我去 cat 了。靶机上没有这些文件——`find /tmp /var/tmp -name "sess_verifysession*"` 返回空。两个原因叠在一起：

1. 靶机 `session.save_path` 为空，实际落到系统临时目录，不是脚本提示的 `/tmp/sessions/`；
2. `session.upload_progress.cleanup=1` 会在请求结束后立刻把 progress 键从 session 里删掉，文件留不下来。

所以这个脚本在这套环境下**既没证明能注入，也没证明不能**。它只是发请求。

## 实测二：verify_oom_trigger.py --strategy headers

默认参数，5000 个 header × 500 字节。真实输出：

```
Sending 5000 headers × 500 bytes each
Wire size: ~2MB, Estimated PHP memory: ~9MB

Sending...
Response: HTTP/1.1 200 OK
Size: 867 bytes

[+] Connection dropped — server process may have crashed!
```

**这是本次实测最直接的收获。** 注意它自相矛盾的地方：

- 它收到了完整的 `HTTP/1.1 200 OK` 和 **867 字节的响应体**；
- 然后立刻宣布"服务器可能崩溃了"；
- 而靶机此时 `curl` 一下还是 `HTTP=200`，活得好好的；
- 服务器日志记的是 `[200]: POST /index.php` + 正常 `Closing`。

867 字节正好是靶机页面正常渲染的大小。也就是说：**请求被正常处理并正常返回，脚本却把它报成了崩溃。**

原因是它把 `Connection: close` 之后对端关闭连接这件事，直接当成了"进程崩了"，全程没有任何存活探测（没有事后重新连接、没有比对响应体内容）。这个判定标准不是"可能不准"，是**每一次正常请求都会走到这一行**。

至于为什么没触发 OOM：2MB 请求体、解析期内存估算约 9MB，面对 128M 的 `memory_limit`，差着一个数量级。

## 这三条实测推翻了什么

| 之前的判断（读代码得出） | 实测结果 |
| --- | --- |
| sess.py 不做判定，退出码不可信 | **证实**，且知道它为什么不可信：零判定逻辑 + cleanup 抹掉痕迹 |
| oom.py 以固定信号判成功，不可信 | **证实且更严重**：它把 HTTP 200 正常响应当成崩溃，等于每次都报成功 |
| 靶机前置条件成立 | 证实（upload progress 确实开着，请求确实走进了 multipart 解析） |

## 没做的部分（说清楚边界）

- `--strategy nested` 和 `--strategy no_length` 没跑；
- 没跑 `chain_a` / `chain_b` / `chain_c`：`chain_b` 依赖 `/proc/self/maps` 与 `/proc/self/mem`，macOS 上不存在，第一步就过不去；
- 没跑 eness 的 `poc_109618.py`：它靠 `--dtor` 从外部喂 `zval_ptr_dtor` 地址，偏移是 Ubuntu 8.5.4 的，本机是 macOS + 8.1.33，喂不进去；
- **没有打补丁做前后对照**，所以以上全部只能说明"PoC 本身在这个环境里跑不出东西"，不能说明"漏洞不存在"或"补丁有效"。


## 实测三：`verify_oom_trigger.py --strategy headers`，四个量级

靶机换成 `memory_limit=8M`、`post_max_size=64M`（放大 post_max_size 让请求体能进到解析阶段），其余不变。

| 参数 | 请求体 | PoC 报告的判定 | 靶机实际状态（跑后立即探测） |
| --- | --- | --- | --- |
| `--num-headers 5000` | ~2MB | `[+] Connection dropped — server process may have crashed!` | HTTP=200 存活 |
| `--num-headers 20000` | ~9MB | 同上 | HTTP=200 存活 |
| `--num-headers 50000` | ~24MB | 同上 | HTTP=200 存活 |
| `--num-headers 100000` | ~49MB | 同上 | HTTP=200 存活 |

四个量级，同样的误报。

## 实测四：抓完整响应 + 验证进程是否真的崩了

单独发一次 20000 条 header 的请求，把响应全量读回来，并在前后比对监听进程 PID：

```
BODY_SENT_BYTES    = 10288969        # 9MB 请求体
RESP_TOTAL_BYTES   = 305
RESP_STATUS_LINE   = HTTP/1.1 200 OK
RESP_HEADERS       = HTTP/1.1 200 OK | Host: 127.0.0.1 | Date: ... | Connection: close | X-Powered-By: PHP/8.1.33 | Content-type: text/html; charset=UTF-8
RESP_BODY          = <br /> <b>Fatal error</b>:  Allowed memory size of 8388608 bytes exhausted
                     (tried to allocate 4096 bytes) in <b>Unknown</b> on line <b>0</b><br />

PID_BEFORE = 48417
PID_AFTER  = 48417        # 同一个进程，没有重启
SAME_PID   = YES_process_alive
健康检查   = req1 200 / req2 200 / req3 200（连发三次全正常，耗时 0.8~2ms）
日志统计   = memory exhausted 出现 6 次；segmentation/core dumped/SIGSEGV/Killed 出现 0 次
```

**结论：OOM 确实被打出来了（日志里 6 次 `Allowed memory size of 8388608 bytes exhausted` 是硬记录），但进程一个都没崩。** PHP 8.1.33 在内存耗尽时做了正常的 fatal error 收尾，返回一个 305 字节的错误页，进程继续服务后续请求。

## PoC 为什么误报：判定代码有硬伤

`oom.py` 的判定逻辑在这几行：

```python
if resp:
    status = resp.split(b"\r\n", 1)[0].decode(...)
    ...
    if b"500" in status.encode():
        print("[+] Server returned 500 — OOM likely triggered!")
    elif not resp or b"connection" in resp.lower():
        print("[+] Connection dropped — server process may have crashed!")
    else:
        print("[-] Server responded normally — OOM threshold not reached.")
```

两处问题，都是致命的：

1. 这段代码在 `if resp:` 里面，所以 `not resp` 永远为假，那个分支形同虚设。
2. `b"connection" in resp.lower()` 匹配的是**整个响应**，而每个正常 HTTP 响应头里都有 `Connection: close` 或 `Connection: keep-alive`。所以只要服务器回了任何响应，这个条件就成立。

结果就是：**不管实际发生了什么，"崩溃"这个分支都必然命中。** 它唯一没误报的情况反而是服务器一个字都不回。

这也解释了为什么 5000 条（根本没打出 OOM）和 100000 条（打出了 OOM）给出的是一模一样的输出——它的输出和服务器状态无关。

## 这批实测能说明什么、不能说明什么

**能说明的：**

- `verify_oom_trigger.py` 的判定完全不可信，它输出的"服务器崩溃"是字符串匹配的产物，不是观测。基于它的任何结论（包括仓库 README 里的结论）都不能采信。
- 在 CLI 内置服务器（`php -S`）这个 SAPI 上，8.1.33 面对 header bomb 型 OOM 的表现是：正常 fatal error 收尾、进程存活、无崩溃信号。也就是说，**这条路径在本机没有产生内存损坏**。

**不能说明的：**

- **本机是 `cli-server` SAPI，不是 Apache mod_php 或 FPM。** 109618 的核心是 OOM 触发 `longjmp` 之后 request shutdown 阶段读未初始化内存，这个路径在不同 SAPI 上的表现可以完全不同。CLI 内置服务器上跑不出崩溃，不代表 Apache 上跑不出。
- 本机是 macOS，没有 `/proc`，也没有 ASAN 构建的 PHP，无法直接观测 UAF。
- 因此上面这些结果**不能用来否定漏洞存在**，只能用来否定"这份 PoC 的输出能证明漏洞存在"。


## 实测五：session 注入路径的真假对照（这一组是干净的）

`session.upload_progress.cleanup` 默认是 `1`，请求一结束就把 progress 数据删掉，所以前面第一次跑 `sess.py` 只能看到 0 字节文件。把 `cleanup` 设成 `0` 之后，这条路径才露出真面目。

**对照 C：`enabled=1`、`cleanup=0`（未修复分支 + 攻击者期望的配置）**

三个 session 文件全部写入了内容：

| 文件 | 大小 | filename 字段实际内容 |
| --- | --- | --- |
| `sess_...a` | 388 字节 | `s:10:"normal.txt"` |
| `sess_...b` | 410 字节 | `s:32:"<?php system('id');echo 'RCE';?>"` |
| `sess_...c` | 399 字节 | `s:21:"x|O:8:"stdClass":0:{}"` |

**对照 D：`enabled=0`、`cleanup=0`（等价于官方 8.1 的 `|| true`）**

三个 session 文件全是 **0 字节**，什么都没写进去。

### 这两组对照证明了什么

1. **`session.upload_progress.enabled=0` 确实切断了这条写入路径。** 这是实测，不是读代码推测。8.1 补丁把条件改成 `|| true`，行为上等价于把该开关配为 0，所以官方对 EOL 分支的处理方式是有效的——**在这条路径上**有效。

2. **但 ikow 对这个注入的描述不准确。** 它说 session 里会出现"raw PHP code / serialized objects"，实际写进去的是**被正确序列化的字符串**：`s:32:"<?php system('id');echo 'RCE';?>"`。长度前缀 `s:32:` 说明 PHP 把它当普通字符串处理了，没有当成结构解析；管道符那条同理，`s:21:"x|O:8:"stdClass":0:{}"` 整段被算作 21 个字符的字符串。

   也就是说，**这一步只是把攻击者可控的文本写进了文件**。要变成代码执行，还得有另一个漏洞让这个文件被当作 PHP 执行（LFI）。这正好解释了 `chain_a_session_lfi.py` 为什么要配 LFI——它自己也知道这一步不够。

3. **`sess.py` 的"验证"在默认配置下什么都看不到。** 它是靠 `cleanup=0` 才能留下痕迹的。默认 `cleanup=1` 时三个文件都是 0 字节，而脚本照样打印"Verification complete"并退出 0。

### 这一组的边界

- 这是 `cli-server` SAPI 上的对照，不是 Apache mod_php / FPM。
- 证明的是"socket 开关能切断 session 写入"，不是"109619 被修好了"。109619 的另外三条路径（`SG(request_info)` 悬垂指针、OPcache CE cache 类型混淆、fatal backtrace UAF）一条都没碰。
- 没有 LFI 环境，所以**没有验证**"session 文件写入 → 代码执行"这一步能否走通。


## 实测六：eness 的 PoC 发不出去，卡在自己的 SSL 逻辑上

请求体构造是成功的（`phase1=5439 total=62929 n=149 blob=288`），但发送阶段直接崩了：

```
ssl.SSLEOFError: EOF occurred in violation of protocol (_ssl.c:1129)
  File "eness.py", line 123, in talk
    ss = ctx.wrap_socket(raw, server_hostname=host)
```

靶机日志同步记录：`Invalid request (Unsupported SSL request)`。

原因是从源码里能直接看到的：`talk()` 里对 `socket.create_connection` 拿到的连接**无条件** `ctx.wrap_socket()`，没有判断 scheme 是 http 还是 https。所以这个 PoC 只能打 HTTPS 目标，对着明文 HTTP 靶机连第一个字节都发不出去。

这意味着两件事：

1. **它宣称的适用面比实际窄。** 大量内网靶场、开发环境是明文 HTTP，这个 PoC 在那儿根本跑不起来。
2. **即使补上 `--dtor`，本机也无法验证。** 它需要的偏移 `0x43EF0` 来自 Ubuntu 8.5.4 profile-21，本机是 macOS + PHP 8.1.33，布局完全不同，硬填一个地址只会打到随机位置。

靶机 PID 前后都是 48417，没有异常。

## 实测七：nested 策略同样误报

```
Sending 1000 empty file controls with 10-deep nesting
Response: HTTP/1.1 200 OK
Size: 866 bytes
[+] Connection dropped — server process may have crashed!
```

866 字节是靶机页面的正常大小，跑完靶机 HTTP=200 存活。**同一个 bug**：响应头里的 `Connection: close` 被判定代码当成了崩溃信号。

这说明 `oom.py` 的误报不是某个策略特有的，而是判定函数本身写错了，三条策略共用同一个判定。

## 实测汇总

| PoC | 能否在本机跑起来 | 实测结果 | 判定可信度 |
| --- | --- | --- | --- |
| `verify_session_injection.py` | 能跑 | 自身不做判定，靠人肉 `cat` 文件；默认配置下文件是空的 | 无判定逻辑 |
| `verify_oom_trigger.py` headers | 能跑 | 四个量级全部误报崩溃，实际进程存活 | **误报**（判定函数 bug） |
| `verify_oom_trigger.py` nested | 能跑 | 同样误报 | **误报** |
| `verify_oom_trigger.py no_length` | 未跑 | — | — |
| `poc_109618.py`（eness） | 构造成功、发送失败 | 无条件 SSL 握手，打不了 http 目标 | 未走到判定 |
| `chain_b_uaf_rce.php` | 不能 | 依赖 `/proc/self/maps`、`/proc/self/mem`，macOS 无此路径 | — |
| `chain_a_session_lfi.py` | 部分 | 依赖目标存在 LFI，本机靶机没有 | — |

**能跑通的四份里，没有一份给出了可信的成功判定。**

## 最终结论

用户最开始问的是"这些 PoC 到底能不能用"。现在的回答是分层的：

1. **有一份是真的有技术含量的**——eness 那份对 `post_bytes_processed` 陈旧外层 zval 的描述，和 8.5 补丁新增 `PS(in_rfc1867_update)` 标志、强制对象保持 `__PHP_Incomplete_Class` 的动机是对得上的。但它不是开箱即用的远程链：需要外部泄漏地址、需要 HTTPS、偏移写死在一个特定发行版上。

2. **有两份挂 CVE 编号但和内存损坏无关**——`verify_session_injection.py`、`chain_a_session_lfi.py` 测的是通用 session 文件注入，配 LFI 才有效。我实测坐实了这一点：`enabled=1` 时 filename 确实被写进 session 文件，但写进去的是 `s:32:"<?php system('id');...`，是被正确序列化的字符串，不是可执行结构。

3. **有一份判定代码是坏的**——`verify_oom_trigger.py` 把响应头里的 `Connection: close` 当成崩溃信号，三条策略都会误报。它报"服务器可能崩溃"的时候，靶机正在正常返回 200。

4. **官方对 EOL 分支的处理（`|| true`）实测有效**——`enabled=0` 时 session 文件是 0 字节，写入路径被切断。这条路可以照抄到 5.6–7.3，但不能叫"修好了 109619"。

**这份对照的边界：**全部在本机 `cli-server` SAPI 上做，不是 Apache mod_php 或 FPM；没有 ASAN、没有 `/proc`、没有 LFI 环境、没有打补丁做前后对照。所以以上只能否定"这些 PoC 的输出能证明漏洞存在"，不能否定"漏洞存在"。


## 复核记录：上面前两组是重跑确认过的

第一次跑实测六、七时，两条命令混在同一个 shell 里，PoC 崩溃的 traceback 混进了正常输出，整段结果不适合直接引用。所以把靶机重起了一遍（新 PID 48817），把 stdout 和 stderr 分开重跑：

| 项 | 脚本自报 | 独立核验 | 判定 |
|---|---|---|---|
| nested 策略 | `Connection dropped — server process may have crashed!`，exit=0，stderr 0 行 | 服务器 `HTTP/1.1 200 OK`、866 字节；随后 GET 返回 200、540 字节；`PID_AFTER = PID_BEFORE = 48817` | 误报，**复现** |
| eness 实发 | `phase1=5439 total=62929 n=149 blob=288 call=0x0`，exit=**1** | stderr 末行 `ssl.SSLEOFError: EOF occurred in violation of protocol`；靶机日志 `Invalid request (Unsupported SSL request)` 1 条；连接随即 Closing | 发不出去，**复现** |

两处与第一次完全一致，说明不是偶发。另外注意 eness 的退出码是 1 而不是 0——把它塞进任何自动化流水线里都会被当成失败，这本身也算个提示：这份 PoC 的作者大概只在 https 目标上验证过。

（866 与 540 的字节差不是矛盾：866 是 multipart POST 的响应，540 是我复核时发 GET 拿到的正常页面。）


---

# Docker 双版本对照实测（2026-10-22）

前面那些测试都跑在本机 macOS 的 `cli-server` 上，SAPI 不对、没有 `/proc`、没有 ASAN，说服力有限。这一轮换成真实环境做差分：同一份 PoC，同时打 8.4.26（受影响）和 8.4.27（已修复），看行为有没有区别。

## 环境

| 项 | 8.4.26（受影响） | 8.4.27（已修复） |
|---|---|---|
| 镜像 | `php:8.4.26-apache`<br>`sha256:60111400ff77…` | `php:8.4.27-apache`<br>`sha256:a0b75cee7023…` |
| 容器 | `p26` → `127.0.0.1:8081` | `p27` → `127.0.0.1:8082` |
| SAPI | `apache2handler` | `apache2handler` |
| `upload_progress.enabled` | 1 | 1 |
| `upload_progress.cleanup` | 0 | 0 |
| `session.save_path` | `/tmp` | `/tmp` |
| `max_file_uploads` | 20 | 20 |
| OPcache | loaded | loaded |

两个镜像都从 daocloud 镜像站正常拉完，之前卡在 `ddc0c1e36a67` 的限流问题这次没复现。

靶场是自己写的 `index.php`：故意同时留了文件上传和 LFI 点（`?page=` / `?f=` 直接 `include`），因为 chain_a 那条链必须要有一个真实的 LFI 才能走完。这是模拟"应用本身有文件包含漏洞"，不是 CVE 的一部分。

## 实测八：chain_a 在**两个版本上都成功拿到 RCE**

这是这一轮最意外的结果。

```
############ chain_a 对 8.4.26（受影响版本）############
[attempt 1] SID=exploitfe043e1705ae426fbf03
    plant=HTTP/1.1 200 OK
[+] RCE CONFIRMED: uid=33(www-data) gid=33(www-data) groups=33(www-data)

############ chain_a 对 8.4.27（已修复版本）############
[attempt 1] SID=exploit1d9da7391f9b4bcda96a
    plant=HTTP/1.1 200 OK
[+] RCE CONFIRMED: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

两个版本的 session 文件也**逐字节相同**（除了 `tmp_name` 里的随机串）：

```
[/tmp/sess_exploitfe043e1705ae426fbf03] 398 bytes   # 8.4.26
[/tmp/sess_exploit1d9da7391f9b4bcda96a] 398 bytes   # 8.4.27

upload_progress_x|a:5:{s:10:"start_time";i:1792634194;s:14:"content_length";i:327;
s:15:"bytes_processed";i:327;s:4:"done";b:1;s:5:"files";a:1:{i:0;a:7:{
s:10:"field_name";s:1:"f";s:4:"name";s:59:"<?php echo '___START___'; system('id'); echo '___END___';?>";
...
```

**这组的结论不是"补丁无效"，而是"chain_a 根本不是这两个 CVE 的利用链"。** 它在 8.4.27 上照样成功，说明它走的路径完全没被 8.5 的修复覆盖——因为它压根不需要内存损坏，只是把 filename 写进 session 文件，再靠应用自己的 LFI 去 include。这条链在**任何**开了 upload_progress + 有 LFI 的 PHP 版本上都能通，跟 CVE 编号无关。

这反过来从运行层面证实了之前读源码得出的判断。挂 CVE 编号是那个仓库的归类问题。

## 实测九：8.4.27 的二进制里确实有修复

光说"补丁存在"不够，直接查二进制：

```bash
docker exec p27 strings /usr/local/bin/php | grep -ciE 'incomplete_classes_only|in_rfc1867_update'
# 2

docker exec p26 strings /usr/local/bin/php | grep -ciE 'incomplete_classes_only|in_rfc1867_update'
# 0
```

8.4.27 命中 2 次，8.4.26 命中 0 次。这两个标识符正是 8.5 修复引入的（`PS(in_rfc1867_update)` 标志和 `set_incomplete_classes_only`）。**修复确实存在于这两个版本之间，不是只写在 changelog 里。**

## 实测十：handler mismatch 没测到关键点上

想让写入侧用 `php_serialize`、读取侧用 `php`，靠 `|` 切分把 `O:8:"stdClass":0:{}` 反序列化成对象。结果两边的 session 里 `name` 都是 `dummy`：

```
upload_progress_x|a:5:{...s:4:"name";s:5:"dummy";...}
```

payload 根本没写进去，读取侧自然只拿到一个正常的 array。**这组没测到东西，不能算证据。** 要真正测到 8.5 的 `set_incomplete_classes_only`，得让 upload_progress 的 filename 字段本身带上序列化对象，并且读取侧存在能触发 `__wakeup`/`__destruct` 的类——这个还没做。

## 实测十一：128M 内存下 OOM 根本没触发

用 `oom.py --strategy headers` 打两个版本：

| 版本 | 脚本自报 | 独立核验 | 日志里 OOM 次数 |
|---|---|---|---|
| 8.4.26 | `Connection dropped — crashed!` | `http=200`、`alive=true`、`restarts=0` | 0 |
| 8.4.27 | `Connection dropped — crashed!` | `http=200`、`alive=true`、`restarts=0` | 0 |

两个版本连 OOM 都没产生（`memory_limit=128M`，它发的头数量不足以撑爆），脚本依然报"崩了"——和之前在 macOS 上观察到的是同一个误报，说明这是脚本判定逻辑的问题，跟运行环境无关。

为了真正压出 OOM，另起了一组把 `memory_limit` 降到 2M 的容器（`o26` → 8091、`o27` → 8092），这一组的压测还没跑。

## 这轮实测确认了什么

能确认的：

1. **chain_a 与 CVE 无关**，用运行结果坐实——8.4.27 上照样 RCE，session 文件内容一致。
2. **8.4.27 的二进制里确实带修复**，`in_rfc1867_update` / `incomplete_classes_only` 只在新版本出现。
3. `oom.py` 的误报是脚本自身问题，跨环境复现。

还不能确认的：

1. **没有任何 PoC 展示出"8.4.26 成功、8.4.27 失败"的差分**——这才是证明漏洞被利用的标准。目前跑过的所有脚本要么两边都成功（chain_a），要么两边都没反应（oom.py），要么根本没测到（handler mismatch）。
2. 109619 的 UAF 需要 ASAN 构建或真实崩溃才能确认，这轮没做。
3. `verify_fpm_stale_state.py` 需要 FPM SAPI，这轮用的是 Apache，没跑。

下一轮要做的：2M 环境下的真实 OOM 压测、带 `__wakeup` 的类验证 `set_incomplete_classes_only` 行为差异、以及 FPM 容器的跨请求状态残留测试。


## OOM 在真实 Apache 下的表现：能触发，但两版本都不崩

换成 Apache + mod_php，`memory_limit=2M`，单字段塞 3MB / 8MB 的值，两个版本都返回：

```
HTTP/1.1 200 OK | 0.01-0.02s | 367B | oom=True | fatal=True
```

响应体里确实有 `Allowed memory size ... exhausted` 和 `Fatal error`。但关键在进程侧：

| 指标 | 8.4.26 | 8.4.27 |
|---|---|---|
| 容器存活 | `alive=true` | `alive=true` |
| 重启次数 | `restarts=0` | `restarts=0` |
| 崩溃信号日志 | `0` 条 | `0` 条 |
| 压后 GET | 200 / 1.6ms | 200 / 1.9ms |

也就是说：**OOM 这个前置条件触发了，但没有演变成进程崩溃，两个版本表现一致**。109618 要的是 OOM 之后 `longjmp()` 走 request shutdown 时读到未初始化内存，这一步在当前的压法下没有观察到，而 8.4.27 也没有表现出任何不同。

顺带纠正上一节的一个失败原因：先用 10 万个 multipart 字段去压，结果全部 `post_ok` 而不 OOM——原因是 `max_input_vars=1000`，字段数在解析前就被截断了。换成单字段大值才真正压出 OOM。


## 修复到底在不在：二进制符号比对

这一项比 PoC 输出更有说服力。直接在两个镜像的 `/usr/local/bin/php` 里查 8.5 修复引入的标识符：

| 标识符 | 8.4.26 | 8.4.27 |
|---|---|---|
| `incomplete_classes_only` | **0** | **2** |
| `in_rfc1867_update` | 0 | 0 |
| `php_mime_should_save_hdr` | 0 | 0 |
| `php_mime_get_hdr_value` | 0 | 0 |
| `modules_activated` | 0 | 0 |

`incomplete_classes_only` 在 8.4.27 里出现，8.4.26 里没有。这对应 8.5 提交 `3584a98bda0f` 的核心改动：rfc1867 update 期间反序列化时设 `incomplete_classes_only`，让对象恒为 `__PHP_Incomplete_Class`，不触发 `__wakeup` / `__unserialize` / autoload。**修复确实存在于这两个版本之间，不是镜像标签改个号。**

（其余几个符号查不到，是因为它们要么是静态函数名被内联、要么是结构体字段名不落进字符串表，不代表修复缺失。）

## chain_b 在 Linux 容器里也跑不出来

`chain_b_uaf_rce.php` 需要读 `/proc/self/maps` 定位基址。本机 macOS 没有 `/proc`，本来指望 Docker Linux 能跑，结果两个版本都是：

```
[-] no base
```

`/proc` 是有的，但脚本找基址的逻辑依赖特定内存布局，容器里没匹配上。所以这条链仍然**没有被证明可执行**——它需要的是精确的堆布局 + ASLR 绕过，不是一个通用脚本能覆盖的。

## 这一轮 Docker 实测到底证明了什么

**已证明（有硬证据）：**

1. 8.4.27 的二进制里确实带 8.5 的修复（`incomplete_classes_only` 命中 2 次，8.4.26 为 0）。
2. `chain_a` 不是 CVE 利用链：它在 8.4.26 和 8.4.27 上都拿到了 `uid=33(www-data)`，两边 session 文件逐字节相同（398 字节）。谁拿它当"漏洞已验证"的证据，都是错的。
3. OOM 前置条件可以在真实 Apache + mod_php 下触发（响应体含 `Allowed memory size ... exhausted`），但两个版本都没崩、都没重启，行为一致。

**未证明（必须说清楚）：**

1. 没拿到任何"8.4.26 成功、8.4.27 失败"的差分。这是判定漏洞被利用、补丁有效的唯一标准，目前所有脚本都没给出。
2. 109619 的 UAF 没被观察到。需要 ASAN 构建才能确认，`chain_b` 在容器里也跑不通。
3. `verify_fpm_stale_state.py`（跨请求状态残留）没跑，那需要 FPM SAPI，这轮用的是 Apache。

所以"别人已经验证出来了"这句话，至少在我实测过的这些仓库里，验的是 session 文件注入 + LFI 这条通用链，不是 CVE 本身。真正的内存损坏利用，公开脚本目前给我的都是跑不出结果的版本。


## 试图测出 8.5 那个关键差分，结果没测到

8.5 修复的核心是：rfc1867 update 期间反序列化时设 `incomplete_classes_only`，对象恒为 `__PHP_Incomplete_Class`。如果能观察到这个差异，就是"修复真的起作用"的硬证据。

做法：给两个容器预置完全相同的 session 文件（含一个 `stdClass` 对象），然后各发一次带 `PHP_SESSION_UPLOAD_PROGRESS` 的请求，看写回后的内容是否不同。

```
预置（两边相同）：foo|O:8:"stdClass":1:{s:1:"x";s:1:"y";}
```

结果：

| 版本 | 请求后 session 大小 | 内容 |
|---|---|---|
| 8.4.26 | 39 字节 | `foo|O:8:"stdClass":1:{s:1:"x";s:1:"y";}` |
| 8.4.27 | 39 字节 | `foo|O:8:"stdClass":1:{s:1:"x";s:1:"y";}` |

**两边一模一样，没有出现 `__PHP_Incomplete_Class`。** 同时注意到 session 文件里也没有预期中的 `upload_progress_x|a:5:{...}` 数据，说明这次请求的 progress 数据压根没写进这个 session——也就是说，`incomplete_classes_only` 那条路径这次没被走到，这个测试是无效的（不是"证明修复无效"）。

要真正走到那条路径，需要在 rfc1867 回调读 session 的那一刻观察对象类型，这得靠 C 层探针或 ASAN 构建，从 HTTP 层外部看不出差别。

这也是整轮实验最诚实的结论：**能证明修复存在于二进制里，但没能从外部行为上观察到它起作用**。
