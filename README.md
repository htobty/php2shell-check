# php2shell-check

CVE-2026-109618 / CVE-2026-109619 的非破坏性自查工具集。

两个漏洞在 2026-10-21 由 PHP 安全团队协调披露，修复版本为 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12。这组工具只回答一个问题：**眼前这套 PHP 环境是否具备被利用的前置条件**。它不尝试让利用成功，也不含任何代码执行载荷。

## 文件

**工具**

| 文件 | 作用 |
|---|---|
| `checker.php` | 静态审计：版本区间、SAPI 暴露等级、关键 INI 项，含「该配置能否被应用运行时覆盖」的判断 |
| `probe.py` | 动态探测，分两层：默认是无害指纹层（零副作用），`--stress` 才是加压层（仅限已授权的隔离环境） |
| `index.php` | 探测靶页，只打印版本与上传相关 INI，不含业务逻辑 |
| `lab/index.php` | 最简 upload progress 靶页，给公开 PoC 提供一个能跑起来的目标 |

**分析与验证文档**

| 文件 | 内容 |
|---|---|
| `EVENT-AND-FIXES.md` | 事件经过与各版本修复方式逐条对照，含受影响版本梳理 |
| `POC-VS-PATCH.md` | 公开 PoC 与官方补丁逐条对照，逐项判定每个 PoC 打的是不是这两个 CVE |
| `REPRODUCED-109619.md` | 109619 的复现记录：环境、请求构造、判定依据、边界 |
| `UPGRADE-MATRIX.md` | 升级矩阵：版本 × 处置路径 × 补偿控制 |
| `SELF-PATCH-5.6-7.3.md` | 5.6–7.3 自建补丁方案，含为什么有些改动在旧分支上无落点 |
| `PATCH81-PORT-MAP-56.md` | 官方 8.1 回补的 20 个文件在 5.6 上的逐项移植对照 |
| `109619-SUBPATHS-56.md` | 109619 修复点在 5.6 上的核对：哪些危险点在、哪些机制根本不存在 |
| `VERIFY-56-FULL.md` | 三补丁组合的设计与三组差分实测数据 |

**补丁与脚本**

| 文件 | 作用 |
|---|---|
| `php2shell-56-109618.patch` | 只改 `zend_alloc.c` 的最小补丁，切断 OOM 的 `longjmp` 出口 |
| `php2shell-56-full.patch` | 三补丁组合（`zend_alloc.c` + `rfc1867.c` + `session.c`，229 行） |
| `php2shell-7.3-109618.patch` | 同思路在 7.3 上的适配版本 |
| `patch-5.6-109618.py` / `patch-7x-109618.py` | 直接修改源码树的脚本版（不走 patch 命令） |
| `apply-56-full.py` | 应用 rfc1867 + session 两处改动的脚本，带替换计数校验 |
| `verify-56-patch.sh` | 一条命令走完下载 → 打补丁 → 双份构建 → 行为对比 |
| `compare.sh` | 8.4.26 / 8.4.27 双容器对照实验（需 Docker） |
| `zz-php2shell.ini` | 收窄攻击面的 INI 配置样例 |

## 用法

静态审计，无副作用：

```bash
php checker.php
php checker.php --json | jq .
```

`probe.py` 分两层，默认只走第一层。

**第一层：无害探测（默认，零副作用）**

发一个普通 GET 加一个小于 2KB 的合法 multipart，从响应头推断版本与 SAPI，再看会话标识是否可达。不会把目标内存打穿，可以对生产跑：

```bash
python3 probe.py --url http://127.0.0.1:8080/
python3 probe.py --url https://你的站点/ --json
```

**第二层：加压探测（`--stress`，会让目标吃内存）**

只有在隔离环境、且你明确授权时才用。三道门槛缺一不可：`--stress`、`--yes`、目标是 IP 字面量形式的回环或私网地址。

```bash
php -d memory_limit=8M -d post_max_size=64M -S 127.0.0.1:8898 -t .   # 隔离靶机
python3 probe.py --url http://127.0.0.1:8898/index.php --stress --yes --headers 100000
```

加压层为什么必须传 IP 而不是域名：域名解析结果不可信，代理的 fake-ip 模式会把任何域名解析到 `198.18.0.x`，而这段在 Python 里恰好被判为「私有」，靠 DNS 判断内网会直接把公网目标放进来（本工具确实踩过这个坑，见实测记录第 6 条）。

默认拒绝探测公网地址，需要显式加 `--allow-remote`；`--allow-remote` 对加压层无效。

**加压能否命中，取决于靶机的两个 ini 怎么配：**

- 载荷字节数必须小于 `post_max_size`，否则请求体被 PHP 丢弃，multipart 解析根本不发生——服务端秒回 200、内存零增长，看着像「没漏洞」，其实是没测到；
- 内部放大后必须大于 `memory_limit`，否则吃不出 OOM。

所以只调 `memory_limit` 是不够的，还得把 `post_max_size` 抬到远高于载荷字节数（上面例子 100000 条约 3.8MB，配 64M 足够）。

## 判定怎么读

`checker.php` 的总体判定：

- `PATCHED`：版本已在修复区间之上
- `CRITICAL_EXPOSURE`：版本未修复 + mod_php / FrankenPHP 一类 SAPI，请求启动失败仍会无条件执行 request shutdown，攻击发生在应用代码之前
- `ELEVATED`：版本未修复，但当前 SAPI 的跨请求面与启动面较小

`probe.py` 的判定：

- `NO_SIGNAL`：没观察到信号，不等于安全，见下面限制
- `PARTIAL`：有异常响应，但没命中 OOM 文案
- `HIT_PATH`：已命中 OOM 提前退出路径，这是 109618 的攻击前提
- `DISCLOSURE_SIGNAL`：出现异常膨胀的 PHPSESSID，符合 109619 的内存泄露特征

除 `PATCHED` 外，任何判定都只代表**具备前置条件**，不代表已被入侵。

## 实测记录

在 macOS + PHP 8.1.33 上跑出来的几件事，直接改掉了工具的实现：

1. **伪造错误的 Content-Length 走不通。** 声明一个远小于实际发送量的长度，服务端直接判 `Malformed HTTP request`，请求进不到 multipart 解析器。换成 RFC 9112 分块传输、完全不给 Content-Length，这条策略才真正生效。
2. **不带 `PHP_SESSION_UPLOAD_PROGRESS` 字段等于没测。** session upload progress 是 109619 已确认路径里的消费者，请求里没有这个字段就不会激活它。补上字段、同时固定同一个 PHPSESSID 之后，响应开始出现 `sessid=26`。
3. **`max_multipart_body_parts` 是一道现成的边界。** 8.1.33 上发 3000 个空文件控件，服务端日志报 `Multipart body parts limit exceeded 1020`；1001 个 part 正常通过。所以 `--files` 默认改成 1000：超过上限时测到的是这道墙，不是漏洞路径。另外这台机器 `ini_get()` 返回 `-1`，那是「沿用版本内置默认值」，不是关闭。
4. **OOM 文案比 5xx 可靠。** 低内存靶机（`memory_limit=8M`）上两条策略都命中 `Allowed memory size ... exhausted`，响应码却是 200——`display_errors` 开着时错误会回显进 body。判定逻辑因此把 OOM 文案作为 `HIT_PATH` 的充分条件，5xx 只当加强证据。

5. **加压能否命中，要看 `post_max_size` 和 `memory_limit` 的相对关系。** 只调 `memory_limit=8M`、`post_max_size` 留在默认 8M 时：20000 条 header 不命中；加到 300000 条（约 11MB）反而更快返回 200、内存零增长——因为请求体超过 `post_max_size` 被直接丢弃，multipart 压根没解析。把靶机改成 `-d memory_limit=8M -d post_max_size=64M` 后，100000 条（约 3.8MB）和 400000 条（约 15MB）都稳定命中 `HIT_PATH`，服务端各留 2 条 OOM 记录。**「没信号」有时是没测到，不是没漏洞。**
6. **靠 DNS 判断「是不是内网」会漏掉公网目标。** 改造时发现本机代理的 fake-ip 模式把 `example.com` 解析到 `198.18.0.100`，而这段（RFC 2544 保留段）在 Python 的 `ipaddress.is_private` 里返回 True，旧护栏因此把公网域名当成私网放行，实测真的对它发出了 11 个请求。现在加压层只接受 IP 字面量：域名一律拒绝，因为解析结果是可被 fake-ip、劫持、CDN 改写的，不能当安全边界。

复现低内存验证（注意两个 `-d` 都要给）：

```bash
php -d memory_limit=8M -d post_max_size=64M -S 127.0.0.1:8898 -t .
python3 probe.py --url http://127.0.0.1:8898/index.php --stress --yes --rounds 1 --headers 100000
```

## 它测不出什么

- **`NO_SIGNAL` 不代表安全。** 利用要求生产者与消费者请求命中同一个 worker，还要配合具体版本的内存布局。单 worker 的内建服务器最容易命中，多 worker 加动态伸缩的 pool 命中率会明显下降。
- **CLI 上的结果不能代表生产 Web SAPI。** CLI 没有 HTTP 请求面，`checker.php` 会直接说明这一点。
- **没有做受影响版本与修复版本的容器对照。** 需要 Docker daemon，当前环境未启动。
- **无害层不回答「能不能打穿」。** 它只给版本、SAPI、会话可达性这些指纹。版本落在受影响区间就说明有 Exposure，不需要也不应该靠加压去「证明」——那一步的代价是目标内存。
- **加压层的「没信号」有多种成因，不能一律读成安全。** 除了 worker 命中率，还可能只是载荷比 `post_max_size` 大而整个请求被丢弃（此时服务端会秒回 200）。先确认靶机的 `post_max_size` 与 `memory_limit` 符合上一节的关系，再讨论结果的含义。
- **加压层有确定的可用性代价。** 它做的事就是让目标内存耗尽，对生产跑等于自造 DoS。即使目标在隔离环境，也要预期这次请求会失败、会留下 OOM 日志、可能被监控告警。
- **不含**内存布局猜解、堆喷、伪造 unserialize 状态、OPcache 类型混淆这些武器化环节。这是有意的，自查工具不该顺手变成攻击工具。

## 配置缓解（替代不了升级）

官方明确说升级是唯一完整缓解。实在升不了时的取舍：

| 目标 | 措施 |
|---|---|
| 109618 | `memory_limit=-1`，用 `php_admin_value` 防止应用覆盖；这是拿可用性换安全 |
| 109619 | `session.upload_progress.enabled=0`；PHP 8.5 另加 `fatal_error_backtraces=0` |
| 收窄放大面 | `post_max_size=8M`（有上传需求 32M）、`upload_max_filesize` 低于 `post_max_size`、`max_multipart_body_parts` 压到 256 以内 |
| 切断跨请求链 | FPM `pm.max_requests=1`，代价是性能 |
| 前置代理 | 限制解码后体积、字段数、part 数、header 数、嵌套深度，且必须覆盖没有可用 Content-Length 的请求 |

两个常见误区：`display_errors=Off` 不是缓解，OOM 照样发生，只是错误不进响应；WAF 不是安全边界。两个 CVE 同源，只升部分实例、或只做配置缓解，都还是留着口子。

## 参考

- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://www.wiz.io/blog/php2shell-php-rce
- http://www.openwall.com/lists/oss-security/2026/10/21/7
- https://php.net/archive/2026.php


---

## 修复前后对照：未执行（2026-10-22）

这一节必须看，避免把本文档的实测记录误读成"补丁前后已验证"。

### 想做什么

用两个只差 PHP 版本的容器，同一份 ini、同样的请求量，各跑一遍 `probe.py`：

- `php:8.4.26-apache` —— 受影响版，预期在 OOM 时走 `longjmp()` 提前退出，留下未初始化请求内存被 request shutdown 读取
- `php:8.4.27-apache` —— 已修复版，预期 OOM 改为 VM 安全点的延迟软 OOM，二次阈值才 `_exit()`，上述信号消失

两个容器都用 mod_php（`apache2handler`），即这组漏洞里最危险的 SAPI：请求启动失败时仍会无条件执行 request shutdown，攻击发生在应用代码之前。

### 为什么没做成

卡在镜像下载，与脚本无关：

- 从 Docker Hub 拉这两个镜像时，双方都卡在同一个大层 `ddc0c1e36a67`，连续重试 10 次未成功，日志中没有任何 error 文案，只有无限的 `Retrying` —— 这是 Hub 对匿名拉取大层的限流或掐断表现
- daemon 里虽已配 `https://docker.m.daocloud.io` 加速器，但按默认镜像名拉取仍被打回 Hub 源
- 改用显式源 `docker.m.daocloud.io/library/php:8.4.27-apache` 后重试计数归零、各层开始正常下载，确认通路可用，但 apache 版单镜像约 500MB 级，两个镜像在可接受时间内拉不完
- 已终止拉取进程，未留下后台任务

**因此本文档中所有"实测"结论均来自本机低内存靶机，不包含受影响版与已修复版的横向对照。**

### 未验证的道具

`compare.sh` 与 `zz-php2shell.ini` 已经写好、`bash -n` 通过，但**从未在真实容器里跑过**，属于未验证资产：

- `zz-php2shell.ini`：`memory_limit=16M`（官方镜像默认 128M，2 万条 header 吃不穿，压小才走得进 OOM 路径）、`post_max_size=32M`、`max_multipart_body_parts=1020`、`session.upload_progress.enabled=1`、`display_errors=On`
- `compare.sh`：起两容器（端口 8401 / 8402）→ 等 `/index.php` 就绪 → 调 `probe.py --yes` → 抓容器日志里的 `Allowed memory size` / `Multipart` / `Fatal` → 退出时自动 `docker rm -f`

镜像到位后可直接执行：

```bash
cd ~/code/php2shell-check
HEADERS=20000 ROUNDS=2 ./compare.sh
```

判读标准：受影响版应出现 OOM 命中且容器日志有 `Allowed memory size ... exhausted`；已修复版该信号应消失，若观察到容器重启或退出属补丁的预期行为。

### 现有替代证据

`probe.py` 的路径有效性已在本机用 `php -d memory_limit=8M -S 127.0.0.1:8898` 打过：`oom-chunked-no-length` 与 `oom-header-flood` 两条策略均命中 OOM 文案，服务端日志出现

```
PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
```

这证明"探测能命中 OOM 提前退出"这条机制在 8.1.33 CLI 上成立，但**不等于验证了 8.4.26 → 8.4.27 的补丁差异**。两者是不同的命题，不要混用。


## 已经 EOL 的版本（7.4 / 8.0 / 8.1）怎么办

官方这次只对四个仍在维护的分支发了正式版本：8.2.35、8.3.36、8.4.27、8.5.12。更早的分支不会再有官方发布，但也不是完全没给东西。

php.net 公告「How to update」一节原文：

> PHP 8.1 and older no longer receive updates from the PHP project. Some distributions and LTS vendors provide backported fixes, so contact your vendor for details, or upgrade to a supported version.

> Given the severity of these vulnerabilities, the PHP security team provided minimal source-backports for PHP 7.4, PHP 8.0, and PHP 8.1 to help people building from source or without access to an LTS vendor.

对应三个分支，已核验真实存在（HEAD 提交均为 `Avoid state corruption via bailout`，日期 2026-10-18，即披露前三天）：

| 分支 | HEAD |
|---|---|
| `PHP-7.4-CVE-2026-109618-109619` | `712e60f9edfd` |
| `PHP-8.0-CVE-2026-109618-109619` | `82f8f31b16a0` |
| `PHP-8.1-CVE-2026-109618-109619` | `1d7dec178a09` |

### 这几个分支不是「发布版本」

- 没有官方二进制、没有 Windows 包、没有安装器，只是 GitHub 上的源码分支；
- 不享受完整发布流程的回归测试与安全支持承诺；
- 公告说得清楚，它的对象是「自己从源码构建」或「拿不到 LTS 厂商补丁」的人。

### 三条路径，按推荐顺序

1. **升级到受支持分支**（唯一官方认可方案）。8.1 → 8.2 起跳是跨小版本，先过一遍 `UPGRADING` 的不兼容变更，本地跑完测试再上。
2. **从源码构建带补丁的 8.1**。适合被框架或扩展绑死、短期升不上去的：

   ```bash
   git clone --branch PHP-8.1-CVE-2026-109618-109619 --depth 1 \
     https://github.com/php/php-src.git php-8.1-fixed
   cd php-8.1-fixed
   ./buildconf --force
   ./configure [你现有部署的原有参数]
   make -j"$(sysctl -n hw.ncpu)"
   ```

   两处必须注意：`./configure` 参数要和现有部署一致，否则 SAPI 或扩展会变；替换前用 `php -v`、`php -m`、`php --ri` 与旧环境逐项比对。
3. **走发行版 / LTS 厂商**。RHEL、Debian、Ubuntu 及商业 LTS 供应商在披露前就拿到了补丁，`apt`/`yum` 里会有带安全回补的包。

### 两个容易踩的坑

- **remi 仓库当天不会有更新**。公告专门点名：依赖 `rpms.remirepo.net` 的，建议立刻切到发行版官方包或自行从源码构建。
- **别跨分支摘 commit**。这三个分支是各自分支的最小回补，混用会引入不兼容改动，7.4/8.0 这种缺失后续重构的分支尤其危险。

### 「7.4 / 8.0 / 8.1 到底受影响吗」

官方受影响版本列表写的是 8.2–8.5，公告并没有把 7.4/8.0/8.1 明确列为受影响；给它们做 backport 的理由原文是「鉴于这些漏洞的严重性」。所以**别把「有 backport」读成「官方确认你受影响」，也别把「不在列表里」读成「确定安全」**——同源代码是否存在、能否到达，取决于具体分支实现和部署形态。要结论就按第 2 条拉源码自己比对，或者直接升级。


## 5.6 自建补丁验证到了哪一层（2026-10-22）

这里要说明清楚，避免把「脚本改对了」当成「修好了」。验证分三层，目前状态如下：

| 层级 | 判据 | 状态 |
| --- | --- | --- |
| 第 1 层 补丁可应用 | `patch -p1 --dry-run` / `git apply --check` 通过 | 已验证（在 PHP-5.6 真实 `Zend/zend_alloc.c` 上通过） |
| 第 2 层 能编译 | 用真实 5.6 头文件编译 `zend_alloc.c` | 部分验证：`clang -fsyntax-only` 在 `main/php_config.h` 等真实头文件下通过（含 `-Wall -Wformat`），但**没有产出 php 二进制** |
| 第 3 层 运行生效 | OOM 时不再走 longjmp、不再执行 shutdown 回调 | **未验证** |

第 2 层为什么卡住：本机是 macOS + Apple clang 17，PHP 5.6.40 这份 2014 年的源码在新工具链上有两处与漏洞无关的环境兼容问题——

- `ext/pcre/pcrelib/sljit/sljitNativeARM_64.c`：`sys_icache_invalidate` 未声明（ARM64 + macOS 缺 `libkern/OSCacheControl.h`）
- `main/reentrancy.c:139`：`readdir_r` 参数个数与新 SDK 不匹配

两处都不是补丁引入的，但会让 `make` 停在半路，`Zend/zend_alloc.lo` 根本轮不到编译。继续在本机硬啃没有价值，所以把第 2、3 层做成脚本交出去：

```bash
# 在 Linux（gcc / clang 均可）上跑，一条命令走完下载 → 打补丁 → 双份构建 → 行为对比
bash verify-56-patch.sh
```

脚本会做四件事：拉官方 `php-5.6.40.tar.gz`；确认这份源码确实带着 `heap->overflow = 1` + longjmp 的漏洞形态；把同一份源码解两份，一份原样编、一份打补丁编；最后用同一个耗尽 `memory_limit` 的脚本跑两个二进制，比较**退出码**与**shutdown 回调是否执行**。

判定逻辑：原始版 OOM 后会执行 `register_shutdown_function` 注册的回调（因为走的是 bailout），补丁版改用 `_exit(1)` 直接退出、回调不执行。这个差异能在二进制层面直接看到，不依赖任何对源码的推理。

即使脚本 PASS，也只说明 **109618 的 OOM 路径被切断**。109619 的四个子漏洞（upload-progress unserialize UAF、远程内存泄露、fatal-error backtrace UAF、OPcache 类型混淆）不在这个补丁范围内，一个都没修。


## 公开 PoC 生态（2026-10-22 核查）

**先更正一处此前说错的话**：本文档早先把「109619 的公开材料里没有可用 PoC」当作「不建议自修」的论据之一，这个前提不成立。2026-10-22 用 GitHub API 检索确认，相关仓库数量如下：

| 检索词 | 仓库总数 |
| --- | --- |
| `CVE-2026-109618` | 252 |
| `CVE-2026-109619` | 235 |
| `php2shell` | 291 |

披露时间 2026-10-21 14:00 UTC，这批仓库绝大多数创建于 2026-10-21 当天，头部几个 star 数在 24 小时内冲到 500–1000：

| 仓库 | star | 创建时间 | 语言 | 体量 |
| --- | --- | --- | --- | --- |
| `ikow/php2shell-poc` | 987 | 2026-10-21T07:55Z | Python | 2.7 MB |
| `eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC` | 600 | 2026-10-21T08:31Z | Shell | 216 KB |
| `9bie/php2shell-bypass-aslr-exp` | 486 | 2026-10-21T11:11Z | Python | 21.5 MB |
| `NCSC-NL/php2shell` | 121 | — | — | 荷兰国家网络安全中心的运营信息 |
| `openai/php2shell-checker` | 413 | — | — | — |

### 内容核查到什么程度

看的是文件树与源码文本，**没有执行任何一个 PoC**。以下几点是实际观察到的：

`ikow/php2shell-poc` 的 28 个文件里有 `exploit/chain_a_session_lfi.py`、`chain_b_uaf_rce.php`、`chain_c_mismatch_rce.py`，另有 `poc/verify_*.py` 五个验证脚本，以及 `detection/` 下的 ModSecurity 规则、Snort/YARA 规则、Lua 检测脚本。

其中 `poc/verify_uaf_asan.php` 声称能触发 `var_unserialize` 的 heap-use-after-free，代码里给了具体定位：`var_unserializer.c:851`（读）与 `var_destroy` 的 `:245`（释放），并说明成因是 `i_zval_ptr_dtor` 在 `BG(serialize_lock)` 未持有时触发 `__destruct`，导致内层 `unserialize('R:1500;')` 复用已释放的 `var_hash`。运行方式是 `USE_ZEND_ALLOC=0 ASAN_OPTIONS="detect_leaks=0"`。

`exploit/chain_b_uaf_rce.php` 走的是 `/proc/self/mem` 覆写函数 handler 的路径：读 `/proc/self/maps` 定位 php 基址，遍历函数表找 `zif_system`，再把 `var_dump` 的 handler 指针改成 `zif_system`。代码里带具体偏移（如 `eg=$base+0x1420900`、函数表偏移 `+0x1b0`）。

这些代码有具体行号、具体结构体偏移、具体运行参数，不是空壳占位符。但**偏移量是否正确、是否只在特定构建/配置下成立，我没有验证**。

### 可信度需要自己掂量

同一个仓库里有 `docs/linkedin_post.md`、`docs/linkedin_article.md`、`docs/substack_article.md`、`docs/cover.png`（2.7 MB 的配图）——这类内容说明作者在同步做传播，不完全是纯研究仓库。披露后一天冲到千星，热度里有相当一部分来自话题性而非代码质量。

另外 `9bie/php2shell-bypass-aslr-exp` 体积 21.5 MB 但只有一个描述为空的仓库，这类体量通常意味着塞了二进制或序列化文件，来源不明的东西不要直接跑。

### 这件事改变了什么

1. **CISA SSVC 的 `Exploitation: none` 判定已经过期**。该判定作出于披露时点，现在公开仓库数量已到这个规模，「无在野利用」不再是可以依赖的假设。升级从「应该做」变成「尽快做」。
2. **攻击门槛显著下降**。之前需要自己从补丁反推，现在有现成代码。哪怕只有一部分仓库的代码真的能打，具备前置条件的目标暴露面就已经变了。
3. **对自修结论的影响**：此前说「109619 不建议自修」的理由之一是「没有 PoC 就无法验证修没修对」。现在这个理由**不成立**了——验证手段公开存在。但自修依然不建议，理由换成更本质的两条：四处子漏洞必须全修、改错 OPcache 持久化内存的后果比漏洞本身更难排查。有 PoC 让「能验证」成立，不等于让「一个人能修对」成立。
4. **防御侧建议不变**：升级到 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12。配置缓解的边界上一章已经写明，不因为 PoC 公开而改变。

### 检测规则的现实价值

`ikow` 那个仓库里的 `detection/` 目录（ModSecurity `.conf` + `.rules`、Snort/YARA、Lua）和 `eness` 的 `apache/modsecurity-php2shell.conf` 可以考虑参考，但**规则有效性未经验证**。是否采用要看它拦截的请求特征与你们真实流量是否冲突——这类基于特定 payload 形态的规则，误报和绕过都常见。

真正可靠的检测仍然是自己看日志：搜索 `Allowed memory size of` 与 `bytes exhausted` 频繁出现的记录、异常大的 multipart 请求、单个请求内 header 数量异常。这些在 [probe.py 的加压层](probe.py) 命中时也会在服务端留下痕迹，可作对照。
