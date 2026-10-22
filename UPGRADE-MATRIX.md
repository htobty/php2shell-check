---
name: php2shell_upgrade_matrix
title: CVE-2026-109618 / 109619 全版本修复方案矩阵（PHP 5.6 及以上）
description: 按 PHP 版本分支给出官方修复状态、可落地目标版本与操作路径，覆盖 5.6 至 8.5，含 EOL 分支自建补丁与补偿控制方案。
summary: 一张表说清每个 PHP 分支该升到哪个版本；官方覆盖 7.4 及以上，5.6–7.3 无官方补丁，需走补偿控制或最小跨度升级。
keywords:
  - CVE-2026-109618
  - CVE-2026-109619
  - PHP2Shell
  - 升级矩阵
  - EOL
  - backport
category: 安全/漏洞响应
---

# 全版本修复方案矩阵（PHP 5.6 及以上）

## 先说一个需要纠正的前提

「线上服务不可能一下子升到 8.2」——这个顾虑在多数情况下不成立。

**绝大多数部署不需要跨大版本。** 两个漏洞的修复版本是分支内的最小升级：

- 跑 8.4 的升 8.4.27（不是 8.2）
- 跑 8.3 的升 8.3.36
- 跑 8.2 的升 8.2.35
- 跑 8.5 的升 8.5.12

这四个都是同分支补丁版本，不涉及语法变更、不涉及扩展重编、不需要改业务代码，等同一次常规安全更新。

真正需要跨大版本的只有 **5.6、7.0、7.1、7.2、7.3** 这五个分支——它们官方没有补丁。

## 方案矩阵

| 当前版本 | 官方修复状态 | 目标版本 | 操作 | 风险 |
|---|---|---|---|---|
| 8.5.x | 正式发布 | 8.5.12 | 分支内升级 | 低 |
| 8.4.x | 正式发布 | 8.4.27 | 分支内升级 | 低 |
| 8.3.x | 正式发布 | 8.3.36 | 分支内升级 | 低 |
| 8.2.x | 正式发布 | 8.2.35 | 分支内升级 | 低 |
| 8.1.x | 仅源码回补分支 | 8.1 + backport | 自行构建 | 中 |
| 8.0.x | 仅源码回补分支 | 8.0 + backport | 自行构建 | 中 |
| 7.4.x | 仅源码回补分支 | 7.4 + backport | 自行构建 | 中 |
| 7.3.x 及更早 | **无官方补丁** | 7.4 + backport 或更高 | 跨版本升级 / 补偿控制 | 高 |
| 5.6.x | **无官方补丁** | 见下文第 3 节 | 跨版本升级 / 补偿控制 | 高 |

官方原文（php.net 公告 How to update 一节）：

> PHP 8.1 and older no longer receive updates from the PHP project. Some distributions and LTS vendors provide backported fixes, so contact your vendor for details, or upgrade to a supported version.

> Given the severity of these vulnerabilities, the PHP security team provided minimal source-backports for PHP 7.4, PHP 8.0, and PHP 8.1 to help people building from source or without access to an LTS vendor.

注意范围：**回补只到 7.4**。5.6 / 7.0 / 7.1 / 7.2 / 7.3 没有任何官方补丁，这一点必须对上讲清楚，不能含糊成"官方都修了"。

## 1. 8.2–8.5：直接升级，无需改造

```bash
# Debian/Ubuntu（以 8.4 为例，需先加对应 PPA 或使用发行版源）
sudo apt-get update && sudo apt-get install --only-upgrade php8.4-cli php8.4-fpm php8.4-common

# RHEL/CentOS（remi 仓库当天不会有更新，官方点名建议切发行版包或源码构建）
sudo dnf update php-cli php-fpm
```

升级后验证：

```bash
php -v                      # 确认版本号
php checker.php             # 应输出 PATCHED
systemctl restart php8.4-fpm
```

这一档是本次响应里成本最低、收益最确定的部分。**优先做这一档，先把大头收掉。**

## 2. 7.4 / 8.0 / 8.1：官方源码回补分支

官方给了三个可直接拉取的分支（已核验存在，HEAD 提交均为 `Avoid state corruption via bailout`，日期 2026-10-18）：

| 分支 | HEAD |
|---|---|
| `PHP-7.4-CVE-2026-109618-109619` | `712e60f9edfd` |
| `PHP-8.0-CVE-2026-109618-109619` | `82f8f31b16a0` |
| `PHP-8.1-CVE-2026-109618-109619` | `1d7dec178a09` |

构建方式：

```bash
git clone --branch PHP-8.1-CVE-2026-109618-109619 --depth 1 \
  https://github.com/php/php-src.git php-8.1-fixed
cd php-8.1-fixed
./buildconf --force
./configure [你现有部署的完整参数]   # 必须一致
make -j"$(nproc)"
sudo make install
```

**关键约束**：`./configure` 参数必须与现有部署一致。SAPI（fpm / apache2handler / cli）、扩展清单、编译选项任一不同，替换后行为就会变。替换前把 `php -m`、`php -i` 的输出存档，替换后逐项比对。

优先级判断：如果发行版或商业 LTS 厂商（Red Hat、SUSE、Ubuntu Pro、CloudLinux 等）提供了带安全回补的包，**优先用厂商包**，不要让业务团队自己编 PHP——包管理能持续跟进后续补丁，自建构建则要靠人盯。

## 3. 5.6 – 7.3：官方无补丁，三条路

这一档没有任何官方修复版本，必须做个取舍。

### 代码级核实：5.6–7.3 确实带着同源缺陷代码

本次直接比对官方源码，确认不是「老版本碰巧没事」：

| 分支 | `Zend/zend_alloc.c` 中 `zend_mm_safe_error()` |
|---|---|
| PHP-5.6 | 第 1743 行起，`heap->overflow` 判断 + `zend_try { zend_error_noreturn(E_ERROR, ...) }` |
| PHP-7.0 | 第 385 行：`heap->overflow = 1; zend_try { zend_error_noreturn(E_ERROR, ...) }` |
| PHP-7.2 | 第 376 行，同上 |
| PHP-7.3 | 第 374 行，同上 |
| PHP-7.4 | 同一结构——所以官方给了它回补分支 |

这正是 109618 的根因形态：OOM 时用 longjmp 提前退出，request shutdown 有机会读到未初始化内存。**这几个分支不是「没被列为受影响所以安全」，而是带着同一种代码结构，只是官方选择不为它们发布补丁。**

所以 5.6–7.3 的处置不能靠「官方公告没提我」来免责。要判断实际可利用性（SAPI 是否 mod_php、是否同 worker 处理生产与消费请求、配置是否可达该路径），仍需按 `checker.php` 的三要素逐项核对。

关于 109619，其四个子漏洞依赖的全局状态项（`EG(last_fatal_error_backtrace)`、`BG(unserialize)`、`PS(id)`、OPcache frontier）在 7.3 及更早分支的存在形态本次未逐一核实，不做断言。

### 路线 A：最小跨度升级到 7.4 + 回补（推荐）

从 5.6/7.0–7.3 升到 7.4，跨度远小于升到 8.2，且能直接拿到官方回补分支。

- 7.3 → 7.4：主要变化是箭头函数、typed properties、`??=`，破坏性改动相对可控
- 7.2 → 7.3/7.4、7.0/7.1 → 7.4：需要逐版本检查废弃项
- 5.6 → 7.4：跨度大（移除 mysql_*、移除 preg 的 /e、移除 ASP 标签等），需要真实改造

配套做法：先在预发环境跑 7.4 + 回补分支，用业务回归测试压一遍，再灰度。

### 路线 B：自建补丁移植（风险高，仅限有能力维护 C 代码的团队）

补丁本身已核验：**23 个文件、1176 行 patch**，核心改动是四处：

1. `Zend/zend_alloc.c`：新增 `zend_mm_safe_error_ex()`，把原来的 `zend_try` + `zend_error_noreturn(E_ERROR)` 路径改成直接 `_exit(1)`——这是 109618 的根因修复，不再用 longjmp 提前退出，杜绝了未初始化内存被 request shutdown 读取
2. `Zend/zend_vm_def.h` + `Zend/zend_vm_execute.h`：VM 指令里的整数溢出检查改走上述函数（`zend_vm_execute.h` 是由 `zend_vm_def.h` 经 `zend_vm_gen.php` 生成的，移植时必须重新生成，不能手改）
3. `main/rfc1867.c`：multipart 头部只保留 `Content-Disposition` / `Content-Type`，并丢弃重复头，压缩单 part 的内存放大面
4. `main/SAPI.c`：request shutdown 时清空 `SG(request_info)` 里的一批残留指针

移植到 7.3 及更早的主要障碍：VM 生成器在 5.6（`zend_vm_gen.php` 老版本）与 7.x 之间差异较大，OPcache 持久化结构（`zend_persist.c`）也不同。**这不是一条可以放心推给大量线上的路**，只在个别无法升级的遗留系统上考虑，且必须有回归测试与快速回退能力。

### 路线 C：补偿控制（止血，不解决根因）

在无法立刻改版本时降低暴露面。官方明确说 **109619 没有通用配置层完全缓解**，所以这些措施只能算争取时间。

| 目标 | 措施 | 说明 |
|---|---|---|
| 109618 | `memory_limit=-1` + `php_admin_value` | 消除可控的内存上限失败，但底层分配失败仍可能进入该路径 |
| 109618 | `post_max_size=8M`（有上传需求 32M），`upload_max_filesize` 低于它 | 收窄请求体放大面 |
| 109619 | `session.upload_progress.enabled=0` | 切断已确认的消费者入口 |
| 109619 | PHP 8.5 另加 `fatal_error_backtraces=0` | 8.5 才有的开关 |
| 通用 | FPM `pm.max_requests=1` | 切断跨请求残留链，代价是性能 |
| 通用 | 反代层限制解码后体积、字段数、part 数、header 数、嵌套深度 | 必须覆盖没有可用 `Content-Length` 的请求（分块传输） |
| 通用 | `max_multipart_body_parts` 压到 256 以内 | 掐断大量 part 的放大路径 |

两个必须避免的误区：`display_errors=Off` 不是缓解（OOM 照样发生，只是错误不回显）；WAF 不是安全边界。

## 4. 建议的落地顺序

按「先收大头、再啃硬骨头」推进：

1. **本周内**：8.2–8.5 全部服务升到对应分支补丁版本。这一档零改造，能覆盖绝大多数实例。
2. **同步启动**：7.4/8.0/8.1 确认走厂商包还是自建构建，排期替换。
3. **同时止血**：对所有暂未升级的实例（含 5.6–7.3）先上路线 C 的配置项，尤其 `session.upload_progress.enabled=0` 和 `memory_limit=-1`。
4. **中长期**：5.6–7.3 排期升到 7.4 以上，或迁到受支持分支。这批是真正的技术债，靠补偿控制撑不了太久。
5. **验证**：每批升级后用 `php checker.php` 确认 `PATCHED`，并核对 `php -m` 扩展清单一致。

## 5. 需要留存的不确定性

- 官方受影响版本列表只列 8.2–8.5，**没有把 5.6–8.1 明确列为受影响，也没有明确排除**。给 7.4/8.0/8.1 做回补的理由原文是「鉴于这些漏洞的严重性」，不是确认受影响。因此：5.6–7.3 的实际可利用性，本次未做代码级核实，不要据此断言"安全"或"确定受影响"。
- 要结论就得自己验证：在预发环境用 7.3 拉源码比对上述四处改动是否等价存在，或用 `probe.py` 的加压层在隔离靶机上验证 OOM 路径是否可达（注意其会真实耗尽目标内存）。
- 无论哪条路线，最终都要回归到升级。补偿控制是时间窗口，不是终态。

## 参考

- https://www.php.net/archive/2026.php
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619
- https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619
- https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619
