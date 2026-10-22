# php2shell-check

CVE-2026-109618 / CVE-2026-109619 的非破坏性自查工具集，附 PHP 5.6–7.3 自建补丁方案。

两个漏洞于 2026-10-21 由 PHP 安全团队协调披露，可导致未授权远程代码执行。本仓库用于判断一套 PHP 环境是否具备被利用的前置条件，并给出旧分支无法升级时的处置路径。

**不含武器化利用代码。** 工具只做版本与配置审计、公开缓解项核查，不包含堆布局猜解、堆喷、伪造 unserialize 状态或 OPcache 类型混淆等环节。

## 漏洞背景

| 编号 | 成因 | 修复版本 |
|---|---|---|
| CVE-2026-109618 | 内存超限触发 `longjmp` 提前退出，请求级结构停在半初始化状态，request shutdown 读取未初始化内存 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| CVE-2026-109619 | 跨请求残留的全局状态被下一个请求当作有效数据消费 | 同上 |

EOL 分支 7.4 / 8.0 / 8.1 由官方提供最小源码回补分支，5.6–7.3 无官方补丁。

## 仓库内容

### 工具

| 文件 | 作用 |
|---|---|
| `checker.php` | 静态审计。读取运行环境真实的版本、SAPI、INI 生效值，判定受影响区间与暴露等级 |
| `probe.py` | 动态探测。默认无害指纹层，`--stress` 为加压层 |
| `index.php` | 探测靶页，仅输出版本与上传相关 INI |
| `lab/index.php` | 最简 upload progress 靶页，供 PoC 复现测试 |

### 补丁

| 文件 | 作用 |
|---|---|
| `php2shell-56-109618.patch` | 5.6 最小补丁，仅改 `zend_alloc.c`，切断 OOM 的 `longjmp` 出口 |
| `php2shell-56-full.patch` | 5.6 三补丁组合：`zend_alloc.c` + `rfc1867.c` + `session.c` |
| `php2shell-7.3-109618.patch` | 7.3 适配版本 |
| `patch-5.6-109618.py` / `patch-7x-109618.py` | 直接修改源码树的脚本版，不依赖 `patch` 命令 |
| `apply-56-full.py` | 应用 rfc1867 与 session 两处改动，带替换计数校验 |
| `verify-56-patch.sh` | 自动化验证：下载源码 → 打补丁 → 双份构建 → 行为对比 |
| `zz-php2shell.ini` | 收窄攻击面的 INI 配置样例 |

### 分析文档

| 文件 | 内容 |
|---|---|
| `EVENT-AND-FIXES.md` | 事件经过与各版本修复方式逐条对照 |
| `POC-VS-PATCH.md` | 公开 PoC 与官方补丁逐条对照，判定每个 PoC 实际命中的目标 |
| `REPRODUCED-109619.md` | 109619 复现记录：环境、请求构造、判定依据、边界 |
| `UPGRADE-MATRIX.md` | 升级矩阵：版本 × 处置路径 × 补偿控制 |
| `SELF-PATCH-5.6-7.3.md` | 5.6–7.3 自建补丁方案与移植取舍 |
| `PATCH81-PORT-MAP-56.md` | 官方 8.1 回补的 20 个文件在 5.6 上的逐项移植对照 |
| `109619-SUBPATHS-56.md` | 109619 修复点在 5.6 上的核对 |
| `VERIFY-56-FULL.md` | 三补丁组合设计与差分实测数据 |
| `compare.sh` | 8.4.26 / 8.4.27 双容器对照实验，需 Docker |

## 环境要求

- `checker.php`：PHP 7.0 及以上，CLI 或 Web 均可
- `probe.py`：Python 3，仅使用标准库
- `verify-56-patch.sh`：Linux x86_64，需 `gcc`/`clang`、`make`、`curl`、`tar`、`patch`

## 用法

### 静态审计

只读判定，不发起任何攻击载荷，可对生产环境执行。

```bash
php checker.php
php checker.php --json | jq .
```

CLI 下 `PHP_SAPI` 为 `cli`，与生产 Web SAPI 不同。评估 Web 侧暴露面时，把文件放到目标站点可访问路径并通过 HTTP 访问：

```bash
curl 'http://your-host/checker.php?format=json'
```

### 动态探测

分两层。默认只执行第一层。

**第一层：无害指纹（零副作用）**

发送普通 GET 与一个小于 2KB 的合法 multipart，从响应头推断版本与 SAPI，检查会话标识可达性。

```bash
python3 probe.py --url http://127.0.0.1:8080/
python3 probe.py --url https://your-site.example/ --json
```

**第二层：加压探测（会让目标耗尽内存）**

仅限隔离环境与已授权目标。三道门槛缺一不可：`--stress`、`--yes`、目标为 IP 字面量形式的回环或私网地址。

```bash
# 先起隔离靶机
php -d memory_limit=8M -d post_max_size=64M -S 127.0.0.1:8898 -t .

python3 probe.py --url http://127.0.0.1:8898/index.php \
  --stress --yes --rounds 1 --headers 100000
```

默认拒绝探测公网地址，需显式加 `--allow-remote`。该开关对加压层无效。

#### 加压层的参数关系

能否命中取决于靶机两个 INI 的相对关系：

- 载荷字节数必须小于 `post_max_size`，否则请求体被 PHP 丢弃，multipart 解析不发生，表现为秒回 200、内存零增长；
- 放大后占用必须大于 `memory_limit`，否则无法触发 OOM。

只调 `memory_limit` 不够。上例 100000 条约 3.8MB，配 `post_max_size=64M`。

#### 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--url` | 必填 | 目标地址 |
| `--rounds` | 3 | 轮数，上限 10 |
| `--headers` | 20000 | header 洪水条数 |
| `--files` | 1000 | 空文件控件数量 |
| `--timeout` | 20 | 单请求超时秒数 |
| `--delay` | 1 | 请求间隔秒数 |
| `--stress` | 关 | 启用加压层 |
| `--yes` | 关 | 确认已获授权 |
| `--allow-remote` | 关 | 允许探测公网地址，不适用于加压层 |
| `--json` | 关 | 输出 JSON 报告 |

## 判定结果

`checker.php`：

| 结果 | 含义 |
|---|---|
| `PATCHED` | 版本已在修复区间之上 |
| `CRITICAL_EXPOSURE` | 版本未修复，且为 mod_php / FrankenPHP 一类 SAPI。请求启动失败时仍无条件执行 request shutdown，攻击发生在应用代码之前 |
| `ELEVATED` | 版本未修复，但当前 SAPI 的跨请求面与启动面较小 |

`probe.py`：

| 结果 | 含义 |
|---|---|
| `NO_SIGNAL` | 未观察到信号。不等于安全 |
| `PARTIAL` | 有异常响应，未命中 OOM 文案 |
| `HIT_PATH` | 命中 OOM 提前退出路径，这是 109618 的攻击前提 |
| `DISCLOSURE_SIGNAL` | 出现异常膨胀的 `PHPSESSID`，符合 109619 的内存泄露特征 |

除 `PATCHED` 外，任何结果只代表具备前置条件，不代表已被入侵。

## 旧版本补丁

5.6–7.3 无官方补丁。补丁覆盖已知落点，不改变官方结论——升级仍是唯一完整方案。

```bash
# 在 PHP 5.6.40 源码根目录
patch -p1 --dry-run < php2shell-56-full.patch
patch -p1 < php2shell-56-full.patch
make -j"$(nproc)"
```

自动验证：

```bash
bash verify-56-patch.sh
```

脚本完成下载、打补丁、双份构建与行为对比，判据为 OOM 时的退出码与 shutdown 回调是否执行。

补丁范围限于 109618 的 OOM 出口与 upload progress 路径。109619 在 5.6 上仅 session 路径存在对应落点，其余机制在该分支不存在。详见 `VERIFY-56-FULL.md` 与 `109619-SUBPATHS-56.md`。

## 边界

- **`NO_SIGNAL` 不代表安全。** 利用要求生产者与消费者请求命中同一 worker，还需配合具体版本的内存布局。单 worker 易命中，多 worker 加动态伸缩的 pool 命中率明显下降。
- **CLI 结果不代表生产 Web SAPI。** CLI 无 HTTP 请求面。
- **加压层有确定的可用性代价。** 它让目标内存耗尽，对生产执行等同自造 DoS。即使目标在隔离环境，也应预期请求失败、留下 OOM 日志、触发监控告警。
- **自建补丁不改变「该升级」的结论。** 官方原文：`There are no complete mitigations, updating is the only safe choice`。

## 免责

加压层仅用于自有环境或已获书面授权的目标。使用者对执行行为及其后果负责。

## 许可证

[MIT](LICENSE)
