---
name: reproduced_109619
title: CVE-2026-109619 本机复现记录
description: 在 php:8.5.11-apache (x86_64) 上按公开 PoC 完整复现 php2shell RCE，含负面对照与缓解验证
summary: 两个 multipart POST 在零功能页面上拿到 uid=33(www-data)，CTORADDR=0 与 enabled=0 两组对照均断链
keywords:
  - CVE-2026-109619
  - php2shell
  - 复现
  - RCE
  - Docker
category: 安全研究/PHP
---

# CVE-2026-109619 本机复现记录

复现日期：2026-10-22
依据：https://mp.weixin.qq.com/s/Xxbro24uPkICH6ZlJP8oDg 的复现过程 + `dinosn/php-cve-2026-10961x-lab-poc` 仓库

## 结论

**已复现。** 在零功能页面上用两个普通 multipart POST 拿到命令执行：

```
MARKER=uid=33(www-data) gid=33(www-data) groups=33(www-data)
FIRE_OK
```

三次独立运行均成功。

## 环境

| 项 | 值 |
|---|---|
| 宿主机 | macOS arm64 + Docker Desktop |
| 镜像 | `php:8.5.11-apache`，**必须以 `--platform linux/amd64` 启动** |
| 容器内架构 | x86_64 |
| SAPI | apache2handler（mod_php） |
| worker | 1 个（`mpm_prefork.conf`：ServerLimit=1 / MaxRequestWorkers=1） |
| 靶场页面 | `<?php echo "OK\n"; ?>`（零功能，无 session_start / 无 LFI / 无上传处理） |
| memory_limit | 16M |
| post_max_size | 32M |
| session.upload_progress | enabled=1，cleanup=1，save_path=/tmp |
| disable_functions | 含 system / exec，但利用直接调 `zif_system`，绕过该限制 |

容器额外参数：`--cap-add=SYS_PTRACE --security-opt seccomp=unconfined`（读 `/proc/<pid>/maps` 取地址必需），并需在容器内装 `python3`。

## 偏移核对（与文章一致）

| 符号 | 值 | 用途 |
|---|---|---|
| `zif_system` | `0x5996e0` | 终点函数 |
| `zval_ptr_dtor` | `0x7b47a0` | libphp 基址推算 |
| `OFF_HT` | `0x7e0d8` | chunk → HashTable data |
| `OFF_R0` | `0x7a6e0` | chunk → PS(http_session_vars) |

## 两次请求做了什么

**Phase A**（`--huge 24`，sid-len 100，107 个 pad）：24MiB 字段在 `php_request_startup` 内 OOM，`longjmp()` 提前退出，request heap 释放但 worker 的 `PS(http_session_vars)` 仍指向已释放的 `zend_reference`。

```
A status='HTTP/1.1 200 OK' req=25174294 resp=342 elapsed=0.20
body = Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 6296371 bytes)
worker_after_A=17      ← worker 存活
```

**Phase B**（live-n 200、fill-n 80、mask-n 8）：用 200 个 31 字节字符串 reclaim 悬空 reference，再伪造 55 字节 fake `zend_reference` 与 167 字节 fake HashTable，令 `pDestructor = zif_system`。`php_session_rfc1867_cleanup → php_session_initialize → zend_hash_destroy` 时触发。

```
B status='<no head>' req=28122 resp=0     ← worker 在调用中崩掉，无响应
MARKER=uid=33(www-data)
FIRE_OK
```

## 因果验证（三轮）

| 实验 | 结果 | 说明 |
|---|---|---|
| `MODE=zif` | `FIRE_OK`，`/tmp/nb9bm` 有 uid=33 | 正常利用 |
| `MODE=neg`（CTORADDR=0） | `FIRE_FAILED`，标记文件不存在 | 同参数只改终点，不执行 |
| `enabled=0` 后重启 | `FIRE_FAILED`，标记文件不存在 | 官方缓解有效，链路断在入口 |
| 恢复 `enabled=1` 再打 | `FIRE_OK`，uid=33 | 排除环境损坏 |

## 前几轮为什么全失败

1. **架构不匹配（根本原因）**：Mac 是 arm64，拉下来的镜像是 aarch64 构建，`zif_system=0x5314f0`、`zval_ptr_dtor=0x761b80`，与文章的 x86_64 偏移完全不同。必须 `--platform linux/amd64`。
2. **靶场缺页面**：仓库 `app/public` 下没有 `index.php`，访问直接 404，OOM 与 session 生命周期路径压根不执行。
3. **跑错了 PoC**：之前跑的 ikow 系列里 `chain_a_session_lfi.py` 是 session 文件注入 + LFI 的通用链，与 CVE 补丁无关（在 8.4.26 与 8.4.27 上都能通）；真正对应 109619 的是 dinosn 仓库这套 OOM + 悬空 reference 链。
4. 容器缺 `python3` 与 `SYS_PTRACE`，取不到地址。

## 这条链的边界

- **lab-assisted**：两个 HTTP 请求本身是普通 multipart POST，但 `libphp` 与内存 chunk 地址来自容器内 `/proc/<worker>/maps`。纯远程需要额外的地址泄露原语，文章第 10 节亦如此声明。
- **单 worker 才稳定**：`ServerLimit=1`；多 worker 部署可靠性未验证。
- 偏移针对 `php:8.5.11-apache` 这个具体构建，换发行版或编译选项需重新定位。

## 复现脚本

`/tmp/nb/fire_local.sh`（改造自仓库 `ninebie/nb_fire.sh`，把 `nb_env.py` 改到容器内执行，以适配 macOS）。

用法：

```sh
cd /tmp/nb
export MODE=zif LIVE_N=200 FILL_N=80 MASK_N=8 SIDLEN=100 A_HUGE=24
bash fire_local.sh
docker exec esc-9b-8511 cat /tmp/nb9bm
```
