#!/usr/bin/env bash
# verify-56-patch.sh
#
# 目的：在**真实 PHP 5.6.40 源码**上验证 php2shell-56-109618.patch 到底做到了哪一层：
#   第 1 层 补丁能应用（patch -p1）
#   第 2 层 补丁后能编译（出 sapi/cli/php 二进制）
#   第 3 层 运行时行为真的变了（OOM 不再走 longjmp → 不再执行 shutdown 回调）
#
# 它只验证 CVE-2026-109618 的 OOM/longjmp 这一条路径，不涉及 109619，
# 也不构造任何攻击载荷。
#
# 环境要求：Linux x86_64（或任意有 gcc/clang 的 unix），bash、curl、tar、make、patch
# 用法：bash verify-56-patch.sh
# 产物：$WORK（默认 /tmp/php2shell-verify）下的两棵源码树、两个二进制、verify-report.txt
#
# 注意：为了绕开老源码在新工具链上的噪音，CFLAGS 里带了 -fcommon（gcc 10+ 需要）与 -Wno-error。
#      本脚本不改动 zend_alloc.c 以外的任何 PHP 代码。
set -uo pipefail

VER=5.6.40
HERE=$(cd "$(dirname "$0")" && pwd)
PATCH_FILE="$HERE/php2shell-56-109618.patch"
WORK=${WORK:-/tmp/php2shell-verify}
TARBALL="$WORK/php-$VER.tar.gz"
URL="https://www.php.net/distributions/php-$VER.tar.gz"
REPORT="$WORK/verify-report.txt"

mkdir -p "$WORK" || exit 1
: > "$REPORT"

say()  { printf '%s\n' "$*" | tee -a "$REPORT"; }
head1() { say ""; say "---- $* ----"; }
die()  { say "[FAIL] $*"; exit 1; }

say "== php2shell：PHP 5.6 补丁分层验证 =="
say "时间    : $(date -Is 2>/dev/null || date)"
say "工作目录: $WORK"
say "补丁    : $PATCH_FILE"
[ -f "$PATCH_FILE" ] || die "找不到补丁文件：$PATCH_FILE"

for c in curl tar make patch; do
  command -v "$c" >/dev/null 2>&1 || die "缺少命令：$c"
done
CC_BIN=$(command -v gcc || command -v clang) || die "缺少 gcc/clang"

# ---------------------------------------------------------------- 1. 源码
head1 "1/5 准备源码"
if [ ! -f "$TARBALL" ]; then
  say "下载 $URL"
  curl -fsSL --max-time 600 -o "$TARBALL" "$URL" || die "下载失败"
else
  say "已存在源码包，跳过下载"
fi
say "包大小: $(wc -c < "$TARBALL" | tr -d ' ') 字节"

rm -rf "$WORK/orig" "$WORK/patched"
mkdir -p "$WORK/orig" "$WORK/patched"
tar -xzf "$TARBALL" -C "$WORK/orig" --strip-components=1 || die "解压失败（orig）"
tar -xzf "$TARBALL" -C "$WORK/patched" --strip-components=1 || die "解压失败（patched）"

BASE_C="$WORK/orig/Zend/zend_alloc.c"
[ -f "$BASE_C" ] || die "源码包结构异常：找不到 Zend/zend_alloc.c"

# 确认这份源码确实带着漏洞形态（否则后面的验证没有意义）
if grep -q "zend_mm_safe_error" "$BASE_C" && grep -q "heap->overflow = 1" "$BASE_C"; then
  say "漏洞形态确认: zend_mm_safe_error 存在，且含 heap->overflow = 1 + longjmp 结构"
else
  die "在原始源码里没找到预期的 zend_mm_safe_error 结构，验证前提不成立"
fi

# ---------------------------------------------------------------- 2. 打补丁
head1 "2/5 应用补丁"
if patch -p1 --dry-run -d "$WORK/patched" < "$PATCH_FILE" > "$WORK/patch-dryrun.log" 2>&1; then
  say "第 1 层 补丁可应用：patch -p1 --dry-run 通过"
else
  say "补丁 dry-run 输出："
  tail -20 "$WORK/patch-dryrun.log" | tee -a "$REPORT"
  die "第 1 层失败：补丁不能应用到 PHP $VER 源码"
fi
patch -p1 -d "$WORK/patched" < "$PATCH_FILE" > "$WORK/patch-apply.log" 2>&1 || die "补丁实际应用失败"
say "补丁已应用（日志：$WORK/patch-apply.log）"

PATCHED_C="$WORK/patched/Zend/zend_alloc.c"
say "应用后自检："
say "  zend_mm_safe_error_ex 出现 $(grep -c 'zend_mm_safe_error_ex' "$PATCHED_C") 次（应 >0）"
say "  zend_error_noreturn  残留 $(grep -c 'zend_error_noreturn' "$PATCHED_C") 处（应为 0）"
say "  zend_bailout         残留 $(grep -c 'zend_bailout' "$PATCHED_C") 处（应为 0）"

# ---------------------------------------------------------------- 3. 构建
build_tree() { # $1=源码目录 $2=输出二进制名
  local dir=$1 out=$2
  ( cd "$dir" \
    && ./configure --disable-all --disable-cgi --enable-cli --without-pear \
         CFLAGS="-O1 -fcommon -Wno-error" > configure.log 2>&1 \
    && make -j"$( (nproc 2>/dev/null || sysctl -n hw.ncpu) 2>/dev/null || echo 2)" > make.log 2>&1 )
  if [ -x "$dir/sapi/cli/php" ]; then
    cp "$dir/sapi/cli/php" "$WORK/$out"
    return 0
  fi
  say "构建失败，$dir 的最后 20 行日志："
  tail -20 "$dir/make.log" 2>/dev/null | tee -a "$REPORT"
  return 1
}

head1 "3/5 构建原始版（对照组）"
build_tree "$WORK/orig" "php-orig" || die "第 2 层失败：原始源码（未打补丁）都编不出来，说明是环境问题而非补丁问题"
say "原始版构建成功：$WORK/php-orig ($(wc -c < "$WORK/php-orig" | tr -d ' ') 字节)"

head1 "4/5 构建打补丁版"
build_tree "$WORK/patched" "php-patched" || die "第 2 层失败：打补丁后编译不通过（这才是真的补丁问题，请贴上面的日志）"
say "打补丁版构建成功：$WORK/php-patched"

# ---------------------------------------------------------------- 4. 行为差异
head1 "5/5 运行行为对比（OOM 路径）"

# 说明：这个脚本只做「耗尽 memory_limit」，不涉及 HTTP、不涉及 multipart，
#      目的是看 OOM 之后 PHP 是走 bailout（→ 执行 shutdown 回调）还是直接退出。
cat > "$WORK/oom.php" <<'PHPEOF'
<?php
// 仅用于观察 OOM 之后的控制流，不含任何攻击代码
$tag = getenv('TAG') ?: 'unknown';
register_shutdown_function(function () use ($tag) {
    fwrite(STDERR, "SHUTDOWN_RAN:$tag\n");
});
ini_set('memory_limit', '8M');
$a = array();
while (true) {
    $a[] = str_repeat('x', 65536);
}
PHPEOF

run_oom() { # $1=二进制 $2=标签 → 输出 rc / 是否有 shutdown / 是否有 fatal 文字
  local bin=$1 tag=$2 outfile="$WORK/oom-$2.out"
  TAG="$tag" "$bin" -n -d display_errors=1 "$WORK/oom.php" > "$outfile" 2>&1
  local rc=$?
  local shut="no"; grep -q "SHUTDOWN_RAN:$tag" "$outfile" && shut="yes"
  local fatal="no"; grep -q "Allowed memory size" "$outfile" && fatal="yes"
  printf '%s\n' "$rc|$shut|$fatal"
}

IFS='|' read -r RC_ORIG SHUT_ORIG FATAL_ORIG <<< "$(run_oom "$WORK/php-orig" orig)"
IFS='|' read -r RC_PAT SHUT_PAT FATAL_PAT     <<< "$(run_oom "$WORK/php-patched" patched)"

say "未打补丁版 : 退出码=$RC_ORIG  shutdown回调执行=$SHUT_ORIG  OOM报错文字=$FATAL_ORIG"
say "打补丁版   : 退出码=$RC_PAT  shutdown回调执行=$SHUT_PAT  OOM报错文字=$FATAL_PAT"
say ""
say "原始版输出末尾："; tail -3 "$WORK/oom-orig.out" 2>/dev/null | tee -a "$REPORT"
say "补丁版输出末尾："; tail -3 "$WORK/oom-patched.out" 2>/dev/null | tee -a "$REPORT"

VERDICT="未判定"
if [ "$FATAL_ORIG" = "yes" ] && [ "$SHUT_ORIG" = "yes" ] \
   && [ "$FATAL_PAT" = "yes" ] && [ "$SHUT_PAT" = "no" ]; then
  VERDICT="PASS：补丁确实切断了 bailout 路径（原始版会执行 shutdown 回调，补丁版直接退出）"
elif [ "$FATAL_ORIG" != "yes" ]; then
  VERDICT="INCONCLUSIVE：原始版都没触发 OOM（memory_limit 调得太高或环境差异），这组测试不成立"
else
  VERDICT="FAIL：补丁版行为与原始版一致或异常，OOM 仍走了 bailout"
fi

say ""
say "================ 结论 ================"
say "第 1 层 补丁可应用 : 通过"
say "第 2 层 可编译     : 通过（两棵树都产出了 sapi/cli/php）"
if [ "$VERDICT" = "未判定" ] || [ "${VERDICT#PASS}" != "$VERDICT" ]; then
  say "第 3 层 运行生效   : $VERDICT"
else
  say "第 3 层 运行生效   : $VERDICT"
fi
say ""
say "本脚本**不**证明的事："
say "  - 不证明 109619（跨请求状态残留 / UAF / OPcache 类型混淆）已被修复，本补丁不涉及那部分"
say "  - 不证明该分支在真实 SAPI（mod_php / FPM）下不可利用"
say "  - 不构成生产可用性评估，务必在预发环境跑完整业务回归"
say "报告已写入：$REPORT"

case "$VERDICT" in
  PASS*) exit 0 ;;
  *)     exit 1 ;;
esac
