#!/usr/bin/env bash
# 修复前后对照实验
#
# 两个容器唯一的差别是 PHP 版本：8.4.26（受影响）与 8.4.27（已修复）。
# SAPI 都用 mod_php（apache2handler）—— 这是这组漏洞里最危险的 SAPI：
# 请求启动失败时仍会无条件执行 request shutdown，攻击发生在应用代码之前。
# ini 覆盖与探测请求量完全一致，容器用完即删。
#
# 用法：./compare.sh
# 可调：HEADERS=40000 ROUNDS=3 ./compare.sh

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
AFFECTED="php:8.4.26-apache"
FIXED="php:8.4.27-apache"
PA=8401
PF=8402
HEADERS="${HEADERS:-20000}"
ROUNDS="${ROUNDS:-2}"

cleanup() {
  docker rm -f php2shell-a php2shell-f >/dev/null 2>&1
}
trap cleanup EXIT

start() {
  local image="$1" port="$2" name="$3"
  docker rm -f "$name" >/dev/null 2>&1
  if ! docker run -d --name "$name" -p "$port:80" \
      -v "$HERE/index.php:/var/www/html/index.php:ro" \
      -v "$HERE/zz-php2shell.ini:/usr/local/etc/php/conf.d/zz-php2shell.ini:ro" \
      "$image" >/dev/null 2>&1; then
    echo "  容器启动失败：$image（镜像是否已拉取？）"
    return 1
  fi
  local i
  for i in $(seq 1 30); do
    if curl -fsS --max-time 2 "http://127.0.0.1:$port/index.php" >/dev/null 2>&1; then
      echo "  $image 已就绪，端口 $port"
      return 0
    fi
    sleep 1
  done
  echo "  $image 30 秒内未就绪，容器日志："
  docker logs --tail 15 "$name" 2>&1 | sed 's/^/    /'
  return 1
}

probe() {
  local port="$1" name="$2" label="$3"
  echo
  echo "── $label ──"
  python3 "$HERE/probe.py" --url "http://127.0.0.1:$port/index.php" --yes \
    --rounds "$ROUNDS" --headers "$HEADERS" --timeout 30 2>&1 |
    grep -E "r[0-9]+-|baseline|判定|统计|  ·" | head -22
  echo
  echo "  容器日志里的内存/解析记录："
  docker logs "$name" 2>&1 | grep -iE "Allowed memory|Multipart|Fatal|child pid" | tail -6 | sed 's/^/    /'
  echo
  echo "  容器是否还活着：$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)"
}

echo "=== 对照实验：8.4.26（受影响） vs 8.4.27（已修复）｜SAPI=apache2handler ==="
echo "    header=$HEADERS  rounds=$ROUNDS  memory_limit=16M"

if start "$AFFECTED" "$PA" php2shell-a; then
  probe "$PA" php2shell-a "受影响版 $AFFECTED"
else
  echo "跳过受影响版对照"
fi

if start "$FIXED" "$PF" php2shell-f; then
  probe "$PF" php2shell-f "已修复版 $FIXED"
else
  echo "跳过已修复版对照"
fi

echo
echo "=== 判读 ==="
echo "受影响版：预期出现 OOM 命中（HIT_PATH / PARTIAL，且容器日志有 Allowed memory size），"
echo "          因为 8.4.26 里 OOM 走 longjmp() 提前退出，请求内存未初始化就被 shutdown 读取。"
echo "已修复版：OOM 改为 VM 安全点的延迟软 OOM，二次阈值才 _exit()，"
echo "          不应再出现未初始化内存被读取的路径；观察到容器重启或退出属于补丁的预期行为。"
echo
echo "注意：单次探测无信号不等于安全，多 worker 与内存布局都会影响命中率。"
