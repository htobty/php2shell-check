#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为 PHP 7.0 / 7.1 / 7.2 / 7.3 的 Zend/zend_alloc.c 打 CVE-2026-109618 补丁。

与 5.6 版脚本的区别：
    5.6 是 TSRMLS 时代、无 ZEND_COLD/ZEND_NORETURN 修饰、lineno 是 uint、
    函数体用 if (heap->overflow == 0) 包裹且要释放 heap->reserve。
    7.x 已剔除 TSRMLS、函数带 ZEND_COLD ZEND_NORETURN 修饰、
    7.2/7.3 的 lineno 是 uint32_t、函数体是 heap->overflow = 1 + zend_try 结构。
    故两个脚本不可互换。

用法（在 7.x 源码树里）：
    python3 patch-7x-109618.py Zend/zend_alloc.c
    git diff > ../php2shell-7x-109618.patch

改了什么：
    1. 新增 static void zend_mm_safe_error_ex(const char *format, ...)
       —— 直接写 stderr 后 _exit(1)，不走 zend_error/zend_bailout。
    2. 原 zend_mm_safe_error() 改为只转调，保留原签名（调用点无需改动），
       删掉 heap->overflow 三态与 zend_bailout()。
    3. 全文 zend_error_noreturn(E_ERROR, ...) 统一改走新函数。
       这是纯参数对齐替换：zend_error_noreturn(E_ERROR, fmt, a, b)
       → zend_mm_safe_error_ex(fmt, a, b)，E_ERROR 是固定首参，
       去掉它后剩余参数与新函数签名天然一致，不需要逐处手工核对。

实测规模（各分支 zend_error_noreturn 调用点数，含将被整段替换的原函数内那处）：
    7.0 / 7.1 共 5 处；7.2 共 6 处；7.3 共 6 处。
    其中 7.3 分布在 376（原函数体内）、1355、1803、2599、2611、2625 行，
    消息分别为 "Possible integer overflow in memory allocation (%zu + %zu)"
    与 "(1 * %zu + 1)"。

注意：本脚本的替换模式已按 7.0-7.3 的真实源码结构编写，但**未在 7.x 分支
实际编译验证**（本机 macOS + PHP 8.1，无 7.x 构建环境）。上生产前必须在
目标分支 make、跑 make test 与业务回归。
"""

import re
import sys
import os

FUNC_RE = re.compile(
    r'static ZEND_COLD ZEND_NORETURN void zend_mm_safe_error\(zend_mm_heap \*heap,.*?zend_bailout\(\);\s*\n\s*exit\(1\);\s*\n\}',
    re.S
)

NEW_FUNC = '''static void zend_mm_safe_error_ex(const char *format, ...)
{
\tva_list args;
\tconst char *error_filename = NULL;
\tuint lineno = 0;

\tif (zend_is_compiling()) {
\t\terror_filename = zend_get_compiled_filename();
\t\tlineno = zend_get_compiled_lineno();
\t} else if (EG(current_execute_data) && EG(current_execute_data)->func) {
\t\terror_filename = EG(current_execute_data)->func->op_array.filename;
\t\tif (EG(current_execute_data)->opline) {
\t\t\tlineno = EG(current_execute_data)->opline->lineno;
\t\t}
\t}
\tif (!error_filename) {
\t\terror_filename = "Unknown";
\t}

\tfprintf(stderr, "\\nFatal error: ");
\tva_start(args, format);
\tvfprintf(stderr, format, args);
\tva_end(args);
\tfprintf(stderr, " in %s on line %u\\n", error_filename, (unsigned) lineno);
\tfflush(stderr);
\t_exit(1);
}

static ZEND_COLD ZEND_NORETURN void zend_mm_safe_error(zend_mm_heap *heap,
\tconst char *format,
\tsize_t limit,
#if ZEND_DEBUG
\tconst char *filename,
\tuint32_t lineno,
#endif
\tsize_t size)
{
\t(void) heap;
\tzend_mm_safe_error_ex(format, limit, size);
\texit(1);
}'''


def patch(path):
    with open(path, 'r', encoding='utf-8', errors='surrogateescape') as f:
        src = f.read()

    if 'zend_mm_safe_error_ex' in src:
        print('[跳过] 文件里已有 zend_mm_safe_error_ex，可能已打过补丁')
        return False

    m = FUNC_RE.search(src)
    if not m:
        print('[失败] 没有匹配到 7.x 形态的 zend_mm_safe_error 函数体。')
        print('       请确认这是 PHP 7.0-7.3 的 Zend/zend_alloc.c，且未被改动。')
        return False

    src = src[:m.start()] + NEW_FUNC + src[m.end():]

    # 剩余调用点：zend_error_noreturn(E_ERROR, fmt, ...) -> zend_mm_safe_error_ex(fmt, ...)
    # 参数天然对齐，无需逐处改写。
    n = len(re.findall(r'zend_error_noreturn\(E_ERROR,\s*', src))
    src = re.sub(r'zend_error_noreturn\(E_ERROR,\s*', 'zend_mm_safe_error_ex(', src)

    left_noreturn = src.count('zend_error_noreturn')
    left_bailout = src.count('zend_bailout()')

    with open(path, 'w', encoding='utf-8', errors='surrogateescape') as f:
        f.write(src)

    print('已替换：调用点 %d 处，原函数已改为转调' % n)
    print('剩余 zend_error_noreturn: %d（应为 0）' % left_noreturn)
    print('剩余 zend_bailout: %d（应为 0）' % left_bailout)
    return left_noreturn == 0 and left_bailout == 0


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    target = sys.argv[1]
    if not os.path.isfile(target):
        raise SystemExit('[失败] 文件不存在: %s' % target)
    sys.exit(0 if patch(target) else 1)
