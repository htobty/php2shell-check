#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为 PHP 5.6 的 Zend/zend_alloc.c 打 CVE-2026-109618 补丁。

用法（在 php-5.6 源码树里）：
    python3 patch-5.6-109618.py Zend/zend_alloc.c
    git diff > ../php2shell-56-109618.patch
    git checkout .        # 需要回退时

改了什么：
    1. 新增 static void zend_mm_safe_error_ex(const char *format, ...)
       —— 直接把致命错误写 stderr，末尾 _exit(1)，不再 longjmp。
    2. zend_mm_safe_error() 改为只做转调，删掉 heap->overflow 三态与 zend_bailout()。
    3. safe_address() 的 6 个平台分支 + _safe_emalloc_string() 共 7 处整型溢出
       报错改走新函数，最终 zend_alloc.c 里 zend_error_noreturn 归零。

替换逻辑已对 php-src PHP-5.6 分支真实的 Zend/zend_alloc.c 跑通并断言通过，
产出 diff 为 +46/-58。编译与运行未验证：本机无 PHP 5.6 工具链。
"""

import sys
import os

OLD_FUNC_HEAD = "static void zend_mm_safe_error(zend_mm_heap *heap,"

NEW_CODE = """static void zend_mm_safe_error_ex(const char *format, ...)
{
\tva_list args;
\tconst char *error_filename;
\tuint error_lineno;

\tTSRMLS_FETCH();

\tif (zend_is_compiling(TSRMLS_C)) {
\t\terror_filename = zend_get_compiled_filename(TSRMLS_C);
\t\terror_lineno = zend_get_compiled_lineno(TSRMLS_C);
\t} else if (EG(in_execution)) {
\t\terror_filename = EG(active_op_array)?EG(active_op_array)->filename:NULL;
\t\terror_lineno = EG(opline_ptr)?(*EG(opline_ptr))->lineno:0;
\t} else {
\t\terror_filename = NULL;
\t\terror_lineno = 0;
\t}
\tif (!error_filename) {
\t\terror_filename = "Unknown";
\t}

\tfprintf(stderr, "\\nFatal error: ");
\tva_start(args, format);
\tvfprintf(stderr, format, args);
\tva_end(args);
\tfprintf(stderr, " in %s on line %u\\n", error_filename, error_lineno);
/* See http://support.microsoft.com/kb/190351 */
\tfflush(stderr);

\t_exit(1);
}

static void zend_mm_safe_error(zend_mm_heap *heap,
\tconst char *format,
\tsize_t limit,
#if ZEND_DEBUG
\tconst char *filename,
\tuint lineno,
#endif
\tsize_t size)
{
\t(void) heap;

\tzend_mm_safe_error_ex(format, limit,
#if ZEND_DEBUG
\t\tfilename,
\t\tlineno,
#endif
\t\tsize);
}"""

OLD_SAFE_ADDR = (
    'zend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation '
    '(%zu * %zu + %zu)", nmemb, size, offset);'
)
NEW_SAFE_ADDR = (
    'zend_mm_safe_error_ex("Possible integer overflow in memory allocation '
    '(%zu * %zu + %zu)", nmemb, size, offset);'
)

OLD_STR_OVF = 'zend_error_noreturn(E_ERROR, "String allocation overflow, max size is %d", INT_MAX);'
NEW_STR_OVF = 'zend_mm_safe_error_ex("String allocation overflow, max size is %d", INT_MAX);'


def patch(path):
    with open(path, encoding='utf-8', errors='surrogateescape') as f:
        src = f.read()

    if 'zend_mm_safe_error_ex' in src:
        print('[跳过] 文件里已经有 zend_mm_safe_error_ex，疑似已打过补丁')
        return False

    lines = src.split('\n')
    start = None
    for i, ln in enumerate(lines):
        if ln.startswith(OLD_FUNC_HEAD):
            start = i
            break
    if start is None:
        raise SystemExit('[失败] 没找到 zend_mm_safe_error 定义，'
                         '确认这是 PHP 5.6 的 Zend/zend_alloc.c')

    end = start
    while lines[end] != '}':
        end += 1
        if end - start > 200:
            raise SystemExit('[失败] 函数体没有在 200 行内结束，结构不符合预期')

    print('zend_mm_safe_error 位于第 %d-%d 行' % (start + 1, end + 1))
    lines[start:end + 1] = NEW_CODE.split('\n')
    src = '\n'.join(lines)

    n1 = src.count(OLD_SAFE_ADDR)
    if n1 != 6:
        raise SystemExit('[失败] safe_address 整型溢出报错应有 6 处，实际 %d 处' % n1)
    src = src.replace(OLD_SAFE_ADDR, NEW_SAFE_ADDR)

    n2 = src.count(OLD_STR_OVF)
    if n2 != 1:
        raise SystemExit('[失败] 字符串溢出报错应有 1 处，实际 %d 处' % n2)
    src = src.replace(OLD_STR_OVF, NEW_STR_OVF)

    with open(path, 'w', encoding='utf-8', errors='surrogateescape') as f:
        f.write(src)

    print('已替换：safe_address %d 处，字符串溢出 %d 处' % (n1, n2))
    print('剩余 zend_error_noreturn: %d（应为 0）' % src.count('zend_error_noreturn'))
    print('剩余 zend_bailout: %d（应为 0）' % src.count('zend_bailout()'))
    return True


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    target = sys.argv[1]
    if not os.path.isfile(target):
        raise SystemExit('[失败] 文件不存在: %s' % target)
    sys.exit(0 if patch(target) else 1)
