#!/usr/bin/env python3
"""给 PHP 5.6.40 源码应用两处安全改动（与远端验证通过的版本一致）

1. main/rfc1867.c —— multipart 头白名单：只保留 Content-Disposition / Content-Type，
   丢弃重复头。切断「大量无关/重复头放大内存」从而更易触发 OOM 的路径。
2. ext/session/session.c —— 硬禁用 upload progress 的 pre-RINIT session 写入。

关键点：php_mime_should_save_hdr / php_mime_get_hdr_value 的使用点在
multipart_buffer_headers() 的头解析循环（第 446 行附近），而 php_mime_get_hdr_value
的定义在第 465 行之后，所以前置声明必须放在文件头部的现有声明区（第 50 行附近），
不能放在定义旁边——否则 GCC 报 implicit declaration + conflicting types。

配合 Zend/zend_alloc.c 的补丁（php2shell-56-109618.patch）构成三补丁组合。

用法: python3 apply-56-full.py <php_src_dir>
"""
import os
import sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
T = "\t"


def patch_file(relpath, old, new, expect_count=1):
    path = os.path.join(root, relpath)
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        src = f.read()
    n = src.count(old)
    if n != expect_count:
        raise SystemExit(
            "FAIL %s: expected %d occurrence(s), found %d"
            % (relpath, expect_count, n)
        )
    src = src.replace(old, new)
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(src)
    print("OK " + relpath)


# ---------- 1: 前置声明放到文件头部声明区 ----------
old_decl = (
    "static char *php_ap_getword(const zend_encoding *encoding, "
    "char **line, char stop TSRMLS_DC);\n"
)
new_decl = (
    "static zend_bool php_mime_should_save_hdr(const char *name);\n"
    "static char *php_mime_get_hdr_value(zend_llist header, char *key);\n"
    + old_decl
)
patch_file("main/rfc1867.c", old_decl, new_decl)


# ---------- 2: 新增头白名单判定函数 ----------
old_def = "static char *php_mime_get_hdr_value(zend_llist header, char *key)\n{\n"
new_def = (
    "/* Only the headers RFC 1867 processing actually reads are kept, so a\n"
    " * request with many unrelated or duplicated headers cannot amplify\n"
    " * memory use. */\n"
    "static zend_bool php_mime_should_save_hdr(const char *name)\n"
    "{\n"
    + T + 'return !strcasecmp(name, "Content-Disposition")\n'
    + T + T + '|| !strcasecmp(name, "Content-Type");\n'
    "}\n"
    "\n"
    + old_def
)
patch_file("main/rfc1867.c", old_def, new_def)


# ---------- 3: 头解析循环里应用白名单与去重 ----------
old_parse = (
    T + T + T + "*value = '\\0';\n"
    + T + T + T + "do { value++; } while(isspace(*value));\n"
    "\n"
    + T + T + T + "key = estrdup(line);\n"
    + T + T + T + "smart_str_appends(&buf_value, value);\n"
)
new_parse = (
    T + T + T + "*value = '\\0';\n"
    "\n"
    + T + T + T + "/* Keep only headers we use, and ignore duplicates */\n"
    + T + T + T + "if (!php_mime_should_save_hdr(line)\n"
    + T + T + T + T + T + "|| php_mime_get_hdr_value(*header, line)) {\n"
    + T + T + T + T + "key = NULL;\n"
    + T + T + T + "} else {\n"
    + T + T + T + T + "key = estrdup(line);\n"
    + T + T + T + T
    + "do { value++; } while (isspace((unsigned char)*value));\n"
    + T + T + T + T + "smart_str_appends(&buf_value, value);\n"
    + T + T + T + "}\n"
)
patch_file("main/rfc1867.c", old_parse, new_parse)


# ---------- 4: session.c 硬禁用 upload progress 路径 ----------
old_sess = (
    T + "if (!PS(rfc1867_enabled)) {\n"
    + T + T + "return retval;\n"
    + T + "}\n"
)
new_sess = (
    T + "/* Upload progress reaches session handling before RINIT, i.e. before\n"
    + T + " * any user code may run. Disable the path outright instead of trusting\n"
    + T + " * an INI value that can be re-enabled per directory. */\n"
    + T + "if (!PS(rfc1867_enabled) || 1) {\n"
    + T + T + "return retval;\n"
    + T + "}\n"
)
patch_file("ext/session/session.c", old_sess, new_sess)

print("ALL_PATCHED")
