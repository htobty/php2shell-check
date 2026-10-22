<?php
declare(strict_types=1);

/**
 * php2shell-check —— CVE-2026-109618 / CVE-2026-109619 可利用性自查
 *
 * 作用：在“运行着目标 PHP 的这个进程里”读取真实的版本、SAPI 与 INI 生效值，
 *      判定是否落在受影响区间、SAPI 暴露等级、以及官方缓解项是否已经到位。
 *
 * 本脚本只做被动判定：不发送任何攻击载荷、不触发 OOM、不修改任何配置。
 *
 * 用法：
 *   php checker.php                 # 人类可读（CLI）
 *   php checker.php --json          # JSON（CLI）
 *   curl 'http://your-host/checker.php?format=json'   # 放到 Web 目录跑，拿到 Web SAPI 的真实值
 *
 * 重要：CLI 下 PHP_SAPI 是 cli，与生产 Web SAPI 不同。要评估 Web 侧暴露面，
 *      请把本文件放到目标站点可访问的位置并通过 HTTP 访问一次，或只在 FPM pool 内 CLI 运行后人工核对 SAPI。
 */

$isCli  = (PHP_SAPI === 'cli');
$asJson = $isCli ? in_array('--json', $argv ?? [], true)
                 : ((string)($_GET['format'] ?? '') === 'json');

/* ---------------------------------------------------------------- 常量表 */

// 官方公布的修复版本（2026-10-21）
$fixedVersion = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];
$fixedId      = ['8.2' => 80235,    '8.3' => 80336,    '8.4' => 80427,    '8.5' => 80512];

$sapiTable = [
    'apache2handler' => ['CRITICAL', 'mod_php：请求启动失败时仍无条件执行 request shutdown，攻击发生在应用代码执行之前，与应用程序无关（已实测未认证 RCE）'],
    'fpm-fcgi'       => ['HIGH',     'PHP-FPM：源码分析判定受影响；启动失败时子进程被杀，需应用相关路径介入（session upload progress 路径已实测）'],
    'frankenphp'     => ['HIGH',     'FrankenPHP：类比 mod_php 无条件执行 request shutdown，很可能存在应用无关路径（官方未完成验证）'],
    'litespeed'      => ['MEDIUM',   'LSAPI 类比 FPM：应用相关利用可能，但官方未验证'],
    'cgi-fcgi'       => ['MEDIUM',   'CGI：每请求新进程，跨请求残留面显著较小'],
    'cli-server'     => ['LOW',      'PHP 内置服务器：通常不承载生产流量'],
    'cli'            => ['LOW',      'CLI：无 HTTP 请求面（本结果不代表生产 Web SAPI 的风险）'],
    'embed'          => ['LOW',      '嵌入层：不直接暴露网络请求'],
];

/* ---------------------------------------------------------------- 工具函数 */

/** 读取某 INI 项的生效值 + 权限掩码（判断应用是否可覆盖） */
function auditIni(string $key): array
{
    $all = @ini_get_all(null, true);
    if (!is_array($all) || !array_key_exists($key, $all)) {
        return ['key' => $key, 'exists' => false, 'value' => null, 'access' => null];
    }
    return [
        'key'    => $key,
        'exists' => true,
        'value'  => $all[$key]['local_value'],
        'access' => (int)$all[$key]['access'],
    ];
}

/** 把 PHP 的字节简写（8M / 1G / -1）换算成字节数；-1 返回 -1，不可解析返回 null */
function toBytes(string $v): ?int
{
    $v = trim($v);
    if ($v === '' ) return null;
    if ($v === '-1') return -1;
    $unit = strtolower(substr($v, -1));
    $num  = (float)$v;
    switch ($unit) {
        case 'g': return (int)($num * 1024 * 1024 * 1024);
        case 'm': return (int)($num * 1024 * 1024);
        case 'k': return (int)($num * 1024);
        default:  return (int)$num;
    }
}

function humanBytes(?int $b): string
{
    if ($b === null) return 'N/A';
    if ($b === -1)   return '-1（不限制）';
    if ($b >= 1073741824) return round($b / 1073741824, 1) . 'G';
    if ($b >= 1048576)    return round($b / 1048576, 1) . 'M';
    if ($b >= 1024)       return round($b / 1024, 1) . 'K';
    return $b . 'B';
}

/* ---------------------------------------------------------------- 1. 版本 */

$branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$vid    = PHP_VERSION_ID;

if (isset($fixedId[$branch])) {
    if ($vid >= $fixedId[$branch]) {
        $versionState = 'PATCHED';
        $versionText  = PHP_VERSION . " 已包含修复（{$branch} 分支修复版本 {$fixedVersion[$branch]}）";
    } else {
        $versionState = 'VULNERABLE';
        $versionText  = PHP_VERSION . " 落在受影响区间，需升级到 {$fixedVersion[$branch]} 或更高";
    }
} elseif ($vid < 80200) {
    $versionState = 'EOL';
    $versionText  = PHP_VERSION . ' 已 EOL，官方无正式修复；安全团队为 7.4/8.0/8.1 提供了 minimal source backport，或向发行版/LTS 厂商索取补丁';
} else {
    $versionState = 'UNKNOWN';
    $versionText  = PHP_VERSION . ' 不属于已公布受影响分支，请核对官方公告';
}

$affected = in_array($versionState, ['VULNERABLE', 'EOL'], true);

/* ---------------------------------------------------------------- 2. SAPI */

$sapi = PHP_SAPI;
[$sapiLevel, $sapiText] = $sapiTable[$sapi] ?? ['UNKNOWN', '未收录的 SAPI：请结合官方公告判断是否会无条件执行 request shutdown'];

/* ---------------------------------------------------------------- 3. 配置审计 */

$checks = [];

/* --- 3.1 memory_limit：109618 的核心缓解项 --- */
$ml    = auditIni('memory_limit');
$mlRaw = $ml['exists'] ? (string)$ml['value'] : '';
$mlB   = toBytes($mlRaw);
// access 含 USER(1) 或 PERDIR(2) 表示应用可覆盖
$mlOverride = $ml['exists'] && (($ml['access'] & (1 | 2)) !== 0);

if (!$ml['exists']) {
    $checks[] = ['id' => 'memory_limit', 'cve' => '109618', 'state' => 'NA',
        'value' => 'N/A', 'detail' => '无法读取 memory_limit'];
} elseif ($mlB === -1) {
    $checks[] = ['id' => 'memory_limit', 'cve' => '109618',
        'state' => $mlOverride ? 'WARN' : 'OK',
        'value' => humanBytes($mlB),
        'detail' => $mlOverride
            ? '已设为 -1，但该设置允许 应用/目录级 覆盖（PERDIR/USER），须确认没有 .user.ini 或 ini_set 把它改回有限值'
            : '已设为 -1，消除了“可控内存限制失败”这条利用路径（仍不覆盖底层分配失败）'];
} else {
    $checks[] = ['id' => 'memory_limit', 'cve' => '109618', 'state' => 'BAD',
        'value' => humanBytes($mlB),
        'detail' => '存在有限内存上限，攻击者可通过官方公开的多条 multipart 策略在 post_max_size 内吃穿 memory_limit，进而命中 OOM 提前退出路径'];
}

/* --- 3.2 post_max_size / upload_max_filesize --- */
$pmsB = toBytes((string)ini_get('post_max_size'));
if ($pmsB === null || $pmsB === -1) {
    $checks[] = ['id' => 'post_max_size', 'cve' => '109618', 'state' => 'WARN',
        'value' => (string)ini_get('post_max_size'),
        'detail' => '未设置有效上限，请求体规模不受控'];
} elseif ($pmsB <= 8 * 1024 * 1024) {
    $checks[] = ['id' => 'post_max_size', 'cve' => '109618', 'state' => 'OK',
        'value' => humanBytes($pmsB), 'detail' => '已按官方建议收紧（无上传需求时 8M）'];
} elseif ($pmsB <= 32 * 1024 * 1024) {
    $checks[] = ['id' => 'post_max_size', 'cve' => '109618', 'state' => 'WARN',
        'value' => humanBytes($pmsB), 'detail' => '处于官方“需上传文件”的 32M 建议阈值内，可接受；建议核对是否确实需要'];
} else {
    $checks[] = ['id' => 'post_max_size', 'cve' => '109618', 'state' => 'BAD',
        'value' => humanBytes($pmsB), 'detail' => '远大于官方建议（8M/32M），扩大了 OOM 诱导的可用空间'];
}

$umfB = toBytes((string)ini_get('upload_max_filesize'));
if ($pmsB !== null && $pmsB > 0 && ($umfB === null || $umfB >= $pmsB)) {
    $checks[] = ['id' => 'upload_max_filesize', 'cve' => '109618', 'state' => 'WARN',
        'value' => humanBytes($umfB), 'detail' => '官方要求 upload_max_filesize 必须小于 post_max_size'];
}

/* --- 3.3 max_file_uploads：空文件控件不计入，但仍创建元数据数组 --- */
$mfu = (int)ini_get('max_file_uploads');
if ($mfu > 20) {
    $checks[] = ['id' => 'max_file_uploads', 'cve' => '109618', 'state' => 'WARN',
        'value' => (string)$mfu, 'detail' => '注意：filename="" 的空文件控件不计入 max_file_uploads，却仍会创建文件元数据数组，无法靠它挡住该放大路径'];
}

/* --- 3.3b max_multipart_body_parts：PHP 内置的 part 数边界（本地实测发现） --- */
// 实测记录：8.1.33 + php -S，发送 3000 个空文件控件时服务端日志出现
//   PHP Warning: Unknown: Multipart body parts limit exceeded 1020.
//     To increase the limit change max_multipart_body_parts in php.ini.
// 而 1001 个 part 的请求正常通过 —— 说明这条边界默认在 1020 处生效。
// 它是反向代理之外少数能直接掐断「大量空文件控件 + 嵌套字段名」放大路径的原生手段。
// 注意 ini_get() 在某些构建下返回 -1，那是「交给版本内置默认值」，不等于关闭。
$mmp = auditIni('max_multipart_body_parts');
$mmpRaw = $mmp['exists'] ? (string)$mmp['value'] : 'N/A';

if (!$mmp['exists']) {
    $checks[] = ['id' => 'max_multipart_body_parts', 'cve' => '109618', 'state' => 'NA',
        'value' => 'N/A',
        'detail' => '当前 PHP 版本无此指令，part 数边界只能依赖版本内置默认值，无法显式收紧；建议升级，或在前置代理层限制 part 数'];
} elseif ($mmpRaw === '-1') {
    $checks[] = ['id' => 'max_multipart_body_parts', 'cve' => '109618', 'state' => 'WARN',
        'value' => '-1',
        'detail' => 'ini_get 返回 -1 表示沿用版本内置默认值（实测该默认值在 1020 生效），并不是「不限」。建议显式写成 256 一类的小值，避免不同版本默认值不一致带来意外'];
} elseif ((int)$mmpRaw > 256) {
    $checks[] = ['id' => 'max_multipart_body_parts', 'cve' => '109618', 'state' => 'WARN',
        'value' => $mmpRaw,
        'detail' => 'part 数边界过宽。建议压到 256 以内，直接压制 multipart 解析阶段的内存放大'];
} else {
    $checks[] = ['id' => 'max_multipart_body_parts', 'cve' => '109618', 'state' => 'OK',
        'value' => $mmpRaw,
        'detail' => 'part 数已被限制在较小范围，能有效压制 multipart 解析阶段的内存放大'];
}

/* --- 3.4 session.upload_progress.enabled：109619 已确认路径 --- */
$sup = auditIni('session.upload_progress.enabled');
$supRaw = $sup['exists'] ? (string)$sup['value'] : '';
$supOff = in_array($supRaw, ['0', '', 'Off', 'off'], true);
$supOverride = $sup['exists'] && (($sup['access'] & (1 | 2)) !== 0);

if (!$sup['exists']) {
    $checks[] = ['id' => 'session.upload_progress.enabled', 'cve' => '109619', 'state' => 'NA',
        'value' => 'N/A', 'detail' => '无法读取'];
} elseif ($supOff) {
    $checks[] = ['id' => 'session.upload_progress.enabled', 'cve' => '109619',
        'state' => $supOverride ? 'WARN' : 'OK',
        'value' => $supRaw,
        'detail' => $supOverride
            ? '已关闭，但允许应用级覆盖；官方要求必须写在 php.ini / FPM pool / 服务端配置，不能靠 ini_set 或 .user.ini'
            : '已关闭，封堵了已确认的 session 上传进度 生产者/消费者 路径'];
} else {
    $checks[] = ['id' => 'session.upload_progress.enabled', 'cve' => '109619', 'state' => 'BAD',
        'value' => $supRaw,
        'detail' => '开启中。该功能默认开启且无需应用调用 session_start() 即可被利用，是已实测 RCE 路径的关键环节；建议无条件关闭'];
}

/* --- 3.5 fatal_error_backtraces（PHP 8.5 起）--- */
$feb = auditIni('fatal_error_backtraces');
if ($feb['exists']) {
    $febRaw = (string)$feb['value'];
    $febOff = in_array($febRaw, ['0', '', 'Off', 'off'], true);
    $checks[] = ['id' => 'fatal_error_backtraces', 'cve' => '109619',
        'state' => $febOff ? 'OK' : 'BAD',
        'value' => $febRaw,
        'detail' => $febOff
            ? '已关闭，封堵了 EG(last_fatal_error_backtrace) 这条已确认 RCE 路径'
            : '开启中：EG(last_fatal_error_backtrace) 会跨请求残留，是已确认的 fatal error 回溯 UAF 路径'];
} else {
    $checks[] = ['id' => 'fatal_error_backtraces', 'cve' => '109619', 'state' => 'NA',
        'value' => 'N/A（本版本无此项）', 'detail' => '该指令仅 PHP 8.5 起存在'];
}

/* --- 3.6 需人工核对的项（PHP 内不可读）--- */
$manual = [
    ['id' => 'pm.max_requests', 'detail' => 'FPM pool 指令，PHP 内不可读。设为 1 可让每个 worker 只处理一次请求就退休，直接切断跨请求链条（性能代价大，仅在无法升级时考虑）'],
    ['id' => '请求级 INI 覆盖',  'detail' => '检查是否存在 .user.ini、Apache <Directory> 内的 php_value、每请求 ini_set，它们可能在初始化前产生诊断或把缓解项改回去'],
    ['id' => '反代/WAF 限额',    'detail' => '在 Web 服务器或代理层限制 解码后请求体大小、字段数、multipart part 数、header 数、嵌套深度，且必须覆盖没有可用 Content-Length 的请求'],
    ['id' => 'RLIMIT_AS/DATA', 'detail' => '不要用 RLIMIT_AS 或 RLIMIT_DATA 做限制，它们本身可能诱发那个分配失败；用容器/cgroup 做可用性边界'],
];

/* ---------------------------------------------------------------- 4. 汇总 */

$badCount = count(array_filter($checks, fn($c) => $c['state'] === 'BAD'));

if ($versionState === 'PATCHED') {
    $overall = 'PATCHED';
    $summary = '当前 PHP 版本已包含修复，两个 CVE 的根因已被移除。以下配置项仅作纵深防御参考。';
} elseif ($sapiLevel === 'CRITICAL') {
    $overall = 'CRITICAL_EXPOSURE';
    $summary = '未修复版本 + mod_php：攻击可在应用代码执行前完成，与跑什么程序无关。立即升级，无替代方案。';
} elseif ($sapiLevel === 'HIGH') {
    $overall = 'HIGH_EXPOSURE';
    $summary = '未修复版本 + FPM/FrankenPHP 类 SAPI：源码判定受影响，且已存在应用相关实测利用路径。立即升级。';
} elseif ($affected) {
    $overall = 'ELEVATED';
    $summary = '未修复版本，但当前 SAPI 的跨请求/请求启动面较小。仍应升级；若该结果来自 CLI，则不代表生产 Web SAPI。';
} else {
    $overall = 'REVIEW';
    $summary = '版本分支未确认，请对照官方公告人工判断。';
}

$result = [
    'generated_at' => gmdate('c'),
    'host'         => gethostname() ?: 'unknown',
    'overall'      => $overall,
    'summary'      => $summary,
    'php' => [
        'version' => PHP_VERSION,
        'version_id' => $vid,
        'branch'  => $branch,
        'sapi'    => $sapi,
        'state'   => $versionState,
        'detail'  => $versionText,
        'sapi_level' => $sapiLevel,
        'sapi_detail' => $sapiText,
    ],
    'checks'      => $checks,
    'manual_review' => $manual,
    'bad_count'   => $badCount,
    'fixed_versions' => $fixedVersion,
];

/* ---------------------------------------------------------------- 5. 输出 */

if ($asJson) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT), PHP_EOL;
    exit;
}

$line = str_repeat('─', 78);

echo PHP_EOL;
echo "php2shell-check  CVE-2026-109618 / CVE-2026-109619 可利用性自查", PHP_EOL;
echo $line, PHP_EOL;
printf("PHP 版本 : %s  （%s）%s", PHP_VERSION, $branch, PHP_EOL);
printf("SAPI     : %s%s", $sapi, PHP_EOL);
printf("主机     : %s%s", $result['host'], PHP_EOL);
printf("时间(UTC): %s%s", $result['generated_at'], PHP_EOL);
echo $line, PHP_EOL;

$tag = static function (string $s): string {
    $map = ['OK' => '[ OK ]', 'WARN' => '[WARN]', 'BAD' => '[BAD ]', 'NA' => '[ NA ]'];
    return $map[$s] ?? '[????]';
};

echo PHP_EOL, "① 版本判定", PHP_EOL;
printf("  %s %s%s", $tag($versionState === 'PATCHED' ? 'OK' : 'BAD'), $versionText, PHP_EOL);

echo PHP_EOL, "② SAPI 暴露等级：{$sapiLevel}", PHP_EOL;
printf("  %s%s", $sapiText, PHP_EOL);

echo PHP_EOL, "③ 配置审计", PHP_EOL;
foreach ($checks as $c) {
    printf("  %s %-32s %-14s %s%s", $tag($c['state']), $c['id'], $c['value'], $c['cve'], PHP_EOL);
    printf("         └ %s%s", $c['detail'], PHP_EOL);
}

echo PHP_EOL, "④ 需人工核对的项（PHP 进程内读不到）", PHP_EOL;
foreach ($manual as $m) {
    printf("  · %-18s %s%s", $m['id'], $m['detail'], PHP_EOL);
}

echo PHP_EOL, $line, PHP_EOL;
echo "总体判定：{$overall}", PHP_EOL;
echo "{$summary}", PHP_EOL;
if ($badCount > 0 && $versionState !== 'PATCHED') {
    echo PHP_EOL, "仍有 {$badCount} 项配置为 BAD —— 但请记住：官方明确说明配置缓解都不完整，", PHP_EOL;
    $upgradeTarget = $fixedVersion[$branch] ?? '该分支最新版本（8.2.35 / 8.3.36 / 8.4.27 / 8.5.12）';
    echo "109619 更不存在通用配置层完全缓解。升级到 {$upgradeTarget} 是唯一完整方案。", PHP_EOL;
}
echo $line, PHP_EOL;
echo "本脚本未发送任何攻击载荷、未触发 OOM。判定为 PATCHED 之外，均不代表“已被入侵”，只代表具备前置条件。", PHP_EOL, PHP_EOL;
