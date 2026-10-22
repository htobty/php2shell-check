<?php
/**
 * 探测靶页：只暴露最少的运行期信息，用于观察探测请求是否引发 worker 抖动。
 * 故意不做任何业务逻辑 —— 因为这两个漏洞位于 PHP 引擎层，与应用代码无关。
 */
declare(strict_types=1);

header('Content-Type: text/plain; charset=utf-8');
echo "OK pid=", getmypid(),
     " sapi=", PHP_SAPI,
     " ver=", PHP_VERSION,
     " mem=", ini_get('memory_limit'),
     " up=", (int)ini_get('session.upload_progress.enabled'), "\n";
