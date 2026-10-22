<!php2shell lab target，仅本机回环使用>
<?php
// 本地靶机：最简 upload progress 使用场景
// 用途：给公开 PoC 提供一个能跑起来的目标，观察其真实行为
session_start();

$progress_name = ini_get('session.upload_progress.name');
$progress = $_SESSION[$progress_name . 'poc'] ?? null;
?>
<!doctype html>
<html><head><meta charset="utf-8"><title>php2shell lab</title></head>
<body>
<h3>target: PHP <?= PHP_VERSION ?></h3>
<p>upload_progress.enabled = <?= ini_get('session.upload_progress.enabled') ?></p>
<p>memory_limit = <?= ini_get('memory_limit') ?> / post_max_size = <?= ini_get('post_max_size') ?></p>
<p>session_id = <?= session_id() ?></p>
<pre><?= htmlspecialchars(var_export($progress, true)) ?></pre>

<form action="" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="<?= htmlspecialchars($progress_name) ?>" value="poc">
  <input type="file" name="f">
  <input type="submit" value="upload">
</form>
</body></html>
