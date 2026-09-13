<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $uploadsDir = __DIR__ . '/uploads';
    if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0777, true);
    $dest = $uploadsDir . '/' . basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        $msg = 'Uploaded: <a href="/uploads/' . htmlspecialchars(basename($dest)) . '">' . htmlspecialchars(basename($dest)) . '</a>';
    } else {
        $msg = 'Upload failed.';
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Corporate Intranet</title>
<style>
body{font-family:system-ui,sans-serif;max-width:600px;margin:40px auto;padding:0 20px}
h1{font-size:1.4em}
form{margin:20px 0;padding:16px;border:1px solid #ccc;border-radius:4px;background:#f9f9f9}
input[type=file]{margin-right:8px}
.msg{padding:8px 12px;background:#e8f5e9;border:1px solid #a5d6a7;border-radius:4px;margin-bottom:12px}
ul{list-style:none;padding:0} li{padding:4px 0}
</style>
</head>
<body>
<h1>Corporate Intranet (PHP)</h1>
<?php if (!empty($msg)): ?><div class="msg"><?= $msg ?></div><?php endif; ?>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <button type="submit">Upload</button>
</form>
<h3>Uploads</h3>
<ul>
<?php
$dir = __DIR__ . '/uploads';
if (is_dir($dir)) {
    foreach (scandir($dir) as $f) {
        if ($f === '.' || $f === '..') continue;
        echo '<li><a href="/uploads/' . htmlspecialchars($f) . '">' . htmlspecialchars($f) . '</a> (' . filesize("$dir/$f") . ' bytes)</li>';
    }
}
?>
</ul>
</body>
</html>
