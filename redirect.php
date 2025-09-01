<?php
$cfg = require __DIR__.'/config.php';

try {
    $pdo = new PDO(
        "mysql:host={$cfg['db']['host']};dbname={$cfg['db']['name']};charset=utf8mb4",
        $cfg['db']['user'],
        $cfg['db']['pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (Exception $e) {
    http_response_code(500);
    exit("Database error");
}

$slug = trim($_GET['slug'] ?? '');
if (!$slug) {
    http_response_code(404);
    exit("Not found");
}

$stmt = $pdo->prepare("SELECT url FROM links WHERE slug = ?");
$stmt->execute([$slug]);
$row = $stmt->fetch();

if ($row) {
    $pdo->prepare("UPDATE links SET clicks = clicks + 1 WHERE slug = ?")->execute([$slug]);
    header("Location: " . $row['url'], true, 302);
    exit;
} else {
    http_response_code(404);
    echo "Short link not found";
}
