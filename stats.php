<?php
header('Content-Type: application/json');
$cfg = require __DIR__.'/config.php';

try {
    $pdo = new PDO(
        "mysql:host={$cfg['db']['host']};dbname={$cfg['db']['name']};charset=utf8mb4",
        $cfg['db']['user'],
        $cfg['db']['pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (Exception $e) {
    echo json_encode(['ok' => false, 'error' => 'Database connection failed']);
    exit;
}

$slug = trim($_GET['slug'] ?? '');
if (!$slug || !preg_match('/^[A-Za-z0-9\-_]+$/', $slug)) {
    echo json_encode(['ok' => false, 'error' => 'Invalid or missing slug']);
    exit;
}

$stmt = $pdo->prepare("SELECT url, clicks, created_at FROM links WHERE slug = ?");
$stmt->execute([$slug]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if ($row) {
    echo json_encode([
        'ok'    => true,
        'slug'  => $slug,
        'url'   => $row['url'],
        'clicks'=> (int)$row['clicks'],
        'created_at' => $row['created_at'],
        'short_url'  => rtrim($cfg['base_url'], '/') . '/' . $slug
    ]);
} else {
    echo json_encode(['ok' => false, 'error' => 'Slug not found']);
}
