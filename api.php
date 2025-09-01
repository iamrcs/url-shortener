<?php
header('Content-Type: application/json');
$cfg = require __DIR__.'/config.php';

// Connect DB
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

// Get POST body
$data = json_decode(file_get_contents('php://input'), true);
$url  = trim($data['url'] ?? '');
$slug = trim($data['slug'] ?? '');

// Validate URL
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    echo json_encode(['ok' => false, 'error' => 'Invalid URL']);
    exit;
}

// ✅ 1. Check if URL already exists
$stmt = $pdo->prepare("SELECT slug FROM links WHERE url = ?");
$stmt->execute([$url]);
$existing = $stmt->fetchColumn();

if ($existing && !$slug) {
    echo json_encode(['ok' => true, 'code' => $existing, 'msg' => 'URL already shortened']);
    exit;
}

// ✅ 2. Slug handling
if ($slug) {
    if (!preg_match('/^[A-Za-z0-9\-_]{3,}$/', $slug)) {
        echo json_encode(['ok' => false, 'error' => 'Invalid slug format']);
        exit;
    }
    $stmt = $pdo->prepare("SELECT id FROM links WHERE slug = ?");
    $stmt->execute([$slug]);
    if ($stmt->fetch()) {
        echo json_encode(['ok' => false, 'error' => 'Custom slug already taken']);
        exit;
    }
} else {
    do {
        $slug = substr(bin2hex(random_bytes(4)), 0, 6);
        $stmt = $pdo->prepare("SELECT id FROM links WHERE slug = ?");
        $stmt->execute([$slug]);
    } while ($stmt->fetch());
}

// ✅ 3. Insert new record
$stmt = $pdo->prepare("INSERT INTO links (slug, url) VALUES (?, ?)");
$stmt->execute([$slug, $url]);

echo json_encode([
    'ok'   => true,
    'code' => $slug,
    'msg'  => 'URL shortened successfully'
]);
