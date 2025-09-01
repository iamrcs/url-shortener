<?php
require __DIR__.'/lib.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_out(['ok' => false, 'error' => 'Method not allowed'], 405);
}

$in = json_decode(file_get_contents('php://input'), true);
$url  = trim($in['url']  ?? '');
$slug = trim($in['slug'] ?? '');

if (!$url || !valid_url($url)) {
    json_out(['ok' => false, 'error' => 'Invalid or empty URL'], 400);
}

$url = normalize_url($url);
$pdo = pdo();

// If slug is provided → validate
if ($slug) {
    if (!preg_match('/^[A-Za-z0-9_-]{3,30}$/', $slug)) {
        json_out(['ok'=>false,'error'=>'Slug must be 3–30 chars, only A-Z, a-z, 0-9, dash (-), underscore (_)'],400);
    }

    // Check if slug already used
    $chk = $pdo->prepare('SELECT 1 FROM urls WHERE code = :c LIMIT 1');
    $chk->execute([':c' => $slug]);
    if ($chk->fetch()) {
        json_out(['ok'=>false,'error'=>'This custom slug is already taken'],409);
    }

    // Insert with custom slug
    try {
        $stmt = $pdo->prepare('INSERT INTO urls (code, long_url, ip_hash) VALUES (:c, :u, :ip)');
        $stmt->execute([
            ':c'  => $slug,
            ':u'  => $url,
            ':ip' => hash_ip(client_ip())
        ]);
        json_out(['ok'=>true,'code'=>$slug,'msg'=>'Custom slug created']);
    } catch (PDOException $e) {
        log_error("DB Insert (slug) error: ".$e->getMessage());
        json_out(['ok'=>false,'error'=>'Database error'],500);
    }
}

// No slug → check if URL already exists
$sel = $pdo->prepare('SELECT code FROM urls WHERE long_url = :u LIMIT 1');
$sel->execute([':u' => $url]);
if ($row = $sel->fetch()) {
    json_out(['ok'=>true,'code'=>$row['code'],'msg'=>'Existing short link']);
}

// Insert new auto-generated code
try {
    $stmt = $pdo->prepare('INSERT INTO urls (code, long_url, ip_hash) VALUES ("", :u, :ip)');
    $stmt->execute([
        ':u'  => $url,
        ':ip' => hash_ip(client_ip())
    ]);
    $id = $pdo->lastInsertId();

    // Generate Base62 short code
    $code = base62_encode((int)$id);

    // Update row with code
    $upd = $pdo->prepare('UPDATE urls SET code = :c WHERE id = :id');
    $upd->execute([':c' => $code, ':id' => $id]);

    json_out(['ok'=>true,'code'=>$code,'msg'=>'New short link created']);
} catch (PDOException $e) {
    log_error("DB Insert (auto) error: ".$e->getMessage());
    json_out(['ok'=>false,'error'=>'Database error'],500);
}
