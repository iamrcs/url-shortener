<?php
require __DIR__.'/lib.php';

$code = trim($_GET['c'] ?? '');

// If no code → 404
if ($code === '') {
    http_response_code(404);
    exit("404 Not Found");
}

$pdo = pdo();

// Lookup the short code
$stmt = $pdo->prepare('SELECT id, long_url FROM urls WHERE code = :c LIMIT 1');
$stmt->execute([':c' => $code]);
$row = $stmt->fetch();

if (!$row) {
    http_response_code(404);
    exit("404 Not Found");
}

$id  = $row['id'];
$url = $row['long_url'];

// Update analytics (clicks, last_accessed, ip_hash)
try {
    $upd = $pdo->prepare('UPDATE urls 
                          SET clicks = clicks + 1, 
                              last_accessed = NOW(),
                              ip_hash = :ip
                          WHERE id = :id');
    $upd->execute([
        ':id' => $id,
        ':ip' => hash_ip(client_ip())
    ]);
} catch (PDOException $e) {
    log_error("DB Update (redirect) error: " . $e->getMessage());
    // redirect anyway even if analytics update fails
}

// Perform redirect
header("Location: " . $url, true, 302);
exit;
