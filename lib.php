<?php
/**
 * Shared Library for URL Shortener
 * Author: Jaydatt Khodave
 */

function cfg() {
    static $cfg = null;
    if ($cfg === null) {
        $cfg = require __DIR__ . '/config.php';
    }
    return $cfg;
}

/**
 * Database connection (PDO, singleton)
 */
function pdo(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;

    $c = cfg()['db'];
    $dsn = "mysql:host={$c['host']};port={$c['port']};dbname={$c['name']};charset={$c['charset']}";

    try {
        $pdo = new PDO($dsn, $c['user'], $c['pass'], [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    } catch (PDOException $e) {
        log_error("DB Connection failed: " . $e->getMessage());
        http_response_code(500);
        exit("Database connection failed.");
    }

    return $pdo;
}

/**
 * Base62 Encoding (for short codes)
 */
function base62_encode(int $num): string {
    $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $base = strlen($chars);
    $s = '';
    while ($num > 0) {
        $s = $chars[$num % $base] . $s;
        $num = intdiv($num, $base);
    }
    return $s ?: '0';
}

/**
 * URL Validation
 */
function valid_url(string $url): bool {
    $cfg = cfg();
    if (strlen($url) > $cfg['security']['max_url_length']) return false;
    if (!filter_var($url, FILTER_VALIDATE_URL)) return false;
    $scheme = strtolower(parse_url($url, PHP_URL_SCHEME));
    return in_array($scheme, $cfg['security']['allowed_schemes'], true);
}

/**
 * Normalize URL
 */
function normalize_url(string $url): string {
    // Remove trailing slash for consistency
    return rtrim($url, "/");
}

/**
 * JSON Response
 */
function json_out($data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Get Client IP
 */
function client_ip(): ?string {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    }
    return $_SERVER['REMOTE_ADDR'] ?? null;
}

/**
 * Hash IP for privacy
 */
function hash_ip(?string $ip): ?string {
    return $ip ? hash('sha256', $ip) : null;
}

/**
 * Error Logging
 */
function log_error(string $msg): void {
    $cfg = cfg();
    if (!empty($cfg['logging']['enabled'])) {
        $file = $cfg['logging']['file'] ?? '/tmp/app.log';
        error_log("[" . date('Y-m-d H:i:s') . "] " . $msg . PHP_EOL, 3, $file);
    }
}
