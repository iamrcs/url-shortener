<?php
/**
 * URL Shortener Configuration
 * 
 * Uses environment variables for security.
 * Local fallback values provided for dev.
 */

return [

    // Database configuration
    'db' => [
        'host'    => getenv('DB_HOST') ?: '127.0.0.1',
        'port'    => getenv('DB_PORT') ?: 3306,
        'name'    => getenv('DB_NAME') ?: 'urlshort',
        'user'    => getenv('DB_USER') ?: 'root',
        'pass'    => getenv('DB_PASS') ?: '',
        'charset' => 'utf8mb4'
    ],

    // Base URL (must match your deployed domain)
    // Example: https://sho.rt
    'base_url' => rtrim(getenv('BASE_URL') ?: 'http://localhost:8080', '/'),

    // Minimum length for auto-generated codes
    'min_code_len' => 6,

    // Security settings
    'security' => [
        'allowed_schemes' => ['http', 'https'],   // Only these URLs allowed
        'max_url_length'  => 2048,                // Prevent abuse with very long input
    ],

    // Logging (set to true to enable error logging to /tmp/app.log)
    'logging' => [
        'enabled' => false,
        'file'    => '/tmp/app.log',
    ],

];
