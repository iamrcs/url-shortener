<?php
return [
    'base_url' => getenv('APP_BASE_URL') ?: 'http://localhost:8080',
    'db' => [
        'host' => getenv('DB_HOST') ?: 'localhost',
        'name' => getenv('DB_NAME') ?: 'shortener',
        'user' => getenv('DB_USER') ?: 'root',
        'pass' => getenv('DB_PASS') ?: ''
    ]
];
