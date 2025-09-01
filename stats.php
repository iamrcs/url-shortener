<?php
require __DIR__.'/lib.php';

$code = trim($_GET['code'] ?? '');

if ($code === '') {
    http_response_code(400);
    exit("Bad Request: Missing code");
}

$pdo = pdo();

// Lookup code
$stmt = $pdo->prepare('SELECT code, long_url, created_at, clicks, last_accessed 
                       FROM urls WHERE code = :c LIMIT 1');
$stmt->execute([':c' => $code]);
$row = $stmt->fetch();

if (!$row) {
    http_response_code(404);
    exit("404 Not Found: Invalid code");
}

$cfg = cfg();
$shortUrl = $cfg['base_url'] . '/' . $row['code'];
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Stats for <?php echo htmlspecialchars($row['code']); ?></title>
  <link rel="stylesheet" href="tool.css"/>
</head>
<body>
  <main>
    <header>
      <h1>Link Statistics</h1>
      <p>Analytics for your short link</p>
    </header>

    <section class="card">
      <h2>Short Link</h2>
      <input type="text" readonly value="<?php echo htmlspecialchars($shortUrl); ?>"/>
      <div class="controls">
        <a class="btn btn-primary" href="<?php echo htmlspecialchars($shortUrl); ?>" target="_blank">Open</a>
      </div>
    </section>

    <section class="card">
      <h2>Details</h2>
      <ul>
        <li><strong>Original URL:</strong> <a href="<?php echo htmlspecialchars($row['long_url']); ?>" target="_blank"><?php echo htmlspecialchars($row['long_url']); ?></a></li>
        <li><strong>Created At:</strong> <?php echo htmlspecialchars($row['created_at']); ?></li>
        <li><strong>Total Clicks:</strong> <?php echo (int)$row['clicks']; ?></li>
        <li><strong>Last Accessed:</strong> <?php echo $row['last_accessed'] ?: 'Never'; ?></li>
      </ul>
    </section>

    <footer>
      <p>Powered by <a href="<?php echo htmlspecialchars($cfg['base_url']); ?>" target="_blank" rel="noopener">
        <?php echo parse_url($cfg['base_url'], PHP_URL_HOST); ?>
      </a></p>
    </footer>
  </main>
</body>
</html>
