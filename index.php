<?php $cfg = require __DIR__.'/config.php'; ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>URL Shortener</title>
  <link rel="stylesheet" href="tool.css" />
</head>
<body>
  <main>
    <header>
      <h1>Professional URL Shortener</h1>
      <p>Fast · Simple · Secure</p>
    </header>

    <!-- URL Shortener Form -->
    <form id="shortForm" autocomplete="off" novalidate>
      <div>
        <label for="longUrl">Enter Long URL</label>
        <input id="longUrl" type="url" required placeholder="https://example.com/very/long/link" aria-required="true" />
      </div>

      <div>
        <label for="slug">Custom Slug (optional)</label>
        <input id="slug" type="text" placeholder="e.g. my-link">
        <p class="small">Allowed: A–Z, a–z, 0–9, dash (-), underscore (_), min 3 chars</p>
      </div>

      <div class="controls">
        <button type="submit" class="btn btn-primary">Shorten URL</button>
        <button type="button" id="clearBtn" class="btn">Clear</button>
      </div>
    </form>

    <!-- Output Section -->
    <section id="outputSection">
      <h2 style="font-size:15px;font-weight:600;margin-bottom:8px">Shortened Link</h2>
      <input id="output" readonly aria-label="Shortened URL" />
      <div class="output-actions">
        <button id="copyBtn" class="btn" title="Copy link">Copy</button>
        <a id="openBtn" class="btn" target="_blank" rel="noopener">Open</a>
      </div>
      <p class="small" id="msg"></p>
    </section>

    <footer>
      <p>Powered by <a href="<?php echo htmlspecialchars($cfg['base_url']); ?>" target="_blank" rel="noopener">
        <?php echo parse_url($cfg['base_url'], PHP_URL_HOST); ?>
      </a></p>
    </footer>
  </main>

  <!-- JavaScript -->
  <script>
    const base = <?php echo json_encode($cfg['base_url']); ?>;
    const form = document.getElementById('shortForm');
    const input = document.getElementById('longUrl');
    const slug  = document.getElementById('slug');
    const output = document.getElementById('output');
    const section = document.getElementById('outputSection');
    const copyBtn = document.getElementById('copyBtn');
    const openBtn = document.getElementById('openBtn');
    const clearBtn = document.getElementById('clearBtn');
    const msg = document.getElementById('msg');

    // Hide output initially
    section.style.display = 'none';

    // Handle form submit
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = input.value.trim();
      const slugVal = slug.value.trim();

      if (!url) {
        alert("Please enter a valid URL");
        return;
      }

      try {
        const res = await fetch('api.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, slug: slugVal })
        });
        const j = await res.json();

        section.style.display = 'block';

        if (j.ok) {
          const shortUrl = base + '/' + j.code;
          output.value = shortUrl;
          openBtn.href = shortUrl;
          msg.textContent = j.msg;
          msg.style.color = "green";
        } else {
          output.value = "";
          openBtn.href = "#";
          msg.textContent = "Error: " + j.error;
          msg.style.color = "red";
        }
      } catch (err) {
        section.style.display = 'block';
        output.value = "";
        msg.textContent = "Network error. Try again.";
        msg.style.color = "red";
      }
    });

    // Copy button
    copyBtn.addEventListener('click', () => {
      if (output.value) {
        output.select();
        navigator.clipboard.writeText(output.value);
      }
    });

    // Clear form
    clearBtn.addEventListener('click', () => {
      input.value = "";
      slug.value  = "";
      output.value = "";
      msg.textContent = "";
      section.style.display = 'none';
    });
  </script>
</body>
</html>
