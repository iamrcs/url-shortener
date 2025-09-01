const base = window.location.origin;
    const form = document.getElementById('shortForm');
    const input = document.getElementById('longUrl');
    const slug = document.getElementById('slug');
    const expiry = document.getElementById('expiry_days');
    const output = document.getElementById('output');
    const section = document.getElementById('outputSection');
    const copyBtn = document.getElementById('copyBtn');
    const openBtn = document.getElementById('openBtn');
    const clearBtn = document.getElementById('clearBtn');
    const msg = document.getElementById('msg');

    section.style.display = 'none';

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = input.value.trim();
      const slugVal = slug.value.trim();
      const expiryVal = expiry ? expiry.value.trim() : "";

      if (!url) {
        alert("Please enter a valid URL");
        return;
      }

      try {
        const res = await fetch('/shorten', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, slug: slugVal, expiry_days: expiryVal })
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

    copyBtn.addEventListener('click', () => {
      if (output.value) {
        output.select();
        navigator.clipboard.writeText(output.value);
      }
    });

    clearBtn.addEventListener('click', () => {
      input.value = "";
      slug.value = "";
      if (expiry) expiry.value = "";
      output.value = "";
      msg.textContent = "";
      section.style.display = 'none';
    });
