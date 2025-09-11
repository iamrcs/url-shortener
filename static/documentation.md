# URL Shortener API Documentation

This documentation explains how to use the URL Shortener API, integrate it into other websites, and manage short URLs.

---

## 1. Base URL

All endpoints are relative to your domain:

```
https://iiuo.org/
```

---

## 2. Shorten a URL via API

**Endpoint:** `POST /shorten`

Create a short URL for a given long URL.

### Request Headers

```
Content-Type: application/json
```

### Request Body

```json
{
  "url": "https://example.com",
  "slug": "customslug",      // optional, custom short code
  "expiry_days": 30           // optional, link expires in X days
}
```

### Response

**Success (201 or 200)**

```json
{
  "ok": true,
  "code": "abc123",
  "short_url": "https://iiuo.org/abc123",
  "msg": "URL shortened successfully!"
}
```

**Error (400 or 409)**

```json
{
  "ok": false,
  "error": "Slug already taken"
}
```

### Example CURL

```bash
curl -X POST https://iiuo.org/shorten \
-H "Content-Type: application/json" \
-d '{"url":"https://example.com","slug":"myalias","expiry_days":30}'
```

---

## 3. Redirect to Long URL

**Endpoint:** `GET /<slug>`

Visit the short URL to redirect to the original long URL.

```
https://iiuo.org/myalias
```

**Error Responses**

```json
{
  "ok": false,
  "error": "Link expired"
}
```

```json
{
  "ok": false,
  "error": "Slug not found"
}
```

---

## 4. Get URL Stats

**Endpoint:** `GET /api/stats/<slug>`

Get click stats and metadata about a short URL.

### Response

```json
{
  "ok": true,
  "slug": "abc123",
  "url": "https://example.com",
  "clicks": 42,
  "created_at": "2025-09-11T12:00:00.000000",
  "last_clicked": "2025-09-11T14:30:00.000000",
  "expires_at": "2025-10-11T12:00:00.000000",
  "short_url": "https://iiuo.org/abc123"
}
```

**If slug not found**

```json
{
  "ok": false,
  "error": "Slug not found"
}
```

---

## 5. Cleanup Expired URLs

**Endpoint:** `POST /cleanup`

Delete all expired URLs from the database.

### Response

```json
{
  "ok": true,
  "deleted": 5,
  "msg": "Expired URLs removed"
}
```

### Example CURL

```bash
curl -X POST https://iiuo.org/cleanup
```

---

## 6. Embedding Shortener Widget on Your Website

You can let visitors shorten URLs directly from your site:

```html
<div id="shortener-widget">
    <input type="text" id="long-url" placeholder="Enter your URL" style="width: 300px;">
    <input type="text" id="custom-slug" placeholder="Custom slug (optional)" style="width: 150px;">
    <button onclick="shorten()">Shorten URL</button>
    <p id="result"></p>
</div>

<script>
async function shorten() {
    const url = document.getElementById("long-url").value;
    const slug = document.getElementById("custom-slug").value;

    const response = await fetch("https://iiuo.org/shorten", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, slug })
    });

    const data = await response.json();
    const resultElem = document.getElementById("result");
    if (data.ok) {
        resultElem.innerHTML = `<a href="${data.short_url}" target="_blank">${data.short_url}</a>`;
    } else {
        resultElem.textContent = "Error: " + data.error;
    }
}
</script>
```

**Usage:** Copy this HTML/JS snippet to any website to embed your shortener.

---

## 7. Error Codes

| Code | Meaning                            |
| ---- | ---------------------------------- |
| 400  | Bad Request (missing/invalid data) |
| 404  | Endpoint not found                 |
| 409  | Slug already taken                 |
| 410  | Link expired                       |
| 429  | Too many requests (rate limited)   |
| 500  | Internal server error              |

---

## 8. Notes

* Custom slug must be **3–50 characters**: letters, digits, dash `-`, or underscore `_`.
* Expiry days are optional; if not provided, link never expires.
* Rate limiting: **1 request per second per IP**.
* Widget is fully embeddable and interactive.
* Use the `/api/stats/<slug>` endpoint to track clicks and usage.

---

✅ Now your shortener can be fully used **via API or embedded on other websites**.
