# URL Shortener Project

A **fast, secure, and feature-rich URL shortener** built with **Flask**, **SQLAlchemy**, and **Redis caching**, capable of shortening long URLs, generating custom slugs, tracking clicks, and handling URL expirations.

Refer to the [API Documentation](https://github.com/iamrcs/url-shortener/blob/main/static/documentation.md) for detailed usage instructions.

This project is ideal for personal, team, or production use and comes with **web interface, REST API, and analytics**.

---

## Table of Contents

1. [Features](#features)
2. [Tech Stack](#tech-stack)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Running the App](#running-the-app)
6. [Usage](#usage)

   * [Web Interface](#web-interface)
   * [API](#api)
7. [Database](#database)
8. [Redis Caching](#redis-caching)
9. [Rate Limiting](#rate-limiting)
10. [Security](#security)
11. [Cleanup Expired URLs](#cleanup-expired-urls)
12. [Error Handling](#error-handling)
13. [Future Improvements](#future-improvements)

---

## Features

* Shorten long URLs with auto-generated slugs.
* Support **custom slugs** (alphanumeric, `_`, `-`, 3-50 characters).
* Track URL **clicks** and **last clicked time**.
* Expiry support (1 day to 10 years).
* Return **existing short URL** if already shortened.
* Redis caching for faster response and lookup.
* Rate limiting to prevent abuse.
* REST API for programmatic access.
* Web interface for user-friendly usage.
* Security headers and protections for safer deployment.

---

## Tech Stack

* **Backend**: Python 3.11+, Flask
* **Database**: SQLite (default) or PostgreSQL
* **Caching**: Redis (optional but recommended)
* **ORM**: SQLAlchemy
* **Rate Limiting**: Flask-Limiter
* **Frontend**: HTML templates + optional JS

---

## Installation

1. **Clone the repository**:

```bash
git clone https://github.com/iamrcs/url-shortener.git
cd url-shortener
```

2. **Create a virtual environment**:

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. **Install dependencies**:

```bash
pip install -r requirements.txt
```

---

## Configuration

You can configure the project using **environment variables**:

| Variable       | Description                | Default                    |
| -------------- | -------------------------- | -------------------------- |
| `DATABASE_URL` | Database connection string | `sqlite:///urls.db`        |
| `REDIS_URL`    | Redis connection string    | `redis://localhost:6379/0` |
| `PORT`         | Port to run the Flask app  | `5000`                     |

---

## Running the App

```bash
python app.py
```

By default, it runs on:

```
http://localhost:5000
```

For production, consider running behind **Gunicorn**:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

---

## Usage

### Web Interface

1. Open `http://localhost:5000` in your browser.
2. Enter the long URL and optional custom slug.
3. Optionally, set the expiry in days.
4. Click **Shorten**.

You will get a **short URL** like:

```
http://localhost:5000/abc123
```

---

### API

**Endpoint:** `POST /api/shorten`

**Request (JSON):**

```json
{
  "url": "https://www.example.com/very-long-url",
  "slug": "custom-slug",
  "expiry_days": 30
}
```

**Response (JSON):**

```json
{
  "ok": true,
  "code": "abc123",
  "short_url": "http://localhost:5000/abc123",
  "msg": "URL shortened successfully!"
}
```

**Get Stats:**

```
GET /api/stats/<slug>
```

Response:

```json
{
  "ok": true,
  "slug": "abc123",
  "url": "https://www.example.com/very-long-url",
  "clicks": 10,
  "created_at": "2025-09-11T19:45:00+00:00",
  "last_clicked": "2025-09-11T20:00:00+00:00",
  "expires_at": "2025-10-11T19:45:00+00:00",
  "short_url": "http://localhost:5000/abc123"
}
```

---

## Database

Default is SQLite (`urls.db`).
Supports PostgreSQL or any SQLAlchemy-compatible database.

**Table: URLMap**

| Column        | Type     | Description             |
| ------------- | -------- | ----------------------- |
| id            | Integer  | Primary key             |
| slug          | String   | Shortened slug (unique) |
| long\_url     | Text     | Original URL            |
| clicks        | Integer  | Number of clicks        |
| created\_at   | DateTime | Timestamp of creation   |
| last\_clicked | DateTime | Timestamp of last click |
| expires\_at   | DateTime | Optional expiration     |

---

## Redis Caching

Redis is used to **speed up URL → slug and slug → URL lookups**.

* Keys: `url:<long_url>` → `slug`, `slug:<slug>` → `long_url`
* TTL: 30 days

If Redis is unavailable, the app falls back to database queries.

---

## Rate Limiting

* Default: `200 requests/day` and `50 requests/hour` per IP.
* Configurable via Flask-Limiter.
* Prevents abuse and brute-force slug guessing.

---

## Security

* `Strict-Transport-Security` header
* `X-Frame-Options: DENY`
* `X-Content-Type-Options: nosniff`
* `Cache-Control: no-store`
* Rejects private IPs or `localhost` URLs.

---

## Cleanup Expired URLs

* Endpoint: `POST /cleanup`
* Deletes URLs with expired timestamps.

**Response:**

```json
{
  "ok": true,
  "deleted": 5,
  "msg": "Expired URLs removed"
}
```

---

## Error Handling

| Status | Message                    |
| ------ | -------------------------- |
| 400    | Invalid URL or slug format |
| 404    | Slug or endpoint not found |
| 409    | Slug already taken         |
| 410    | Link expired               |
| 429    | Too many requests          |
| 500    | Internal server error      |

---

## Future Improvements

* Async FastAPI version for ultra-fast response.
* JWT or API key authentication for API usage.
* Frontend dashboard with analytics charts.
* QR code generation for shortened URLs.
* Multi-user support with custom domains.

---

**Author:** Jaydatt Khodave
**License:** MIT
