-- ======================================================
-- URL Shortener Database Schema (Final v2)
-- Author: Jaydatt Khodave
-- ======================================================

CREATE TABLE IF NOT EXISTS urls (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- Short code (auto-generated or custom slug)
  code VARCHAR(30) NOT NULL UNIQUE,
  
  -- Original Long URL
  long_url TEXT NOT NULL,
  
  -- Metadata
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  clicks BIGINT UNSIGNED NOT NULL DEFAULT 0,
  last_accessed TIMESTAMP NULL DEFAULT NULL,
  
  -- Store hashed client IP (privacy-friendly analytics)
  ip_hash CHAR(64) NULL DEFAULT NULL,
  
  PRIMARY KEY (id),
  
  -- Prevent duplicate URLs (first 255 chars indexed)
  UNIQUE KEY uniq_url (long_url(255)),
  
  -- Index for faster redirect lookup
  INDEX idx_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
