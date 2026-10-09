-- Système NTT — schéma complet (facultatif : l'application crée/migre
-- automatiquement les tables au premier accès). Le compte administrateur
-- (identifiant : admin) est créé automatiquement par l'application.
CREATE DATABASE IF NOT EXISTS systeme_ntt
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE systeme_ntt;

CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  username VARCHAR(60) NULL UNIQUE,
  email VARCHAR(190) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  email_verified TINYINT(1) NOT NULL DEFAULT 0,
  role VARCHAR(10) NOT NULL DEFAULT 'user',            -- admin | user | visitor
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  must_change_password TINYINT(1) NOT NULL DEFAULT 0,
  verification_token_hash CHAR(64) NULL,
  verification_expires DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  verified_at DATETIME NULL,
  last_login DATETIME NULL,
  INDEX idx_verification_token (verification_token_hash)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS settings (
  k VARCHAR(64) NOT NULL PRIMARY KEY,
  v TEXT NULL,
  updated_at DATETIME NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_attempts (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ident VARCHAR(190) NOT NULL,
  ip VARCHAR(45) NOT NULL,
  attempted_at DATETIME NOT NULL,
  INDEX idx_la_ident (ident, attempted_at),
  INDEX idx_la_ip (ip, attempted_at)
) ENGINE=InnoDB;
