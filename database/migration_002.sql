-- Casa Monarca v2 - Migration 002: Add firma column to documentos
USE casa_monarca;

ALTER TABLE documentos
ADD COLUMN firma LONGTEXT NULL AFTER hash_sha256;
