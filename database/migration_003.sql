-- ============================================================
-- Migration 003: Soporte para llaves client-side ECDSA P-256
--
-- Cambios:
--   1. usuario_claves: permitir clave_privada_encriptada vacía
--      (la clave privada ya no se almacena en el servidor)
--   2. usuario_claves: agregar columna algoritmo para distinguir
--      claves RSA-3072 (legacy) de ECDSA P-256 (nuevo)
--   3. documentos: documentar que firma ahora puede ser hex ECDSA
--      además del base64 RSA (no hay cambio estructural)
--   4. Nueva tabla: firma_sessions (alternativa robusta a $_SESSION
--      para ambientes multi-servidor / sin sticky sessions)
-- ============================================================

USE casa_monarca;

-- 1. Permitir clave_privada_encriptada vacía (antes era NOT NULL sin default)
ALTER TABLE usuario_claves
    MODIFY COLUMN clave_privada_encriptada BLOB NULL DEFAULT NULL;

-- 2. Columna algoritmo para distinguir tipo de llave
ALTER TABLE usuario_claves
    ADD COLUMN algoritmo ENUM('RSA-3072','ECDSA-P256') NOT NULL DEFAULT 'ECDSA-P256'
    AFTER version;

-- Marcar llaves existentes (RSA-3072) como legacy
UPDATE usuario_claves
    SET algoritmo = 'RSA-3072'
    WHERE clave_privada_encriptada IS NOT NULL AND clave_privada_encriptada != '';

-- 3. Tabla firma_sessions: reemplaza $_SESSION para flujo hash → firma
--    Necesaria en producción con múltiples contenedores Docker
--    (la sesión PHP no se comparte entre instancias)
CREATE TABLE IF NOT EXISTS firma_sessions (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    usuario_id    INT UNSIGNED    NOT NULL,
    documento_id  INT UNSIGNED    NOT NULL,
    hash_hex      VARCHAR(64)     NOT NULL,
    expires_at    DATETIME        NOT NULL,
    usado_en      DATETIME        NULL,
    creado_en     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id)   REFERENCES usuarios(id)   ON DELETE CASCADE,
    FOREIGN KEY (documento_id) REFERENCES documentos(id) ON DELETE CASCADE,
    INDEX idx_usuario_doc (usuario_id, documento_id),
    INDEX idx_expires     (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Limpieza automática de sesiones expiradas (ejecutar periódicamente o via evento)
-- DELETE FROM firma_sessions WHERE expires_at < NOW() AND usado_en IS NOT NULL;
