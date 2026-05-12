<?php
/**
 * POST /api/claves-registrar-publica.php
 *
 * Recibe la clave pública ECDSA P-256 (hex, 33 bytes comprimida) generada
 * en el browser. La clave privada NUNCA llega al servidor.
 *
 * Body: { "public_key": "02a1b2c3...hex..." }
 */
require_once __DIR__ . '/../auth/middleware.php';
require_once __DIR__ . '/../modules/bitacora.php';

setSecurityHeaders();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonError('Método no permitido', 405);
$user = requireAuth();

$body = getJsonBody();
$publicKeyHex = trim($body['public_key'] ?? '');

// Validar formato: hex de 66 caracteres (33 bytes comprimidos P-256)
// o 130 caracteres (65 bytes sin comprimir)
if (!preg_match('/^[0-9a-f]{66}$|^[0-9a-f]{130}$/i', $publicKeyHex)) {
    jsonError('Clave pública inválida. Se espera ECDSA P-256 en hex (comprimida o sin comprimir).');
}

// Normalizar a minúsculas
$publicKeyHex = strtolower($publicKeyHex);

// Fingerprint = SHA-256 del hex de la clave pública
$fingerprint = hash('sha256', $publicKeyHex);

$pdo = getDB();

// Verificar si ya tiene clave registrada
$stmt = $pdo->prepare('SELECT id, version FROM usuario_claves WHERE usuario_id = ?');
$stmt->execute([$user['id']]);
$existing = $stmt->fetch();

if ($existing) {
    // Rotar: incrementar versión, actualizar clave pública
    $pdo->prepare('
        UPDATE usuario_claves SET
            version = version + 1,
            certificado_publico = ?,
            fingerprint = ?,
            activo = 1,
            clave_privada_encriptada = "",
            iv_encriptacion = "",
            created_at = NOW(),
            revocada_en = NULL,
            download_count = 0,
            last_downloaded_at = NULL
        WHERE usuario_id = ?
    ')->execute([$publicKeyHex, $fingerprint, $user['id']]);

    registrarBitacora($user['id'], 'key_rotated', 'claves', null, null,
        "Clave pública ECDSA P-256 rotada. Fingerprint: {$fingerprint}");
} else {
    // Primer registro
    $pdo->prepare('
        INSERT INTO usuario_claves
            (usuario_id, clave_privada_encriptada, iv_encriptacion, certificado_publico, fingerprint)
        VALUES (?, "", "", ?, ?)
    ')->execute([$user['id'], $publicKeyHex, $fingerprint]);

    registrarBitacora($user['id'], 'key_registered', 'claves', null, null,
        "Clave pública ECDSA P-256 registrada. Fingerprint: {$fingerprint}");
}

jsonSuccess('Clave pública registrada correctamente', [
    'fingerprint' => $fingerprint,
    'algoritmo'   => 'ECDSA P-256',
]);
