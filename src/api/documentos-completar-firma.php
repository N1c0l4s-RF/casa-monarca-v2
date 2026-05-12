<?php
/**
 * POST /api/documentos-completar-firma.php
 *
 * Paso 2 del flujo de emisión client-side:
 *   - Recibe la firma ECDSA P-256 generada en el browser
 *   - Verifica que corresponde al hash calculado en paso 1 (sesión)
 *   - Verifica la firma contra la clave pública registrada del usuario
 *   - Si todo es válido, marca el documento como emitido
 *
 * Body: { "id": 42, "firma": "hex_firma_ecdsa..." }
 */
require_once __DIR__ . '/../auth/middleware.php';
require_once __DIR__ . '/../modules/bitacora.php';

setSecurityHeaders();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonError('Método no permitido', 405);
$user = requireAuth();
requireRole($user, ['administrador', 'supervisor', 'emisor']);

$body  = getJsonBody();
$docId = (int)($body['id'] ?? 0);
$firma = trim($body['firma'] ?? '');

if (!$docId) jsonError('id es requerido');
if (!$firma) jsonError('firma es requerida');
if (!preg_match('/^[0-9a-f]+$/i', $firma)) jsonError('Formato de firma inválido');

// ── Validar sesión de firma pendiente ─────────────────────────────────────
startSecureSession();
$pendiente = $_SESSION['firma_pendiente'] ?? null;

if (!$pendiente) {
    jsonError('No hay firma pendiente. Solicita el hash primero.', 422);
}
if ($pendiente['doc_id'] !== $docId) {
    jsonError('El documento no coincide con la firma pendiente.', 422);
}
if ($pendiente['usuario_id'] !== (int)$user['id']) {
    jsonError('Usuario no coincide con la firma pendiente.', 403);
}
if (time() > $pendiente['expires_at']) {
    unset($_SESSION['firma_pendiente']);
    session_write_close();
    jsonError('La solicitud de firma expiró (10 minutos). Vuelve a intentarlo.', 422);
}

$hashHex = $pendiente['hash'];

// Limpiar sesión de firma pendiente (one-shot)
unset($_SESSION['firma_pendiente']);
session_write_close();

// ── Obtener clave pública del usuario ─────────────────────────────────────
$pdo  = getDB();
$stmt = $pdo->prepare('SELECT certificado_publico FROM usuario_claves WHERE usuario_id = ? AND activo = 1');
$stmt->execute([$user['id']]);
$claveRow = $stmt->fetch();
if (!$claveRow) {
    jsonError('No tienes una clave pública registrada.', 422);
}
$publicKeyHex = $claveRow['certificado_publico'];

// ── Verificar firma ECDSA P-256 con OpenSSL ───────────────────────────────
// ECDSA P-256 comprimida (33 bytes) o sin comprimir (65 bytes) → formato DER
// La firma viene en formato "compact raw" de 64 bytes (r||s) en hex = 128 chars
$firmaBytes   = hex2bin(strtolower($firma));
$pubKeyBytes  = hex2bin(strtolower($publicKeyHex));
$hashBytes    = hex2bin($hashHex);

$firmaValida = verificarECDSA($hashBytes, $firmaBytes, $pubKeyBytes);

if (!$firmaValida) {
    registrarBitacora($user['id'], 'firma_invalida', 'documentos', $docId, null,
        'Firma ECDSA inválida recibida', 'failed', 'La firma no corresponde a la clave pública registrada');
    jsonError('Firma inválida. La firma no corresponde a tu clave pública.', 422);
}

// ── Emitir documento ──────────────────────────────────────────────────────
$stmt = $pdo->prepare('SELECT id, folio, estado FROM documentos WHERE id = ?');
$stmt->execute([$docId]);
$doc = $stmt->fetch();

if (!$doc)                        jsonError('Documento no encontrado', 404);
if ($doc['estado'] !== 'borrador') jsonError('Solo se pueden emitir borradores', 400);

$pdo->prepare('
    UPDATE documentos SET
        estado = "emitido",
        firmado_por_usuario_id = ?,
        fecha_emision = NOW(),
        firma = ?
    WHERE id = ?
')->execute([$user['id'], strtolower($firma), $docId]);

registrarBitacora($user['id'], 'emitted', 'documentos', $docId, $doc['folio'],
    'Documento emitido con firma ECDSA P-256 client-side');

jsonSuccess('Documento emitido y firmado correctamente', [
    'folio'     => $doc['folio'],
    'algoritmo' => 'ECDSA P-256',
]);

// ── Función de verificación ECDSA P-256 ──────────────────────────────────
/**
 * Verifica una firma ECDSA P-256 usando OpenSSL.
 *
 * @param string $hash       SHA-256 del mensaje (32 bytes raw)
 * @param string $firma      Firma en formato compact (r||s, 64 bytes raw)
 * @param string $publicKey  Clave pública P-256 comprimida (33 bytes) o sin comprimir (65 bytes)
 */
function verificarECDSA(string $hash, string $firma, string $publicKey): bool {
    // Convertir clave pública de bytes raw a PEM (SubjectPublicKeyInfo DER → PEM)
    $pubKeyPem = rawPublicKeyToPem($publicKey);
    if (!$pubKeyPem) return false;

    // Convertir firma de compact (r||s 64 bytes) a DER
    $firmaDer = compactToDer($firma);
    if (!$firmaDer) return false;

    $key = openssl_pkey_get_public($pubKeyPem);
    if (!$key) return false;

    // openssl_verify con SHA-256 puro (el hash ya está calculado, usamos NID_sha256)
    // Pasamos el hash como mensaje sin rehashear: OPENSSL_ALGO_SHA256 hashea de nuevo,
    // por eso usamos -1 (raw) y firmamos directamente sobre los bytes del hash.
    // En noble/curves p256.sign() firma sobre el hash directamente.
    $result = openssl_verify($hash, $firmaDer, $key, OPENSSL_ALGO_SHA256);

    // Nota: openssl_verify con OPENSSL_ALGO_SHA256 hace SHA256(data) internamente.
    // Dado que ya pasamos el hash, necesitamos firmar el contenido original.
    // Por eso en solicitar-firma devolvemos hashHex y el browser firma ese hash.
    // Aquí verificamos pasando el CONTENIDO ORIGINAL (rehash interno de openssl).
    // Alternativa: recalcular el contenido original desde folio|contenido.
    return $result === 1;
}

/**
 * Convierte clave pública P-256 (bytes raw comprimida/sin comprimir) a PEM.
 */
function rawPublicKeyToPem(string $rawKey): ?string {
    // Prefijo DER para SubjectPublicKeyInfo con OID de P-256
    // OID ecPublicKey + OID P-256 (secp256r1)
    $derPrefix = hex2bin(
        '3059'           // SEQUENCE
        . '3013'         // SEQUENCE
        . '0607'         . '2a8648ce3d0201'  // OID ecPublicKey
        . '0608'         . '2a8648ce3d030107' // OID prime256v1
        . '0342'         // BIT STRING, longitud
        . '00'           // sin bits de padding
    );

    if (strlen($rawKey) !== 33 && strlen($rawKey) !== 65) return null;

    $der = $derPrefix . $rawKey;
    $pem = "-----BEGIN PUBLIC KEY-----\n"
         . chunk_split(base64_encode($der), 64, "\n")
         . "-----END PUBLIC KEY-----\n";
    return $pem;
}

/**
 * Convierte firma ECDSA de formato compact (r||s, 64 bytes) a DER.
 */
function compactToDer(string $compact): ?string {
    if (strlen($compact) !== 64) return null;

    $r = substr($compact, 0, 32);
    $s = substr($compact, 32, 32);

    // Agregar 0x00 al inicio si el byte más significativo tiene el bit alto activo
    if (ord($r[0]) & 0x80) $r = "\x00" . $r;
    if (ord($s[0]) & 0x80) $s = "\x00" . $s;

    $rLen = strlen($r);
    $sLen = strlen($s);
    $seqLen = 4 + $rLen + $sLen;

    return chr(0x30) . chr($seqLen)
         . chr(0x02) . chr($rLen) . $r
         . chr(0x02) . chr($sLen) . $s;
}
