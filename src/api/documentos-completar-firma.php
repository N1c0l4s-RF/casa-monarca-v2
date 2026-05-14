<?php
/**
 * POST /api/documentos-completar-firma.php
 * Paso 2: recibe firma ECDSA, verifica contra clave pública, emite documento.
 * Body: { "id": 42, "firma": "hex_firma_ecdsa...", "session_id": N }
 */
require_once __DIR__ . '/../auth/middleware.php';
require_once __DIR__ . '/../modules/bitacora.php';

setSecurityHeaders();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonError('Método no permitido', 405);
$user = requireAuth();
requireRole($user, ['administrador', 'supervisor', 'emisor']);

$body      = getJsonBody();
$docId     = (int)($body['id'] ?? 0);
$firma     = trim($body['firma'] ?? '');
$sessionId = (int)($body['session_id'] ?? 0);

if (!$docId) jsonError('id es requerido');
if (!$firma) jsonError('firma es requerida');
if (!preg_match('/^[0-9a-f]+$/i', $firma)) jsonError('Formato de firma inválido');

// ── Validar firma_session en DB ───────────────────────────────────────────
$pdo = getDB();
$stmt = $pdo->prepare('
    SELECT id, hash_hex, expires_at, usado_en
    FROM firma_sessions
    WHERE usuario_id = ? AND documento_id = ? AND usado_en IS NULL
    ORDER BY id DESC LIMIT 1
');
$stmt->execute([$user['id'], $docId]);
$session = $stmt->fetch();

if (!$session) {
    jsonError('No hay firma pendiente. Solicita el hash primero.', 422);
}
if (new DateTime() > new DateTime($session['expires_at'])) {
    jsonError('La solicitud de firma expiró (10 minutos). Vuelve a intentarlo.', 422);
}

$hashHex = $session['hash_hex'];

// Marcar como usada (one-shot)
$pdo->prepare('UPDATE firma_sessions SET usado_en = NOW() WHERE id = ?')
    ->execute([$session['id']]);

// ── Obtener documento y reconstruir contenido a firmar ────────────────────
$stmt = $pdo->prepare('SELECT id, folio, contenido, estado FROM documentos WHERE id = ?');
$stmt->execute([$docId]);
$doc = $stmt->fetch();

if (!$doc)                         jsonError('Documento no encontrado', 404);
if ($doc['estado'] !== 'borrador') jsonError('Solo se pueden emitir borradores', 400);
if ((int)$doc['creado_por'] === (int)$user['id'] && $user['rol'] !== 'administrador') {
    jsonError('No puedes firmar tu propio documento. Se requiere un firmante diferente al creador.', 403);
}

$contenidoAFirmar = $doc['folio'] . '|' . $doc['contenido'];

// Validar que el hash en DB corresponde al documento actual
if (hash('sha256', $contenidoAFirmar) !== $hashHex) {
    jsonError('El contenido del documento fue modificado. Vuelve a solicitar la firma.', 422);
}

// ── Obtener clave pública del usuario ─────────────────────────────────────
$stmt = $pdo->prepare('SELECT certificado_publico FROM usuario_claves WHERE usuario_id = ? AND activo = 1');
$stmt->execute([$user['id']]);
$claveRow = $stmt->fetch();
if (!$claveRow) jsonError('No tienes una clave pública registrada.', 422);

$publicKeyHex = $claveRow['certificado_publico'];

// ── Verificar firma ECDSA P-256 con OpenSSL ───────────────────────────────
$firmaBytes  = hex2bin(strtolower($firma));
$pubKeyBytes = hex2bin(strtolower($publicKeyHex));

// openssl_verify con OPENSSL_ALGO_SHA256 hashea $data internamente.
// El browser firmó SHA256(contenidoAFirmar), así que pasamos el contenido original.
$firmaValida = verificarECDSA($contenidoAFirmar, $firmaBytes, $pubKeyBytes);

if (!$firmaValida) {
    registrarBitacora($user['id'], 'firma_invalida', 'documentos', $docId, null,
        'Firma ECDSA inválida recibida', 'failed', 'La firma no corresponde a la clave pública registrada');
    jsonError('Firma inválida. La firma no corresponde a tu clave pública.', 422);
}

// ── Emitir documento ──────────────────────────────────────────────────────
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

// ── Funciones de verificación ECDSA P-256 ────────────────────────────────
function verificarECDSA(string $data, string $firma, string $publicKey): bool {
    $pubKeyPem = rawPublicKeyToPem($publicKey);
    if (!$pubKeyPem) return false;
    $firmaDer = compactToDer($firma);
    if (!$firmaDer) return false;
    $key = openssl_pkey_get_public($pubKeyPem);
    if (!$key) return false;
    return openssl_verify($data, $firmaDer, $key, OPENSSL_ALGO_SHA256) === 1;
}

function rawPublicKeyToPem(string $rawKey): ?string {
    $len = strlen($rawKey);
    if ($len === 33) {
        // Compressed P-256: SEQUENCE(57) = algoSeq(21) + BITSTRING(34+2)
        $derPrefix = hex2bin('3039' . '3013'
            . '0607' . '2a8648ce3d0201'
            . '0608' . '2a8648ce3d030107'
            . '0322' . '00');
    } elseif ($len === 65) {
        // Uncompressed P-256: SEQUENCE(89) = algoSeq(21) + BITSTRING(66+2)
        $derPrefix = hex2bin('3059' . '3013'
            . '0607' . '2a8648ce3d0201'
            . '0608' . '2a8648ce3d030107'
            . '0342' . '00');
    } else {
        return null;
    }
    $der = $derPrefix . $rawKey;
    return "-----BEGIN PUBLIC KEY-----\n"
         . chunk_split(base64_encode($der), 64, "\n")
         . "-----END PUBLIC KEY-----\n";
}

function compactToDer(string $compact): ?string {
    if (strlen($compact) !== 64) return null;
    $r = substr($compact, 0, 32);
    $s = substr($compact, 32, 32);
    if (ord($r[0]) & 0x80) $r = "\x00" . $r;
    if (ord($s[0]) & 0x80) $s = "\x00" . $s;
    $rLen = strlen($r); $sLen = strlen($s);
    return chr(0x30) . chr(4 + $rLen + $sLen)
         . chr(0x02) . chr($rLen) . $r
         . chr(0x02) . chr($sLen) . $s;
}
