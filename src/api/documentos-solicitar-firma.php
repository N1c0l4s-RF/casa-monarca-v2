<?php
/**
 * POST /api/documentos-solicitar-firma.php
 * Paso 1: calcula SHA-256(folio|contenido) y lo guarda en firma_sessions (DB).
 * Body: { "id": 42 }
 * Response: { "hash": "hex_sha256...", "session_id": N }
 */
require_once __DIR__ . '/../auth/middleware.php';
require_once __DIR__ . '/../modules/bitacora.php';

setSecurityHeaders();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonError('Método no permitido', 405);
$user = requireAuth();
requireRole($user, ['administrador', 'supervisor', 'emisor']);

$body = getJsonBody();
$docId = (int)($body['id'] ?? 0);
if (!$docId) jsonError('id es requerido');

$pdo  = getDB();
$stmt = $pdo->prepare('SELECT id, folio, contenido, estado FROM documentos WHERE id = ?');
$stmt->execute([$docId]);
$doc = $stmt->fetch();

if (!$doc) jsonError('Documento no encontrado', 404);
if ($doc['estado'] !== 'borrador') jsonError('Solo se pueden emitir documentos en borrador', 400);

// Verificar que el usuario tiene clave pública registrada
$clave = $pdo->prepare('SELECT fingerprint FROM usuario_claves WHERE usuario_id = ? AND activo = 1');
$clave->execute([$user['id']]);
if (!$clave->fetch()) {
    jsonError('No tienes una clave pública registrada. Ve a Gestión de Llaves primero.', 422);
}

// Calcular hash
$contenidoAFirmar = $doc['folio'] . '|' . $doc['contenido'];
$hashHex = hash('sha256', $contenidoAFirmar);

// Guardar en firma_sessions (válida 10 minutos)
// Limpiar sesiones previas del mismo usuario+documento
$pdo->prepare('DELETE FROM firma_sessions WHERE usuario_id = ? AND documento_id = ?')
    ->execute([$user['id'], $docId]);

$ins = $pdo->prepare('
    INSERT INTO firma_sessions (usuario_id, documento_id, hash_hex, expires_at)
    VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))
');
$ins->execute([$user['id'], $docId, $hashHex]);
$sessionId = $pdo->lastInsertId();

jsonSuccess('Hash listo para firmar', [
    'hash'       => $hashHex,
    'session_id' => (int)$sessionId,
    'folio'      => $doc['folio'],
    'algoritmo'  => 'ECDSA P-256 + SHA-256',
]);
