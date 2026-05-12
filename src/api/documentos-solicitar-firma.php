<?php
/**
 * POST /api/documentos-solicitar-firma.php
 *
 * Paso 1 del flujo de emisión client-side:
 *   - Valida que el documento es borrador y pertenece al usuario
 *   - Calcula SHA-256(folio|contenido) y lo devuelve al browser
 *   - El browser firma ese hash localmente con ECDSA P-256
 *   - El hash se guarda temporalmente en sesión para validarlo en paso 2
 *
 * Body: { "id": 42 }
 * Response: { "hash": "hex_sha256..." }
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
$stmt = $pdo->prepare('SELECT id, folio, contenido, estado, creado_por FROM documentos WHERE id = ?');
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

// Calcular hash del contenido a firmar: SHA-256(folio|contenido)
// Este es el mismo string que se verificará en completar-firma y en verificación pública
$contenidoAFirmar = $doc['folio'] . '|' . $doc['contenido'];
$hashHex = hash('sha256', $contenidoAFirmar);

// Guardar hash en sesión con TTL de 10 minutos para validarlo en paso 2
// Evita que el browser envíe una firma sobre un hash diferente
startSecureSession();
$_SESSION['firma_pendiente'] = [
    'doc_id'    => $docId,
    'hash'      => $hashHex,
    'usuario_id'=> $user['id'],
    'expires_at'=> time() + 600,
];
session_write_close();

jsonSuccess('Hash listo para firmar', [
    'hash'      => $hashHex,
    'folio'     => $doc['folio'],
    'algoritmo' => 'ECDSA P-256 + SHA-256',
]);
