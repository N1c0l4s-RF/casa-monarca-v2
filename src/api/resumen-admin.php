<?php
/**
 * GET /api/resumen-admin.php
 * Resumen ejecutivo de actividad para administradores y supervisores.
 */
require_once __DIR__ . '/../auth/middleware.php';
setSecurityHeaders();
$user = requireAuth();
requireRole($user, ['administrador', 'supervisor']);

$pdo = getDB();

// ── Contadores de documentos ──────────────────────────────────────────────
$docStats = $pdo->query("
    SELECT
        COUNT(*)                                          AS total,
        SUM(estado = 'emitido')                          AS emitidos,
        SUM(estado = 'borrador')                         AS borradores,
        SUM(estado = 'revocado')                         AS revocados,
        SUM(estado = 'emitido' AND DATE(fecha_emision) = CURDATE()) AS emitidos_hoy,
        SUM(estado = 'revocado' AND DATE(fecha_revocacion) = CURDATE()) AS revocados_hoy
    FROM documentos
")->fetch();

// ── Actividad por usuario (top firmantes) ────────────────────────────────
$topFirmantes = $pdo->query("
    SELECT u.nombre, u.rol,
           COUNT(*) AS total_firmas
    FROM documentos d
    JOIN usuarios u ON u.id = d.firmado_por_usuario_id
    WHERE d.estado = 'emitido'
    GROUP BY u.id
    ORDER BY total_firmas DESC
    LIMIT 5
")->fetchAll();

// ── Firmas fallidas ──────────────────────────────────────────────────────
$firmasFallidas = (int)$pdo->query("
    SELECT COUNT(*) FROM bitacora
    WHERE accion = 'firma_invalida' AND resultado = 'failed'
")->fetchColumn();

$firmasFallidasHoy = (int)$pdo->query("
    SELECT COUNT(*) FROM bitacora
    WHERE accion = 'firma_invalida' AND resultado = 'failed'
      AND DATE(fecha) = CURDATE()
")->fetchColumn();

// ── Últimos 60 eventos de bitácora con nombre de usuario ─────────────────
$eventos = $pdo->query("
    SELECT b.id, b.accion, b.modulo, b.documento_folio,
           b.descripcion, b.resultado, b.motivo_fallo,
           b.ip_address, b.fecha,
           u.nombre AS usuario_nombre, u.rol AS usuario_rol
    FROM bitacora b
    LEFT JOIN usuarios u ON u.id = b.usuario_id
    ORDER BY b.fecha DESC
    LIMIT 60
")->fetchAll();

// ── Actividad últimos 7 días (por día) ───────────────────────────────────
$porDia = $pdo->query("
    SELECT DATE(fecha) AS dia,
           SUM(accion = 'emitted')  AS emitidos,
           SUM(accion = 'revoked')  AS revocados,
           SUM(accion = 'created')  AS creados
    FROM bitacora
    WHERE fecha >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
    GROUP BY DATE(fecha)
    ORDER BY dia ASC
")->fetchAll();

jsonSuccess('Resumen obtenido', [
    'documentos'       => $docStats,
    'top_firmantes'    => $topFirmantes,
    'firmas_fallidas'  => $firmasFallidas,
    'firmas_fallidas_hoy' => $firmasFallidasHoy,
    'eventos'          => $eventos,
    'actividad_semana' => $porDia,
]);
