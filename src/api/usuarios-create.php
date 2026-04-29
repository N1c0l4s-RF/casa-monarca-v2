<?php
require_once __DIR__ . '/../auth/middleware.php';
require_once __DIR__ . '/../modules/usuarios.php';
require_once __DIR__ . '/../modules/bitacora.php';

setSecurityHeaders();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonError('Método no permitido', 405);
}

$user = requireAuth();
requireRole($user, ['administrador']);

$body = getJsonBody();

if (empty($body['nombre'])) jsonError('El nombre es requerido');
if (empty($body['email'])) jsonError('El email es requerido');
if (empty($body['password'])) jsonError('La contraseña es requerida');
if (empty($body['rol'])) jsonError('El rol es requerido');

if (!filter_var($body['email'], FILTER_VALIDATE_EMAIL)) {
    jsonError('Email inválido');
}

if (strlen($body['password']) < 6) {
    jsonError('La contraseña debe tener al menos 6 caracteres');
}

try {
    $pdo = getDB();

    // Verificar que el email no existe
    $stmt = $pdo->prepare('SELECT id FROM usuarios WHERE email = ?');
    $stmt->execute([$body['email']]);
    if ($stmt->fetch()) {
        jsonError('El email ya está registrado', 400);
    }

    // Crear usuario
    $passwordHash = password_hash($body['password'], PASSWORD_BCRYPT, ['cost' => 10]);
    $stmt = $pdo->prepare('
        INSERT INTO usuarios (nombre, email, password_hash, rol, activo)
        VALUES (?, ?, ?, ?, 1)
    ');
    $stmt->execute([
        $body['nombre'],
        $body['email'],
        $passwordHash,
        $body['rol'],
    ]);

    $newUserId = (int)$pdo->lastInsertId();

    registrarBitacora((int)$user['id'], 'created', 'usuarios', null, null, "Usuario creado: {$body['nombre']} ({$body['email']}) con rol {$body['rol']}");

    jsonSuccess('Usuario creado exitosamente', ['usuario_id' => $newUserId], 201);

} catch (\RuntimeException $e) {
    jsonError($e->getMessage(), 400);
}
