-- Casa Monarca v2 - Migration 001: Datos iniciales
USE casa_monarca;

-- Admin por defecto: admin@empresa.local / admin123
-- password_hash = bcrypt("admin123") con cost 10
INSERT INTO usuarios (nombre, email, password_hash, rol, activo)
VALUES (
    'Administrador',
    'admin@empresa.local',
    '$2y$10$lvMB2zhRbYMGzkERcVkRc.IgTYtpVGJ0SLJLTkEedrmR12xenh9fO',
    'administrador',
    1
) ON DUPLICATE KEY UPDATE id=id;
