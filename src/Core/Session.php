<?php
declare(strict_types=1);

namespace Core;

/**
 * Única puerta de acceso a la sesión.
 * Ninguna otra clase llama a session_start() ni toca $_SESSION.
 */
final class Session
{
    // Tiempo máximo que puede pasar sin que el usuario haga ninguna petición
    // Valor para pruebas (segundos). En producción sería mucho mayor.
    private const INACTIVIDAD_MAX = 60;

    // ---------- Etapa 1 y 4: arranque ----------
    public static function iniciar(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        // Etapa 4 (Exp. A - fijación de sesión):
        // - use_strict_mode: PHP rechaza IDs que él no ha generado (un atacante
        //   no puede "inventar" un PHPSESSID y forzar a la víctima a usarlo).
        // - use_only_cookies: el ID solo viaja en la cookie, nunca en la URL.
        // - use_trans_sid: PHP no añade el ID a los enlaces (?PHPSESSID=...).
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');

        // Etapa 4 (Exp. B - robo de cookie con JavaScript):
        // 'secure' solo si la petición llega por HTTPS; si no, en local
        // (http://localhost) el navegador no enviaría la cookie.
        $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

        session_set_cookie_params([
            'lifetime' => 0,          // cookie de sesión: muere al cerrar el navegador
            'path'     => '/',
            'secure'   => $https,     // solo por HTTPS (cuando lo haya)
            'httponly' => true,       // document.cookie NO puede leerla
            'samesite' => 'Lax',      // no se envía en peticiones POST de otros sitios
        ]);

        session_start();
    }

    // ---------- Etapa 1: métodos básicos ----------
    public static function get(string $clave, mixed $defecto = null): mixed
    {
        return $_SESSION[$clave] ?? $defecto;
    }

    public static function set(string $clave, mixed $valor): void
    {
        $_SESSION[$clave] = $valor;
    }

    public static function has(string $clave): bool
    {
        return isset($_SESSION[$clave]);
    }

    public static function remove(string $clave): void
    {
        unset($_SESSION[$clave]);
    }

    // ---------- Etapa 1 y 2: cierre de sesión ----------
    public static function destruir(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return;
        }

        // 1) Vaciar los datos de la sesión en memoria
        $_SESSION = [];

        // 2) Borrar la cookie del navegador (misma configuración con la que se creó
        //    y fecha en el pasado para que el navegador la elimine)
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires'  => time() - 42000,
                'path'     => $p['path'],
                'domain'   => $p['domain'],
                'secure'   => $p['secure'],
                'httponly' => $p['httponly'],
                'samesite' => $p['samesite'],
            ]);
        }

        // 3) Borrar el fichero de sesión del servidor
        session_destroy();
    }

    // ---------- Etapa 4: regeneración del ID ----------
    public static function regenerar(): void
    {
        // Nuevo ID y borrado del antiguo (true): el ID que conociera un
        // atacante antes del login deja de servir.
        session_regenerate_id(true);
    }

    // ---------- Etapa 5: mensajes flash ----------
    public static function setFlash(string $clave, string $mensaje): void
    {
        $_SESSION['_flash'][$clave] = $mensaje;
    }

    public static function getFlash(string $clave): ?string
    {
        $mensaje = $_SESSION['_flash'][$clave] ?? null;
        unset($_SESSION['_flash'][$clave]);   // se lee una sola vez

        if (empty($_SESSION['_flash'])) {
            unset($_SESSION['_flash']);
        }

        return $mensaje;
    }

    // ---------- Etapa 6: caducidad por inactividad ----------
    public static function comprobarCaducidad(): void
    {
        // Solo afecta a usuarios autenticados
        if (!self::has('user_id')) {
            return;
        }

        $ultima = (int) self::get('ultima_actividad', time());

        if (time() - $ultima > self::INACTIVIDAD_MAX) {
            // 1) Destruir la sesión caducada (datos, cookie y fichero)
            self::destruir();
            // 2) Abrir una sesión nueva y vacía: sin ella no hay dónde guardar el flash
            self::iniciar();
            // 3) Avisar al usuario
            self::setFlash('error', 'Tu sesión ha caducado por inactividad');
            // 4) Llevarlo al login
            redirect('login');
        }

        // Sigue activo: se renueva la marca de tiempo
        self::set('ultima_actividad', time());
    }
}
