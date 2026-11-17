<?php
declare(strict_types=1);

namespace Controllers;

use Core\Pages;
use Core\Session;
use Models\UserModel;

/**
 * Autenticación: comprueba credenciales y abre/cierra la sesión.
 * NO es el controlador de UserModel (para eso está UserController).
 */
final class AuthController
{
    // Hash de relleno: si el correo no existe se verifica contra él para que
    // la respuesta tarde lo mismo que con un correo real (no se filtra qué
    // correos están registrados midiendo tiempos).
    private const HASH_FALSO = '$2y$10$X.sLvISy80uyYlgByzTVMuTd8YBgB9AvhD8JlQGkZIP1fYuSW.uHy';

    // Etapa 5: se leen los flash y se pasan a la vista (la vista no accede a Session).
    public function showLogin(): void
    {
        // Si ya hay sesión abierta, no tiene sentido volver a identificarse
        if (Session::has('user_id')) {
            redirect('perfil');
        }

        (new Pages())->render('auth/login', [
            'error' => Session::getFlash('error'),
            'info'  => Session::getFlash('info'),
        ]);
    }

    public function login(): void
    {
        $email    = trim((string) ($_POST['email'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');

        $usuario = (new UserModel())->findByEmail($email);

        // Siempre se ejecuta password_verify (exista o no el usuario)
        $hash   = $usuario['hash'] ?? self::HASH_FALSO;
        $valido = password_verify($password, $hash) && $usuario !== null;

        if (!$valido) {
            // Mismo mensaje si el correo no existe o si la contraseña es incorrecta
            Session::setFlash('error', 'Correo o contraseña incorrectos');
            redirect('login');
        }

        // Etapa 4: nuevo ID de sesión ANTES de guardar al usuario (evita la fijación)
        Session::regenerar();

        Session::set('user_id', $usuario['id']);
        Session::set('ultima_actividad', time());

        redirect('perfil');
    }

    public function logout(): void
    {
        Session::destruir();

        // Para dejar un flash hace falta una sesión (nueva y vacía)
        Session::iniciar();
        Session::setFlash('info', 'Has cerrado sesión correctamente');

        redirect('login');
    }
}
