<?php
// Ne publiez jamais ce fichier dans un dépôt public.
// Détection automatique : réglages locaux (EasyPHP) ou réglages du serveur InfinityFree.
$host = isset($_SERVER['HTTP_HOST']) ? strtolower($_SERVER['HTTP_HOST']) : 'localhost';
$isLocal = (strpos($host, 'localhost') === 0 || strpos($host, '127.0.0.1') === 0);

if ($isLocal) {
    $db = array(
        'host' => '127.0.0.1',
        'name' => 'systeme_ntt',
        'user' => 'root',
        'password' => '',
        'charset' => 'utf8mb4',
    );
    $baseUrl = 'http://127.0.0.1:8000/edsa-systeme-ntt/edsa-systeme-ntt';
} else {
    // A REMPLACER par les valeurs du panneau InfinityFree (MySQL Databases).
    $db = array(
        'host' => 'sqlXXX.infinityfree.com',
        'name' => 'if0_XXXXXXXX_ntt',
        'user' => 'if0_XXXXXXXX',
        'password' => 'MOT_DE_PASSE_MYSQL',
        'charset' => 'utf8mb4',
    );
    $baseUrl = 'http://ntt.infinityfree.me';
}

return [
  'db' => $db,
  'app' => [
    // URL du dossier qui contient verify.php, sans slash final.
    'base_url' => $baseUrl,
    'session_name' => 'SYSTEME_NTT_SESSION',
    // Clé servant à chiffrer le mot de passe SMTP enregistré en base. Ne la changez pas après usage.
    'secret_key' => '29a0e3f4a1859dd26f88b8ebdf07b8c3999aac89e4e62da7784a03a8fb3486c6',
    // true = affiche la cause exacte des erreurs (à garder false en ligne).
    'debug' => $isLocal,
  ],
  'smtp' => [
    'host' => 'smtp.gmail.com',
    'port' => 587,
    'encryption' => 'tls',
    'username' => 'userhhouimli@gmail.com',
    // Mot de passe D'APPLICATION Google (16 lettres, sans espaces), PAS le mot de passe du compte.
    'password' => 'azertyuiopqsdfgh',
    'from_email' => 'userhhouimli@gmail.com',
    'from_name' => 'Système NTT',
  ],
];
