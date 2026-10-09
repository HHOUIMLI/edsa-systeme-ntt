<?php
// Copiez ce fichier sous le nom config.php puis renseignez vos paramètres.
// Ne publiez jamais ce fichier dans un dépôt public.
return [
  'db' => [
    'host' => '127.0.0.1',
    'name' => 'systeme_ntt',
    'user' => 'root',
    'password' => '',
    'charset' => 'utf8mb4',
  ],
  'app' => [
    // URL publique du dossier, sans slash final. Exemple : https://votre-domaine.tn/systeme-ntt
    'base_url' => 'http://localhost/systeme-ntt',
    'session_name' => 'SYSTEME_NTT_SESSION',
  ],
'smtp' => [
    'host' => 'smtp.gmail.com',
    'port' => 587,
    'encryption' => 'tls',
    'username' => 'userhhouimli@gmail.com',
    'password' => 'VOTRE@admin2026',
    'from_email' => 'userhhouimli@gmail.com',
    'from_name' => 'Système NTT',
],
];
