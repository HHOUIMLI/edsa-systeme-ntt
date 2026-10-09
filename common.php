<?php
// Système NTT — fonctions communes (compatible PHP 5.5 et supérieur).
// IMPORTANT : ce fichier ne doit produire aucune sortie (pas d'espace avant <?php).

// ---------------------------------------------------------------------------
// Utilitaires de base
// ---------------------------------------------------------------------------
if (!function_exists('ntt_random_bytes')) {
    function ntt_random_bytes($length) {
        if (function_exists('random_bytes')) {
            return random_bytes($length);
        }
        if (function_exists('openssl_random_pseudo_bytes')) {
            $strong = false;
            $bytes = openssl_random_pseudo_bytes($length, $strong);
            if ($bytes !== false && $strong === true) {
                return $bytes;
            }
        }
        if (function_exists('mcrypt_create_iv') && defined('MCRYPT_DEV_URANDOM')) {
            $bytes = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            if ($bytes !== false && strlen($bytes) === $length) {
                return $bytes;
            }
        }
        throw new RuntimeException(
            'Aucune source aléatoire sécurisée disponible. Activez OpenSSL dans le php.ini utilisé par Apache, puis redémarrez EasyPHP.'
        );
    }
}

// hash_equals() n'existe qu'à partir de PHP 5.6 : version de remplacement.
if (!function_exists('hash_equals')) {
    function hash_equals($a, $b) {
        $a = (string)$a; $b = (string)$b;
        if (strlen($a) !== strlen($b)) return false;
        $res = 0;
        for ($i = 0; $i < strlen($a); $i++) {
            $res |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $res === 0;
    }
}

function ntt_h($s) {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function ntt_strlen($s) {
    return function_exists('mb_strlen') ? mb_strlen($s, 'UTF-8') : strlen($s);
}

if (session_id() === '') {
    session_start();
}

$configFile = __DIR__ . '/config.php';
if (!is_file($configFile)) {
    http_response_code(500);
    exit('Configuration manquante : copiez config.example.php en config.php et renseignez SMTP/MySQL.');
}
$c = require $configFile;

// Compte administrateur créé automatiquement s'il n'en existe aucun.
// Le mot de passe doit être changé à la première connexion.
define('NTT_DEFAULT_ADMIN_USER', 'admin');
define('NTT_DEFAULT_ADMIN_PASS', 'admin2026');
define('NTT_DEFAULT_ADMIN_EMAIL', 'admin@systeme-ntt.local');

// ---------------------------------------------------------------------------
// Base de données + migration automatique
// ---------------------------------------------------------------------------
function db() {
    global $c;
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $d = $c['db'];
    if (strpos($d['host'], 'XXX') !== false || strpos($d['name'], 'XXX') !== false || $d['password'] === 'MOT_DE_PASSE_MYSQL') {
        http_response_code(500);
        exit('Configuration MySQL incomplète : renseignez host, name, user et password dans config.php (valeurs du panneau InfinityFree).');
    }
    try {
        $p = new PDO("mysql:host={$d['host']};dbname={$d['name']};charset={$d['charset']}", $d['user'], $d['password'], array(
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ));
    } catch (PDOException $e) {
        error_log('NTT connexion MySQL : ' . $e->getMessage());
        http_response_code(500);
        $dbg = !empty($c['app']['debug']) ? ' (' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . ')' : '';
        exit('Erreur de base de données. Vérifiez la configuration MySQL dans config.php.' . $dbg);
    }
    ntt_ensure_schema($p);
    $pdo = $p;
    return $pdo;
}

function ntt_ensure_schema($pdo) {
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        email VARCHAR(190) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        email_verified TINYINT(1) NOT NULL DEFAULT 0,
        verification_token_hash CHAR(64) NULL,
        verification_expires DATETIME NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        verified_at DATETIME NULL,
        INDEX idx_verification_token (verification_token_hash)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS settings (
        k VARCHAR(64) NOT NULL PRIMARY KEY,
        v TEXT NULL,
        updated_at DATETIME NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        ident VARCHAR(190) NOT NULL,
        ip VARCHAR(45) NOT NULL,
        attempted_at DATETIME NOT NULL,
        INDEX idx_la_ident (ident, attempted_at),
        INDEX idx_la_ip (ip, attempted_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Colonnes ajoutées pour la gestion des rôles (migration d'une ancienne table).
    $cols = array();
    foreach ($pdo->query('SHOW COLUMNS FROM users') as $r) {
        $cols[$r['Field']] = true;
    }
    $add = array(
        'verified_at'          => 'ADD COLUMN verified_at DATETIME NULL',
        'username'             => 'ADD COLUMN username VARCHAR(60) NULL',
        'role'                 => "ADD COLUMN role VARCHAR(10) NOT NULL DEFAULT 'user'",
        'is_active'            => 'ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1',
        'must_change_password' => 'ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 0',
        'last_login'           => 'ADD COLUMN last_login DATETIME NULL'
    );
    foreach ($add as $col => $ddl) {
        if (!isset($cols[$col])) {
            $pdo->exec('ALTER TABLE users ' . $ddl);
            if ($col === 'username') {
                try { $pdo->exec('ALTER TABLE users ADD UNIQUE INDEX uq_username (username)'); }
                catch (Exception $e) { /* index déjà présent */ }
            }
        }
    }

    // Création du compte administrateur par défaut s'il n'y en a aucun.
    $q = $pdo->query("SELECT id FROM users WHERE role='admin' LIMIT 1");
    if (!$q->fetch()) {
        $st = $pdo->prepare("INSERT INTO users
            (name, username, email, password_hash, email_verified, role, is_active, must_change_password, created_at, verified_at)
            VALUES ('Administrateur', ?, ?, ?, 1, 'admin', 1, 1, NOW(), NOW())");
        try {
            $st->execute(array(NTT_DEFAULT_ADMIN_USER, NTT_DEFAULT_ADMIN_EMAIL, password_hash(NTT_DEFAULT_ADMIN_PASS, PASSWORD_DEFAULT)));
        } catch (Exception $e) {
            error_log('NTT: création du compte admin impossible : ' . $e->getMessage());
        }
    }
}

// ---------------------------------------------------------------------------
// Paramètres (table settings) et chiffrement du mot de passe SMTP
// ---------------------------------------------------------------------------
function ntt_settings($reload = false) {
    static $cache = null;
    if ($cache === null || $reload) {
        $cache = array();
        foreach (db()->query('SELECT k, v FROM settings') as $r) {
            $cache[$r['k']] = $r['v'];
        }
    }
    return $cache;
}

function ntt_setting($key, $default = '') {
    $s = ntt_settings();
    return (array_key_exists($key, $s) && $s[$key] !== null) ? $s[$key] : $default;
}

function ntt_set_setting($key, $value) {
    $q = db()->prepare('INSERT INTO settings (k, v, updated_at) VALUES (?, ?, NOW())
                        ON DUPLICATE KEY UPDATE v = VALUES(v), updated_at = NOW()');
    $q->execute(array($key, (string)$value));
    ntt_settings(true);
}

function ntt_secret_key() {
    global $c;
    $k = isset($c['app']['secret_key']) ? (string)$c['app']['secret_key'] : '';
    if (strlen($k) < 16) {
        // Repli : clé dérivée de la configuration locale (ajoutez app.secret_key dans config.php).
        $k = 'ntt|' . $c['db']['name'] . '|' . $c['db']['password'] . '|' . __DIR__;
    }
    return hash('sha256', $k, true);
}

function ntt_encrypt($plain) {
    $plain = (string)$plain;
    if ($plain === '') return '';
    if (!function_exists('openssl_encrypt')) {
        return 'plain:' . base64_encode($plain);
    }
    $key = ntt_secret_key();
    $iv = ntt_random_bytes(16);
    $ct = openssl_encrypt($plain, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    $mac = hash_hmac('sha256', $iv . $ct, $key, true);
    return 'v1:' . base64_encode($iv . $mac . $ct);
}

function ntt_decrypt($stored) {
    $stored = (string)$stored;
    if ($stored === '') return '';
    if (strpos($stored, 'plain:') === 0) {
        return (string)base64_decode(substr($stored, 6));
    }
    if (strpos($stored, 'v1:') !== 0 || !function_exists('openssl_decrypt')) return '';
    $raw = base64_decode(substr($stored, 3), true);
    if ($raw === false || strlen($raw) < 49) return '';
    $iv = substr($raw, 0, 16);
    $mac = substr($raw, 16, 32);
    $ct = substr($raw, 48);
    $key = ntt_secret_key();
    if (!hash_equals(hash_hmac('sha256', $iv . $ct, $key, true), $mac)) return '';
    $p = openssl_decrypt($ct, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return ($p === false) ? '' : $p;
}

// ---------------------------------------------------------------------------
// SMTP / PHPMailer
// ---------------------------------------------------------------------------
// Configuration SMTP effective : réglages enregistrés par l'administrateur,
// sinon valeurs de config.php.
function ntt_smtp_config() {
    global $c;
    $defaults = array(
        'host' => 'smtp.gmail.com', 'port' => 587, 'encryption' => 'tls',
        'username' => '', 'password' => '', 'from_email' => '', 'from_name' => 'Système NTT'
    );
    $s = array_merge($defaults, isset($c['smtp']) && is_array($c['smtp']) ? $c['smtp'] : array());
    if (ntt_setting('smtp_configured', '0') === '1') {
        $s['host']       = ntt_setting('smtp_host', $s['host']);
        $s['port']       = (int)ntt_setting('smtp_port', $s['port']);
        $s['encryption'] = ntt_setting('smtp_encryption', $s['encryption']);
        $s['username']   = ntt_setting('smtp_username', $s['username']);
        $s['from_email'] = ntt_setting('smtp_from_email', $s['from_email']);
        $s['from_name']  = ntt_setting('smtp_from_name', $s['from_name']);
        $s['password']   = ntt_decrypt(ntt_setting('smtp_password', ''));
    }
    $s['password'] = str_replace(array(' ', "\xC2\xA0"), '', (string)$s['password']);
    $s['verify_peer'] = (ntt_setting('smtp_verify_peer', '1') === '1');
    return $s;
}

function ntt_smtp_ready($s, &$why) {
    if (!extension_loaded('openssl')) {
        $why = 'Extension PHP openssl désactivée : ouvrez le php.ini utilisé par Apache/EasyPHP, activez extension=openssl (retirez le « ; »), puis redémarrez le serveur.';
        return false;
    }
    if (!filter_var($s['from_email'], FILTER_VALIDATE_EMAIL)) {
        $why = 'Adresse expéditeur SMTP invalide : renseignez-la dans Administration → SMTP Gmail.';
        return false;
    }
    if ($s['host'] === '' || strpos($s['host'], 'example.com') !== false) {
        $why = 'Serveur SMTP non configuré : Administration → SMTP Gmail.';
        return false;
    }
    if ($s['username'] === '' || $s['password'] === '' || strpos($s['password'], 'COLLEZ_ICI') === 0) {
        $why = 'Identifiant ou mot de passe d’application SMTP manquant : Administration → SMTP Gmail.';
        return false;
    }
    return true;
}

function ntt_load_phpmailer() {
    $candidates = array(
        __DIR__ . '/phpmailer/src/',
        __DIR__ . '/PHPMailer/src/',
        __DIR__ . '/phpmailer/',
        __DIR__ . '/PHPMailer/',
        __DIR__ . '/src/',
        __DIR__ . '/'
    );
    foreach ($candidates as $dir) {
        if (is_file($dir . 'Exception.php') && is_file($dir . 'PHPMailer.php') && is_file($dir . 'SMTP.php')) {
            require_once $dir . 'Exception.php';
            require_once $dir . 'PHPMailer.php';
            require_once $dir . 'SMTP.php';
            return true;
        }
    }
    throw new RuntimeException('PHPMailer introuvable. Placez Exception.php, PHPMailer.php et SMTP.php dans : ' . __DIR__ . DIRECTORY_SEPARATOR . 'phpmailer' . DIRECTORY_SEPARATOR . 'src');
}

function ntt_build_mailer($s) {
    ntt_load_phpmailer();
    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = $s['host'];
    $mail->SMTPAuth = true;
    $mail->Username = $s['username'];
    $mail->Password = $s['password'];
    $mail->Port = (int)$s['port'];
    $mail->SMTPSecure = ($s['encryption'] === 'ssl')
        ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS
        : PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Timeout = 20;
    $mail->CharSet = 'UTF-8';
    if (empty($s['verify_peer'])) {
        // À n'utiliser qu'en local si Windows/EasyPHP n'a pas de certificats racine.
        $mail->SMTPOptions = array('ssl' => array(
            'verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true
        ));
    }
    $mail->setFrom($s['from_email'], $s['from_name']);
    return $mail;
}

// Masque les identifiants dans le journal SMTP affiché à l'administrateur.
function ntt_redact_smtp($line, $password) {
    if ($password !== '') {
        $line = str_replace($password, '********', $line);
    }
    $line = preg_replace('/(AUTH (?:PLAIN|XOAUTH2)\s+)\S+/', '$1[masqué]', $line);
    if (preg_match('/CLIENT -> SERVER:\s*([A-Za-z0-9+\/]{8,}={0,2})\s*$/', $line, $m) && $m[1] !== 'STARTTLS') {
        $line = preg_replace('/(CLIENT -> SERVER:\s*)[A-Za-z0-9+\/]{8,}={0,2}/', '$1[masqué]', $line);
    }
    return $line;
}

function ntt_send_confirmation($email, $name, $token) {
    global $c;
    $s = ntt_smtp_config();
    $why = '';
    if (!ntt_smtp_ready($s, $why)) {
        throw new RuntimeException($why);
    }
    $mail = ntt_build_mailer($s);
    $mail->addAddress($email, $name);
    $url = rtrim($c['app']['base_url'], '/') . '/verify.php?token=' . rawurlencode($token);
    $safeName = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safeUrl = htmlspecialchars($url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $mail->isHTML(true);
    $mail->Subject = 'Confirmez votre inscription — Système NTT';
    $mail->Body = "<p>Bonjour {$safeName},</p><p>Pour confirmer votre adresse e-mail et activer votre compte Système NTT, cliquez sur le lien suivant :</p><p><a href=\"{$safeUrl}\">Confirmer mon adresse e-mail</a></p><p>Ce lien expire dans 24 heures. Si vous n’êtes pas à l’origine de cette demande, ignorez ce message.</p>";
    $mail->AltBody = "Bonjour $name,\nConfirmez votre adresse e-mail avec ce lien (valable 24 heures) : $url";
    $mail->send();
}

// Génère un nouveau jeton de confirmation (24 h) pour un compte et le retourne.
function ntt_new_verification($pdo, $userId) {
    $token = bin2hex(ntt_random_bytes(32));
    $q = $pdo->prepare('UPDATE users SET verification_token_hash=?, verification_expires=DATE_ADD(NOW(), INTERVAL 24 HOUR) WHERE id=?');
    $q->execute(array(hash('sha256', $token), (int)$userId));
    return $token;
}

// ---------------------------------------------------------------------------
// Sessions, rôles, CSRF
// ---------------------------------------------------------------------------
function ntt_go($message, $where = 'login.php') {
    $_SESSION['ntt_flash'] = $message;
    header('Location: ' . $where);
    exit;
}

function ntt_clear_session_user() {
    foreach (array('ntt_user_id', 'ntt_user_name', 'ntt_user_email', 'ntt_email_verified', 'ntt_role') as $k) {
        unset($_SESSION[$k]);
    }
}

function ntt_fetch_user($id) {
    $q = db()->prepare('SELECT id, name, username, email, role, email_verified, is_active, must_change_password FROM users WHERE id=? LIMIT 1');
    $q->execute(array((int)$id));
    return $q->fetch();
}

// $need : 'app' (application), 'admin' (administration) ou 'account' (changement de mot de passe).
function ntt_require_login($need) {
    $u = null;
    try {
        if (!empty($_SESSION['ntt_user_id'])) {
            $u = ntt_fetch_user($_SESSION['ntt_user_id']);
        }
    } catch (Exception $e) {
        error_log('NTT session check error: ' . $e->getMessage());
        http_response_code(500);
        exit('Erreur de base de données. Vérifiez la configuration MySQL.');
    }
    if (!$u) {
        ntt_clear_session_user();
        ntt_go('Veuillez vous connecter.');
    }
    if (!(int)$u['is_active']) {
        ntt_clear_session_user();
        ntt_go('Ce compte est désactivé. Contactez l’administrateur.');
    }
    if (!(int)$u['email_verified']) {
        ntt_clear_session_user();
        ntt_go('Confirmez votre adresse e-mail avant de vous connecter.');
    }
    $_SESSION['ntt_role'] = $u['role'];
    $_SESSION['ntt_user_name'] = $u['name'];
    $_SESSION['ntt_user_email'] = $u['email'];
    $_SESSION['ntt_email_verified'] = true;

    if ($need === 'admin' && $u['role'] !== 'admin') {
        header('Location: index.php');
        exit;
    }
    if ($need === 'app' && $u['role'] === 'visitor') {
        ntt_clear_session_user();
        ntt_go('Compte visiteur : l’accès à l’application sera ouvert dès que l’administrateur vous attribuera le rôle Utilisateur.');
    }
    if ($need !== 'account' && (int)$u['must_change_password']) {
        header('Location: account.php');
        exit;
    }
    return $u;
}

function ntt_csrf() {
    if (empty($_SESSION['ntt_csrf'])) {
        $_SESSION['ntt_csrf'] = bin2hex(ntt_random_bytes(16));
    }
    return $_SESSION['ntt_csrf'];
}

function ntt_csrf_valid() {
    $t = isset($_POST['csrf']) ? (string)$_POST['csrf'] : '';
    return !empty($_SESSION['ntt_csrf']) && hash_equals($_SESSION['ntt_csrf'], $t);
}

// ---------------------------------------------------------------------------
// Limitation des tentatives de connexion
// ---------------------------------------------------------------------------
function ntt_login_blocked($pdo, $ident, $ip) {
    $q = $pdo->prepare('SELECT COUNT(*) FROM login_attempts WHERE ident=? AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)');
    $q->execute(array($ident));
    if ((int)$q->fetchColumn() >= 5) return true;
    $q = $pdo->prepare('SELECT COUNT(*) FROM login_attempts WHERE ip=? AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)');
    $q->execute(array($ip));
    return ((int)$q->fetchColumn() >= 30);
}

function ntt_login_fail($pdo, $ident, $ip) {
    $q = $pdo->prepare('INSERT INTO login_attempts (ident, ip, attempted_at) VALUES (?, ?, NOW())');
    $q->execute(array(substr($ident, 0, 190), substr($ip, 0, 45)));
    $pdo->exec('DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 1 DAY)');
}

function ntt_login_clear($pdo, $ident) {
    $q = $pdo->prepare('DELETE FROM login_attempts WHERE ident=?');
    $q->execute(array(substr($ident, 0, 190)));
}
