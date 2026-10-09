<?php
require_once __DIR__ . '/common.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: login.php'); exit; }
$action = (isset($_POST['action']) ? $_POST['action'] : '');

try {
  // -------------------------------------------------------------- INSCRIPTION
  if ($action === 'register') {
    if (ntt_setting('registration_mode', 'open') !== 'open') {
      ntt_go('Les inscriptions sont actuellement fermées. Contactez l’administrateur.');
    }
    $name = trim((string)((isset($_POST['name']) ? $_POST['name'] : '')));
    $email = strtolower(trim((string)((isset($_POST['email']) ? $_POST['email'] : ''))));
    $password = (string)((isset($_POST['password']) ? $_POST['password'] : ''));
    $confirm = (string)((isset($_POST['password_confirm']) ? $_POST['password_confirm'] : ''));
    if ($name === '' || ntt_strlen($name) > 120 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190) ntt_go('Veuillez vérifier le nom et l’adresse e-mail.');
    if (strlen($password) < 12) ntt_go('Le mot de passe doit contenir au moins 12 caractères.');
    if (!hash_equals($password, $confirm)) ntt_go('Les deux mots de passe ne correspondent pas.');
    $pdo = db();
    $q = $pdo->prepare('SELECT id FROM users WHERE email=?'); $q->execute(array($email));
    if ($q->fetch()) ntt_go('Cette adresse e-mail possède déjà un compte.');

    $role = ntt_setting('default_role', 'user');
    if ($role !== 'user' && $role !== 'visitor') $role = 'user';
    $needVerify = (ntt_setting('require_email_verification', '1') === '1');
    $verified = $needVerify ? 0 : 1;

    $hash = password_hash($password, PASSWORD_DEFAULT);
    $q = $pdo->prepare('INSERT INTO users (name,email,password_hash,email_verified,role,is_active,created_at,verified_at) VALUES (?,?,?,?,?,1,NOW(),IF(?=1,NOW(),NULL))');
    $q->execute(array($name, $email, $hash, $verified, $role, $verified));
    $userId = (int)$pdo->lastInsertId();

    if (!$needVerify) {
      ntt_go('Compte créé. Vous pouvez maintenant vous connecter.');
    }

    $mailError = null;
    try {
      $token = ntt_new_verification($pdo, $userId);
      ntt_send_confirmation($email, $name, $token);
    }
    catch (Exception $e) { $mailError = $e; }      // PHP 5 et 7
    catch (Throwable $e) { $mailError = $e; }      // PHP 7+ uniquement (ignoré sur PHP 5)

    if ($mailError !== null) {
      $q = $pdo->prepare('DELETE FROM users WHERE id=? AND email_verified=0'); $q->execute(array($userId));
      error_log('NTT mail error: ' . $mailError->getMessage());
      if (!empty($c['app']['debug'])) {
        ntt_go('Inscription non terminée (diagnostic) : ' . $mailError->getMessage());
      }
      ntt_go('Inscription non terminée : l’envoi d’e-mail est indisponible. Prévenez l’administrateur (Administration → SMTP Gmail).');
    }
    ntt_go('Compte créé. Consultez votre boîte e-mail et cliquez sur le lien de confirmation.');
  }

  // --------------------------------------------------------------- CONNEXION
  if ($action === 'login') {
    $raw = isset($_POST['login']) ? $_POST['login'] : (isset($_POST['email']) ? $_POST['email'] : '');
    $ident = strtolower(trim((string)$raw));
    $password = (string)((isset($_POST['password']) ? $_POST['password'] : ''));
    if ($ident === '' || $password === '') ntt_go('Identifiant ou mot de passe incorrect.');
    $ip = isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';

    $pdo = db();
    if (ntt_login_blocked($pdo, $ident, $ip)) {
      ntt_go('Trop de tentatives échouées. Réessayez dans 15 minutes.');
    }
    $q = $pdo->prepare('SELECT id,name,username,email,password_hash,email_verified,role,is_active,must_change_password FROM users WHERE email=? OR username=? LIMIT 1');
    $q->execute(array($ident, $ident)); $u = $q->fetch();
    if (!$u || !password_verify($password, $u['password_hash'])) {
      ntt_login_fail($pdo, $ident, $ip);
      ntt_go('Identifiant ou mot de passe incorrect.');
    }
    if (!(int)$u['is_active']) ntt_go('Ce compte est désactivé. Contactez l’administrateur.');
    if (!(int)$u['email_verified']) ntt_go('Confirmez votre adresse e-mail avant de vous connecter.');
    if ($u['role'] === 'visitor') ntt_go('Compte visiteur confirmé : l’accès à l’application sera ouvert dès que l’administrateur vous attribuera le rôle Utilisateur.');

    ntt_login_clear($pdo, $ident);
    $q = $pdo->prepare('UPDATE users SET last_login=NOW() WHERE id=?'); $q->execute(array((int)$u['id']));

    session_regenerate_id(true);
    $_SESSION['ntt_user_id'] = (int)$u['id']; $_SESSION['ntt_user_name'] = $u['name'];
    $_SESSION['ntt_user_email'] = $u['email']; $_SESSION['ntt_email_verified'] = true;
    $_SESSION['ntt_role'] = $u['role'];

    if ((int)$u['must_change_password']) { header('Location: account.php'); exit; }
    header('Location: ' . ($u['role'] === 'admin' ? 'admin.php' : 'index.php')); exit;
  }
  ntt_go('Action inconnue.');
} catch (PDOException $e) {
  error_log('NTT DB error: ' . $e->getMessage());
  ntt_go('Erreur de base de données. Vérifiez la création de la base (systeme_ntt) et les paramètres MySQL de config.php.');
} catch (Exception $e) {
  error_log('NTT auth error: ' . $e->getMessage());
  ntt_go('Erreur technique. Vérifiez les journaux PHP et la configuration.');
} catch (Throwable $e) {
  error_log('NTT auth error: ' . $e->getMessage());
  ntt_go('Erreur technique. Vérifiez les journaux PHP et la configuration.');
}
