<?php
require_once __DIR__ . '/common.php';
try {
  $pdo = db();
  $token = isset($_GET['token']) ? (string)$_GET['token'] : '';
  if (!preg_match('/^[a-f0-9]{64}$/', $token)) throw new RuntimeException('Lien invalide.');
  $q = $pdo->prepare('SELECT id FROM users WHERE verification_token_hash=? AND email_verified=0 AND verification_expires>NOW() LIMIT 1');
  $q->execute(array(hash('sha256', $token))); $u = $q->fetch();
  if (!$u) throw new RuntimeException('Lien invalide ou expiré. Demandez à l’administrateur de renvoyer l’e-mail ou recommencez l’inscription.');
  $q = $pdo->prepare('UPDATE users SET email_verified=1, verification_token_hash=NULL, verification_expires=NULL, verified_at=NOW() WHERE id=?');
  $q->execute(array($u['id']));
  $_SESSION['ntt_flash'] = 'Adresse e-mail confirmée. Vous pouvez maintenant vous connecter.';
} catch (Exception $e) {
  $_SESSION['ntt_flash'] = ($e instanceof RuntimeException && !($e instanceof PDOException)) ? $e->getMessage() : 'Impossible de confirmer le compte. Vérifiez la configuration.';
  error_log('NTT verify error: ' . $e->getMessage());
} catch (Throwable $e) {
  $_SESSION['ntt_flash'] = 'Impossible de confirmer le compte. Vérifiez la configuration.';
  error_log('NTT verify error: ' . $e->getMessage());
}
header('Location: login.php'); exit;
