<?php
require_once __DIR__ . '/common.php';
$me = ntt_require_login('account');
$pdo = db();
$forced = (int)$me['must_change_password'] === 1;
$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  try {
    $cur = (string)(isset($_POST['current']) ? $_POST['current'] : '');
    $new = (string)(isset($_POST['new']) ? $_POST['new'] : '');
    $conf = (string)(isset($_POST['confirm']) ? $_POST['confirm'] : '');
    $q = $pdo->prepare('SELECT password_hash FROM users WHERE id=?');
    $q->execute(array((int)$me['id']));
    $row = $q->fetch();
    if (!ntt_csrf_valid()) {
      $msg = 'Session expirée. Rechargez la page et réessayez.';
    } elseif (!$row || !password_verify($cur, $row['password_hash'])) {
      $msg = 'Le mot de passe actuel est incorrect.';
    } elseif (strlen($new) < 12) {
      $msg = 'Le nouveau mot de passe doit contenir au moins 12 caractères.';
    } elseif (!hash_equals($new, $conf)) {
      $msg = 'Les deux nouveaux mots de passe ne correspondent pas.';
    } elseif (hash_equals($cur, $new) || $new === NTT_DEFAULT_ADMIN_PASS) {
      $msg = 'Choisissez un mot de passe différent de l’actuel.';
    } else {
      $q = $pdo->prepare('UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?');
      $q->execute(array(password_hash($new, PASSWORD_DEFAULT), (int)$me['id']));
      session_regenerate_id(true);
      if ($me['role'] === 'admin') {
        $_SESSION['ntt_admin_flash'] = array('ok', 'Mot de passe modifié.');
        header('Location: admin.php'); exit;
      }
      header('Location: index.php'); exit;
    }
  } catch (Exception $e) {
    error_log('NTT account error: ' . $e->getMessage());
    $msg = 'Erreur technique. Vérifiez les journaux PHP.';
  }
}
?>
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mon compte — Système NTT</title>
<style>
:root{color-scheme:dark;--bg:#06110c;--card:#0b1c15;--line:#1e4a36;--text:#e9f6ee;--muted:#8fb3a0;--green:#8bd24a}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(900px 500px at 70% 0%,#13402d,#06110c 65%);font:15px Segoe UI,Arial;color:var(--text);padding:20px}
.card{width:min(460px,100%);background:var(--card);border:1px solid var(--line);border-radius:20px;padding:28px;box-shadow:0 20px 60px #0008}
h1{margin:0 0 6px;font-size:24px}p{color:var(--muted);line-height:1.5}
label{display:block;margin:12px 0 6px;color:var(--muted)}input{width:100%;padding:12px;border:1px solid var(--line);border-radius:10px;background:#07150f;color:var(--text);font:inherit}
button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:999px;background:linear-gradient(90deg,#5fae2f,#8bd24a);color:#06210f;font-weight:800;cursor:pointer}
.msg{padding:11px;border-radius:10px;background:#3a1d1d;color:#ffd1d1;margin:12px 0}.warn{padding:11px;border-radius:10px;background:#3a2f12;color:#ffe4a6;margin:12px 0}
a{color:var(--green)}.nav{margin-top:16px;font-size:13px}
</style></head><body><div class="card">
<h1>Changer le mot de passe</h1>
<p>Compte : <strong><?= ntt_h($me['name']) ?></strong></p>
<?php if ($forced): ?><div class="warn">Pour votre sécurité, vous devez choisir un nouveau mot de passe avant de continuer.</div><?php endif; ?>
<?php if ($msg): ?><div class="msg"><?= ntt_h($msg) ?></div><?php endif; ?>
<form method="post" action="account.php" autocomplete="off">
<input type="hidden" name="csrf" value="<?= ntt_h(ntt_csrf()) ?>">
<label>Mot de passe actuel</label><input type="password" name="current" required autocomplete="current-password">
<label>Nouveau mot de passe (12 caractères minimum)</label><input type="password" name="new" required minlength="12" autocomplete="new-password">
<label>Confirmer le nouveau mot de passe</label><input type="password" name="confirm" required minlength="12" autocomplete="new-password">
<button type="submit">Enregistrer</button>
</form>
<div class="nav">
<?php if (!$forced): ?><a href="<?= $me['role'] === 'admin' ? 'admin.php' : 'index.php' ?>">← Retour</a> · <?php endif; ?>
<a href="logout.php">Déconnexion</a>
</div>
</div></body></html>
