<?php
require_once __DIR__ . '/common.php';
$me = ntt_require_login('admin');
$pdo = db();
$roles = array('admin' => 'Administrateur', 'user' => 'Utilisateur', 'visitor' => 'Visiteur');

function adm_back($ok, $msg, $tab) {
  $_SESSION['ntt_admin_flash'] = array($ok ? 'ok' : 'err', $msg);
  header('Location: admin.php?tab=' . $tab);
  exit;
}
function adm_admin_count($pdo) {
  $q = $pdo->query("SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1");
  return (int)$q->fetchColumn();
}
function adm_temp_password() {
  $chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  $b = ntt_random_bytes(14);
  $o = '';
  for ($i = 0; $i < 14; $i++) { $o .= $chars[ord($b[$i]) % strlen($chars)]; }
  return $o;
}
function adm_post($k) { return isset($_POST[$k]) ? trim((string)$_POST[$k]) : ''; }

$tab = isset($_GET['tab']) ? (string)$_GET['tab'] : 'users';
if (!in_array($tab, array('users', 'registration', 'smtp'), true)) $tab = 'users';

// ------------------------------------------------------------------ ACTIONS
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $action = adm_post('action');
  $back = 'users';
  if ($action === 'save_registration') $back = 'registration';
  if ($action === 'save_smtp' || $action === 'test_smtp') $back = 'smtp';
  if (!ntt_csrf_valid()) adm_back(false, 'Session expirée. Rechargez la page et réessayez.', $back);

  try {
    // ---- Créer un compte
    if ($action === 'create_user') {
      $name = adm_post('name');
      $email = strtolower(adm_post('email'));
      $username = strtolower(adm_post('username'));
      $role = adm_post('role');
      $pw = (string)(isset($_POST['password']) ? $_POST['password'] : '');
      $verified = !empty($_POST['verified']) ? 1 : 0;
      if ($name === '' || ntt_strlen($name) > 120) adm_back(false, 'Nom invalide.', 'users');
      if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190) adm_back(false, 'Adresse e-mail invalide.', 'users');
      if ($username !== '' && !preg_match('/^[a-z0-9._-]{3,60}$/', $username)) adm_back(false, 'Identifiant invalide (3 à 60 caractères : lettres, chiffres, . _ -).', 'users');
      if (!isset($roles[$role])) adm_back(false, 'Rôle invalide.', 'users');
      if (strlen($pw) < 12) adm_back(false, 'Le mot de passe doit contenir au moins 12 caractères.', 'users');
      $uname = ($username === '') ? null : $username;
      $q = $pdo->prepare('SELECT id FROM users WHERE email=? OR username=? LIMIT 1');
      $q->execute(array($email, $uname));
      if ($q->fetch()) adm_back(false, 'Cette adresse e-mail ou cet identifiant existe déjà.', 'users');
      $q = $pdo->prepare('INSERT INTO users (name,username,email,password_hash,email_verified,role,is_active,must_change_password,created_at,verified_at) VALUES (?,?,?,?,?,?,1,1,NOW(),IF(?=1,NOW(),NULL))');
      $q->execute(array($name, $uname, $email, password_hash($pw, PASSWORD_DEFAULT), $verified, $role, $verified));
      $id = (int)$pdo->lastInsertId();
      if (!$verified) {
        try {
          $token = ntt_new_verification($pdo, $id);
          ntt_send_confirmation($email, $name, $token);
        } catch (Exception $e) {
          $pdo->prepare('DELETE FROM users WHERE id=?')->execute(array($id));
          adm_back(false, 'Compte non créé : envoi de l’e-mail impossible (' . $e->getMessage() . ').', 'users');
        }
        adm_back(true, 'Compte créé. Un e-mail de confirmation a été envoyé à ' . $email . '. L’utilisateur devra changer son mot de passe à la première connexion.', 'users');
      }
      adm_back(true, 'Compte créé et confirmé. L’utilisateur devra changer son mot de passe à la première connexion.', 'users');
    }

    // ---- Actions sur un compte existant
    if (in_array($action, array('set_role', 'toggle_active', 'verify_user', 'resend_confirm', 'reset_password', 'delete_user'), true)) {
      $id = (int)adm_post('id');
      $target = ntt_fetch_user($id);
      if (!$target) adm_back(false, 'Compte introuvable.', 'users');
      $isSelf = ($id === (int)$me['id']);
      $isLastAdmin = ($target['role'] === 'admin' && (int)$target['is_active'] === 1 && adm_admin_count($pdo) <= 1);

      if ($action === 'set_role') {
        $role = adm_post('role');
        if (!isset($roles[$role])) adm_back(false, 'Rôle invalide.', 'users');
        if ($target['role'] === 'admin' && $role !== 'admin' && ($isSelf || $isLastAdmin)) {
          adm_back(false, 'Impossible de retirer le rôle administrateur à ce compte (il faut au moins un administrateur actif).', 'users');
        }
        $pdo->prepare('UPDATE users SET role=? WHERE id=?')->execute(array($role, $id));
        adm_back(true, 'Rôle de ' . $target['email'] . ' : ' . $roles[$role] . '.', 'users');
      }
      if ($action === 'toggle_active') {
        if ($isSelf) adm_back(false, 'Vous ne pouvez pas désactiver votre propre compte.', 'users');
        $new = (int)$target['is_active'] ? 0 : 1;
        if ($new === 0 && $isLastAdmin) adm_back(false, 'Impossible de désactiver le dernier administrateur.', 'users');
        $pdo->prepare('UPDATE users SET is_active=? WHERE id=?')->execute(array($new, $id));
        adm_back(true, 'Compte ' . $target['email'] . ($new ? ' activé.' : ' désactivé.'), 'users');
      }
      if ($action === 'verify_user') {
        $pdo->prepare('UPDATE users SET email_verified=1, verification_token_hash=NULL, verification_expires=NULL, verified_at=NOW() WHERE id=?')->execute(array($id));
        adm_back(true, 'Adresse ' . $target['email'] . ' marquée comme confirmée.', 'users');
      }
      if ($action === 'resend_confirm') {
        if ((int)$target['email_verified']) adm_back(false, 'Ce compte est déjà confirmé.', 'users');
        try {
          $token = ntt_new_verification($pdo, $id);
          ntt_send_confirmation($target['email'], $target['name'], $token);
        } catch (Exception $e) {
          adm_back(false, 'Envoi impossible : ' . $e->getMessage(), 'users');
        }
        adm_back(true, 'E-mail de confirmation renvoyé à ' . $target['email'] . '.', 'users');
      }
      if ($action === 'reset_password') {
        $tmp = adm_temp_password();
        $pdo->prepare('UPDATE users SET password_hash=?, must_change_password=1 WHERE id=?')->execute(array(password_hash($tmp, PASSWORD_DEFAULT), $id));
        adm_back(true, 'Mot de passe temporaire pour ' . $target['email'] . ' : ' . $tmp . ' (à communiquer à l’utilisateur ; il devra le changer à la connexion ; affiché une seule fois).', 'users');
      }
      if ($action === 'delete_user') {
        if ($isSelf) adm_back(false, 'Vous ne pouvez pas supprimer votre propre compte.', 'users');
        if ($isLastAdmin) adm_back(false, 'Impossible de supprimer le dernier administrateur.', 'users');
        $pdo->prepare('DELETE FROM users WHERE id=?')->execute(array($id));
        adm_back(true, 'Compte ' . $target['email'] . ' supprimé.', 'users');
      }
    }

    // ---- Réglages des inscriptions
    if ($action === 'save_registration') {
      $mode = adm_post('registration_mode');
      $drole = adm_post('default_role');
      if ($mode !== 'open' && $mode !== 'closed') adm_back(false, 'Mode d’inscription invalide.', 'registration');
      if ($drole !== 'user' && $drole !== 'visitor') adm_back(false, 'Rôle par défaut invalide.', 'registration');
      ntt_set_setting('registration_mode', $mode);
      ntt_set_setting('default_role', $drole);
      ntt_set_setting('require_email_verification', !empty($_POST['require_email_verification']) ? '1' : '0');
      adm_back(true, 'Réglages d’inscription enregistrés.', 'registration');
    }

    // ---- Réglages SMTP Gmail
    if ($action === 'save_smtp') {
      $host = adm_post('host');
      $port = (int)adm_post('port');
      $enc = adm_post('encryption');
      $user = adm_post('username');
      $fromEmail = adm_post('from_email');
      $fromName = adm_post('from_name');
      $pw = preg_replace('/\s+/', '', (string)(isset($_POST['password']) ? $_POST['password'] : ''));
      if ($host === '' || strlen($host) > 190) adm_back(false, 'Serveur SMTP invalide.', 'smtp');
      if ($port < 1 || $port > 65535) adm_back(false, 'Port invalide.', 'smtp');
      if ($enc !== 'tls' && $enc !== 'ssl') adm_back(false, 'Chiffrement invalide.', 'smtp');
      if ($user === '') adm_back(false, 'Identifiant SMTP obligatoire (adresse Gmail complète).', 'smtp');
      if (!filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) adm_back(false, 'Adresse expéditeur invalide.', 'smtp');
      if ($fromName === '' || ntt_strlen($fromName) > 120) $fromName = 'Système NTT';
      if ($pw === '' && ntt_setting('smtp_password', '') === '') adm_back(false, 'Saisissez le mot de passe d’application Google.', 'smtp');
      ntt_set_setting('smtp_host', $host);
      ntt_set_setting('smtp_port', (string)$port);
      ntt_set_setting('smtp_encryption', $enc);
      ntt_set_setting('smtp_username', $user);
      ntt_set_setting('smtp_from_email', $fromEmail);
      ntt_set_setting('smtp_from_name', $fromName);
      if ($pw !== '') ntt_set_setting('smtp_password', ntt_encrypt($pw));
      ntt_set_setting('smtp_verify_peer', !empty($_POST['verify_peer']) ? '1' : '0');
      ntt_set_setting('smtp_configured', '1');
      adm_back(true, 'Réglages SMTP enregistrés. Envoyez un e-mail de test pour les vérifier.', 'smtp');
    }

    // ---- E-mail de test (avec journal SMTP, identifiants masqués)
    if ($action === 'test_smtp') {
      $to = strtolower(adm_post('to'));
      if (!filter_var($to, FILTER_VALIDATE_EMAIL)) adm_back(false, 'Adresse de destination invalide.', 'smtp');
      $s = ntt_smtp_config();
      $why = '';
      if (!ntt_smtp_ready($s, $why)) adm_back(false, $why, 'smtp');
      $log = '';
      $result = null;
      try {
        $mail = ntt_build_mailer($s);
        $mail->SMTPDebug = 2;
        $pwd = $s['password'];
        $mail->Debugoutput = function ($str, $level) use (&$log, $pwd) {
          $log .= ntt_redact_smtp($str, $pwd);
        };
        $mail->addAddress($to);
        $mail->Subject = 'Test SMTP — Système NTT';
        $mail->Body = 'Ce message confirme que l’envoi d’e-mails du Système NTT fonctionne.';
        $mail->send();
        $result = array(true, 'E-mail de test envoyé à ' . $to . '. Vérifiez la boîte de réception et les spams.');
      } catch (Exception $e) {
        $result = array(false, 'Échec de l’envoi : ' . $e->getMessage());
      } catch (Throwable $e) {
        $result = array(false, 'Échec de l’envoi : ' . $e->getMessage());
      }
      $_SESSION['ntt_smtp_log'] = $log;
      adm_back($result[0], $result[1], 'smtp');
    }

    adm_back(false, 'Action inconnue.', $back);
  } catch (Exception $e) {
    error_log('NTT admin error: ' . $e->getMessage());
    adm_back(false, 'Erreur : ' . $e->getMessage(), $back);
  } catch (Throwable $e) {
    error_log('NTT admin error: ' . $e->getMessage());
    adm_back(false, 'Erreur : ' . $e->getMessage(), $back);
  }
}

// ------------------------------------------------------------------ DONNÉES
$flash = isset($_SESSION['ntt_admin_flash']) ? $_SESSION['ntt_admin_flash'] : null;
unset($_SESSION['ntt_admin_flash']);
$smtpLog = isset($_SESSION['ntt_smtp_log']) ? $_SESSION['ntt_smtp_log'] : '';
unset($_SESSION['ntt_smtp_log']);
$csrf = ntt_csrf();

$search = isset($_GET['q']) ? trim((string)$_GET['q']) : '';
$cols = 'id,name,username,email,role,email_verified,is_active,created_at,last_login';
if ($search !== '') {
  $like = '%' . str_replace(array('\\', '%', '_'), array('\\\\', '\\%', '\\_'), $search) . '%';
  $st = $pdo->prepare("SELECT $cols FROM users WHERE name LIKE ? OR email LIKE ? OR username LIKE ? ORDER BY id DESC LIMIT 300");
  $st->execute(array($like, $like, $like));
} else {
  $st = $pdo->query("SELECT $cols FROM users ORDER BY (role='admin') DESC, id DESC LIMIT 300");
}
$users = $st->fetchAll();
$stats = $pdo->query('SELECT COUNT(*) AS total, SUM(email_verified=0) AS pending, SUM(is_active=0) AS disabled FROM users')->fetch();

$regMode = ntt_setting('registration_mode', 'open');
$defRole = ntt_setting('default_role', 'user');
$reqVerify = (ntt_setting('require_email_verification', '1') === '1');
$s = ntt_smtp_config();
$smtpFromDb = (ntt_setting('smtp_configured', '0') === '1');
$hasPw = ($s['password'] !== '' && strpos($s['password'], 'COLLEZ_ICI') !== 0);
?>
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Administration — Système NTT</title>
<style>
:root{color-scheme:dark;--bg:#06110c;--card:#0b1c15;--line:#1e4a36;--text:#e9f6ee;--muted:#8fb3a0;--green:#8bd24a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(900px 500px at 70% 0%,#13402d,#06110c 65%);font:14px Segoe UI,Arial;color:var(--text);min-height:100vh}
.wrap{max-width:1100px;margin:0 auto;padding:20px}
header{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;margin-bottom:14px}
h1{margin:0;font-size:24px}h1 span{color:var(--green)}h2{margin:0 0 10px;font-size:17px}
a{color:var(--green)}.muted{color:var(--muted)}
.tabs{display:flex;gap:8px;margin:10px 0 16px;flex-wrap:wrap}.tabs a{padding:9px 16px;border:1px solid var(--line);border-radius:999px;background:#07150f;color:var(--muted);text-decoration:none}.tabs a.on{background:var(--green);color:#06210f;font-weight:700}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;margin-bottom:16px}
.msg{padding:11px 14px;border-radius:10px;margin-bottom:14px;word-break:break-word}.ok{background:#182e21;color:#d6f3ce}.err{background:#3a1d1d;color:#ffd1d1}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}.stat{background:#07150f;border:1px solid var(--line);border-radius:12px;padding:10px 16px}.stat b{display:block;font-size:20px}
table{width:100%;border-collapse:collapse}th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}
.scroll{overflow-x:auto}
input[type=text],input[type=email],input[type=password],input[type=number],select{padding:9px;border:1px solid var(--line);border-radius:8px;background:#07150f;color:var(--text);font:inherit;width:100%}
select.small{width:auto;padding:5px}
label{display:block;margin:10px 0 5px;color:var(--muted)}
button,.btn{padding:8px 14px;border:1px solid var(--line);border-radius:999px;background:#0f2a1f;color:var(--text);cursor:pointer;font:inherit;text-decoration:none;display:inline-block}
button.main{background:linear-gradient(90deg,#5fae2f,#8bd24a);color:#06210f;font-weight:800;border:0;padding:10px 20px}
button.danger{border-color:#7a2b2b;color:#ffb4b4}button.sm{padding:4px 10px;font-size:12px}
form.inline{display:inline}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}
.badge{padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line)}.b-ok{color:#b6f08a}.b-warn{color:#ffd37a}.b-off{color:#ff9d9d}
pre{background:#050e0a;border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;max-height:320px;font:12px Consolas,monospace;white-space:pre-wrap}
.hint{background:#0f2a1f;border-radius:10px;padding:12px;margin:12px 0;line-height:1.5}
.chk{display:flex;gap:8px;align-items:center;margin:12px 0;color:var(--text)}.chk input{width:auto}
</style></head><body><div class="wrap">
<header>
  <h1>Administration <span>NTT</span></h1>
  <div class="muted"><?= ntt_h($me['name']) ?> · <a href="index.php">Application</a> · <a href="account.php">Mon compte</a> · <a href="logout.php">Déconnexion</a></div>
</header>
<div class="tabs">
  <a href="admin.php?tab=users" class="<?= $tab === 'users' ? 'on' : '' ?>">Comptes</a>
  <a href="admin.php?tab=registration" class="<?= $tab === 'registration' ? 'on' : '' ?>">Inscriptions</a>
  <a href="admin.php?tab=smtp" class="<?= $tab === 'smtp' ? 'on' : '' ?>">SMTP Gmail</a>
</div>
<?php if ($flash): ?><div class="msg <?= $flash[0] === 'ok' ? 'ok' : 'err' ?>"><?= ntt_h($flash[1]) ?></div><?php endif; ?>

<?php if ($tab === 'users'): ?>
<div class="stats">
  <div class="stat"><b><?= (int)$stats['total'] ?></b>comptes</div>
  <div class="stat"><b><?= (int)$stats['pending'] ?></b>e-mails à confirmer</div>
  <div class="stat"><b><?= (int)$stats['disabled'] ?></b>désactivés</div>
</div>

<div class="card">
  <h2>Créer un compte</h2>
  <form method="post" action="admin.php?tab=users" autocomplete="off">
    <input type="hidden" name="csrf" value="<?= ntt_h($csrf) ?>"><input type="hidden" name="action" value="create_user">
    <div class="grid">
      <div><label>Nom complet</label><input type="text" name="name" required maxlength="120"></div>
      <div><label>E-mail</label><input type="email" name="email" required maxlength="190"></div>
      <div><label>Identifiant (facultatif)</label><input type="text" name="username" maxlength="60" placeholder="ex : jdupont"></div>
      <div><label>Rôle</label><select name="role"><?php foreach ($roles as $k => $label): ?><option value="<?= ntt_h($k) ?>"<?= $k === 'user' ? ' selected' : '' ?>><?= ntt_h($label) ?></option><?php endforeach; ?></select></div>
      <div><label>Mot de passe temporaire (12 car. min.)</label><input type="password" name="password" required minlength="12" autocomplete="new-password"></div>
    </div>
    <div class="chk"><input type="checkbox" name="verified" id="vf" value="1" checked><label for="vf" style="margin:0;color:var(--text)">Considérer l’e-mail comme confirmé (sinon un e-mail de confirmation est envoyé)</label></div>
    <button class="main" type="submit">Créer le compte</button>
  </form>
</div>

<div class="card">
  <form method="get" action="admin.php" style="display:flex;gap:8px;margin-bottom:12px">
    <input type="hidden" name="tab" value="users">
    <input type="text" name="q" value="<?= ntt_h($search) ?>" placeholder="Rechercher nom, e-mail ou identifiant">
    <button type="submit">Rechercher</button>
  </form>
  <div class="scroll"><table>
    <tr><th>Compte</th><th>Rôle</th><th>État</th><th>Dernière connexion</th><th>Actions</th></tr>
    <?php foreach ($users as $u): $self = ((int)$u['id'] === (int)$me['id']); ?>
    <tr>
      <td><strong><?= ntt_h($u['name']) ?></strong><?= $self ? ' <span class="muted">(vous)</span>' : '' ?><br>
        <span class="muted"><?= ntt_h($u['email']) ?><?= $u['username'] ? ' · @' . ntt_h($u['username']) : '' ?></span></td>
      <td>
        <form method="post" action="admin.php?tab=users" class="inline">
          <input type="hidden" name="csrf" value="<?= ntt_h($csrf) ?>"><input type="hidden" name="action" value="set_role"><input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
          <select name="role" class="small" onchange="this.form.submit()"<?= $self ? ' disabled' : '' ?>>
            <?php foreach ($roles as $k => $label): ?><option value="<?= ntt_h($k) ?>"<?= $u['role'] === $k ? ' selected' : '' ?>><?= ntt_h($label) ?></option><?php endforeach; ?>
          </select>
        </form>
      </td>
      <td>
        <?php if (!(int)$u['is_active']): ?><span class="badge b-off">désactivé</span>
        <?php elseif (!(int)$u['email_verified']): ?><span class="badge b-warn">e-mail non confirmé</span>
        <?php else: ?><span class="badge b-ok">actif</span><?php endif; ?>
      </td>
      <td class="muted"><?= $u['last_login'] ? ntt_h($u['last_login']) : '—' ?></td>
      <td>
        <?php if (!(int)$u['email_verified']): ?>
          <form method="post" action="admin.php?tab=users" class="inline"><input type="hidden" name="csrf" value="<?= ntt_h($csrf) ?>"><input type="hidden" name="action" value="verify_user"><input type="hidden" name="id" value="<?= (int)$u['id'] ?>"><button class="sm" type="submit">Confirmer</button></form>
          <form method="post" action="admin.php?tab=users" class="inline"><input type="hidden" name="csrf" value="<?= ntt_h($csrf) ?>"><input type="hidden" name="action" value="resend_confirm"><input type="hidden" name="id" value="<?= (int)$u['id'] ?>"><button class="sm" type="submit">Renvoyer l’e-mail</button></form>
        <?php endif; ?>
        <?php if (!$self): ?>
          <form method="post" action="admin.php?tab=users" class="inline"><input type="hidden" name="csrf" value="<?= ntt_h($csrf) ?>"><input type="hidden" name="action" value="toggle_active"><input type="hidden" name="id" value="<?= (int)$u['id'] ?>"><button class="sm" type="submit"><?= (int)$u['is_active'] ? 'Désactiver' : 'Activer' ?></button></form>
        <?php endif; ?>
        <form method="post" action="admin.php?tab=users" class="inline" onsubmit="return confirm('Générer un mot de passe temporaire pour ce compte ?')"><input type="hidden" name="csrf" value="<?= ntt_h($csrf) ?>"><input type="hidden" name="action" value="reset_password"><input type="hidden" name="id" value="<?= (int)$u['id'] ?>"><button class="sm" type="submit">Mot de passe</button></form>
        <?php if (!$self): ?>
          <form method="post" action="admin.php?tab=users" class="inline" onsubmit="return confirm('Supprimer définitivement ce compte ?')"><input type="hidden" name="csrf" value="<?= ntt_h($csrf) ?>"><input type="hidden" name="action" value="delete_user"><input type="hidden" name="id" value="<?= (int)$u['id'] ?>"><button class="sm danger" type="submit">Supprimer</button></form>
        <?php endif; ?>
      </td>
    </tr>
    <?php endforeach; ?>
    <?php if (!$users): ?><tr><td colspan="5" class="muted">Aucun compte.</td></tr><?php endif; ?>
  </table></div>
</div>

<?php elseif ($tab === 'registration'): ?>
<div class="card">
  <h2>Inscription des visiteurs et utilisateurs</h2>
  <p class="muted">Ces réglages s’appliquent au formulaire « Inscription » de la page de connexion.</p>
  <form method="post" action="admin.php?tab=registration">
    <input type="hidden" name="csrf" value="<?= ntt_h($csrf) ?>"><input type="hidden" name="action" value="save_registration">
    <label>Inscriptions publiques</label>
    <select name="registration_mode">
      <option value="open"<?= $regMode === 'open' ? ' selected' : '' ?>>Ouvertes — chacun peut s’inscrire</option>
      <option value="closed"<?= $regMode === 'closed' ? ' selected' : '' ?>>Fermées — seuls les comptes créés par l’administrateur</option>
    </select>
    <label>Rôle donné aux nouveaux inscrits</label>
    <select name="default_role">
      <option value="user"<?= $defRole === 'user' ? ' selected' : '' ?>>Utilisateur — accès direct à l’application après confirmation</option>
      <option value="visitor"<?= $defRole === 'visitor' ? ' selected' : '' ?>>Visiteur — pas d’accès tant que l’administrateur ne les passe pas Utilisateur</option>
    </select>
    <div class="chk"><input type="checkbox" name="require_email_verification" id="rv" value="1"<?= $reqVerify ? ' checked' : '' ?>><label for="rv" style="margin:0;color:var(--text)">Exiger la confirmation de l’e-mail (nécessite un SMTP fonctionnel)</label></div>
    <button class="main" type="submit">Enregistrer</button>
  </form>
</div>

<?php else: ?>
<div class="card">
  <h2>SMTP Gmail (envoi des e-mails de confirmation)</h2>
  <p class="muted">Source actuelle : <?= $smtpFromDb ? 'réglages enregistrés ici' : 'fichier config.php (aucun réglage enregistré ici)' ?>.
     Le mot de passe est enregistré chiffré ; il n’est jamais réaffiché.</p>
  <div class="hint">
    <strong>Mot de passe d’application Google</strong> (obligatoire, le mot de passe normal du compte est refusé) :
    1) activez la validation en deux étapes sur le compte Gmail ;
    2) ouvrez <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noopener">myaccount.google.com/apppasswords</a> ;
    3) créez un mot de passe nommé « Systeme NTT » ;
    4) collez ici les 16 lettres (les espaces sont retirés automatiquement).
  </div>
  <form method="post" action="admin.php?tab=smtp" autocomplete="off">
    <input type="hidden" name="csrf" value="<?= ntt_h($csrf) ?>"><input type="hidden" name="action" value="save_smtp">
    <div class="grid">
      <div><label>Serveur SMTP</label><input type="text" name="host" value="<?= ntt_h($s['host']) ?>" required></div>
      <div><label>Port</label><input type="number" name="port" value="<?= (int)$s['port'] ?>" min="1" max="65535" required></div>
      <div><label>Chiffrement</label><select name="encryption">
        <option value="tls"<?= $s['encryption'] !== 'ssl' ? ' selected' : '' ?>>STARTTLS (port 587)</option>
        <option value="ssl"<?= $s['encryption'] === 'ssl' ? ' selected' : '' ?>>SSL/TLS (port 465)</option></select></div>
      <div><label>Adresse Gmail (identifiant)</label><input type="text" name="username" value="<?= ntt_h($s['username']) ?>" required></div>
      <div><label>Adresse expéditeur</label><input type="text" name="from_email" value="<?= ntt_h($s['from_email']) ?>" required></div>
      <div><label>Nom expéditeur</label><input type="text" name="from_name" value="<?= ntt_h($s['from_name']) ?>"></div>
      <div><label>Mot de passe d’application <?= ($smtpFromDb && $hasPw) ? '(laisser vide pour conserver)' : '' ?></label><input type="password" name="password" autocomplete="new-password" placeholder="<?= ($smtpFromDb && $hasPw) ? '•••••••• enregistré' : 'abcd efgh ijkl mnop' ?>"></div>
    </div>
    <div class="chk"><input type="checkbox" name="verify_peer" id="vp" value="1"<?= $s['verify_peer'] ? ' checked' : '' ?>><label for="vp" style="margin:0;color:var(--text)">Vérifier le certificat du serveur (recommandé). Décochez seulement en local si le test indique « certificate verify failed ».</label></div>
    <button class="main" type="submit">Enregistrer</button>
  </form>
</div>
<div class="card">
  <h2>Tester l’envoi</h2>
  <form method="post" action="admin.php?tab=smtp" style="display:flex;gap:8px;flex-wrap:wrap">
    <input type="hidden" name="csrf" value="<?= ntt_h($csrf) ?>"><input type="hidden" name="action" value="test_smtp">
    <input type="email" name="to" required placeholder="adresse de destination" style="flex:1;min-width:220px">
    <button type="submit">Envoyer un e-mail de test</button>
  </form>
  <?php if ($smtpLog !== ''): ?><p class="muted">Journal SMTP (identifiants masqués) :</p><pre><?= ntt_h($smtpLog) ?></pre><?php endif; ?>
</div>
<?php endif; ?>
</div></body></html>
