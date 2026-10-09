<?php
session_start();
if (!empty($_SESSION['ntt_user_id']) && !empty($_SESSION['ntt_email_verified'])) {
    header('Location: index.php'); exit;
}
$msg = isset($_SESSION['ntt_flash']) ? $_SESSION['ntt_flash'] : ''; unset($_SESSION['ntt_flash']);
?>
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Accès sécurisé — Système NTT</title>
<style>
:root{color-scheme:dark;--bg:#06110c;--card:#0b1c15;--line:#1e4a36;--text:#e9f6ee;--muted:#8fb3a0;--green:#8bd24a}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(900px 500px at 70% 0%,#13402d,#06110c 65%);font:15px Segoe UI,Arial;color:var(--text);padding:20px}
.card{width:min(460px,100%);background:var(--card);border:1px solid var(--line);border-radius:20px;padding:28px;box-shadow:0 20px 60px #0008}
h1{margin:0 0 6px;font-size:26px}p{color:var(--muted);line-height:1.5}.tabs{display:flex;gap:8px;margin:22px 0 14px}.tabs button{flex:1;border:1px solid var(--line);background:#07150f;color:var(--muted);padding:10px;border-radius:10px;cursor:pointer}.tabs button.active{background:var(--green);color:#06210f;font-weight:700}
label{display:block;margin:12px 0 6px;color:var(--muted)}input{width:100%;padding:12px;border:1px solid var(--line);border-radius:10px;background:#07150f;color:var(--text);font:inherit}
button.submit{width:100%;margin-top:18px;padding:12px;border:0;border-radius:999px;background:linear-gradient(90deg,#5fae2f,#8bd24a);color:#06210f;font-weight:800;cursor:pointer}
.msg{padding:11px;border-radius:10px;background:#182e21;color:#d6f3ce;margin:12px 0}.fine{font-size:12px}.hidden{display:none}
</style></head><body><div class="card">
<h1>Système <span style="color:#8bd24a">NTT</span></h1><p>Accès réservé aux comptes inscrits et confirmés par e-mail.</p>
<?php if ($msg): ?><div class="msg"><?= htmlspecialchars($msg, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
<div class="tabs"><button type="button" id="tabLogin" class="active" onclick="showForm('login')">Connexion</button><button type="button" id="tabRegister" onclick="showForm('register')">Inscription</button></div>
<form id="loginForm" method="post" action="auth.php">
<input type="hidden" name="action" value="login">
<label>E-mail ou identifiant</label><input type="text" name="login" required autocomplete="username">
<label>Mot de passe</label><input type="password" name="password" required autocomplete="current-password">
<button class="submit" type="submit">Se connecter</button>
</form>
<form id="registerForm" class="hidden" method="post" action="auth.php">
<input type="hidden" name="action" value="register">
<label>Nom complet</label><input type="text" name="name" required maxlength="120" autocomplete="name">
<label>E-mail</label><input type="email" name="email" required maxlength="190" autocomplete="email">
<label>Mot de passe (12 caractères minimum)</label><input type="password" name="password" required minlength="12" autocomplete="new-password">
<label>Confirmer le mot de passe</label><input type="password" name="password_confirm" required minlength="12" autocomplete="new-password">
<button class="submit" type="submit">Créer le compte et envoyer l'e-mail</button>
<p class="fine">Après l'inscription, ouvrez le lien de confirmation reçu par e-mail. Aucun accès n'est accordé avant la confirmation.</p>
</form>
<p class="fine">Si vous n'avez pas reçu le message, vérifiez le dossier Courrier indésirable.</p>
</div><script>
function showForm(which){const login=which==='login';document.getElementById('loginForm').classList.toggle('hidden',!login);document.getElementById('registerForm').classList.toggle('hidden',login);document.getElementById('tabLogin').classList.toggle('active',login);document.getElementById('tabRegister').classList.toggle('active',!login)}
</script></body></html>