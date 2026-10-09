SYSTÈME NTT — AUTHENTIFICATION PAR E-MAIL
==========================================

Contenu
-------
- index.php : application Système NTT originale protégée par session.
- login.php : connexion et inscription.
- auth.php : traitement des comptes et mots de passe.
- verify.php : confirmation d'adresse e-mail (lien temporaire de 24 h).
- logout.php : déconnexion.
- database.sql : base MySQL et table des comptes.
- config.example.php : exemple de configuration.

IMPORTANT
---------
Une authentification réelle nécessite PHP + MySQL + SMTP. N'ouvrez pas index.php
en double-cliquant dessus (file://). Utilisez EasyPHP/Apache.

Installation sur EasyPHP
------------------------
1. Copiez le contenu du dossier dans un nouveau dossier du serveur, par exemple :
   C:\\Program Files (x86)\\EasyPHP-Devserver-17\\eds-www\\systeme-ntt\\
2. Dans phpMyAdmin, importez database.sql.
3. Copiez config.example.php en config.php.
4. Modifiez config.php :
   - les paramètres MySQL ;
   - app.base_url, par exemple http://localhost/systeme-ntt ;
   - les paramètres SMTP réels de votre fournisseur de messagerie.
5. Dans un terminal ouvert dans le dossier du projet, installez PHPMailer :
   composer require phpmailer/phpmailer
   (Composer doit être installé et accessible dans le PATH.)
6. Ouvrez http://localhost/systeme-ntt/login.php
7. Inscrivez-vous puis cliquez sur le lien reçu par e-mail.

Configuration e-mail
--------------------
Utilisez les paramètres SMTP officiels de votre fournisseur. Pour Gmail, un mot
de passe d'application peut être nécessaire si la validation en deux étapes est
activée. N'utilisez pas le mot de passe principal de votre boîte si le fournisseur
recommande un mot de passe d'application.

Sécurité / déploiement
----------------------
- Ne partagez jamais config.php : il contient le mot de passe SMTP et MySQL.
- Pour un site public, utilisez HTTPS.
- Utilisez un compte MySQL dédié avec les droits minimaux plutôt que root.
- Activez les protections anti-spam / limitation de tentatives avant d'ouvrir
  les inscriptions publiquement.
- Cette version protège l'accès à l'application HTML. Les calculs et exports
  restent exécutés dans le navigateur après authentification ; les fichiers
  exportés sont téléchargés par l'utilisateur, ils ne sont pas automatiquement
  stockés sur le serveur.
