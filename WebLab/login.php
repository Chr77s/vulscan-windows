<?php
require_once "config.php";

$error = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = $_POST["username"] ?? "";
    $password = $_POST["password"] ?? "";

    // VULN INTENTIONNELLE : SQLi error/boolean-based (CWE-89)
    $sql = "SELECT id, username, role FROM users WHERE username = '$username' AND password = '" . weak_hash($password) . "'";
    $pdo = db();
    $stmt = $pdo->query($sql);

    if ($stmt && ($user = $stmt->fetch(PDO::FETCH_ASSOC))) {
        $_SESSION["user"] = $user;
        header("Location: profile.php");
        exit;
    } else {
        // VULN : message d'erreur révélateur — exfiltre la requête (CWE-209)
        $error = "Identifiants invalides. Requête : <code>" . htmlspecialchars($sql) . "</code>";
    }
}

render_header("Connexion");
?>

<div class="container-form">
  <div class="card">
    <h1>Connexion</h1>
    <p class="text-small mb-16">Accédez à votre compte WebLab.</p>

    <?php if ($error): ?>
      <div class="alert alert-error"><?= $error /* HTML non échappé volontairement */ ?></div>
    <?php endif; ?>

    <!-- VULN : pas de token CSRF (CWE-352) -->
    <form method="POST">
      <div class="form-group">
        <label for="username">Nom d'utilisateur</label>
        <input type="text" id="username" name="username" autocomplete="username" required>
      </div>
      <div class="form-group">
        <label for="password">Mot de passe</label>
        <input type="password" id="password" name="password" autocomplete="current-password" required>
      </div>
      <button class="btn btn-block" type="submit">Se connecter</button>
    </form>

    <p class="text-small mt-16" style="text-align:center">
      Pas encore de compte ? <a href="register.php">Créer un compte</a>
    </p>

    <div class="devnote">
      <strong>Note développeur :</strong> essayer <code>admin' OR '1'='1'-- </code> dans le champ utilisateur.
    </div>
  </div>
</div>

<?php render_footer(); ?>
