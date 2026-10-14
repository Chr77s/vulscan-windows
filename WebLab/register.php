<?php
require_once "config.php";

$error = "";
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = $_POST["username"] ?? "";
    $email    = $_POST["email"]    ?? "";
    $password = $_POST["password"] ?? "";

    // VULN : politique de mot de passe absente (CWE-521)
    if (strlen($username) < 1) {
        $error = "Le nom d'utilisateur est requis.";
    } else {
        // VULN : md5 sans salt (CWE-916)
        $hash = weak_hash($password);
        // VULN : SQLi sur les 3 champs (CWE-89)
        db()->exec("INSERT INTO users (username, email, password, role, bio) VALUES (
            '$username', '$email', '$hash', 'user', ''
        )");
        header("Location: login.php");
        exit;
    }
}

render_header("Inscription");
?>

<div class="container-form">
  <div class="card">
    <h1>Créer un compte</h1>
    <p class="text-small mb-16">Quelques secondes suffisent.</p>

    <?php if ($error): ?>
      <div class="alert alert-error"><?= $error ?></div>
    <?php endif; ?>

    <form method="POST">
      <div class="form-group">
        <label for="username">Nom d'utilisateur</label>
        <input type="text" id="username" name="username" autocomplete="username" required>
      </div>
      <div class="form-group">
        <label for="email">Adresse email</label>
        <input type="email" id="email" name="email" autocomplete="email" required>
      </div>
      <div class="form-group">
        <label for="password">Mot de passe</label>
        <input type="password" id="password" name="password" autocomplete="new-password" required>
      </div>
      <button type="submit" class="btn btn-block">Créer mon compte</button>
    </form>

    <p class="text-small mt-16" style="text-align:center">
      Déjà inscrit ? <a href="login.php">Se connecter</a>
    </p>
  </div>
</div>

<?php render_footer(); ?>
