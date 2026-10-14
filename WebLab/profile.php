<?php
require_once "config.php";

if (!isset($_SESSION["user"])) {
    header("Location: login.php");
    exit;
}
$uid = $_SESSION["user"]["id"];

// VULN : update sans CSRF token, ni vérification d'authz fine
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $bio   = $_POST["bio"]   ?? "";
    $email = $_POST["email"] ?? "";
    // VULN : SQLi sur email (et stored XSS sur bio à l'affichage)
    db()->exec("UPDATE users SET bio = '" . addslashes($bio) . "', email = '$email' WHERE id = $uid");
    $_SESSION["user"]["bio"] = $bio;
    header("Location: profile.php?saved=1");
    exit;
}

$user = db()->query("SELECT * FROM users WHERE id = $uid")->fetch(PDO::FETCH_ASSOC);

render_header("Profil");
?>

<div class="container-narrow">

  <div class="card">
    <h1>Mon profil</h1>
    <?php if (isset($_GET["saved"])): ?>
      <div class="alert alert-success mt-16">Profil mis à jour.</div>
    <?php endif; ?>

    <form method="POST" class="mt-16">
      <div class="form-group">
        <label for="username">Nom d'utilisateur</label>
        <input type="text" id="username" value="<?= htmlspecialchars($user["username"]) ?>" disabled>
      </div>
      <div class="form-group">
        <label for="email">Adresse email</label>
        <input type="email" id="email" name="email" value="<?= htmlspecialchars($user["email"]) ?>">
      </div>
      <div class="form-group">
        <label for="bio">Bio</label>
        <textarea id="bio" name="bio" rows="4" placeholder="Quelques mots sur vous…"><?= htmlspecialchars($user["bio"] ?? "") ?></textarea>
      </div>
      <button type="submit" class="btn">Enregistrer les modifications</button>
    </form>
  </div>

  <div class="card">
    <h2>Aperçu public</h2>
    <p class="text-small mb-16">Voici comment votre bio apparaît aux autres utilisateurs.</p>
    <div class="comment">
      <div class="comment-head">
        <span class="author"><?= htmlspecialchars($user["username"]) ?></span>
      </div>
      <!-- VULN Stored XSS : la bio est affichée sans échappement (CWE-79) -->
      <div class="text"><?= $user["bio"] ?? "" ?></div>
    </div>
  </div>

</div>

<?php render_footer(); ?>
