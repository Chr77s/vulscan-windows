<?php
require_once "config.php";

// VULN : POST sans token CSRF (CWE-352)
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["comment"])) {
    $author  = $_POST["author"]  ?? "anonyme";
    $comment = $_POST["comment"] ?? "";
    // VULN : insertion brute sans échappement → Stored XSS (CWE-79)
    db()->exec("INSERT INTO comments (author, content, created_at) VALUES (
        '" . addslashes($author) . "',
        '" . addslashes($comment) . "',
        NOW()
    )");
    header("Location: comments.php");
    exit;
}

// VULN IDOR : suppression sans vérifier le propriétaire (CWE-639)
if (isset($_GET["delete"])) {
    db()->exec("DELETE FROM comments WHERE id = " . intval($_GET["delete"]));
    header("Location: comments.php");
    exit;
}

render_header("Commentaires");
$comments = db()->query("SELECT * FROM comments ORDER BY created_at DESC LIMIT 30")->fetchAll(PDO::FETCH_ASSOC);
?>

<div class="container-narrow">

  <div class="card">
    <h2>Laisser un commentaire</h2>
    <form method="POST">
      <div class="form-group">
        <label for="author">Nom</label>
        <input type="text" id="author" name="author" placeholder="Comment vous appelez-vous ?">
      </div>
      <div class="form-group">
        <label for="comment">Commentaire</label>
        <textarea id="comment" name="comment" rows="4" placeholder="Votre avis…"></textarea>
      </div>
      <button type="submit" class="btn">Publier</button>
    </form>
  </div>

  <div class="card">
    <div class="page-head">
      <h2>Discussions récentes</h2>
      <span class="page-subtitle"><?= count($comments) ?> messages</span>
    </div>
    <?php if (empty($comments)): ?>
      <p class="text-small">Aucun commentaire pour le moment.</p>
    <?php else: foreach ($comments as $c): ?>
      <div class="comment">
        <div class="comment-head">
          <span class="author"><?= htmlspecialchars($c["author"]) ?></span>
          <span class="date"><?= $c["created_at"] ?></span>
        </div>
        <!-- VULN STORED XSS : contenu affiché sans échappement (CWE-79) -->
        <div class="text"><?= $c["content"] ?></div>
        <div class="actions">
          <!-- VULN IDOR : tout le monde peut supprimer (CWE-639) -->
          <a href="?delete=<?= $c["id"] ?>">supprimer</a>
        </div>
      </div>
    <?php endforeach; endif; ?>
  </div>

</div>

<?php render_footer(); ?>
