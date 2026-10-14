<?php
require_once "../config.php";

// VULN MAJEURE :
//  - Aucune authentification (CWE-862)
//  - Aucun token CSRF (CWE-352)
//  - GET pour une action destructive (CWE-650)
//  - SQLi sur ?id= (CWE-89)
$id = $_GET["id"] ?? null;

if ($id) {
    db()->exec("DELETE FROM users WHERE id = $id");
    header("Location: index.php?deleted=$id");
    exit;
}

render_header("Suppression utilisateur");
?>

<div class="container-form">
  <div class="card">
    <h1>Supprimer un utilisateur</h1>

    <div class="alert alert-error">
      <strong>Action irréversible.</strong> Aucune confirmation supplémentaire n'est demandée.
    </div>

    <form method="GET">
      <div class="form-group">
        <label for="id">ID de l'utilisateur</label>
        <input type="text" id="id" name="id" placeholder="Ex: 2" required>
      </div>
      <button class="btn btn-danger btn-block" type="submit">Supprimer</button>
    </form>

    <div class="devnote">
      <strong>Note développeur :</strong> action destructive en GET, sans authentification,
      sans token CSRF, et avec SQLi sur <code>?id=</code>. Tester <code>?id=2 OR 1=1</code>
      pour supprimer la totalité de la table.
    </div>
  </div>
</div>

<?php render_footer(); ?>
