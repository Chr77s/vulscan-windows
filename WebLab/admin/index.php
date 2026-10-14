<?php
require_once "../config.php";

// VULN MAJEURE : aucun contrôle d'accès (CWE-862, CWE-284)
render_header("Administration");

$users = db()->query("SELECT id, username, email, role, password, created_at FROM users")->fetchAll(PDO::FETCH_ASSOC);
?>

<div class="container">

  <div class="alert alert-error">
    <strong>Accès non protégé.</strong> Aucun contrôle d'accès n'est en place sur cette section.
  </div>

  <div class="card">
    <div class="page-head">
      <h1>Utilisateurs</h1>
      <span class="page-subtitle"><?= count($users) ?> comptes</span>
    </div>

    <table>
      <thead>
        <tr><th>ID</th><th>Identifiant</th><th>Email</th><th>Rôle</th><th>Hash mot de passe</th><th>Créé le</th></tr>
      </thead>
      <tbody>
        <?php foreach ($users as $u): ?>
          <tr>
            <td class="text-mono"><?= $u["id"] ?></td>
            <td><?= htmlspecialchars($u["username"]) ?></td>
            <td class="text-small"><?= htmlspecialchars($u["email"]) ?></td>
            <td><span class="tag <?= $u["role"] === "admin" ? "tag-danger" : "" ?>"><?= $u["role"] ?></span></td>
            <td class="text-mono" style="font-size:11px"><?= $u["password"] ?></td>
            <td class="text-small"><?= $u["created_at"] ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Actions rapides</h2>
    <p class="text-small mb-16">Outils de modération.</p>
    <a href="delete_user.php" class="btn btn-danger">Supprimer un utilisateur</a>
  </div>

</div>

<?php render_footer(); ?>
