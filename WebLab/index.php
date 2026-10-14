<?php
require_once "config.php";
render_header("Accueil");

// Récup produits vedette pour rendre la home crédible
try {
    $featured = db()->query("SELECT id, name, description, price FROM products LIMIT 6")->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    $featured = [];
}
?>

<div class="container">

  <section class="hero">
    <h1>WebLab Store</h1>
    <p>Plateforme de démonstration interne pour tests d'application web. Les pages, formulaires et endpoints réutilisent les schémas classiques d'un site e-commerce.</p>
    <div class="mt-16 flex gap-10">
      <a href="products.php" class="btn">Voir le catalogue</a>
      <a href="login.php" class="btn btn-secondary">Se connecter</a>
    </div>
  </section>

  <?php if ($featured): ?>
  <section class="mb-24">
    <div class="page-head">
      <h2>Produits en vedette</h2>
      <a href="products.php" class="text-small">Voir tout →</a>
    </div>
    <div class="grid-3">
      <?php foreach ($featured as $p): ?>
        <div class="product-card">
          <?php render_product_image($p["id"], $p["name"], "card") ?>
          <div class="product-body">
            <div class="product-name"><?= htmlspecialchars($p['name']) ?></div>
            <div class="product-desc"><?= htmlspecialchars(mb_substr($p['description'], 0, 90)) ?>…</div>
            <div class="price"><?= number_format((float)$p['price'], 2, ',', ' ') ?> €</div>
            <a href="product.php?id=<?= $p['id'] ?>" class="btn btn-secondary btn-small product-cta">Détail produit</a>
          </div>
        </div>
      <?php endforeach; ?>
    </div>
  </section>
  <?php endif; ?>

  <section class="card">
    <div class="page-head">
      <h2>Pages disponibles</h2>
      <span class="page-subtitle">Surface de l'application</span>
    </div>
    <div class="grid-3">
      <div>
        <h3>Authentification</h3>
        <p class="text-small">Connexion, inscription, gestion de session.</p>
        <div class="mt-8 flex gap-10">
          <a href="login.php" class="btn-link">Connexion</a>
          <a href="register.php" class="btn-link">Inscription</a>
        </div>
      </div>
      <div>
        <h3>Catalogue</h3>
        <p class="text-small">Recherche produit, fiche détaillée, panier.</p>
        <div class="mt-8 flex gap-10">
          <a href="search.php" class="btn-link">Recherche</a>
          <a href="products.php" class="btn-link">Produits</a>
        </div>
      </div>
      <div>
        <h3>Communauté</h3>
        <p class="text-small">Commentaires publics et avis.</p>
        <div class="mt-8 flex gap-10">
          <a href="comments.php" class="btn-link">Commentaires</a>
        </div>
      </div>
      <div>
        <h3>Espace personnel</h3>
        <p class="text-small">Profil utilisateur, bio, préférences.</p>
        <div class="mt-8 flex gap-10">
          <a href="profile.php" class="btn-link">Mon profil</a>
        </div>
      </div>
      <div>
        <h3>Outils</h3>
        <p class="text-small">Upload de fichier, proxy URL, parseur XML.</p>
        <div class="mt-8 flex gap-10">
          <a href="upload.php" class="btn-link">Upload</a>
          <a href="ssrf.php" class="btn-link">Fetcher URL</a>
          <a href="xxe.php" class="btn-link">Endpoint XML</a>
        </div>
      </div>
      <div>
        <h3>API</h3>
        <p class="text-small">Endpoints REST publics : utilisateurs, commandes, JWT.</p>
        <div class="mt-8 flex gap-10">
          <a href="api/users.php" class="btn-link">/api/users</a>
          <a href="api/jwt.php?user_id=1" class="btn-link">/api/jwt</a>
        </div>
      </div>
    </div>
  </section>

  <section class="card">
    <h2>Comptes de démonstration</h2>
    <p class="text-small mb-16">Utilisables pour tester les flux authentifiés.</p>
    <table>
      <thead>
        <tr><th>Identifiant</th><th>Mot de passe</th><th>Rôle</th><th>Notes</th></tr>
      </thead>
      <tbody>
        <tr><td>admin</td><td class="text-mono">admin123</td><td><span class="tag">admin</span></td><td>Compte par défaut.</td></tr>
        <tr><td>alice</td><td class="text-mono">password</td><td><span class="tag">user</span></td><td>Profil avec bio.</td></tr>
        <tr><td>bob</td><td class="text-mono">qwerty</td><td><span class="tag">user</span></td><td>A des commandes.</td></tr>
        <tr><td>charlie</td><td class="text-mono">letmein</td><td><span class="tag">user</span></td><td>—</td></tr>
      </tbody>
    </table>
  </section>

  <div class="alert alert-warn mt-24">
    <strong>Environnement de test.</strong>
    Cette application est volontairement vulnérable à des fins de démonstration et d'exercice. Ne pas exposer sur Internet.
  </div>

</div>

<?php render_footer(); ?>
