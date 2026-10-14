<?php
require_once "config.php";
render_header("Catalogue");

$products = db()->query("SELECT * FROM products LIMIT 50")->fetchAll(PDO::FETCH_ASSOC);
?>

<div class="container">
  <div class="page-head">
    <h1>Catalogue</h1>
    <span class="page-subtitle"><?= count($products) ?> produits disponibles</span>
  </div>

  <div class="grid-3">
    <?php foreach ($products as $p): ?>
      <div class="product-card">
        <?php render_product_image($p["id"], $p["name"], "card") ?>
        <div class="product-body">
          <div class="product-name"><?= htmlspecialchars($p["name"]) ?></div>
          <div class="product-desc"><?= htmlspecialchars(mb_substr($p["description"], 0, 90)) ?>…</div>
          <div class="price"><?= number_format((float)$p["price"], 2, ',', ' ') ?> €</div>
          <!-- VULN IDOR : id incrémental sans check ownership -->
          <a href="product.php?id=<?= $p["id"] ?>" class="btn btn-secondary btn-small product-cta">Voir le détail</a>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
</div>

<?php render_footer(); ?>
