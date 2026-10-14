<?php
require_once "config.php";
render_header("Produit");

$id = $_GET["id"] ?? "1";

// VULN : SQLi sur ?id= (concaténation directe)
$sql = "SELECT * FROM products WHERE id = $id";
$stmt = db()->query($sql);
$product = $stmt ? $stmt->fetch(PDO::FETCH_ASSOC) : null;

if (!$product) {
    echo "<div class='container'><div class='alert alert-error'>Produit introuvable.<br>";
    echo "<span class='text-mono'>" . htmlspecialchars($sql) . "</span></div></div>";
    render_footer();
    exit;
}
?>

<div class="container-narrow">
  <div class="card">
    <?php render_product_image($product["id"], $product["name"], "detail") ?>
    <h1><?= htmlspecialchars($product["name"]) ?></h1>
    <p class="mt-8 mb-16"><?= htmlspecialchars($product["description"]) ?></p>

    <div class="flex-between mt-16 mb-24">
      <div class="price" style="font-size:24px;font-weight:700;color:var(--text-0)">
        <?= number_format((float)$product["price"], 2, ',', ' ') ?> €
      </div>
      <div class="text-small">Note : <strong><?= $product["rating"] ?? "4.5" ?>/5</strong></div>
    </div>

    <div class="form-row">
      <button class="btn">Ajouter au panier</button>
      <button class="btn btn-secondary">Mettre en favori</button>
    </div>

    <div class="divider"></div>

    <h3>Caractéristiques</h3>
    <dl class="dl">
      <dt>Référence</dt><dd class="text-mono">PROD-<?= str_pad((string)$product["id"], 5, "0", STR_PAD_LEFT) ?></dd>
      <dt>Disponibilité</dt><dd><?= ($product["stock"] ?? 0) > 0 ? "En stock" : "Épuisé" ?></dd>
      <dt>Note moyenne</dt><dd><?= $product["rating"] ?? "—" ?>/5</dd>
    </dl>

    <div class="devnote">
      <strong>Note développeur :</strong>
      incrémenter <code>?id=</code> donne accès aux autres produits (IDOR).
      Tester aussi <code>?id=1 UNION SELECT 1,username,password,4,5,6,7,8,9 FROM users-- </code>.
    </div>
  </div>
</div>

<?php render_footer(); ?>
