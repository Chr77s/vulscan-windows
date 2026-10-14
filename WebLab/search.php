<?php
require_once "config.php";
render_header("Recherche");

$q = $_GET["q"] ?? "";
?>

<div class="container">
  <div class="card">
    <div class="page-head">
      <h2>Rechercher dans le catalogue</h2>
    </div>

    <form method="GET" class="form-row">
      <!-- VULN : valeur non échappée — Reflected XSS (CWE-79) -->
      <input type="text" name="q" value="<?= /* NON ÉCHAPPÉ */ $q ?>" placeholder="Mots-clés produits" style="flex:1">
      <button class="btn" type="submit">Rechercher</button>
    </form>

    <?php if ($q): ?>
      <!-- VULN : injection directe dans le HTML — XSS reflété -->
      <div class="alert alert-info mt-16">
        Vous avez recherché : <strong><?= $q ?></strong>
      </div>

      <?php
      // VULN : SQLi sur LIKE (concaténation)
      $sql = "SELECT * FROM products WHERE name LIKE '%$q%' OR description LIKE '%$q%'";
      $stmt = db()->query($sql);
      if ($stmt) {
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          if (count($results) > 0):
      ?>
        <table class="mt-16">
          <thead>
            <tr><th>Produit</th><th>Description</th><th>Prix</th></tr>
          </thead>
          <tbody>
            <?php foreach ($results as $r): ?>
              <tr>
                <td><a href="product.php?id=<?= $r['id'] ?>"><?= htmlspecialchars($r['name']) ?></a></td>
                <td class="text-small"><?= htmlspecialchars(mb_substr($r['description'], 0, 80)) ?>…</td>
                <td class="text-mono"><?= number_format((float)$r['price'], 2, ',', ' ') ?> €</td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      <?php else: ?>
        <p class="text-small mt-16">Aucun résultat pour cette recherche.</p>
      <?php endif; } ?>
    <?php endif; ?>

    <div class="devnote">
      <strong>Note développeur :</strong> tester <code>?q=&lt;script&gt;alert(1)&lt;/script&gt;</code> pour XSS,
      ou <code>?q=' UNION SELECT 1,username,password,4,5,6,7,8,9 FROM users-- </code> pour SQLi.
    </div>
  </div>
</div>

<?php render_footer(); ?>
