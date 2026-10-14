<?php
require_once "config.php";
render_header("Fetcher d'URL");

$url = $_GET["url"] ?? "";
$result = null;

if ($url) {
    // VULN : fetch direct sans validation d'hôte (CWE-918)
    $ctx = stream_context_create(["http" => ["timeout" => 5]]);
    $result = @file_get_contents($url, false, $ctx);
}
?>

<div class="container-narrow">
  <div class="card">
    <h1>Fetcher d'URL</h1>
    <p class="text-small mb-16">Récupère le contenu d'une URL distante côté serveur.</p>

    <form method="GET" class="form-row">
      <input type="text" name="url" value="<?= htmlspecialchars($url) ?>" placeholder="https://example.com" style="flex:1">
      <button class="btn" type="submit">Récupérer</button>
    </form>

    <?php if ($result !== null): ?>
      <div class="flex-between mt-16 mb-8">
        <h3>Contenu récupéré</h3>
        <span class="text-small"><?= strlen($result) ?> octets</span>
      </div>
      <pre class="code"><?= htmlspecialchars(substr($result, 0, 2000)) ?><?= strlen($result) > 2000 ? "\n…" : "" ?></pre>
    <?php endif; ?>

    <div class="devnote">
      <strong>Note développeur :</strong> aucune liste blanche d'hôtes. Tester
      <code>?url=http://127.0.0.1</code>, <code>?url=file:///etc/hostname</code>,
      ou <code>?url=http://169.254.169.254/latest/meta-data/</code>.
    </div>
  </div>
</div>

<?php render_footer(); ?>
