<?php
// VULN CRLF Injection (CWE-93) — paramètre injecté brut dans un header HTTP
$lang = $_GET["lang"] ?? "fr";
header("Set-Cookie: lang=$lang");

require_once "config.php";
render_header("Préférences");
?>

<div class="container-narrow">
  <div class="card">
    <h1>Préférences linguistiques</h1>
    <p class="mt-8 mb-16">Langue active : <strong><?= htmlspecialchars($lang) ?></strong></p>

    <div class="flex gap-10">
      <a href="?lang=fr" class="btn btn-secondary btn-small">Français</a>
      <a href="?lang=en" class="btn btn-secondary btn-small">English</a>
      <a href="?lang=es" class="btn btn-secondary btn-small">Español</a>
    </div>

    <div class="devnote">
      <strong>Note développeur :</strong> la valeur de <code>?lang=</code> est insérée brute
      dans le header <code>Set-Cookie</code>. Tester
      <code>?lang=fr%0d%0aSet-Cookie:%20admin=true</code> pour injecter un second cookie,
      ou couper la réponse HTTP avec <code>%0d%0a%0d%0a</code> (HTTP Response Splitting).
    </div>
  </div>
</div>

<?php render_footer(); ?>
