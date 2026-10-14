<?php
require_once "config.php";
render_header("Pages");

$page = $_GET["page"] ?? "home";

// VULN LFI : inclusion sans validation (CWE-22, CWE-98)
$file = __DIR__ . "/pages/" . $page . ".php";
?>

<div class="container-narrow">
  <div class="card">
    <h2>Contenu dynamique</h2>

    <div class="flex gap-10 mb-16">
      <a href="?page=home" class="btn btn-secondary btn-small">Accueil</a>
      <a href="?page=about" class="btn btn-secondary btn-small">À propos</a>
    </div>

    <div class="card-section">
      <?php
      if (file_exists($file)) {
          include($file);
      } else {
          // VULN : fallback inclusion brute
          @include($page);
      }
      ?>
    </div>

    <div class="devnote">
      <strong>Note développeur :</strong> le paramètre <code>?page=</code> est passé directement
      à <code>include()</code>. Tester
      <code>?page=../../../../wamp64/www/WebLab/config</code> ou
      <code>?page=php://filter/read=convert.base64-encode/resource=config</code>.
    </div>
  </div>
</div>

<?php render_footer(); ?>
