<?php
require_once "config.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $xml_input = file_get_contents("php://input");
    if (!$xml_input) {
        $xml_input = $_POST["xml"] ?? "";
    }

    // VULN : entités externes non désactivées (CWE-611)
    if (PHP_VERSION_ID < 80000) {
        libxml_disable_entity_loader(false);
    }
    $opts = LIBXML_NOENT | LIBXML_DTDLOAD;
    libxml_use_internal_errors(true);

    try {
        $doc = new DOMDocument();
        $doc->loadXML($xml_input, $opts);
        $output = $doc->saveXML();
        header("Content-Type: application/xml");
        echo $output;
        exit;
    } catch (Exception $e) {
        header("Content-Type: text/plain", true, 400);
        echo "XML error: " . $e->getMessage();
        exit;
    }
}

render_header("Endpoint XML");
?>

<div class="container-narrow">
  <div class="card">
    <h1>Endpoint de parsing XML</h1>
    <p class="text-small mb-16">Envoyez un document XML, recevez sa version normalisée.</p>

    <form method="POST">
      <div class="form-group">
        <label for="xml">Document XML</label>
        <textarea id="xml" name="xml" rows="8" class="text-mono" style="font-family:var(--mono);font-size:12px"><?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root>&xxe;</root></textarea>
      </div>
      <button class="btn" type="submit">Analyser</button>
    </form>

    <div class="devnote">
      <strong>Note développeur :</strong> le parseur autorise les entités externes
      (<code>LIBXML_NOENT | LIBXML_DTDLOAD</code>). Tester un payload XXE comme ci-dessus
      pour lire <code>/etc/hostname</code> ou tout fichier accessible par le process Apache.
    </div>
  </div>
</div>

<?php render_footer(); ?>
