<?php
require_once "config.php";

// VULN Weak Session Management (CWE-330)
function weak_session_token() {
    return md5(time() . "_weblab");
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $token = weak_session_token();
    db()->exec("INSERT INTO sessions (id, token, expires_at, ip, user_agent) VALUES (
        '" . md5(time()) . "', '$token', NOW() + INTERVAL 1 HOUR,
        '" . $_SERVER["REMOTE_ADDR"] . "', '" . addslashes($_SERVER["HTTP_USER_AGENT"]) . "'
    )");
    header("Location: sessions.php?created=$token");
    exit;
}

render_header("Sessions");
$sessions = db()->query("SELECT * FROM sessions ORDER BY id DESC LIMIT 20")->fetchAll(PDO::FETCH_ASSOC);
?>

<div class="container">

  <div class="card">
    <div class="page-head">
      <h1>Gestion des sessions</h1>
      <span class="page-subtitle">Génération et suivi des tokens applicatifs</span>
    </div>

    <?php if (isset($_GET["created"])): ?>
      <div class="alert alert-success">
        Nouvelle session créée — token <span class="text-mono"><?= htmlspecialchars($_GET["created"]) ?></span>
      </div>
    <?php endif; ?>

    <form method="POST">
      <button class="btn" type="submit">Générer un nouveau token</button>
    </form>

    <div class="devnote">
      <strong>Note développeur :</strong> les tokens sont générés via
      <code>md5(time() . "_weblab")</code>. Connaissant l'horodatage approximatif,
      l'espace est brute-forçable en quelques secondes.
    </div>
  </div>

  <div class="card">
    <h2>Sessions actives</h2>
    <?php if (empty($sessions)): ?>
      <p class="text-small">Aucune session enregistrée.</p>
    <?php else: ?>
    <table>
      <thead><tr><th>ID</th><th>Token</th><th>Expire</th><th>IP</th></tr></thead>
      <tbody>
        <?php foreach ($sessions as $s): ?>
          <tr>
            <td class="text-mono"><?= htmlspecialchars($s["id"]) ?></td>
            <td class="text-mono"><?= htmlspecialchars($s["token"]) ?></td>
            <td class="text-small"><?= $s["expires_at"] ?></td>
            <td class="text-small"><?= htmlspecialchars($s["ip"]) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
    <?php endif; ?>
  </div>

</div>

<?php render_footer(); ?>
