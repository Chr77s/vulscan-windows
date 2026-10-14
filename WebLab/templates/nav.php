<?php
global $BASE_URL;
$u = $_SESSION['user'] ?? null;
$current = basename($_SERVER['SCRIPT_NAME']);
function _na($f, $current) { return $f === $current ? 'class="active"' : ''; }
?>
<nav class="navbar">
  <a href="<?= $BASE_URL ?>/index.php" class="nav-brand">WebLab</a>
  <a href="<?= $BASE_URL ?>/products.php" <?= _na('products.php', $current) ?>>Produits</a>
  <a href="<?= $BASE_URL ?>/search.php"   <?= _na('search.php', $current) ?>>Recherche</a>
  <a href="<?= $BASE_URL ?>/comments.php" <?= _na('comments.php', $current) ?>>Commentaires</a>
  <span class="spacer"></span>
  <?php if ($u): ?>
    <a href="<?= $BASE_URL ?>/profile.php" <?= _na('profile.php', $current) ?>>
      <span class="nav-user"><?= htmlspecialchars($u['username']) ?></span>
    </a>
    <a href="<?= $BASE_URL ?>/logout.php">Déconnexion</a>
  <?php else: ?>
    <a href="<?= $BASE_URL ?>/login.php"    <?= _na('login.php', $current) ?>>Connexion</a>
    <a href="<?= $BASE_URL ?>/register.php" <?= _na('register.php', $current) ?>>Inscription</a>
  <?php endif; ?>
</nav>
