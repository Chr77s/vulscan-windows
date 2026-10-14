<?php
// ============================================================
//  WebLab — Configuration globale
//  Volontairement non-sécurisée pour exercices pédagogiques
// ============================================================

// --- Database (MySQL via WAMP) ---
$DB_HOST = "localhost";
$DB_NAME = "weblab";
$DB_USER = "root";
$DB_PASS = "";   // mot de passe vide par défaut WAMP

// --- Application ---
$APP_NAME    = "WebLab Store";
$APP_VERSION = "1.0";
$BASE_URL    = "/WebLab";

// --- Secrets (EXPOSÉS DELIBÉRÉMENT) ---
$JWT_SECRET    = "secret123";                    // CWE-798
$ADMIN_API_KEY = "sk_live_weblab_admin_42_lab";  // CWE-798
$ENCRYPTION_KEY = "weblab_encrypt_2024";         // CWE-326

// --- Connexion DB ---
function db() {
    global $DB_HOST, $DB_NAME, $DB_USER, $DB_PASS;
    static $pdo = null;
    if ($pdo === null) {
        try {
            $pdo = new PDO("mysql:host=$DB_HOST;dbname=$DB_NAME;charset=utf8mb4", $DB_USER, $DB_PASS);
            // Volontaire : erreurs en mode "warning" pour exposer les requêtes SQL
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_WARNING);
        } catch (PDOException $e) {
            die("DB connexion error: " . $e->getMessage());  // Stack trace exposée (CWE-209)
        }
    }
    return $pdo;
}

// --- Session non sécurisée volontairement ---
session_start();  // Pas de session_set_cookie_params() — manque Secure/HttpOnly/SameSite

// --- Inclure le header HTML commun ---
function render_header($title = "WebLab") {
    global $APP_NAME, $BASE_URL;
    echo "<!DOCTYPE html><html lang='fr'><head><meta charset='UTF-8'>";
    echo "<title>$title — $APP_NAME</title>";
    // Aucun X-Frame-Options, aucun CSP, aucun HSTS
    echo "<link rel='stylesheet' href='$BASE_URL/assets/style.css'>";
    echo "</head><body>";
    include __DIR__ . "/templates/nav.php";
    echo "<main class='container'>";
}

function render_footer() {
    echo "</main>";
    echo "<footer><div class='container'>WebLab — environnement de démonstration. Ne pas exposer en production.</div></footer>";
    echo "</body></html>";
}

// --- Hash non-sécurisé volontaire (CWE-327 / CWE-916) ---
function weak_hash($password) {
    return md5($password);  // md5 = obsolète, sans salt
}

// --- Helper image produit ---
// Cherche une image dans assets/products/{id}.{ext} parmi plusieurs extensions.
// Retourne soit l'URL relative, soit null si rien trouvé → on affichera un placeholder.
function product_image_url($product_id) {
    global $BASE_URL;
    foreach (["jpg", "jpeg", "png", "webp", "avif"] as $ext) {
        $rel = "assets/products/{$product_id}.{$ext}";
        $abs = __DIR__ . "/" . $rel;
        if (file_exists($abs)) {
            return "{$BASE_URL}/{$rel}";
        }
    }
    return null;
}

// Affiche soit <img>, soit un placeholder gris avec initiale.
function render_product_image($product_id, $product_name, $size = "card") {
    $url = product_image_url($product_id);
    $initial = strtoupper(mb_substr($product_name, 0, 1));
    $class = "product-image product-image-{$size}";
    if ($url) {
        echo '<div class="' . $class . '"><img src="' . htmlspecialchars($url) . '" alt="' . htmlspecialchars($product_name) . '" loading="lazy"></div>';
    } else {
        echo '<div class="' . $class . ' product-image-placeholder"><span>' . htmlspecialchars($initial) . '</span></div>';
    }
}
