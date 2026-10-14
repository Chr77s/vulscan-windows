<?php
require_once "../config.php";
header("Content-Type: application/json");
// 💀 VULN CORS : permissif (CWE-942)
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Credentials: true");

// 💀 VULN : pas d'authentification. Retourne TOUT (CWE-306)
$users = db()->query("SELECT * FROM users")->fetchAll(PDO::FETCH_ASSOC);
echo json_encode([
    "users" => $users,
    "internal_api_key" => $ADMIN_API_KEY,
    "jwt_secret" => $JWT_SECRET,
]);
