<?php
require_once "../config.php";
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");

// 💀 VULN JWT : signé avec un secret trivial "secret123" (CWE-798)
// Et : algorithme HS256 sans vérification "alg: none"

function b64url($data) { return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); }

function jwt_sign($payload, $secret) {
    $h = b64url(json_encode(["alg" => "HS256", "typ" => "JWT"]));
    $p = b64url(json_encode($payload));
    $s = b64url(hash_hmac("sha256", "$h.$p", $secret, true));
    return "$h.$p.$s";
}

$user_id = $_GET["user_id"] ?? 1;
$payload = [
    "sub"  => $user_id,
    "role" => "user",
    "iat"  => time(),
    "exp"  => time() + 3600,
];
$token = jwt_sign($payload, $JWT_SECRET);

echo json_encode([
    "token" => $token,
    "secret_hint" => "Try cracking with john/hashcat — the secret is short and weak",
]);
