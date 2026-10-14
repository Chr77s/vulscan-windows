<?php
require_once "../config.php";
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");

// 💀 VULN IDOR + Broken Access Control (CWE-639, CWE-862)
// N'importe qui peut voir n'importe quelle commande en changeant ?user_id=
$user_id = $_GET["user_id"] ?? 1;

// SQL injection sur user_id par la même occasion
$sql = "SELECT o.*, p.name as product_name, u.username
        FROM orders o
        JOIN products p ON o.product_id = p.id
        JOIN users u ON o.user_id = u.id
        WHERE o.user_id = $user_id";

$stmt = db()->query($sql);
$orders = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];

echo json_encode([
    "user_id" => $user_id,
    "orders" => $orders,
    "_debug_sql" => $sql,  // 💀 expose la requête (CWE-209)
]);
