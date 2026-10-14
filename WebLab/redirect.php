<?php
// 💀 VULN Open Redirect (CWE-601)
// Aucune validation : ?url=https://evil.com → redirige sans broncher
$url = $_GET["url"] ?? "/";
header("Location: $url");
exit;
