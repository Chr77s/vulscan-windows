"""
Module : exposition de fichiers sensibles (focus + intelligence par rapport
au dir-bruteforce générique).

Vérifie spécifiquement :
  - .git/HEAD avec contenu attendu "ref: refs/heads/..."
  - .git/config avec contenu attendu "[core]"
  - .env avec lignes KEY=VALUE
  - swagger.json valide
  - .DS_Store avec magic bytes
  - phpinfo.php → page typique

Chaque détection est confirmée par signature de contenu, pas juste un 200,
ce qui réduit drastiquement les faux positifs.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse
import requests
import re

from scanner.core.module_base import ScannerModule, Finding


class FileExposureModule(ScannerModule):
    name = "file-exposure"
    category = "discovery"
    title = "Sensitive File Exposure"
    description = "Vérifie l'exposition de fichiers spécifiques (.git, .env, backup, phpinfo)."
    default_enabled = True  # passe-passe, peu de requêtes

    # (path, content_pattern, severity, label, cwe)
    SIGNATURES = [
        ("/.git/HEAD",     re.compile(r"^ref:\s*refs/heads/", re.M),     "critical",
         ".git/HEAD exposé — repo Git public",                            "CWE-538"),
        ("/.git/config",   re.compile(r"\[core\]|\[remote\s+\"", re.I),   "critical",
         ".git/config exposé — peut révéler les remotes",                 "CWE-538"),
        ("/.env",          re.compile(r"^[A-Z_]+=", re.M),               "critical",
         ".env exposé — secrets potentiels accessibles",                  "CWE-538"),
        ("/.env.local",    re.compile(r"^[A-Z_]+=", re.M),               "critical",
         ".env.local exposé",                                            "CWE-538"),
        ("/swagger.json",  re.compile(r'"openapi"|"swagger"', re.I),      "medium",
         "Spec OpenAPI/Swagger exposée — cartographie l'API",             "CWE-200"),
        ("/.DS_Store",     re.compile(rb"\x00\x00\x00\x01Bud1", re.S),    "low",
         ".DS_Store exposé — révèle structure de dossier macOS",          "CWE-538"),
        ("/phpinfo.php",   re.compile(r"PHP Version|<title>phpinfo", re.I), "high",
         "phpinfo() exposé — révèle config PHP complète",                 "CWE-200"),
        ("/server-status", re.compile(r"Apache Server Status|Server uptime", re.I), "high",
         "Apache server-status exposé",                                  "CWE-200"),
        ("/.htpasswd",     re.compile(rb":\$apr|^[a-zA-Z]+:[\$\w]+", re.M), "high",
         ".htpasswd exposé — hash de mots de passe",                      "CWE-538"),
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path, pattern, sev, label, cwe in self.SIGNATURES:
            try:
                r = requests.get(base + path, timeout=5,
                                 headers={"User-Agent": "VulnScan/1.2"},
                                 allow_redirects=False)
            except Exception:
                continue
            if r.status_code != 200:
                continue

            # Vérifier signature (sur text ou bytes selon la regex)
            body = r.text if isinstance(pattern.pattern, str) else r.content
            try:
                m = pattern.search(body)
            except TypeError:
                m = None
            if not m:
                continue

            findings.append(Finding(
                type="exposed-secret-file" if "env" in path or "git" in path or "htpasswd" in path
                     else "info-disclosure",
                severity=sev,
                title=label,
                description=(
                    f"Le fichier {path} est servi publiquement avec signature de contenu valide. "
                    f"Ne devrait pas être accessible."
                ),
                recommendation=(
                    "Bloquer ce chemin côté serveur :\n"
                    " - Apache : .htaccess `Require all denied`\n"
                    " - Nginx : `location ~ /\\.git { deny all; }`\n"
                    " - IIS : configurer dans web.config\n"
                    "Supprimer le fichier si possible."
                ),
                url=base + path, parameter=path,
                evidence=str(m.group(0))[:200] if hasattr(m, "group") else "(match binaire)",
                confidence=95,
                cwe_id=cwe, owasp_id="A05:2021",
                cvss_base=9.1 if sev == "critical" else 7.5 if sev == "high" else 5.3 if sev == "medium" else 3.7,
                detection_method="content-signature",
                source="module:file-exposure",
            ))
        return findings
