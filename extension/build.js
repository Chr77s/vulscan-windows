/**
 * build.js — Script de build cross-platform (Windows + Mac + Linux)
 * Remplace les commandes cp/xcopy par du Node.js pur
 * Usage : node build.js
 */

const fs   = require("fs");
const path = require("path");

// ---- Utilitaires ----
function copyDir(src, dest) {
  if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath  = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

function copyFile(src, dest) {
  const destDir = path.dirname(dest);
  if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
  fs.copyFileSync(src, dest);
}

function log(msg) {
  console.log("[build] " + msg);
}

// ---- Étapes du build ----
log("Démarrage du build VulnScan...");

const SRC  = path.join(__dirname, "src");
const DIST = path.join(__dirname, "dist");

// 1. Nettoyer dist/
if (fs.existsSync(DIST)) {
  fs.rmSync(DIST, { recursive: true, force: true });
  log("dist/ nettoyé");
}
fs.mkdirSync(DIST, { recursive: true });

// 2. Copier le manifest
copyFile(
  path.join(__dirname, "manifest.json"),
  path.join(DIST, "manifest.json")
);
log("manifest.json copié");

// 3. Copier les icônes
const iconsDir = path.join(__dirname, "icons");
if (fs.existsSync(iconsDir)) {
  copyDir(iconsDir, path.join(DIST, "icons"));
  log("icons/ copié");
} else {
  log("ATTENTION : dossier icons/ absent (l'extension fonctionnera sans icones)");
}

// 4. Copier tous les fichiers JS/HTML/CSS/JSON de src/
function copySrcFiles(srcDir, destDir) {
  if (!fs.existsSync(srcDir)) return;
  const entries = fs.readdirSync(srcDir, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath  = path.join(srcDir, entry.name);
    const destPath = path.join(destDir, entry.name);
    if (entry.isDirectory()) {
      copySrcFiles(srcPath, destPath);
    } else if (/\.(js|html|css|json)$/.test(entry.name)) {
      if (!fs.existsSync(path.dirname(destPath))) {
        fs.mkdirSync(path.dirname(destPath), { recursive: true });
      }
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

copySrcFiles(SRC, path.join(DIST, "src"));
log("Fichiers src/ copiés (js, html, css, json)");

log("");
log("==============================================");
log("  Build terminé avec succès !");
log("  Chargez le dossier dist/ dans Chrome.");
log("  chrome://extensions/ > Mode dev > Charger");
log("==============================================");
