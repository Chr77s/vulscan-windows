@echo off
REM ============================================================
REM  VulnScan Backend - lanceur Windows
REM  Crée un venv si besoin, installe les deps, lance Flask
REM ============================================================

cd /d "%~dp0"

echo [VulnScan] Verification de Python...
where python >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe ou pas dans le PATH.
    echo Telechargez Python 3.10+ sur https://www.python.org/downloads/
    pause
    exit /b 1
)

if not exist ".venv" (
    echo [VulnScan] Creation de l'environnement virtuel...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERREUR] Impossible de creer le venv.
        pause
        exit /b 1
    )
)

echo [VulnScan] Activation du venv...
call .venv\Scripts\activate.bat

echo [VulnScan] Installation des dependances...
pip install --quiet -r requirements.txt
if errorlevel 1 (
    echo [ERREUR] Echec installation des dependances.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   VulnScan Backend Python demarre sur http://127.0.0.1:9876
echo   Ctrl+C pour arreter
echo ============================================================
echo.
python app.py
pause
