@echo off
cd /d "%~dp0"
if not exist ".venv" call start.bat
call .venv\Scripts\activate.bat
pip install --quiet pytest pytest-mock
python -m pytest tests/ -v --tb=short
pause
