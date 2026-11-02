@echo off
REM Lance le tableau de bord SOC sur http://127.0.0.1:8765
cd /d "%~dp0"
python app.py %*
