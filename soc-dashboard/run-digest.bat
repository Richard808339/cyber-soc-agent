@echo off
REM Bilan quotidien du SOC vers Telegram. Lance par la tache planifiee
REM "SOC Bilan Quotidien" (08:00). Les erreurs sont journalisees.
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python -u daily_digest.py >> "logs\digest.log" 2>&1
