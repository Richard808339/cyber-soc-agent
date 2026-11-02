@echo off
REM Ecoute Telegram en continu pour le broker d'autorisation (HITL).
REM Lance au logon par SOC-Broker-Telegram.vbs (dossier Demarrage).
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python -u broker.py watch >> "logs\broker.log" 2>&1
