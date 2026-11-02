@echo off
REM Collecte Wazuh -> tableau de bord SOC.
REM Appele par la tache planifiee "SOC Dashboard Collector" toutes les 5 minutes.
setlocal
cd /d "%~dp0"
set PY="C:\Users\HP\AppData\Local\Python\pythoncore-3.14-64\python.exe"
if not exist %PY% set PY=python
echo ---- %DATE% %TIME% ---- >> collector.log
%PY% collector.py >> collector.log 2>&1
echo code=%ERRORLEVEL% >> collector.log
endlocal
