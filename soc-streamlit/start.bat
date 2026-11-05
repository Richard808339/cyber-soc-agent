@echo off
rem Lance le tableau de bord Streamlit sur http://127.0.0.1:8501
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  .venv\Scripts\python.exe -m pip install -r requirements.txt
)
.venv\Scripts\python.exe -m streamlit run app.py --server.port 8501
