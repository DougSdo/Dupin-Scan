@echo off
REM Executa o Dupin-Scan direto do codigo, sem instalar nada no sistema (usa uma venv local).
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  python -m venv .venv || (echo Python nao encontrado no PATH & exit /b 1)
  .venv\Scripts\python -m pip install --upgrade pip
  .venv\Scripts\python -m pip install PySide6 psutil
  .venv\Scripts\python -m pip install yara-python || echo [aviso] seguindo sem YARA
)
start "" .venv\Scripts\pythonw.exe run_dupin_scan.py
