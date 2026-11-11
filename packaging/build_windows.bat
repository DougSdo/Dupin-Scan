@echo off
REM Gera dist\Dupin-Scan\Dupin-Scan.exe (interface), dist\dupin-scan-cli\dupin-scan-cli.exe (linha de comando),
REM o instalador Output\Dupin-Scan-Setup-1.0.0.exe, os .exe UNICOS (portateis) Output\Dupin-Scan-Portatil.exe e
REM Output\dupin-scan-cli-portatil.exe, e Output\SHA256SUMS.txt.
REM Requisitos: Python 3.10+ (marque "Add to PATH" na instalacao) e Inno Setup 6.
REM
REM Assinatura de codigo (opcional): defina DUPIN_SCAN_SIGN_CERT_NAME com o nome (Subject) de um certificado ja instalado
REM no repositorio do Windows e o signtool (Windows SDK) no PATH. Sem isso, nada e assinado e o SmartScreen avisara.
REM A senha de um .pfx NAO e aceita aqui de proposito (apareceria na lista de processos): importe o certificado.
setlocal
cd /d "%~dp0\.."

python -m pip install --upgrade pip
python -m pip install PySide6 psutil pyinstaller pillow || goto :err
REM Opcionais: se falharem, o Dupin-Scan funciona sem eles (YARA, .evtx e hives exportados).
python -m pip install yara-python || echo [aviso] yara-python nao instalado; seguindo sem YARA.
python -m pip install python-evtx regipy || echo [aviso] python-evtx/regipy nao instalados; sem forense offline.
python packaging\make_icon.py || goto :err

REM Acrescente --uac-admin se quiser que o app sempre peca elevacao ao abrir.
python -m PyInstaller --noconfirm --clean --windowed --name Dupin-Scan ^
  --icon assets\dupin-scan.ico --add-data "assets;assets" run_dupin_scan.py || goto :err

REM Linha de comando: executavel separado, com console e SEM o Qt (fica bem menor).
python -m PyInstaller --noconfirm --clean --console --name dupin-scan-cli ^
  --exclude-module PySide6 dupin_scan_cli.py || goto :err

REM Versao PORTATIL: um unico .exe, sem instalar (serve para pendrive/enviar a alguem). O custo e abrir mais devagar:
REM ele se descompacta em %TEMP% a cada execucao. Vai para Output\ ao lado do instalador.
python -m PyInstaller --noconfirm --clean --onefile --windowed --name Dupin-Scan-Portatil ^
  --icon assets\dupin-scan.ico --add-data "assets;assets" --version-file packaging\version_info.txt run_dupin_scan.py || goto :err
python -m PyInstaller --noconfirm --clean --onefile --console --name dupin-scan-cli-portatil ^
  --exclude-module PySide6 --version-file packaging\version_info.txt dupin_scan_cli.py || goto :err

if defined DUPIN_SCAN_SIGN_CERT_NAME (
  where signtool >nul 2>nul || (echo [erro] signtool nao encontrado no PATH & goto :err)
  for %%F in (dist\Dupin-Scan\Dupin-Scan.exe dist\dupin-scan-cli\dupin-scan-cli.exe dist\Dupin-Scan-Portatil.exe dist\dupin-scan-cli-portatil.exe) do (
    signtool sign /n "%DUPIN_SCAN_SIGN_CERT_NAME%" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "%%F" || goto :err
  )
) else (
  echo [aviso] Sem DUPIN_SCAN_SIGN_CERT_NAME: executaveis NAO assinados.
)

if not exist Output mkdir Output
copy /y dist\Dupin-Scan-Portatil.exe Output\ >nul || goto :err
copy /y dist\dupin-scan-cli-portatil.exe Output\ >nul || goto :err

set ISCC=
where iscc >nul 2>nul && set ISCC=iscc
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set ISCC="%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set ISCC="%ProgramFiles%\Inno Setup 6\ISCC.exe"
REM Instalacao por usuario (ex.: winget --scope user)
if not defined ISCC if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set ISCC="%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"

if not defined ISCC (
  echo.
  echo [!] Inno Setup nao encontrado. O app portatil ja esta em dist\Dupin-Scan\Dupin-Scan.exe
  echo     Para gerar o instalador, instale o Inno Setup 6 e rode este script de novo.
  goto :eof
)
%ISCC% packaging\dupin-scan.iss || goto :err

if defined DUPIN_SCAN_SIGN_CERT_NAME (
  for %%F in (Output\Dupin-Scan-Setup-*.exe) do (
    signtool sign /n "%DUPIN_SCAN_SIGN_CERT_NAME%" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "%%F" || goto :err
  )
)

REM Checksums para quem baixar conferir a integridade.
if exist Output\SHA256SUMS.txt del Output\SHA256SUMS.txt
for %%F in (Output\*.exe) do (
  echo %%~nxF>>Output\SHA256SUMS.txt
  certutil -hashfile "%%F" SHA256 | findstr /v /i /c:"hash" /c:"CertUtil">>Output\SHA256SUMS.txt
)
echo.
echo Instalador e checksums gerados em Output\
goto :eof

:err
echo.
echo Falha na build.
exit /b 1
