@echo off
REM Gera dist\Vigil\Vigil.exe (interface), dist\vigil-cli\vigil-cli.exe (linha de comando),
REM o instalador Output\Vigil-Setup-1.0.0.exe, os .exe UNICOS (portateis) Output\Vigil-Portatil.exe e
REM Output\vigil-cli-portatil.exe, e Output\SHA256SUMS.txt.
REM Requisitos: Python 3.10+ (marque "Add to PATH" na instalacao) e Inno Setup 6.
REM
REM Assinatura de codigo (opcional): defina VIGIL_SIGN_CERT_NAME com o nome (Subject) de um certificado ja instalado
REM no repositorio do Windows e o signtool (Windows SDK) no PATH. Sem isso, nada e assinado e o SmartScreen avisara.
REM A senha de um .pfx NAO e aceita aqui de proposito (apareceria na lista de processos): importe o certificado.
setlocal
cd /d "%~dp0\.."

python -m pip install --upgrade pip
python -m pip install PySide6 psutil pyinstaller pillow || goto :err
REM Opcionais: se falharem, o Vigil funciona sem eles (YARA, .evtx e hives exportados).
python -m pip install yara-python || echo [aviso] yara-python nao instalado; seguindo sem YARA.
python -m pip install python-evtx regipy || echo [aviso] python-evtx/regipy nao instalados; sem forense offline.
python packaging\make_icon.py || goto :err

REM Acrescente --uac-admin se quiser que o app sempre peca elevacao ao abrir.
python -m PyInstaller --noconfirm --clean --windowed --name Vigil ^
  --icon assets\vigil.ico --add-data "assets;assets" run_vigil.py || goto :err

REM Linha de comando: executavel separado, com console e SEM o Qt (fica bem menor).
python -m PyInstaller --noconfirm --clean --console --name vigil-cli ^
  --exclude-module PySide6 vigil_cli.py || goto :err

REM Versao PORTATIL: um unico .exe, sem instalar (serve para pendrive/enviar a alguem). O custo e abrir mais devagar:
REM ele se descompacta em %TEMP% a cada execucao. Vai para Output\ ao lado do instalador.
python -m PyInstaller --noconfirm --clean --onefile --windowed --name Vigil-Portatil ^
  --icon assets\vigil.ico --add-data "assets;assets" --version-file packaging\version_info.txt run_vigil.py || goto :err
python -m PyInstaller --noconfirm --clean --onefile --console --name vigil-cli-portatil ^
  --exclude-module PySide6 --version-file packaging\version_info.txt vigil_cli.py || goto :err

if defined VIGIL_SIGN_CERT_NAME (
  where signtool >nul 2>nul || (echo [erro] signtool nao encontrado no PATH & goto :err)
  for %%F in (dist\Vigil\Vigil.exe dist\vigil-cli\vigil-cli.exe dist\Vigil-Portatil.exe dist\vigil-cli-portatil.exe) do (
    signtool sign /n "%VIGIL_SIGN_CERT_NAME%" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "%%F" || goto :err
  )
) else (
  echo [aviso] Sem VIGIL_SIGN_CERT_NAME: executaveis NAO assinados.
)

if not exist Output mkdir Output
copy /y dist\Vigil-Portatil.exe Output\ >nul || goto :err
copy /y dist\vigil-cli-portatil.exe Output\ >nul || goto :err

set ISCC=
where iscc >nul 2>nul && set ISCC=iscc
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set ISCC="%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set ISCC="%ProgramFiles%\Inno Setup 6\ISCC.exe"
REM Instalacao por usuario (ex.: winget --scope user)
if not defined ISCC if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set ISCC="%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"

if not defined ISCC (
  echo.
  echo [!] Inno Setup nao encontrado. O app portatil ja esta em dist\Vigil\Vigil.exe
  echo     Para gerar o instalador, instale o Inno Setup 6 e rode este script de novo.
  goto :eof
)
%ISCC% packaging\vigil.iss || goto :err

if defined VIGIL_SIGN_CERT_NAME (
  for %%F in (Output\Vigil-Setup-*.exe) do (
    signtool sign /n "%VIGIL_SIGN_CERT_NAME%" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "%%F" || goto :err
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
