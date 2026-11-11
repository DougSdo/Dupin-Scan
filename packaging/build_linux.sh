#!/usr/bin/env bash
# Gera dist/Vigil/ (interface), dist/vigil-cli/ (linha de comando, sem o Qt) e build/vigil_<versão>_<arch>.deb
# Requisitos: python3, python3-venv, dpkg-deb (Debian/Ubuntu e derivados)
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="1.0.0"
command -v dpkg-deb >/dev/null || { echo "dpkg-deb não encontrado (use Debian/Ubuntu)"; exit 1; }
ARCH="$(dpkg --print-architecture)"

python3 -m venv .venv-build
source .venv-build/bin/activate
pip install -q --upgrade pip
pip install -q PySide6 psutil pyinstaller pillow
# Opcionais: se falharem, o Vigil funciona sem eles (YARA, .evtx e hives exportados).
pip install -q yara-python || echo "[aviso] yara-python não instalado; seguindo sem YARA."
pip install -q python-evtx regipy || echo "[aviso] python-evtx/regipy não instalados; sem forense offline."
python packaging/make_icon.py

pyinstaller --noconfirm --clean --windowed --name Vigil \
  --icon assets/vigil.png --add-data "assets:assets" run_vigil.py
# Linha de comando: executável separado, com console e SEM o Qt (bem menor).
pyinstaller --noconfirm --clean --console --name vigil-cli \
  --exclude-module PySide6 vigil_cli.py

PKG="build/vigil_${VERSION}_${ARCH}"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN" "$PKG/opt/vigil/cli" "$PKG/usr/bin" \
         "$PKG/usr/share/applications" "$PKG/usr/share/icons/hicolor/512x512/apps"
cp -r dist/Vigil/* "$PKG/opt/vigil/"
cp -r dist/vigil-cli/* "$PKG/opt/vigil/cli/"
cp assets/vigil.png "$PKG/usr/share/icons/hicolor/512x512/apps/vigil.png"

# "vigil" abre a interface; subcomandos (scan, analyze, ...) vão para a CLI. "vigil-cli" é o executável só de console.
cat > "$PKG/usr/bin/vigil" <<'SH'
#!/bin/sh
exec /opt/vigil/Vigil "$@"
SH
cat > "$PKG/usr/bin/vigil-cli" <<'SH'
#!/bin/sh
exec /opt/vigil/cli/vigil-cli "$@"
SH
# Lançador com privilégios elevados (necessário para ver todos os processos/pastas).
# Em alguns ambientes Wayland, root não consegue abrir janelas: use "sudo -E vigil".
cat > "$PKG/usr/bin/vigil-root" <<'SH'
#!/bin/sh
exec pkexec env DISPLAY="$DISPLAY" XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
  WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
  /opt/vigil/Vigil "$@"
SH
chmod 755 "$PKG/usr/bin/vigil" "$PKG/usr/bin/vigil-cli" "$PKG/usr/bin/vigil-root"

cat > "$PKG/usr/share/applications/vigil.desktop" <<'DESK'
[Desktop Entry]
Type=Application
Name=Vigil
Comment=Triagem de ameaças: arquivos, persistência, processos e artefatos forenses
Exec=vigil %F
Icon=vigil
Terminal=false
Categories=System;Security;
Actions=root;

[Desktop Action root]
Name=Executar com privilégios elevados
Exec=vigil-root
DESK

cat > "$PKG/DEBIAN/control" <<CTL
Package: vigil
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Depends: libc6, libgl1, libegl1, libxkbcommon-x11-0, libxcb-cursor0, libfontconfig1, libdbus-1-3
Recommends: policykit-1
Maintainer: Douglas <noreply@example.com>
Description: Vigil - triagem de ameaças
 Varredura de arquivos, persistência, processos e artefatos forenses, com quarentena
 reversível, mapeamento MITRE ATT&CK e exportação de regras Sigma/YARA.
 Interface gráfica (vigil) e linha de comando (vigil-cli).
 Ferramenta de triagem; não substitui antivírus ou EDR.
CTL

dpkg-deb --build --root-owner-group "$PKG" "build/vigil_${VERSION}_${ARCH}.deb"
( cd build && sha256sum "vigil_${VERSION}_${ARCH}.deb" > SHA256SUMS )
echo "Pacote: build/vigil_${VERSION}_${ARCH}.deb (checksum em build/SHA256SUMS)"
