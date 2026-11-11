#!/usr/bin/env bash
# Gera dist/Dupin-Scan/ (interface), dist/dupin-scan-cli/ (linha de comando, sem o Qt) e build/dupin-scan_<versão>_<arch>.deb
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
# Opcionais: se falharem, o Dupin-Scan funciona sem eles (YARA, .evtx e hives exportados).
pip install -q yara-python || echo "[aviso] yara-python não instalado; seguindo sem YARA."
pip install -q python-evtx regipy || echo "[aviso] python-evtx/regipy não instalados; sem forense offline."
python packaging/make_icon.py

pyinstaller --noconfirm --clean --windowed --name Dupin-Scan \
  --icon assets/dupin-scan.png --add-data "assets:assets" run_dupin_scan.py
# Linha de comando: executável separado, com console e SEM o Qt (bem menor).
pyinstaller --noconfirm --clean --console --name dupin-scan-cli \
  --exclude-module PySide6 dupin_scan_cli.py

PKG="build/dupin-scan_${VERSION}_${ARCH}"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN" "$PKG/opt/dupin_scan/cli" "$PKG/usr/bin" \
         "$PKG/usr/share/applications" "$PKG/usr/share/icons/hicolor/512x512/apps"
cp -r dist/Dupin-Scan/* "$PKG/opt/dupin_scan/"
cp -r dist/dupin-scan-cli/* "$PKG/opt/dupin_scan/cli/"
cp assets/dupin-scan.png "$PKG/usr/share/icons/hicolor/512x512/apps/dupin-scan.png"

# "dupin-scan" abre a interface; subcomandos (scan, analyze, ...) vão para a CLI. "dupin-scan-cli" é o executável só de console.
cat > "$PKG/usr/bin/dupin-scan" <<'SH'
#!/bin/sh
exec /opt/dupin_scan/Dupin-Scan "$@"
SH
cat > "$PKG/usr/bin/dupin-scan-cli" <<'SH'
#!/bin/sh
exec /opt/dupin_scan/cli/dupin-scan-cli "$@"
SH
# Lançador com privilégios elevados (necessário para ver todos os processos/pastas).
# Em alguns ambientes Wayland, root não consegue abrir janelas: use "sudo -E dupin-scan".
cat > "$PKG/usr/bin/dupin-scan-root" <<'SH'
#!/bin/sh
exec pkexec env DISPLAY="$DISPLAY" XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
  WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
  /opt/dupin_scan/Dupin-Scan "$@"
SH
chmod 755 "$PKG/usr/bin/dupin-scan" "$PKG/usr/bin/dupin-scan-cli" "$PKG/usr/bin/dupin-scan-root"

cat > "$PKG/usr/share/applications/dupin-scan.desktop" <<'DESK'
[Desktop Entry]
Type=Application
Name=Dupin-Scan
Comment=Triagem de ameaças: arquivos, persistência, processos e artefatos forenses
Exec=dupin-scan %F
Icon=dupin-scan
Terminal=false
Categories=System;Security;
Actions=root;

[Desktop Action root]
Name=Executar com privilégios elevados
Exec=dupin-scan-root
DESK

cat > "$PKG/DEBIAN/control" <<CTL
Package: dupin-scan
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Depends: libc6, libgl1, libegl1, libxkbcommon-x11-0, libxcb-cursor0, libfontconfig1, libdbus-1-3
Recommends: policykit-1
Maintainer: Douglas <noreply@example.com>
Description: Dupin-Scan - triagem de ameaças
 Varredura de arquivos, persistência, processos e artefatos forenses, com quarentena
 reversível, mapeamento MITRE ATT&CK e exportação de regras Sigma/YARA.
 Interface gráfica (dupin-scan) e linha de comando (dupin-scan-cli).
 Ferramenta de triagem; não substitui antivírus ou EDR.
CTL

dpkg-deb --build --root-owner-group "$PKG" "build/dupin-scan_${VERSION}_${ARCH}.deb"
( cd build && sha256sum "dupin-scan_${VERSION}_${ARCH}.deb" > SHA256SUMS )
echo "Pacote: build/dupin-scan_${VERSION}_${ARCH}.deb (checksum em build/SHA256SUMS)"
