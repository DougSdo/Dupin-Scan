"""Entrada da linha de comando para empacotamento (PyInstaller --console): não importa a interface gráfica."""
import sys

from dupin_scan.cli import main

if __name__ == "__main__":
    sys.exit(main())
