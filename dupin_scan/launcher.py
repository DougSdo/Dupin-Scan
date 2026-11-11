"""Ponto de entrada único: subcomandos vão para a CLI; o resto abre a interface gráfica.

    dupin-scan                      abre a interface
    dupin-scan arquivo1 pasta2      abre a interface já com esses alvos (menu "Abrir com" / "Varrer com o Dupin-Scan")
    dupin-scan scan --out r.json    linha de comando (ver `dupin-scan scan --help`)

A interface (PySide6) só é importada quando necessária, para a CLI funcionar em servidores sem ambiente gráfico.
"""
import sys

from . import cli


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and (argv[0] in cli.COMMANDS or argv[0] in ("-h", "--help")):
        return cli.main(argv)
    from .gui import main as gui_main
    return gui_main(argv)
