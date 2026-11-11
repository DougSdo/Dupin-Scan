"""Executa o laboratório (artefatos inofensivos) como teste de integração. Não usa --registry."""
import importlib.util
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent / "lab" / "run_lab.py"


def _load():
    spec = importlib.util.spec_from_file_location("run_lab", LAB)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_laboratorio_sem_falhas():
    results = _load().run(registry=False, processes=True)
    falhas = [r for r in results if r.status == "FAIL"]
    assert not falhas, "\n".join(f"{r.name}: {r.detail}" for r in falhas)
    assert sum(r.status == "PASS" for r in results) >= 10
