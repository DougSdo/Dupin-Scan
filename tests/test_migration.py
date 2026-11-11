"""Migração dos dados e configurações do tempo em que o programa se chamava Vigil."""
import json
import os

import pytest

from dupin_scan import core


@pytest.fixture
def base(tmp_path, monkeypatch):
    """Pasta-base de dados isolada (vale para Windows e Linux)."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    return tmp_path


def nomes():
    return core.APP_DIR["windows" if os.name == "nt" else "linux"], core.LEGACY_APP_DIR["windows" if os.name == "nt" else "linux"]


def test_nomes_novo_e_antigo():
    assert core.APP_DIR == {"windows": "Dupin-Scan", "linux": "dupin-scan"}
    assert core.LEGACY_APP_DIR == {"windows": "Vigil", "linux": "vigil"}


def test_instalacao_limpa_usa_a_pasta_nova(base):
    novo, _ = nomes()
    assert core.data_dir() == base / novo
    assert not core.data_dir().exists()  # só é criada quando algo for gravado


def test_pasta_antiga_e_renomeada_com_todo_o_conteudo(base):
    novo, antigo = nomes()
    q = base / antigo / "quarantine"
    q.mkdir(parents=True)
    (q / "abc123.quar").write_bytes(b"conteudo isolado")
    (q / "index.json").write_text(json.dumps([{"id": "abc123", "original": "C:\\x\\a.exe", "reasons": [], "sha256": "",
                                               "date": "2026-01-01T00:00:00"}]), encoding="utf-8")
    (base / antigo / "state.json").write_text("{}", encoding="utf-8")
    assert core.data_dir() == base / novo
    assert not (base / antigo).exists()
    assert (base / novo / "quarantine" / "abc123.quar").read_bytes() == b"conteudo isolado"
    assert (base / novo / "state.json").exists()


def test_quarentena_antiga_continua_restauravel(base, tmp_path):
    novo, antigo = nomes()
    q = base / antigo / "quarantine"
    q.mkdir(parents=True)
    (q / "abc123.quar").write_bytes(b"dados")
    destino = tmp_path / "restaurado" / "a.exe"
    (q / "index.json").write_text(json.dumps([{"id": "abc123", "original": str(destino), "reasons": ["r"], "sha256": "s",
                                               "date": "2026-01-01T00:00:00"}]), encoding="utf-8")
    assert [i["id"] for i in core.list_quarantine()] == ["abc123"]
    assert core.restore_quarantine("abc123") == str(destino) and destino.read_bytes() == b"dados"


def test_migracao_e_idempotente(base):
    novo, antigo = nomes()
    (base / antigo).mkdir()
    (base / antigo / "state.json").write_text("1", encoding="utf-8")
    core.data_dir()
    (base / novo / "state.json").write_text("2", encoding="utf-8")  # o usuário já usa a pasta nova
    core.data_dir()
    assert (base / novo / "state.json").read_text(encoding="utf-8") == "2"


def test_se_as_duas_existem_nao_mexe_na_antiga(base):
    novo, antigo = nomes()
    (base / antigo).mkdir()
    (base / antigo / "velho.txt").write_text("velho", encoding="utf-8")
    (base / novo).mkdir()
    (base / novo / "novo.txt").write_text("novo", encoding="utf-8")
    assert core.data_dir() == base / novo
    assert (base / antigo / "velho.txt").exists() and (base / novo / "novo.txt").exists()  # nada é mesclado nem apagado


def test_se_nao_conseguir_mover_continua_na_pasta_antiga_sem_perder_nada(base, monkeypatch):
    novo, antigo = nomes()
    (base / antigo).mkdir()
    (base / antigo / "state.json").write_text("dados", encoding="utf-8")

    def negado(*a, **k):
        raise PermissionError("em uso")

    monkeypatch.setattr(os, "replace", negado)
    assert core.data_dir() == base / antigo
    assert (base / antigo / "state.json").read_text(encoding="utf-8") == "dados"


def test_legacy_data_dir(base):
    _, antigo = nomes()
    assert core.legacy_data_dir() == base / antigo
