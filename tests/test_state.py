"""Lista de ignorados e histórico de achados vistos (baseline)."""
import json
from datetime import datetime

import pytest

from dupin_scan import core, forensics, state


@pytest.fixture(autouse=True)
def pasta_de_dados(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "data_dir", lambda: tmp_path / "dados")
    return tmp_path / "dados"


def arq(where="C:\\x\\a.exe", sha="aa", **k):
    return {"type": "file", "where": where, "score": 50, "reasons": ["r"], "sha256": sha, **k}


def proc(pid, name="x.exe", exe="C:\\x.exe", cmd="x -a"):
    return {"type": "process", "where": f"PID {pid} {name}", "score": 50, "reasons": ["r"], "exe": exe, "cmdline": cmd}


# ------------------------------------------------------------ chave
def test_chave_do_processo_nao_depende_do_pid():
    assert state.fingerprint(proc(100)) == state.fingerprint(proc(9999))
    assert state.fingerprint(proc(1)) != state.fingerprint(proc(1, cmd="x -b"))


def test_chave_do_arquivo_muda_se_o_conteudo_muda():
    assert state.fingerprint(arq(sha="aa")) == state.fingerprint(arq(sha="aa"))
    assert state.fingerprint(arq(sha="aa")) != state.fingerprint(arq(sha="bb"))
    assert state.fingerprint(arq(where="C:\\x\\a.exe")) != state.fingerprint(arq(where="C:\\y\\a.exe"))


def test_chave_do_artefato_ignora_contagens():
    a = {"type": "artifact", "where": "auth.log · 1.2.3.4", "source": "auth.log", "reasons": ["10 falhas"]}
    b = {**a, "reasons": ["25 falhas"]}
    assert state.fingerprint(a) == state.fingerprint(b)


def test_chave_nao_colide_entre_tipos():
    assert state.fingerprint({"type": "file", "where": "x"}) != state.fingerprint({"type": "persistence", "where": "x"})


# ------------------------------------------------------------ ignorados
def test_ignorar_e_desfazer():
    f = arq()
    key = state.ignore(f, "esperado")
    assert state.ignore(f) == key and len(state.list_ignored()) == 1  # idempotente
    assert state.list_ignored()[0]["note"] == "esperado"
    assert state.unignore(key) is True and state.list_ignored() == []
    assert state.unignore(key) is False


def test_annotate_remove_os_ignorados_e_devolve_separados():
    state.ignore(arq("A"))
    kept, ignored = state.annotate([arq("A"), arq("B")], {"file"})
    assert [f["where"] for f in kept] == ["B"] and [f["where"] for f in ignored] == ["A"]


def test_arquivo_ignorado_que_muda_volta_a_aparecer():
    state.ignore(arq("A", sha="aa"))
    kept, _ = state.annotate([arq("A", sha="novo")], {"file"})
    assert len(kept) == 1


# ------------------------------------------------------------ novo desde a última vez
def test_primeira_varredura_nao_marca_nada_como_novo():
    kept, _ = state.annotate([arq("A")], {"file"})
    assert kept[0]["new"] is None


def test_segunda_varredura_distingue_novo_de_conhecido():
    state.annotate([arq("A")], {"file"})
    kept, _ = state.annotate([arq("A"), arq("B")], {"file"})
    por_local = {f["where"]: f for f in kept}
    assert por_local["A"]["new"] is False and por_local["B"]["new"] is True
    assert por_local["A"]["first_seen"] <= por_local["B"]["first_seen"]


def test_tipo_nunca_varrido_continua_sem_marca():
    state.annotate([arq("A")], {"file"})
    kept, _ = state.annotate([proc(1)], {"process"})
    assert kept[0]["new"] is None  # a 1ª varredura de processos não afirma nada


def test_first_seen_e_preservado():
    state.annotate([arq("A")], {"file"}, now=datetime(2026, 1, 1))
    kept, _ = state.annotate([arq("A")], {"file"}, now=datetime(2026, 6, 1))
    assert kept[0]["first_seen"].startswith("2026-01-01")


def test_varredura_cancelada_nao_grava():
    kept, _ = state.annotate([arq("A")], {"file"}, update=False)
    assert state.load()["seen"] == {} and state.load()["types"] == []


# ------------------------------------------------------------ arquivo de estado
def test_estado_corrompido_e_preservado(pasta_de_dados):
    state.ignore(arq("A"))
    (pasta_de_dados / "state.json").write_text("{ lixo", encoding="utf-8")
    assert state.list_ignored() == []
    assert list(pasta_de_dados.glob("state.corrompido-*.json"))


def test_estado_com_formato_errado_e_tratado_como_corrompido(pasta_de_dados):
    pasta_de_dados.mkdir(parents=True)
    (pasta_de_dados / "state.json").write_text(json.dumps({"ignore": "nao-e-lista", "seen": []}), encoding="utf-8")
    assert state.load()["ignore"] == []


def test_gravacao_atomica_sem_sobras(pasta_de_dados):
    state.ignore(arq("A"))
    assert not list(pasta_de_dados.glob("*.tmp"))


def test_limite_de_historico(monkeypatch):
    monkeypatch.setattr(state, "MAX_SEEN", 5)
    state.annotate([arq(f"f{i}") for i in range(20)], {"file"})
    assert len(state.load()["seen"]) == 5


# ------------------------------------------------------------ integração com run_scan
def _forense(monkeypatch, achados):
    monkeypatch.setattr(forensics, "run_forensics", lambda *a, **k: [dict(x) for x in achados])


def test_run_scan_sem_track_nao_escreve_nada(monkeypatch, pasta_de_dados):
    _forense(monkeypatch, [core.finding("artifact", "x", [("t", 50)], source="s", detail="d")])
    rep = core.run_scan(modules=("forensics",))
    assert not pasta_de_dados.exists() and rep["ignored"] == [] and rep["findings"][0].get("new") is None


def test_run_scan_com_track_marca_novos_e_separa_ignorados(monkeypatch):
    base = [core.finding("artifact", "A", [("t", 50)], source="s", detail="d"),
            core.finding("artifact", "B", [("t", 60)], source="s", detail="d")]
    _forense(monkeypatch, base[:1])
    core.run_scan(modules=("forensics",), track=True)
    _forense(monkeypatch, base)
    rep = core.run_scan(modules=("forensics",), track=True)
    assert rep["new"] == 1 and [f["where"] for f in rep["findings"] if f["new"]] == ["B"]
    state.ignore(rep["findings"][0])
    rep = core.run_scan(modules=("forensics",), track=True)
    assert len(rep["ignored"]) == 1 and len(rep["findings"]) == 1 and rep["ignored"][0]["level"]
