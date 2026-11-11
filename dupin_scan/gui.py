"""Dupin-Scan - interface gráfica (PySide6)."""
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QSettings, QThread, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QCheckBox, QComboBox, QFileDialog, QFrame, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QProgressBar,
    QPushButton, QScrollArea, QStackedWidget, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout,
    QWidget, QAbstractItemView,
)

from . import attack, core, export_rules, forensics, intel, report, state

APP_NAME = "Dupin-Scan"
APP_VERSION = "1.0.0"

LEVEL_COLORS = {"ALTO": "#ef4444", "MÉDIO": "#f59e0b", "BAIXO": "#60a5fa"}

def migrate_legacy_settings(new):
    """Copia as configurações do tempo em que o programa se chamava Vigil, se ainda não há nenhuma nas novas.
    Caminhos que apontavam para a pasta de dados antiga são reescritos para a nova. A chave antiga não é apagada.
    Devolve quantas configurações foram copiadas."""
    if new.allKeys():
        return 0
    old = QSettings("Vigil", "Vigil")
    keys = old.allKeys()
    legacy_root, new_root = str(core.legacy_data_dir()), str(core.data_dir())
    for k in keys:
        v = old.value(k)
        if isinstance(v, str) and legacy_root and v.startswith(legacy_root):
            v = new_root + v[len(legacy_root):]
        new.setValue(k, v)
    new.sync()
    return len(keys)


def asset(name):
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return str(base / "assets" / name).replace("\\", "/")


QSS = """
* { font-family: "Segoe UI", "Inter", "Noto Sans", "Ubuntu", sans-serif; font-size: 13px; }
QMainWindow, QWidget#root { background: #0f172a; }
QWidget { color: #e2e8f0; }
QFrame#sidebar { background: #0b1222; border-right: 1px solid #1e293b; }
QLabel#brand { font-size: 20px; font-weight: 700; color: #f8fafc; }
QLabel#brandSub { color: #64748b; font-size: 11px; }
QPushButton#nav { text-align: left; padding: 10px 14px; border: none; border-radius: 8px;
    color: #94a3b8; background: transparent; font-size: 14px; }
QPushButton#nav:hover { background: #162038; color: #e2e8f0; }
QPushButton#nav:checked { background: #1e3a5f; color: #ffffff; font-weight: 600; }
QLabel#h1 { font-size: 24px; font-weight: 700; color: #f8fafc; }
QLabel#sub { color: #94a3b8; }
QFrame#card { background: #131c31; border: 1px solid #1e293b; border-radius: 12px; }
QLabel#cardTitle { font-weight: 600; font-size: 14px; color: #f1f5f9; }
QLabel#muted { color: #94a3b8; }
QPushButton { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 8px 14px; color: #e2e8f0; }
QPushButton:hover { background: #26354d; }
QPushButton:disabled { color: #475569; background: #172033; border-color: #1e293b; }
QPushButton#primary { background: #2563eb; border: none; color: white; font-weight: 600; font-size: 14px; padding: 12px 22px; }
QPushButton#primary:hover { background: #3b82f6; }
QPushButton#danger { background: #7f1d1d; border: none; color: #fecaca; }
QPushButton#danger:hover { background: #991b1b; }
QComboBox, QLineEdit { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 7px 10px; }
QComboBox QAbstractItemView { background: #131c31; selection-background-color: #1e3a5f; border: 1px solid #334155; }
QListWidget, QTextEdit { background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 4px; }
QListWidget::item { padding: 5px; }
QListWidget::item:selected { background: #1e3a5f; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 18px; height: 18px; border-radius: 5px; border: 1px solid #475569; background: #0f172a; }
QCheckBox::indicator:checked { background: #2563eb; border-color: #2563eb; image: url(@CHECK@); }
QProgressBar { background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; height: 14px; text-align: center; color: transparent; }
QProgressBar::chunk { background: #2563eb; border-radius: 7px; }
QTableWidget { background: #0f172a; border: 1px solid #1e293b; border-radius: 10px; gridline-color: #1e293b;
    selection-background-color: #1e3a5f; selection-color: #ffffff; alternate-background-color: #111a2e; }
QHeaderView::section { background: #131c31; color: #94a3b8; border: none; border-bottom: 1px solid #1e293b; padding: 8px; font-weight: 600; }
QScrollBar:vertical { background: transparent; width: 10px; }
QScrollBar::handle:vertical { background: #334155; border-radius: 5px; min-height: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QLabel#chip { border-radius: 10px; padding: 6px 14px; font-weight: 600; }
QScrollArea { background: transparent; border: none; }
QScrollArea > QWidget > QWidget { background: transparent; }
"""


def card(title=None):
    f = QFrame()
    f.setObjectName("card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(18, 16, 18, 16)
    lay.setSpacing(10)
    if title:
        t = QLabel(title)
        t.setObjectName("cardTitle")
        lay.addWidget(t)
    return f, lay


def header(title, subtitle):
    box = QVBoxLayout()
    box.setSpacing(2)
    a = QLabel(title)
    a.setObjectName("h1")
    b = QLabel(subtitle)
    b.setObjectName("sub")
    b.setWordWrap(True)
    box.addWidget(a)
    box.addWidget(b)
    return box


# ------------------------------------------------------------------ worker
class ScanWorker(QThread):
    progress = Signal(str, int)
    found = Signal(dict)
    done = Signal(dict)

    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            rep = core.run_scan(**self.cfg, on_progress=lambda m, n: self.progress.emit(m, n),
                                on_finding=lambda f: self.found.emit(f),
                                cancelled=lambda: self._cancel)
        except Exception as e:  # noqa
            rep = {"error": str(e), "findings": [], "files_scanned": 0, "notes": [str(e)]}
        self.done.emit(rep)


class FuncWorker(QThread):
    """Roda uma função em segundo plano (rede, análise de arquivo) sem travar a janela."""
    done = Signal(object, str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs

    def run(self):
        try:
            self.done.emit(self.fn(*self.args, **self.kwargs), "")
        except Exception as e:  # noqa
            self.done.emit(None, str(e) or type(e).__name__)


def run_async(owner, fn, on_done, *args, **kwargs):
    """Executa fn(*args) numa thread; on_done(resultado, erro) roda na thread da interface."""
    w = FuncWorker(fn, *args, **kwargs)
    workers = owner.__dict__.setdefault("_workers", [])
    workers.append(w)
    w.done.connect(on_done)
    w.finished.connect(lambda: workers.remove(w) if w in workers else None)
    w.start()
    return w


def wait_workers(owner, ms=3000):
    for w in list(owner.__dict__.get("_workers", [])):
        w.wait(ms)


# ------------------------------------------------------------------ páginas
class ScanPage(QWidget):
    scan_finished = Signal(dict)
    artifact_report = Signal(dict)

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self.worker = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(16)
        lay.addLayout(header("Varredura", "Procure arquivos, persistências e processos suspeitos neste computador."))

        row = QHBoxLayout()
        row.setSpacing(16)

        c1, l1 = card("Sistema operacional")
        self.os_combo = QComboBox()
        self.os_combo.addItem("Detectar automaticamente", None)
        self.os_combo.addItem("Windows", "windows")
        self.os_combo.addItem("Linux", "linux")
        self.os_combo.currentIndexChanged.connect(self.fill_default_targets)
        l1.addWidget(self.os_combo)
        hint = QLabel(f"Detectado: {'Windows' if core.host_os() == 'windows' else 'Linux'}")
        hint.setObjectName("muted")
        l1.addWidget(hint)
        row.addWidget(c1)

        c2, l2 = card("O que verificar")
        self.cb_files = QCheckBox("Arquivos (hash, YARA, heurísticas)")
        self.cb_pers = QCheckBox("Persistência (inicialização, tarefas, cron)")
        self.cb_proc = QCheckBox("Processos em execução")
        self.cb_for = QCheckBox("Artefatos forenses (logs de eventos, auth.log, históricos)")
        for cb in (self.cb_files, self.cb_pers, self.cb_proc, self.cb_for):
            cb.setChecked(True)
            l2.addWidget(cb)
        row.addWidget(c2)
        lay.addLayout(row)

        c3, l3 = card("Pastas e arquivos a varrer")
        self.targets = QListWidget()
        self.targets.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.targets.setMinimumHeight(110)
        l3.addWidget(self.targets)
        br = QHBoxLayout()
        b_add = QPushButton("Adicionar pasta…")
        b_file = QPushButton("Adicionar arquivo…")
        b_rm = QPushButton("Remover")
        b_def = QPushButton("Restaurar padrão")
        b_add.clicked.connect(self.add_target)
        b_file.clicked.connect(self.add_files)
        b_rm.clicked.connect(self.remove_target)
        b_def.clicked.connect(self.fill_default_targets)
        for b in (b_add, b_file, b_rm, b_def):
            br.addWidget(b)
        br.addStretch()
        l3.addLayout(br)
        lay.addWidget(c3)

        c4, l4 = card()
        top = QHBoxLayout()
        self.status = QLabel("Pronto para iniciar.")
        self.status.setObjectName("muted")
        self.status.setMinimumWidth(10)
        self.counter = QLabel("")
        self.counter.setObjectName("muted")
        top.addWidget(self.status, 1)
        top.addWidget(self.counter)
        l4.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setRange(0, 1)
        self.bar.setValue(0)
        l4.addWidget(self.bar)
        bottom = QHBoxLayout()
        self.btn_art = QPushButton("Analisar artefato exportado…")
        self.btn_art.setToolTip("Abre um .evtx, hive (Amcache/SYSTEM), auth.log, histórico de shell ou .pf copiado de outra máquina")
        self.btn_art.clicked.connect(self.analyze_artifact)
        self.btn = QPushButton("Iniciar varredura")
        self.btn.setObjectName("primary")
        self.btn.setCursor(Qt.PointingHandCursor)
        self.btn.clicked.connect(self.toggle)
        bottom.addWidget(self.btn_art)
        bottom.addStretch()
        bottom.addWidget(self.btn)
        l4.addLayout(bottom)
        lay.addWidget(c4)
        lay.addStretch()
        self.fill_default_targets()
        self.n_found = 0

    def current_os(self):
        return self.os_combo.currentData() or core.host_os()

    def fill_default_targets(self):
        self.targets.clear()
        self.targets.addItems(core.default_targets(self.current_os()))

    def add_target(self):
        d = QFileDialog.getExistingDirectory(self, "Escolha a pasta")
        if d:
            self.targets.addItem(d)

    def add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Escolha os arquivos")
        for p in paths:
            self.targets.addItem(p)

    def set_targets(self, paths):
        """Substitui os alvos (arrastar e soltar, 'Abrir com', linha de comando)."""
        self.targets.clear()
        self.targets.addItems([str(p) for p in paths])
        self.cb_pers.setChecked(False)  # varrer um arquivo avulso não deve revarrer o computador todo
        self.cb_proc.setChecked(False)
        self.cb_for.setChecked(False)
        self.cb_files.setChecked(True)

    def remove_target(self):
        for it in self.targets.selectedItems():
            self.targets.takeItem(self.targets.row(it))

    def analyze_artifact(self):
        if not hasattr(forensics, "analyze_artifact_file"):
            QMessageBox.information(self, APP_NAME, "Esta versão não analisa artefatos exportados.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Artefato exportado", "",
                                              "Artefatos (*.evtx *.hve *.hiv *.pf *.log *.gz *_history *.txt);;Todos (*)")
        if not path:
            return
        self.btn_art.setEnabled(False)
        self.status.setText(f"Analisando {Path(path).name}…")

        def work():
            findings, notes = forensics.analyze_artifact_file(path)
            return core.make_report(findings, notes)

        def done(rep, err):
            self.btn_art.setEnabled(True)
            if err:
                self.status.setText("Falha ao analisar o artefato.")
                QMessageBox.warning(self, APP_NAME, f"Não foi possível analisar:\n{err}")
                return
            self.status.setText(f"Artefato analisado: {len(rep['findings'])} achados.")
            self.artifact_report.emit(rep)

        run_async(self, work, done)

    def toggle(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.btn.setEnabled(False)
            self.status.setText("Cancelando…")
            return
        modules = [m for m, cb in (("files", self.cb_files), ("persistence", self.cb_pers),
                                   ("processes", self.cb_proc), ("forensics", self.cb_for)) if cb.isChecked()]
        if not modules:
            QMessageBox.information(self, APP_NAME, "Selecione ao menos um item para verificar.")
            return
        cfg = dict(
            os_name=self.current_os(), modules=modules,
            targets=[self.targets.item(i).text() for i in range(self.targets.count())] or None,
            hashes_path=self.settings.value("hashes", "") or None,
            yara_dir=self.settings.value("yara", "") or None,
            check_trust=True, track=True,  # confiança do binário + lista de ignorados + "novo desde a última vez"
        )
        self.n_found = 0
        self.worker = ScanWorker(cfg)
        self.worker.progress.connect(self.on_progress)
        self.worker.found.connect(self.on_found)
        self.worker.done.connect(self.on_done)
        self.bar.setRange(0, 0)  # indeterminada
        self.btn.setText("Cancelar")
        self.btn.setObjectName("danger")
        self.btn.setStyleSheet("")
        self.btn.style().unpolish(self.btn)
        self.btn.style().polish(self.btn)
        self.status.setText("Varrendo…")
        self.worker.start()

    def shutdown(self):
        """Chamado ao fechar a janela: cancela a varredura e espera a thread terminar."""
        w = self.worker
        if not (w and w.isRunning()):
            return
        for sig, slot in ((w.progress, self.on_progress), (w.found, self.on_found), (w.done, self.on_done)):
            try:
                sig.disconnect(slot)
            except (RuntimeError, TypeError):
                pass
        w.cancel()
        if not w.wait(15000):  # último recurso: uma etapa travada (ex.: schtasks lento)
            w.terminate()
            w.wait()

    def on_progress(self, msg, n):
        fm = self.status.fontMetrics()
        self.status.setText(fm.elidedText(msg, Qt.ElideMiddle, max(self.status.width(), 300)))
        self.counter.setText(f"{n:,} arquivos · {self.n_found} achados".replace(",", "."))

    def on_found(self, _f):
        self.n_found += 1

    def on_done(self, rep):
        self.bar.setRange(0, 1)
        self.bar.setValue(1)
        self.btn.setEnabled(True)
        self.btn.setText("Iniciar varredura")
        self.btn.setObjectName("primary")
        self.btn.style().unpolish(self.btn)
        self.btn.style().polish(self.btn)
        msg = "Varredura cancelada." if rep.get("cancelled") else "Varredura concluída."
        self.status.setText(msg)
        self.counter.setText(f"{rep.get('files_scanned', 0):,} arquivos · {len(rep.get('findings', []))} achados".replace(",", "."))
        self.scan_finished.emit(rep)


LEVEL_RANK = {"BAIXO": 0, "MÉDIO": 1, "ALTO": 2}


class LevelItem(QTableWidgetItem):
    """Ordena por gravidade (ALTO > MÉDIO > BAIXO) em vez de ordem alfabética."""

    def __lt__(self, other):
        a, b = LEVEL_RANK.get(self.text(), 0), LEVEL_RANK.get(other.text(), 0)
        if a != b:
            return a < b
        fa, fb = self.data(Qt.UserRole), other.data(Qt.UserRole)
        return (fa or {}).get("score", 0) < (fb or {}).get("score", 0)


class ResultsPage(QWidget):
    quarantine_changed = Signal()
    ignored_changed = Signal()

    def __init__(self, settings=None):
        super().__init__()
        self.settings = settings
        self.report = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(14)
        lay.addLayout(header("Resultados", "Achados são triagem: confirme antes de agir. Falsos positivos são esperados."))

        self.chips = QHBoxLayout()
        self.chips.setSpacing(10)
        self.chip_labels = {}
        self.vt_worker = None
        for lv in ("ALTO", "MÉDIO", "BAIXO"):
            c = QLabel()
            c.setObjectName("chip")
            self.chip_labels[lv] = c
            self.chips.addWidget(c)
        self.summary = QLabel("")
        self.summary.setObjectName("muted")
        self.chips.addWidget(self.summary)
        self.chips.addStretch()
        self.cb_new = QCheckBox("Só os novos")
        self.cb_new.setToolTip("Mostra apenas o que não tinha aparecido em varreduras anteriores")
        self.cb_new.stateChanged.connect(self.apply_filter)
        self.chips.addWidget(self.cb_new)
        lay.addLayout(self.chips)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Gravidade", "Tipo", "Local", "ATT&CK", "Pontos", "Novo"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSortingEnabled(True)
        h = self.table.horizontalHeader()
        for col, mode in enumerate((QHeaderView.ResizeToContents, QHeaderView.ResizeToContents,
                                    QHeaderView.Stretch, QHeaderView.ResizeToContents,
                                    QHeaderView.ResizeToContents, QHeaderView.ResizeToContents)):
            h.setSectionResizeMode(col, mode)
        self.table.itemSelectionChanged.connect(self.show_details)
        lay.addWidget(self.table, 3)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Selecione um achado para ver os detalhes.")
        lay.addWidget(self.details, 2)

        br = QHBoxLayout()
        self.b_q = QPushButton("Enviar para quarentena")
        self.b_open = QPushButton("Abrir pasta")
        self.b_ign = QPushButton("Ignorar este achado")
        self.b_ign.setToolTip("Marca como esperado: não aparece mais nas próximas varreduras (reversível em Configurações)")
        self.b_vt = QPushButton("Consultar VirusTotal")
        self.b_vt.setToolTip("Envia SÓ o hash SHA-256 (nunca o arquivo) à VirusTotal, depois da sua confirmação")
        self.b_exp = QPushButton("Exportar relatório…")
        self.b_q.clicked.connect(self.quarantine)
        self.b_open.clicked.connect(self.open_folder)
        self.b_ign.clicked.connect(self.ignore_current)
        self.b_vt.clicked.connect(self.lookup_vt)
        self.b_exp.clicked.connect(self.export)
        for b in (self.b_q, self.b_open, self.b_ign, self.b_vt):
            br.addWidget(b)
        br.addStretch()
        br.addWidget(self.b_exp)
        lay.addLayout(br)
        self.set_report(None)

    def update_chips(self):
        counts = {"ALTO": 0, "MÉDIO": 0, "BAIXO": 0}
        for f in (self.report or {}).get("findings", []):
            counts[f.get("level", "BAIXO")] += 1
        for lv, lab in self.chip_labels.items():
            col = LEVEL_COLORS[lv]
            lab.setText(f"{counts[lv]}  {lv.capitalize()}")
            r, g, b = (int(col[i:i + 2], 16) for i in (1, 3, 5))
            lab.setStyleSheet(f"background: rgba({r},{g},{b},40); color: {col};")
        rep = self.report or {}
        bits = []
        if rep.get("new"):
            bits.append(f"{rep['new']} novos")
        if rep.get("ignored"):
            bits.append(f"{len(rep['ignored'])} ignorados")
        self.summary.setText(" · ".join(bits))

    def apply_filter(self):
        only_new = self.cb_new.isChecked()
        for r in range(self.table.rowCount()):
            f = self.table.item(r, 0).data(Qt.UserRole) or {}
            self.table.setRowHidden(r, only_new and not f.get("new"))

    def set_report(self, rep):
        self.report = rep
        findings = (rep or {}).get("findings", [])
        self.update_chips()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for f in findings:
            r = self.table.rowCount()
            self.table.insertRow(r)
            lv = LevelItem(f["level"])
            lv.setForeground(QColor(LEVEL_COLORS[f["level"]]))
            lv.setData(Qt.UserRole, f)
            kind = {"file": "Arquivo", "persistence": "Persistência", "process": "Processo",
                    "artifact": "Artefato"}.get(f["type"], f["type"])
            sc = QTableWidgetItem()
            sc.setData(Qt.DisplayRole, int(f["score"]))
            self.table.setItem(r, 0, lv)
            self.table.setItem(r, 1, QTableWidgetItem(kind))
            self.table.setItem(r, 2, QTableWidgetItem(f["where"]))
            techs = f.get("attack", [])
            tech_item = QTableWidgetItem(", ".join(t["id"] for t in techs))
            tech_item.setToolTip("\n".join(attack.describe(t) for t in techs))
            self.table.setItem(r, 3, tech_item)
            self.table.setItem(r, 4, sc)
            novo = QTableWidgetItem("●" if f.get("new") else "")
            novo.setForeground(QColor("#60a5fa"))
            novo.setToolTip("Primeira vez que aparece" if f.get("new") else "")
            self.table.setItem(r, 5, novo)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(4, Qt.DescendingOrder)
        self.apply_filter()
        self.details.clear()
        if rep and not findings:
            self.details.setHtml("<p style='color:#4ade80'>Nenhum achado nesta varredura.</p>")
        if rep and rep.get("notes"):
            self.details.append("<p style='color:#fbbf24'>" + "<br>".join(self.esc(n) for n in rep["notes"]) + "</p>")
        self.update_buttons()

    def current(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.table.item(rows[0].row(), 0).data(Qt.UserRole)

    def update_buttons(self):
        f = self.current()
        self.b_q.setEnabled(bool(f and f["type"] == "file"))
        self.b_open.setEnabled(bool(f and f["type"] == "file"))
        self.b_ign.setEnabled(bool(f))
        self.b_vt.setEnabled(bool(f and self.hash_of(f)))
        self.b_exp.setEnabled(bool(self.report))

    @staticmethod
    def hash_of(f):
        return f.get("sha256") or (f.get("target") or {}).get("sha256") or ""

    def show_details(self):
        f = self.current()
        self.update_buttons()
        if not f:
            return
        col = LEVEL_COLORS[f["level"]]
        html = [f"<h3 style='color:{col}; margin:0'>{f['level']} · {f['score']} pontos</h3>",
                f"<p><b>Local:</b> {self.esc(f['where'])}</p>", "<p><b>Motivos:</b></p><ul>"]
        html += [f"<li>{self.esc(r)}</li>" for r in f["reasons"]]
        html.append("</ul>")
        if f.get("attack"):
            html.append("<p><b>MITRE ATT&amp;CK:</b></p><ul>")
            html += [f"<li>{self.esc(attack.describe(t))}</li>" for t in f["attack"]]
            html.append("</ul>")
        for k, label in (("sha256", "SHA-256"), ("exe", "Executável"), ("cmdline", "Linha de comando"),
                         ("detail", "Entrada"), ("source", "Fonte"), ("when", "Quando")):
            if f.get(k):
                html.append(f"<p><b>{label}:</b> <code>{self.esc(f[k])}</code></p>")
        if f.get("trust"):
            html.append(f"<p><b>Confiança:</b> {self.esc((f['trust'] or {}).get('label') or '')}</p>")
        if f.get("target"):
            t = f["target"]
            html.append(f"<p><b>Binário referenciado:</b> <code>{self.esc(t.get('path', ''))}</code>"
                        + (f"<br>SHA-256: <code>{self.esc(t['sha256'])}</code>" if t.get("sha256") else "") + "</p>")
        if f.get("new") is not None:
            html.append("<p><b>Histórico:</b> " + ("primeira vez que aparece" if f["new"] else
                        f"já visto em {self.esc(f.get('first_seen', ''))}") + "</p>")
        if f.get("failures"):
            users = ", ".join(self.esc(u) for u in f.get("users", []))
            html.append(f"<p><b>Tentativas falhas:</b> {int(f['failures'])}" + (f" · <b>Usuários:</b> {users}" if users else "") + "</p>")
        if f.get("remotes"):
            html.append("<p><b>Conexões externas:</b> " + ", ".join(self.esc(x) for x in f["remotes"]) + "</p>")
        self.details.setHtml("".join(html))

    @staticmethod
    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def quarantine(self):
        f = self.current()
        if not f:
            return
        ok = QMessageBox.question(
            self, APP_NAME,
            f"Mover para a quarentena?\n\n{f['where']}\n\nO arquivo não será apagado e pode ser restaurado depois.")
        if ok != QMessageBox.Yes:
            return
        try:
            core.quarantine_file(f["where"], f.get("sha256", ""), f["reasons"])
        except Exception as e:  # noqa
            QMessageBox.warning(self, APP_NAME, f"Não foi possível mover o arquivo:\n{e}")
            return
        if self.report:  # mantém o relatório exportado consistente com a tela
            self.report["findings"] = [x for x in self.report.get("findings", [])
                                       if not (x["type"] == "file" and x["where"] == f["where"])]
            self.report.setdefault("quarantined", []).append(f["where"])
            self.update_chips()
        row = self.table.selectionModel().selectedRows()[0].row()
        self.table.removeRow(row)
        self.details.setHtml("<p style='color:#4ade80'>Arquivo enviado para a quarentena.</p>")
        self.quarantine_changed.emit()

    def open_folder(self):
        f = self.current()
        if f:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(f["where"]).parent)))

    EXPORT_FORMATS = (("json", "Relatório JSON (*.json)", ".json"), ("html", "Relatório HTML (*.html)", ".html"),
                      ("csv", "Achados em CSV (*.csv)", ".csv"),
                      ("timeline", "Linha do tempo em CSV (*.timeline.csv)", ".timeline.csv"))

    def export(self):
        name = f"dupin-scan-relatorio-{datetime.now():%Y%m%d-%H%M}"
        path, flt = QFileDialog.getSaveFileName(self, "Exportar relatório", name,
                                                ";;".join(f[1] for f in self.EXPORT_FORMATS))
        if not path:
            return
        kind, _, suffix = next((f for f in self.EXPORT_FORMATS if f[1] == flt), self.EXPORT_FORMATS[0])
        if not path.lower().endswith(suffix):
            base = path[:-len(Path(path).suffix)] if Path(path).suffix and kind != "timeline" else path
            path = base + suffix
        try:
            report.write_report(self.report, path, kind)
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, APP_NAME, f"Não foi possível gravar o relatório:\n{e}")

    def remove_current_row(self):
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self.table.removeRow(rows[0].row())

    def ignore_current(self):
        f = self.current()
        if not f:
            return
        if QMessageBox.question(self, APP_NAME, f"Ignorar este achado nas próximas varreduras?\n\n{f['where']}\n\n"
                                "Você pode desfazer em Configurações > Itens ignorados.") != QMessageBox.Yes:
            return
        try:
            key = state.ignore(f)
        except OSError as e:
            QMessageBox.warning(self, APP_NAME, f"Não foi possível salvar a lista de ignorados:\n{e}")
            return
        if self.report:
            self.report["findings"] = [x for x in self.report.get("findings", []) if state.fingerprint(x) != key]
            self.report.setdefault("ignored", []).append(f)
            self.update_chips()
        self.remove_current_row()
        self.details.setHtml("<p style='color:#4ade80'>Achado ignorado.</p>")
        self.ignored_changed.emit()

    def vt_api_key(self):
        return os.environ.get("VT_API_KEY") or (self.settings.value("vt_key", "") if self.settings else "")

    def lookup_vt(self):
        f = self.current()
        sha = self.hash_of(f) if f else ""
        if not sha:
            return
        key = self.vt_api_key()
        if not key:
            QMessageBox.information(self, APP_NAME, "Informe sua chave da API da VirusTotal em Configurações > Inteligência de ameaças.")
            return
        if QMessageBox.question(self, APP_NAME, f"Consultar este hash na VirusTotal?\n\n{sha}\n\nSó o hash SHA-256 é enviado, "
                                "nunca o arquivo nem o caminho. A VirusTotal registra a consulta.") != QMessageBox.Yes:
            return
        self.details.append("<p style='color:#94a3b8'>Consultando a VirusTotal…</p>")

        def done(r, err):
            if err or not r:
                self.details.append(f"<p style='color:#f87171'>Falha: {self.esc(err or 'sem resposta')}</p>")
            elif r["status"] == "found":
                self.details.append(f"<p><b>VirusTotal:</b> {r['malicious']} malicioso(s), {r['suspicious']} suspeito(s), "
                                    f"{r['harmless']} inofensivo(s), {r['undetected']} sem detecção.<br>{self.esc(r['link'])}</p>")
            else:
                self.details.append(f"<p style='color:#fbbf24'><b>VirusTotal:</b> {self.esc(r['message'])}</p>")

        self.vt_worker = run_async(self, intel.vt_lookup, done, sha, key)


class QuarantinePage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(14)
        lay.addLayout(header("Quarentena", "Arquivos isolados ficam sem permissão de execução. Restaure se for falso positivo."))
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Arquivo original", "Data", "Motivos"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.Stretch)
        lay.addWidget(self.table, 1)
        br = QHBoxLayout()
        b_r = QPushButton("Restaurar")
        b_d = QPushButton("Excluir definitivamente")
        b_d.setObjectName("danger")
        b_r.clicked.connect(self.restore)
        b_d.clicked.connect(self.delete)
        br.addWidget(b_r)
        br.addStretch()
        br.addWidget(b_d)
        lay.addLayout(br)
        self.refresh()

    def refresh(self):
        items = core.list_quarantine()
        self.table.setRowCount(0)
        for it in items:
            r = self.table.rowCount()
            self.table.insertRow(r)
            a = QTableWidgetItem(it["original"])
            a.setData(Qt.UserRole, it["id"])
            self.table.setItem(r, 0, a)
            self.table.setItem(r, 1, QTableWidgetItem(it["date"].replace("T", " ")))
            self.table.setItem(r, 2, QTableWidgetItem("; ".join(it.get("reasons", []))))

    def selected_id(self):
        rows = self.table.selectionModel().selectedRows()
        return self.table.item(rows[0].row(), 0).data(Qt.UserRole) if rows else None

    def restore(self):
        qid = self.selected_id()
        if not qid:
            return
        try:
            dest = core.restore_quarantine(qid)
            QMessageBox.information(self, APP_NAME, f"Restaurado em:\n{dest}")
        except Exception as e:  # noqa
            QMessageBox.warning(self, APP_NAME, str(e))
        self.refresh()

    def delete(self):
        qid = self.selected_id()
        if qid and QMessageBox.question(self, APP_NAME, "Excluir este arquivo definitivamente? Isso não pode ser desfeito.") == QMessageBox.Yes:
            core.delete_quarantine(qid)
            self.refresh()


class SettingsPage(QWidget):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        # A página tem muitos cartões: o conteúdo rola em vez de ser espremido em janelas pequenas.
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        body = QWidget()
        scroll.setWidget(body)
        outer.addWidget(scroll)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(16)
        lay.addLayout(header("Configurações", "Fontes de detecção usadas na varredura de arquivos."))

        c1, l1 = card("Lista de hashes maliciosos (SHA-256)")
        d = QLabel("Um hash por linha. Listas públicas: MalwareBazaar (abuse.ch).")
        d.setObjectName("muted")
        l1.addWidget(d)
        self.hashes = self.picker(l1, "hashes", file=True, flt="Texto (*.txt *.csv *.list);;Todos (*)")
        lay.addWidget(c1)

        c2, l2 = card("Regras YARA")
        d = QLabel("Pasta com arquivos .yar / .yara.")
        d.setObjectName("muted")
        l2.addWidget(d)
        self.yara = self.picker(l2, "yara", file=False)
        lay.addWidget(c2)

        ci, li = card("Inteligência de ameaças (opcional, usa a internet)")
        d = QLabel("O Dupin-Scan funciona 100% offline. Estes botões só acessam a rede quando você clica e confirma. "
                   "As chaves ficam salvas neste computador, sem criptografia (ou use as variáveis ABUSECH_AUTH_KEY e VT_API_KEY).")
        d.setObjectName("muted")
        d.setWordWrap(True)
        li.addWidget(d)
        self.intel_status = QLabel("")
        self.intel_status.setObjectName("muted")
        self.intel_status.setWordWrap(True)
        li.addWidget(self.intel_status)
        self.abuse_key = self.secret_field(li, "abusech_key", "Auth-Key da abuse.ch (gratuita, https://auth.abuse.ch/)")
        self.vt_key = self.secret_field(li, "vt_key", "Chave da API da VirusTotal (para o botão em Resultados)")
        rowi = QHBoxLayout()
        self.b_up_hash = QPushButton("Atualizar lista de hashes (MalwareBazaar)")
        self.b_up_yara = QPushButton("Atualizar regras YARA (signature-base)")
        self.b_up_hash.clicked.connect(self.update_hashes)
        self.b_up_yara.clicked.connect(self.update_yara)
        rowi.addWidget(self.b_up_hash)
        rowi.addWidget(self.b_up_yara)
        rowi.addStretch()
        li.addLayout(rowi)
        lay.addWidget(ci)
        self.refresh_intel()

        cg, lg = card("Itens ignorados")
        d = QLabel("Achados que você marcou como esperados. Se o arquivo mudar, ele volta a aparecer.")
        d.setObjectName("muted")
        lg.addWidget(d)
        self.ignored_list = QListWidget()
        self.ignored_list.setMinimumHeight(80)
        lg.addWidget(self.ignored_list)
        b_unign = QPushButton("Remover da lista")
        b_unign.clicked.connect(self.unignore)
        lg.addWidget(b_unign, alignment=Qt.AlignLeft)
        lay.addWidget(cg)
        self.refresh_ignored()

        c4, l4 = card("Exportar regras de detecção")
        d = QLabel("Gera as detecções do Dupin-Scan como regras Sigma (YAML) e YARA, com a técnica MITRE ATT&CK de cada uma.")
        d.setObjectName("muted")
        d.setWordWrap(True)
        l4.addWidget(d)
        b_exp = QPushButton("Exportar para uma pasta…")
        b_exp.clicked.connect(self.export_rules)
        l4.addWidget(b_exp, alignment=Qt.AlignLeft)
        lay.addWidget(c4)

        c3, l3 = card("Componentes")
        for name, ok, hint in (("psutil (processos)", core.psutil is not None, "pip install psutil"),
                               ("yara-python (regras YARA)", core.yara is not None, "pip install yara-python")):
            l = QLabel(f"{'●' if ok else '○'}  {name}  —  " + ("disponível" if ok else f"não instalado ({hint})"))
            l.setStyleSheet(f"color: {'#4ade80' if ok else '#fbbf24'};")
            l3.addWidget(l)
        admin = self.is_admin()
        l = QLabel(f"{'●' if admin else '○'}  Privilégios elevados  —  " +
                   ("sim" if admin else "não (alguns processos e pastas do sistema ficarão ilegíveis)"))
        l.setStyleSheet(f"color: {'#4ade80' if admin else '#fbbf24'};")
        l3.addWidget(l)
        lay.addWidget(c3)
        lay.addStretch()
        v = QLabel(f"{APP_NAME} {APP_VERSION} · ferramenta de triagem, não substitui antivírus/EDR")
        v.setObjectName("muted")
        lay.addWidget(v)

    def secret_field(self, layout, key, placeholder):
        edit = QLineEdit(self.settings.value(key, ""))
        edit.setEchoMode(QLineEdit.Password)
        edit.setPlaceholderText(placeholder)
        edit.textChanged.connect(lambda t: self.settings.setValue(key, t.strip()))
        layout.addWidget(edit)
        return edit

    def refresh_intel(self):
        st = intel.status()
        h, y = st["hashes"], st["yara"]
        self.intel_status.setText(
            "Hashes: " + (f"{h['count']} em {h['path']} ({h['date']})" if h["present"] else "nenhuma lista baixada") +
            "\nRegras YARA: " + (f"{y['files']} arquivos em {y['path']} ({y['date']})" if y["present"] else "nenhuma regra baixada"))

    def _confirm_net(self, what, source):
        return QMessageBox.question(self, APP_NAME, f"{what}\n\nFonte: {source}\n\nIsto acessa a internet. Continuar?") == QMessageBox.Yes

    def update_hashes(self):
        key = os.environ.get("ABUSECH_AUTH_KEY") or self.abuse_key.text().strip()
        if not key:
            QMessageBox.information(self, APP_NAME, "A MalwareBazaar exige uma Auth-Key gratuita: crie a sua em https://auth.abuse.ch/ e cole no campo acima.")
            return
        if not self._confirm_net("Baixar a lista recente de hashes SHA-256 maliciosos?", "mb-api.abuse.ch"):
            return
        self.b_up_hash.setEnabled(False)

        def done(r, err):
            self.b_up_hash.setEnabled(True)
            if err:
                QMessageBox.warning(self, APP_NAME, f"Não foi possível atualizar:\n{err}")
                return
            self.hashes.setText(r["path"])  # já passa a valer nas próximas varreduras
            self.refresh_intel()
            QMessageBox.information(self, APP_NAME, f"{r['count']} hashes baixados e ativados.")

        run_async(self, intel.update_hashes, done, auth_key=key)

    def update_yara(self):
        if core.yara is None:
            QMessageBox.information(self, APP_NAME, "Instale o yara-python para usar regras YARA (pip install yara-python).")
            return
        if not self._confirm_net("Baixar e validar o repositório de regras YARA?", "github.com/Neo23x0/signature-base"):
            return
        self.b_up_yara.setEnabled(False)

        def done(r, err):
            self.b_up_yara.setEnabled(True)
            if err:
                QMessageBox.warning(self, APP_NAME, f"Não foi possível atualizar:\n{err}")
                return
            self.yara.setText(str(intel.yara_dir() or ""))
            self.refresh_intel()
            QMessageBox.information(self, APP_NAME, f"{r['files']} regras aceitas, {len(r.get('skipped', [])) + len(r.get('errors', []))} descartadas e ativadas.")

        run_async(self, intel.update_yara, done)

    def refresh_ignored(self):
        self.ignored_list.clear()
        for i in state.list_ignored():
            it = QListWidgetItem(f"{i.get('type', '')} · {i.get('where', '')}")
            it.setData(Qt.UserRole, i.get("key"))
            self.ignored_list.addItem(it)

    def unignore(self):
        for it in self.ignored_list.selectedItems():
            state.unignore(it.data(Qt.UserRole))
        self.refresh_ignored()

    def export_rules(self):
        d = QFileDialog.getExistingDirectory(self, "Pasta de destino das regras")
        if not d:
            return
        try:
            files = export_rules.write_all(Path(d) / "dupin-scan-rules")
        except OSError as e:
            QMessageBox.warning(self, APP_NAME, f"Não foi possível gravar as regras:\n{e}")
            return
        QMessageBox.information(self, APP_NAME, f"{len(files)} arquivos gravados em:\n{Path(d) / 'dupin-scan-rules'}")

    @staticmethod
    def is_admin():
        try:
            if os.name == "nt":
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            return os.geteuid() == 0
        except Exception:  # noqa
            return False

    def picker(self, layout, key, file, flt=""):
        row = QHBoxLayout()
        edit = QLineEdit(self.settings.value(key, ""))
        edit.setPlaceholderText("Não configurado")
        edit.textChanged.connect(lambda t: self.settings.setValue(key, t))
        b = QPushButton("Escolher…")
        c = QPushButton("Limpar")

        def pick():
            p = QFileDialog.getOpenFileName(self, "Escolha o arquivo", "", flt)[0] if file \
                else QFileDialog.getExistingDirectory(self, "Escolha a pasta")
            if p:
                edit.setText(p)

        b.clicked.connect(pick)
        c.clicked.connect(lambda: edit.setText(""))
        row.addWidget(edit, 1)
        row.addWidget(b)
        row.addWidget(c)
        layout.addLayout(row)
        return edit


# ------------------------------------------------------------------ janela
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1120, 760)
        self.settings = QSettings("Dupin-Scan", "Dupin-Scan")
        migrate_legacy_settings(self.settings)

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)

        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(220)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(14, 22, 14, 18)
        sl.setSpacing(4)
        b = QLabel(APP_NAME)
        b.setObjectName("brand")
        bs = QLabel("Triagem de ameaças")
        bs.setObjectName("brandSub")
        sl.addWidget(b)
        sl.addWidget(bs)
        sl.addSpacing(22)

        self.stack = QStackedWidget()
        self.scan = ScanPage(self.settings)
        self.results = ResultsPage(self.settings)
        self.quar = QuarantinePage()
        self.sett = SettingsPage(self.settings)
        pages = [("Varredura", self.scan), ("Resultados", self.results),
                 ("Quarentena", self.quar), ("Configurações", self.sett)]
        group = QButtonGroup(self)
        group.setExclusive(True)
        for i, (name, page) in enumerate(pages):
            self.stack.addWidget(page)
            btn = QPushButton(name)
            btn.setObjectName("nav")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            group.addButton(btn, i)
            sl.addWidget(btn)
            if i == 0:
                btn.setChecked(True)
        group.idClicked.connect(self.on_nav)
        self.group = group
        sl.addStretch()

        h.addWidget(side)
        h.addWidget(self.stack, 1)

        self.scan.scan_finished.connect(self.on_scan_finished)
        self.scan.artifact_report.connect(self.on_scan_finished)
        self.results.quarantine_changed.connect(self.quar.refresh)
        self.results.ignored_changed.connect(self.sett.refresh_ignored)
        self.setAcceptDrops(True)

    def closeEvent(self, event):
        self.scan.shutdown()
        for page in (self.scan, self.results, self.sett):
            wait_workers(page)
        super().closeEvent(event)

    def on_nav(self, i):
        self.stack.setCurrentIndex(i)
        if i == 2:
            self.quar.refresh()
        elif i == 3:
            self.sett.refresh_ignored()
            self.sett.refresh_intel()

    # arrastar e soltar arquivos/pastas na janela
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        self.open_paths([os.path.normpath(u.toLocalFile()) for u in event.mimeData().urls() if u.isLocalFile()])

    def open_paths(self, paths):
        """Aponta a varredura para estes arquivos/pastas e mostra a página de varredura."""
        paths = [p for p in paths if p and os.path.exists(p)]
        if not paths:
            return
        self.scan.set_targets(paths)
        self.group.button(0).setChecked(True)
        self.stack.setCurrentIndex(0)
        self.scan.status.setText(f"{len(paths)} item(ns) selecionado(s). Clique em Iniciar varredura.")

    def on_scan_finished(self, rep):
        self.results.set_report(rep)
        self.group.button(1).setChecked(True)
        self.stack.setCurrentIndex(1)


def main(argv=None):
    """Abre a interface. `argv`: arquivos/pastas para já deixar selecionados (menu 'Abrir com')."""
    argv = sys.argv[1:] if argv is None else list(argv)
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(QSS.replace("@CHECK@", asset("check.png")))
    if Path(asset("dupin-scan.png")).exists():
        app.setWindowIcon(QIcon(asset("dupin-scan.png")))
    w = MainWindow()
    w.open_paths(argv)
    w.show()
    return app.exec()
