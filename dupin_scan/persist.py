"""Dupin-Scan - persistência e processos (sem dependência de interface).

Novidades em relação à primeira versão:
  - Segue o executável que cada entrada de persistência aponta (chave Run, tarefa, serviço, cron, ExecStart...) e o
    analisa como um arquivo qualquer: hash, YARA, heurísticas e confiança (assinatura/pacote). Antes só o TEXTO do
    comando era julgado.
  - Mais locais: serviços, Winlogon, IFEO, AppInit_DLLs, Run do WOW6432Node e assinaturas WMI (Windows);
    drop-ins e timers do systemd, authorized_keys, at, anacron, cron.{hourly,daily,...}, init.d e udev (Linux).
  - Processos: executável do processo analisado, nome de binário do Windows fora do lugar, nomes parecidos e
    relação pai-filho (Office/IIS gerando interpretadores; servidor web gerando shell).
"""
import csv
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

from . import attack as att
from . import core
from .core import EXEC_EXT, SUSPECT_DIRS, check_cmd, finding

# ---------------------------------------------------------------- executáveis referenciados por um comando
_WIN_EXTS = "exe|dll|bat|cmd|ps1|vbs|js|jar|msi|com|scr|sys|cpl|hta"
_WIN_PATH = re.compile(r'[A-Za-z]:\\[^"<>|*?\r\n]*?\.(?:%s)\b' % _WIN_EXTS, re.I)
_WIN_QUOTED = re.compile(r'"([^"]+)"')
_UNIX_PATH = re.compile(r"(?<![\w./])(/(?:[\w.+@~-]+/)*[\w.+@~-]+)")  # o lookbehind descarta URLs (http://...)
_SKIP_UNIX = ("/dev/", "/proc/", "/sys/")


def extract_exes(cmd, os_name):
    """Caminhos absolutos que um comando parece executar/carregar (sem checar se existem)."""
    if os_name == "windows":
        s = os.path.expandvars(cmd)
        found = [m.group(0) for m in _WIN_PATH.finditer(s)]
        found += [q for q in _WIN_QUOTED.findall(s) if re.search(r"\.(?:%s)$" % _WIN_EXTS, q, re.I)]
    else:
        found = [m for m in _UNIX_PATH.findall(cmd) if not m.startswith(_SKIP_UNIX)]
    return list(dict.fromkeys(f.strip() for f in found if f.strip()))


def _referenced(cmd, ctx):
    """(caminho, análise) do primeiro executável referenciado que gera achado, ou None."""
    for p in extract_exes(cmd, ctx.os_name)[:5]:
        if os.path.isabs(p) and os.path.isfile(p):
            a = ctx.analyze(p)
            if a:
                return p, a
    return None


def _first_file(cmd, ctx):
    for p in extract_exes(cmd, ctx.os_name)[:5]:
        if os.path.isabs(p) and os.path.isfile(p):
            return p
    return None


def abate_dir_reasons(reasons, exe, ctx):
    """Se o binário é confiável (assinatura válida / pacote íntegro), remove os motivos baseados só na PASTA de onde
    ele roda ('...de diretório suspeito'): apps legítimos vivem em AppData e ProgramData. Motivos de comando
    (ex.: powershell -enc) ficam: um binário assinado também pode ser usado de forma maliciosa."""
    dir_idx = {i for i, r in enumerate(reasons) if "diretório suspeito" in r[0] or r[0] == "Caminho temporário no comando"}
    if not (dir_idx and exe and ctx.check_trust):
        return reasons
    from . import trust as trust_mod
    info = trust_mod.check(exe, ctx.os_name)
    if info and info["trusted"]:
        return [r for i, r in enumerate(reasons) if i not in dir_idx]
    return reasons


def _iso(ts):
    try:
        return datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError, TypeError):
        return ""


def entry(where, cmd, ctx, attack=(), dir_reason=None, extra_reasons=(), **extra):
    """Achado de persistência para uma entrada que executa `cmd`, ou None se nada nela for suspeito."""
    r = check_cmd(cmd) + list(extra_reasons)
    if dir_reason and any(d in cmd.lower() for d in SUSPECT_DIRS[ctx.os_name]):
        r.append((dir_reason, 25))
    r = abate_dir_reasons(r, _first_file(cmd, ctx), ctx)
    ref = _referenced(cmd, ctx)
    if ref:
        path, a = ref
        r.append((f"Binário referenciado ({Path(path).name}): " + "; ".join(a["reasons"]), a["score"],
                  tuple(t["id"] for t in a["attack"])))
        extra["target"] = {"path": path, "sha256": a.get("sha256", ""), "score": a["score"],
                           **({"trust": a["trust"]} if a.get("trust") else {})}
    if not r:
        return None
    return finding("persistence", where, r, attack=attack, detail=cmd[:200], **extra)


# ---------------------------------------------------------------- arquivos de texto (Linux)
def scan_text_file(path, technique=(), ctx=None):
    """Procura comandos suspeitos (e executáveis suspeitos referenciados) num arquivo de persistência."""
    ctx = ctx or core.Ctx(core.host_os())
    out = []
    try:
        lines = Path(path).read_text(errors="ignore").splitlines()
        when = _iso(os.stat(path).st_mtime)
    except OSError:
        return out
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        f = entry(f"{path}:{n}", s, ctx, technique, when=when)
        if f:
            out.append(f)
    return out


_KEY_TYPE = re.compile(r"(?:^|\s)(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+)\s")
_FORCED_CMD = re.compile(r'command="((?:[^"\\]|\\.)*)"')


def scan_authorized_keys(path, ctx):
    """Chaves SSH com `command=` (comando forçado) ou com comando suspeito nas opções."""
    out = []
    try:
        lines = Path(path).read_text(errors="ignore").splitlines()
        when = _iso(os.stat(path).st_mtime)
    except OSError:
        return out
    for n, line in enumerate(lines, 1):
        s = line.strip()
        m = _KEY_TYPE.search(s) if s and not s.startswith("#") else None
        if not m or m.start() == 0:
            continue  # sem opções antes do tipo da chave: nada a avaliar
        options = s[:m.start()]
        forced = _FORCED_CMD.search(options)
        if not forced:
            continue
        cmd = forced.group(1).replace('\\"', '"')
        f = entry(f"{path}:{n}", cmd, ctx, (att.SSH_KEYS,), extra_reasons=[("Chave SSH com comando forçado (command=)", 30)],
                  when=when)
        if f:
            f["detail"] = options[:200]  # nunca o conteúdo da chave
            out.append(f)
    return out


def _homes():
    homes = [Path.home(), Path("/root")]
    try:
        homes += sorted(p for p in Path("/home").iterdir() if p.is_dir())
    except OSError:
        pass
    seen, out = set(), []
    for h in homes:
        if str(h) not in seen:
            seen.add(str(h))
            out.append(h)
    return out


def linux_persistence(ctx=None, notes=None):
    ctx = ctx or core.Ctx("linux")
    out, home = [], Path.home()
    cron, shell, sysd = (att.CRON,), (att.SHELL_PROFILE,), (att.SYSTEMD,)
    files = [(Path("/etc/crontab"), cron), (Path("/etc/anacrontab"), cron), (Path("/etc/rc.local"), (att.RC_LOCAL,)),
             (home / ".bashrc", shell), (home / ".profile", shell), (home / ".bash_profile", shell),
             (home / ".zshrc", shell)]
    user_systemd = home / ".config" / "systemd" / "user"
    globs = [("/etc/cron.d", "*", cron), ("/etc/cron.hourly", "*", cron), ("/etc/cron.daily", "*", cron),
             ("/etc/cron.weekly", "*", cron), ("/etc/cron.monthly", "*", cron),
             ("/var/spool/cron", "*", cron), ("/var/spool/cron/crontabs", "*", cron),
             ("/var/spool/cron/atjobs", "*", (att.AT_JOB,)), ("/var/spool/at", "*", (att.AT_JOB,)),
             ("/etc/profile.d", "*.sh", shell), ("/etc/init.d", "*", (att.RC_LOCAL,)),
             ("/etc/udev/rules.d", "*.rules", (att.UDEV,)),
             ("/etc/systemd/system", "*.service", sysd), ("/etc/systemd/system", "*.d/*.conf", sysd),
             (str(user_systemd), "*.service", sysd), (str(user_systemd), "*.d/*.conf", sysd),
             (str(home / ".config/autostart"), "*.desktop", (att.XDG_AUTOSTART,))]
    timers = {p.stem for d in ("/etc/systemd/system", str(user_systemd)) if Path(d).is_dir()
              for p in Path(d).glob("*.timer")}
    for d, pat, tech in globs:
        if Path(d).is_dir():
            for f in Path(d).glob(pat):
                if f.is_file():
                    # um serviço acionado por timer também é persistência por T1053.006
                    t = tech + (att.SYSTEMD_TIMER,) if f.suffix == ".service" and f.stem in timers else tech
                    files.append((f, t))
    for f, tech in files:
        if f.is_file():
            out += scan_text_file(f, tech, ctx)

    for h in _homes():
        for name in ("authorized_keys", "authorized_keys2"):
            p = h / ".ssh" / name
            if p.is_file():
                out += scan_authorized_keys(p, ctx)

    preload = Path("/etc/ld.so.preload")
    try:
        if preload.is_file() and preload.read_text(errors="ignore").strip():
            out.append(finding("persistence", str(preload),
                               [("ld.so.preload não vazio (técnica de rootkit userland)", 50)],
                               attack=(att.LD_PRELOAD,), when=_iso(preload.stat().st_mtime)))
    except OSError:
        pass
    return out


# ---------------------------------------------------------------- Windows
def _reg_values(winreg, hive, sub):
    """[(nome, valor)] de uma chave; vazio se não existir ou não puder ser lida."""
    out = []
    try:
        with winreg.OpenKey(hive, sub) as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out.append((name, val))
                i += 1
    except OSError:
        pass
    return out


def _reg_subkeys(winreg, hive, sub):
    out = []
    try:
        with winreg.OpenKey(hive, sub) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def _service_image(raw):
    """Normaliza o ImagePath de um serviço (\\SystemRoot\\..., \\??\\C:\\..., caminho relativo ao System32)."""
    s = str(raw).strip()
    root = os.environ.get("SystemRoot", r"C:\Windows")
    if s.lower().startswith("\\systemroot\\"):
        s = root + s[len("\\SystemRoot"):]
    elif s.startswith("\\??\\"):
        s = s[4:]
    elif re.match(r"^(system32|syswow64)\\", s, re.I):
        s = root + "\\" + s
    return s


_WMI_PS = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='Stop';$r=@();"
           "$r+=@(Get-CimInstance -Namespace root\\subscription -ClassName CommandLineEventConsumer|%{[pscustomobject]@{"
           "Kind='CommandLine';Name=$_.Name;Cmd=($_.CommandLineTemplate+' '+$_.ExecutablePath)}});"
           "$r+=@(Get-CimInstance -Namespace root\\subscription -ClassName ActiveScriptEventConsumer|%{[pscustomobject]@{"
           "Kind='ActiveScript';Name=$_.Name;Cmd=$_.ScriptText}});"
           "ConvertTo-Json -InputObject $r -Compress")

_WINLOGON = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
_IFEO = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
_WINDOWS_NT = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"


def windows_wmi_consumers(ctx, notes):
    """Assinaturas WMI permanentes (CommandLine/ActiveScript): técnica clássica de persistência sem arquivo."""
    ps = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    try:
        res = subprocess.run([ps if os.path.exists(ps) else "powershell", "-NoProfile", "-NonInteractive", "-Command", _WMI_PS],
                             capture_output=True, timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError) as e:
        notes.append(f"WMI (root\\subscription): {e}")
        return []
    if res.returncode != 0:
        notes.append("Assinaturas WMI ilegíveis sem administrador (root\\subscription).")
        return []
    try:
        items = json.loads(res.stdout.decode("utf-8", "replace").strip().lstrip("\ufeff") or "[]")
    except ValueError:
        notes.append("WMI (root\\subscription): resposta inesperada.")
        return []
    if isinstance(items, dict):
        items = [items]
    out = []
    for it in items:
        cmd = str(it.get("Cmd") or "")
        f = entry(f"WMI {it.get('Kind')}EventConsumer {it.get('Name')}", cmd, ctx, (att.WMI_SUBSCRIPTION,),
                  extra_reasons=[("Assinatura WMI permanente que executa comando/script", 60)])
        if f:
            out.append(f)
    return out


def windows_persistence(ctx=None, notes=None):
    import winreg

    ctx = ctx or core.Ctx("windows")
    notes = notes if notes is not None else []
    out = []

    def add(f):
        if f:
            out.append(f)

    # Run / RunOnce (inclui o Run de 32 bits em máquinas de 64)
    cv = r"Software\Microsoft\Windows\CurrentVersion"
    for hive, hname in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
        subs = [cv + r"\Run", cv + r"\RunOnce"]
        if hname == "HKLM":
            subs += [r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                     r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"]
        for sub in subs:
            for name, val in _reg_values(winreg, hive, sub):
                add(entry(f"{hname}\\{sub}\\{name}", str(val), ctx, (att.RUN_KEYS,), "Executa de diretório suspeito"))

    # Pastas Startup
    for env, parts in [("APPDATA", ("Microsoft", "Windows", "Start Menu", "Programs", "Startup")),
                       ("PROGRAMDATA", ("Microsoft", "Windows", "Start Menu", "Programs", "StartUp"))]:
        base = os.environ.get(env)
        d = Path(base, *parts) if base else None
        if d and d.is_dir():
            for f in d.iterdir():
                if f.suffix.lower() in EXEC_EXT["windows"]:
                    r = [("Executável na pasta Startup", 25)]
                    a = ctx.analyze(str(f)) if f.is_file() else None
                    if a:
                        r.append((f"Conteúdo do arquivo: " + "; ".join(a["reasons"]), a["score"],
                                  tuple(t["id"] for t in a["attack"])))
                    out.append(finding("persistence", str(f), r, attack=(att.RUN_KEYS,), when=_iso(f.stat().st_mtime)))

    # Tarefas agendadas: usa índices de coluna (independe do idioma do Windows)
    try:
        res = subprocess.run(["schtasks", "/query", "/fo", "csv", "/v"], capture_output=True,
                             text=True, errors="replace", timeout=120,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        seen = set()
        for row in csv.reader(res.stdout.splitlines()):
            if len(row) > 8 and row[1] and not row[1].lower().startswith(("taskname", "nome")) and (row[1], row[8]) not in seen:
                seen.add((row[1], row[8]))
                add(entry(f"Tarefa agendada {row[1]}", row[8], ctx, (att.SCHEDULED_TASK,),
                          "Tarefa executa de diretório suspeito"))
    except (OSError, subprocess.SubprocessError):
        pass

    # Serviços configurados para iniciar com o sistema (boot, sistema, automático)
    svc = r"SYSTEM\CurrentControlSet\Services"
    for name in _reg_subkeys(winreg, winreg.HKEY_LOCAL_MACHINE, svc):
        vals = dict(_reg_values(winreg, winreg.HKEY_LOCAL_MACHINE, svc + "\\" + name))
        if vals.get("Start") in (0, 1, 2) and vals.get("ImagePath"):
            add(entry(f"Serviço {name}", _service_image(vals["ImagePath"]), ctx, (att.WINDOWS_SERVICE,),
                      "Serviço executa de diretório suspeito"))

    # Winlogon (Shell/Userinit), IFEO (Debugger) e AppInit_DLLs
    hklm = winreg.HKEY_LOCAL_MACHINE
    wl = dict(_reg_values(winreg, hklm, _WINLOGON))
    root = os.environ.get("SystemRoot", r"C:\Windows")
    if str(wl.get("Shell", "explorer.exe")).strip().lower() != "explorer.exe":
        add(entry(f"HKLM\\{_WINLOGON}\\Shell", str(wl["Shell"]), ctx, (att.WINLOGON,),
                  extra_reasons=[("Shell do Winlogon diferente de explorer.exe", 60)]))
    expected = os.path.join(root, "system32", "userinit.exe").lower()
    if "Userinit" in wl and str(wl["Userinit"]).strip().rstrip(",").strip().lower() != expected:
        add(entry(f"HKLM\\{_WINLOGON}\\Userinit", str(wl["Userinit"]), ctx, (att.WINLOGON,),
                  extra_reasons=[("Userinit do Winlogon alterado (carrega outro programa no logon)", 60)]))
    for sub in _reg_subkeys(winreg, hklm, _IFEO):
        dbg = dict(_reg_values(winreg, hklm, _IFEO + "\\" + sub)).get("Debugger")
        if dbg:
            add(entry(f"HKLM\\{_IFEO}\\{sub}\\Debugger", str(dbg), ctx, (att.IFEO,),
                      extra_reasons=[(f"Debugger configurado para {sub} (IFEO): o programa abre outro no lugar", 50)]))
    for base in (_WINDOWS_NT, _WINDOWS_NT.replace("Software\\", "Software\\WOW6432Node\\", 1)):
        dlls = dict(_reg_values(winreg, hklm, base)).get("AppInit_DLLs")
        if dlls and str(dlls).strip():
            add(entry(f"HKLM\\{base}\\AppInit_DLLs", str(dlls), ctx, (att.APPINIT,),
                      extra_reasons=[("AppInit_DLLs não vazio (DLL injetada em processos que usam user32)", 60)]))

    out += windows_wmi_consumers(ctx, notes)
    return out


# ---------------------------------------------------------------- processos
_WIN_SYS32 = ("system32", "syswow64")
# nome -> pastas (relativas ao %SystemRoot%) onde o binário legítimo pode estar
WIN_SYSTEM_PROCS = {
    "svchost.exe": _WIN_SYS32, "lsass.exe": ("system32",), "csrss.exe": ("system32",), "smss.exe": ("system32",),
    "services.exe": ("system32",), "winlogon.exe": ("system32",), "wininit.exe": ("system32",),
    "taskhostw.exe": ("system32",), "spoolsv.exe": ("system32",), "dllhost.exe": _WIN_SYS32,
    "conhost.exe": ("system32",), "explorer.exe": ("",), "dwm.exe": ("system32",), "sihost.exe": ("system32",),
    "fontdrvhost.exe": ("system32",), "runtimebroker.exe": ("system32",),
}
_LOOKALIKE_BASE = ["svchost", "lsass", "csrss", "smss", "services", "winlogon", "wininit", "explorer", "taskhostw",
                   "spoolsv", "dllhost", "conhost"]
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe",
                  "onenote.exe", "acrord32.exe", "acrobat.exe"}
WIN_SHELL_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                      "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
LINUX_SHELLS = {"sh", "bash", "dash", "zsh", "nc", "ncat", "netcat", "perl", "python", "python3"}
LINUX_WEB_PARENTS = ("apache2", "httpd", "nginx", "php-fpm", "php-cgi", "lighttpd", "caddy")


def _edit1(a, b):
    """True se a e b diferem por uma inserção, remoção, troca de letra ou troca de duas letras vizinhas
    (os erros típicos de nomes feitos para se passar por outro: svch0st, svchst, scvhost)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]]
                                  and a[diff[1]] == b[diff[0]])
    s, l = sorted((a, b), key=len)
    return any(l[:i] + l[i + 1:] == s for i in range(len(l)))


def masquerade_reasons(name, exe):
    """Razões para um processo cujo NOME é de um binário do Windows mas que roda de outro lugar (ou parece ser)."""
    name = (name or "").lower()
    r = []
    root = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    if name in WIN_SYSTEM_PROCS and exe:
        allowed = {os.path.normcase(os.path.join(root, d)) if d else root for d in WIN_SYSTEM_PROCS[name]}
        if os.path.normcase(os.path.dirname(exe)) not in allowed:
            r.append((f"{name} deveria rodar de {os.path.join(root, WIN_SYSTEM_PROCS[name][0])}, não de {os.path.dirname(exe)}",
                      60, (att.MASQUERADE,)))
    elif name.endswith(".exe") and len(name) >= 9 and name not in WIN_SYSTEM_PROCS:
        stem = name[:-4]
        if any(_edit1(stem, base) for base in _LOOKALIKE_BASE):
            r.append(("Nome muito parecido com um processo do Windows", 50, (att.MASQUERADE,)))
    return r


def parent_child_reasons(os_name, parent, child):
    p, c = (parent or "").lower(), (child or "").lower()
    if os_name == "windows":
        if p in OFFICE_PARENTS and c in WIN_SHELL_CHILDREN:
            return [(f"{parent} iniciou {child} (documento abrindo interpretador de comandos)", 70, ("T1204.002",))]
        if p == "w3wp.exe" and c in WIN_SHELL_CHILDREN:
            return [(f"Servidor IIS (w3wp.exe) iniciou {child}", 70, (att.WEB_SHELL,))]
    elif p.startswith(LINUX_WEB_PARENTS) and c in LINUX_SHELLS:
        return [(f"Servidor web ({parent}) iniciou {child} (possível web shell)", 70, (att.WEB_SHELL,))]
    return []


def scan_processes(os_name, ctx=None):
    out = []
    if not core.psutil:
        return out
    psutil = core.psutil
    ctx = ctx or core.Ctx(os_name)
    procs = list(psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]))
    names = {p.info["pid"]: p.info["name"] or "" for p in procs}
    for p in procs:
        try:
            exe = p.info["exe"] or ""
            cmd = " ".join(p.info["cmdline"] or [])
            name = p.info["name"] or ""
            r = check_cmd(cmd)
            if exe and any(d in exe.lower() for d in SUSPECT_DIRS[os_name]):
                r.append(("Processo executando de diretório suspeito", 35))
            if os_name == "linux" and exe.endswith("(deleted)"):
                r.append(("Binário do processo foi apagado do disco", 60, ("T1070.004",)))
            if exe and not exe.endswith("(deleted)"):
                r = abate_dir_reasons(r, exe, ctx)
            if os_name == "windows":
                r += masquerade_reasons(name, exe)
            r += parent_child_reasons(os_name, names.get(p.info["ppid"], ""), name)
            if exe and not exe.endswith("(deleted)") and os.path.isfile(exe):
                a = ctx.analyze(exe)
                if a:
                    r.append(("Executável do processo: " + "; ".join(a["reasons"]), a["score"],
                              tuple(t["id"] for t in a["attack"])))
            if not r:
                continue
            get_conns = getattr(p, "net_connections", None) or p.connections
            remotes = sorted({f"{c.raddr.ip}:{c.raddr.port}" for c in get_conns(kind="inet")
                              if c.status == "ESTABLISHED" and c.raddr and core.is_public(c.raddr.ip)})
            if remotes:
                r.append(("Conexão externa estabelecida", 20))
            out.append(finding("process", f"PID {p.info['pid']} {name}", r, exe=exe, cmdline=cmd[:200],
                               remotes=remotes, when=_iso(p.info.get("create_time"))))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return out
