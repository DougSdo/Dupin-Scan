"""Dupin-Scan - artefatos forenses (sem dependência de interface).

Lê o que o sistema já registrou e procura rastros de ataque, no mesmo formato de achado do restante do núcleo
(`type == "artifact"`, com `source` e `when`):

  Windows  logs de eventos (via wevtutil), histórico do PowerShell (PSReadLine) e Prefetch (só pelo nome do arquivo)
  Linux    auth.log / secure (inclusive rotacionados) e históricos de shell (bash, zsh, fish)

As funções de análise são puras (recebem texto/eventos), para poderem ser testadas sem o sistema real.
Limites conhecidos estão no README ("O que o Dupin-Scan não detecta").
"""
import contextlib
import gzip
import logging
import ntpath
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import attack as att
from . import core
from .core import CmdRule, finding

DEFAULT_DAYS = 30
BRUTE_THRESHOLD = 10  # falhas do mesmo endereço para considerar força bruta
ADMIN_GROUPS = {"sudo", "wheel", "admin", "root"}
ADMINS_SID = "S-1-5-32-544"  # grupo Administradores local do Windows


# ---------------------------------------------------------------- utilidades
def _rules(extra=()):
    """Regras de comando com técnica ATT&CK (ignora o ruído de 'caminho temporário') + regras extras."""
    return [r for r in core.SUSPECT_CMD if r.attack] + list(extra)


def _check(text, extra=()):
    return core.check_cmd(text, _rules(extra))


def _artifact(where, reasons, source, when="", attack=(), **extra):
    return finding("artifact", where, reasons, attack=attack, source=source, when=when, **extra)


def _when(dt):
    return dt.isoformat(timespec="seconds") if dt else ""


def _bruteforce(source, failures, successes, threshold=BRUTE_THRESHOLD):
    """failures/successes: {ip: [(datetime|None, usuário)]}. Um achado por endereço com falhas demais;
    se o mesmo endereço entrou com sucesso depois da primeira falha, a nota sobe (credencial provavelmente adivinhada)."""
    out = []
    for ip, fails in failures.items():
        if len(fails) < threshold:
            continue
        fails = sorted(fails, key=lambda t: t[0] or datetime.min)
        first = fails[0][0]
        reasons = [(f"{len(fails)} falhas de autenticação do mesmo endereço", 40, ("T1110",))]
        ok = [s for s in successes.get(ip, []) if s[0] is None or first is None or s[0] >= first]
        if ok:
            reasons.append((f"Login bem-sucedido do mesmo endereço (usuário {ok[0][1]}) depois das falhas", 40, ("T1078",)))
        out.append(_artifact(f"{source} · {ip}", reasons, source, when=_when(first), failures=len(fails),
                             users=sorted({u for _, u in fails if u})[:10]))
    return out


# ---------------------------------------------------------------- Linux: auth.log
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_SYSLOG = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<rest>.*)$")
_CLASSIC = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})$")
_FAIL = re.compile(r"sshd(?:-session)?\[\d+\]: Failed (?:password|publickey|keyboard-interactive/pam|none) for "
                   r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port")
_OK = re.compile(r"sshd(?:-session)?\[\d+\]: Accepted (?:password|publickey|keyboard-interactive/pam|hostbased) for "
                 r"(?P<user>\S+) from (?P<ip>\S+) port")
_NEWUSER = re.compile(r"useradd\[\d+\]: new user: name=(?P<user>[^,\s]+)")
_ADMGRP = re.compile(r"(?:usermod|gpasswd|useradd|adduser)\[\d+\]: (?:add '(?P<u1>[^']+)' to (?:shadow )?group '(?P<g1>[^']+)'"
                     r"|user (?P<u2>\S+) added by \S+ to group (?P<g2>\S+))")
_SUDO = re.compile(r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$")


def _parse_ts(ts, now):
    """Aceita o formato clássico do syslog (sem ano) e o ISO 8601 do rsyslog moderno. Devolve datetime local ou None."""
    try:
        if ts[0].isdigit():
            ts = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", ts)  # journald (short-iso) usa +0000; o Python 3.10 só aceita +00:00
            dt = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", ts))
            return dt.astimezone().replace(tzinfo=None) if dt.tzinfo else dt
        m = _CLASSIC.match(ts)
        if not m or m[1] not in _MONTHS:
            return None
        dt = datetime(now.year, _MONTHS[m[1]], int(m[2]), int(m[3]), int(m[4]), int(m[5]))
        return dt.replace(year=now.year - 1) if dt > now + timedelta(days=1) else dt  # log de dezembro lido em janeiro
    except ValueError:
        return None


def _default_auth_files():
    base = Path("/var/log")
    found = []
    for pat in ("auth.log", "auth.log.*", "secure", "secure-*", "secure.*"):
        found += sorted(p for p in base.glob(pat) if p.is_file())
    return found[:8]  # os mais recentes bastam; evita ler anos de logs rotacionados


def _iter_lines(path):
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
        yield from f


_JOURNAL_COMMS = ("sshd", "sshd-session", "sudo", "useradd", "usermod", "gpasswd", "adduser")  # OpenSSH >= 9.8 loga como sshd-session


def journald_lines(days=DEFAULT_DAYS, notes=None):
    """Linhas de autenticação do journald, no mesmo formato do auth.log (`short-iso`: 'ISO host proc[pid]: msg').
    Devolve None se o journalctl não existe ou falhou (com nota); [] se leu e não havia nada."""
    notes = notes if notes is not None else []
    cmd = ["journalctl", "-o", "short-iso", "--no-pager", f"--since=-{int(days)}d"] + [f"_COMM={c}" for c in _JOURNAL_COMMS]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    except FileNotFoundError:
        notes.append("journalctl não encontrado: o journald não pôde ser lido.")
        return None
    except (OSError, subprocess.SubprocessError) as e:
        notes.append(f"journalctl falhou: {e}")
        return None
    err = (res.stderr or "").strip()
    if res.returncode != 0:
        notes.append(f"journalctl retornou {res.returncode}: {err[:160]} (sem permissão? execute como root ou use o grupo systemd-journal/adm).")
        return None
    if "not seeing messages" in err:  # sem root/grupo, o journald mostra só as mensagens do próprio usuário
        notes.append("journalctl sem permissão para ver as mensagens do sistema: resultado incompleto "
                     "(execute como root ou adicione o usuário ao grupo systemd-journal/adm).")
    return (res.stdout or "").splitlines()


def linux_auth(paths=None, days=DEFAULT_DAYS, notes=None, now=None):
    """Analisa logs de autenticação: força bruta de SSH, login após falhas, contas criadas, grupos
    administrativos e comandos suspeitos via sudo. Sem arquivos de log, tenta o journald."""
    notes = notes if notes is not None else []
    now = now or datetime.now()
    cutoff = now - timedelta(days=days)
    explicit = paths is not None
    paths = list(paths) if explicit else _default_auth_files()
    sources = [(str(p), (lambda p=p: _iter_lines(p))) for p in paths]
    if not paths:
        jl = None if explicit else journald_lines(days, notes)
        if jl is None:
            notes.append("Nenhum log de autenticação encontrado (/var/log/auth.log ou /var/log/secure) "
                         "e o journald também não pôde ser lido.")
        else:
            sources = [("journald", lambda: iter(jl))]
    label = "journald" if sources and sources[0][0] == "journald" else "auth.log"
    out, failures, successes = [], defaultdict(list), defaultdict(list)
    for path, opener in sources:
        try:
            for n, line in enumerate(opener(), 1):
                m = _SYSLOG.match(line.rstrip("\n"))
                if not m:
                    continue
                dt = _parse_ts(m["ts"], now)
                if dt and dt < cutoff:
                    continue
                rest, where = m["rest"], f"{path}:{n}"
                if (f := _FAIL.search(rest)):
                    failures[f["ip"]].append((dt, f["user"]))
                elif (a := _OK.search(rest)):
                    successes[a["ip"]].append((dt, a["user"]))
                    if a["user"] == "root" and core.is_public(a["ip"]):
                        out.append(_artifact(where, [("Login SSH como root a partir de endereço público", 30, ("T1078",))],
                                             label, _when(dt), detail=rest[:200]))
                elif (u := _NEWUSER.search(rest)):
                    out.append(_artifact(where, [(f"Conta de usuário criada: {u['user']}", 40, ("T1136.001",))],
                                         label, _when(dt), detail=rest[:200]))
                elif (g := _ADMGRP.search(rest)):
                    user, group = g["u1"] or g["u2"], g["g1"] or g["g2"]
                    if group in ADMIN_GROUPS:
                        out.append(_artifact(where, [(f"Usuário {user} adicionado ao grupo administrativo {group}", 50, ("T1098",))],
                                             label, _when(dt), detail=rest[:200]))
                elif (s := _SUDO.search(rest)):
                    r = _check(s["cmd"])
                    if r:
                        out.append(_artifact(where, r, label, _when(dt), detail=s["cmd"][:200]))
        except OSError as e:
            notes.append(f"Não foi possível ler {path}: {e}")
    return out + _bruteforce(label, failures, successes)


# ---------------------------------------------------------------- históricos de shell
HISTORY_RULES = {
    "linux": [
        CmdRule(r"\bhistory\s+-c\b", "Histórico do shell apagado (history -c)", 40, ("T1070.003",), "linux"),
        CmdRule(r"\bunset\s+histfile\b|\bhistfile\s*=\s*/dev/null|\bhist(file)?size\s*=\s*0\b",
                "Histórico do shell desativado", 40, ("T1070.003",), "linux"),
        CmdRule(r"\b(rm|shred|truncate)\b[^|;&]*_history\b",
                "Arquivo de histórico removido ou sobrescrito", 40, ("T1070.003",), "linux"),
        CmdRule(r"\bln\s+-\w*s\w*\s+/dev/null\s+\S*_history",
                "Histórico redirecionado para /dev/null", 40, ("T1070.003",), "linux"),
    ],
    "windows": [
        CmdRule(r"\bclear-history\b", "Histórico do PowerShell apagado (Clear-History)", 40, ("T1070.003",), "windows"),
        CmdRule(r"set-psreadlineoption.*-historysavestyle\s+savenothing",
                "Histórico do PowerShell desativado", 40, ("T1070.003",), "windows"),
        CmdRule(r"(remove-item|\bdel\b|\brm\b)[^|;&]*consolehost_history",
                "Arquivo de histórico do PowerShell removido", 40, ("T1070.003",), "windows"),
    ],
}
_BASH_TS = re.compile(r"^#(\d{9,11})$")
_ZSH_LINE = re.compile(r"^: (\d{9,11}):\d+;(.*)$")
_HISTORY_FILES = (".bash_history", ".zsh_history", ".sh_history", ".local/share/fish/fish_history")


def _ts_to_dt(value):
    try:
        return datetime.fromtimestamp(int(value))
    except (ValueError, OverflowError, OSError):
        return None


def _scan_history_file(path, os_name, source):
    out = []
    p = Path(path)
    if os_name == "linux" and p.is_symlink() and os.readlink(p) == "/dev/null":
        out.append(_artifact(str(p), [("Histórico de shell redirecionado para /dev/null", 40, ("T1070.003",))], source))
    lines = p.read_text(errors="ignore").splitlines()
    ts = None
    for n, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s:
            continue
        if (b := _BASH_TS.match(s)):
            ts = _ts_to_dt(b[1])
            continue
        if (z := _ZSH_LINE.match(s)):
            ts, s = _ts_to_dt(z[1]), z[2].strip()
        elif s.startswith("- cmd: "):  # fish
            s = s[7:]
        r = _check(s, HISTORY_RULES[os_name])
        if r:
            out.append(_artifact(f"{p}:{n}", r, source, _when(ts), detail=s[:200]))
        ts = None
    return out


def _linux_homes():
    homes = [Path.home(), Path("/root")]
    try:
        homes += sorted(p for p in Path("/home").iterdir() if p.is_dir())
    except OSError:
        pass
    seen, out = set(), []
    for h in homes:
        k = str(h)
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out


def linux_history(homes=None, notes=None):
    """Procura comandos suspeitos e sinais de limpeza de histórico (bash, zsh, sh, fish)."""
    notes = notes if notes is not None else []
    out, unreadable = [], 0
    for home in (homes if homes is not None else _linux_homes()):
        for rel in _HISTORY_FILES:
            p = Path(home) / rel
            if not (p.exists() or p.is_symlink()):
                continue
            try:
                out += _scan_history_file(p, "linux", "histórico de shell")
            except OSError:
                unreadable += 1
    if unreadable:
        notes.append(f"{unreadable} arquivo(s) de histórico ilegível(is): execute como root para ler os de outros usuários.")
    return out


def windows_history(paths=None, notes=None):
    """Histórico do PowerShell (PSReadLine). Como administrador, inclui os perfis de outros usuários."""
    notes = notes if notes is not None else []
    rel = Path("Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
    if paths is None:
        paths = []
        if os.environ.get("APPDATA"):
            paths.append(Path(os.environ["APPDATA"]) / rel)
        try:
            paths += list(Path(os.environ.get("SystemDrive", "C:") + "\\Users").glob(f"*/AppData/Roaming/{rel.as_posix()}"))
        except OSError:
            pass
    out, seen = [], set()
    for p in paths:
        key = os.path.normcase(str(p))
        if key in seen or not Path(p).is_file():
            continue
        seen.add(key)
        try:
            out += _scan_history_file(p, "windows", "histórico do PowerShell")
        except OSError as e:
            notes.append(f"Não foi possível ler {p}: {e}")
    return out


# ---------------------------------------------------------------- Windows: Prefetch
# (regex no nome do executável, descrição, peso, técnicas)
PREFETCH_TOOLS = [
    (re.compile(r"^mimikatz"), "mimikatz (extração de credenciais)", 80, ("T1003.001",)),
    (re.compile(r"^lazagne"), "LaZagne (senhas salvas)", 70, ("T1555",)),
    (re.compile(r"^rubeus"), "Rubeus (tickets Kerberos)", 70, ("T1558",)),
    (re.compile(r"^(psexec|psexesvc)"), "PsExec (execução remota, usada em movimento lateral)", 40, ("T1569.002",)),
    (re.compile(r"^procdump"), "ProcDump (pode despejar a memória do LSASS)", 25, ("T1003.001",)),
]
_PF_NAME = re.compile(r"^(?P<exe>.+)-(?P<hash>[0-9A-Fa-f]{8})\.pf$")


def windows_prefetch(directory=None, notes=None):
    """Lê só os NOMES dos .pf (EXECUTAVEL-HASH.pf) e a data de modificação, que aproxima a última execução.
    Não interpreta o conteúdo (contagem de execuções, arquivos carregados): isso exigiria descompressão XPRESS
    Huffman e um parser de formato que não foi validado contra amostras reais."""
    notes = notes if notes is not None else []
    d = Path(directory or os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch"))
    try:
        names = os.listdir(d)
    except PermissionError:
        notes.append("Prefetch ilegível: execute como administrador.")
        return []
    except OSError:
        notes.append("Pasta Prefetch inexistente ou ilegível (o Prefetch pode estar desativado).")
        return []
    pf = [n for n in names if n.lower().endswith(".pf")]
    if not pf:
        notes.append("Pasta Prefetch vazia (recurso desativado ou arquivos apagados).")
    out = []
    for name in pf:
        m = _PF_NAME.match(name)
        if not m:
            continue
        exe = m["exe"].lower()
        for rx, desc, weight, techs in PREFETCH_TOOLS:
            if rx.match(exe):
                try:
                    when = _when(datetime.fromtimestamp((d / name).stat().st_mtime))
                except OSError:
                    when = ""
                out.append(_artifact(str(d / name), [(f"Execução registrada no Prefetch: {desc}", weight, techs)],
                                     "Prefetch", when, detail=f"{m['exe']} (hash do caminho {m['hash'].upper()})"))
                break
    return out


# ---------------------------------------------------------------- Windows: logs de eventos
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"


def parse_events(xml_text):
    """Saída de `wevtutil qe ... /f:xml` (vários <Event> concatenados) -> lista de dicts."""
    root = ET.fromstring("<Events>" + _CTRL.sub("", xml_text) + "</Events>")
    out = []
    for ev in root.iter(_NS + "Event"):
        sysel = ev.find(_NS + "System")
        if sysel is None or not (sysel.findtext(_NS + "EventID") or "").strip().isdigit():
            continue
        tc = sysel.find(_NS + "TimeCreated")
        data = {}
        ed = ev.find(_NS + "EventData")
        if ed is not None:
            data.update({d.get("Name"): d.text or "" for d in ed.findall(_NS + "Data") if d.get("Name")})
        ud = ev.find(_NS + "UserData")  # ex.: o evento 1102 guarda os campos aqui
        if ud is not None:
            for el in ud.iter():
                if el.text and el.text.strip():
                    data.setdefault(el.tag.rsplit("}", 1)[-1], el.text.strip())
        rec = (sysel.findtext(_NS + "EventRecordID") or "").strip()
        out.append({"id": int(sysel.findtext(_NS + "EventID").strip()), "channel": sysel.findtext(_NS + "Channel") or "",
                    "time": tc.get("SystemTime", "") if tc is not None else "", "record": rec, "data": data})
    return out


def _win_dt(s):
    """'2026-08-20T11:07:29.8995939Z' (UTC) -> datetime local sem fuso."""
    try:
        dt = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", s))
        return dt.astimezone().replace(tzinfo=None) if dt.tzinfo else dt
    except ValueError:
        return None


def _suspect_dir(text):
    low = text.lower()
    return any(d in low for d in core.SUSPECT_DIRS["windows"])


def analyze_windows_events(events, threshold=BRUTE_THRESHOLD):
    out, failures, successes = [], defaultdict(list), defaultdict(list)
    for e in events:
        eid, ch, d = e["id"], e["channel"], e["data"]
        dt = _win_dt(e["time"])
        when = _when(dt)
        where = f"{ch} · evento {eid}" + (f" (registro {e['record']})" if e["record"] else "")

        if ch == "Security" and eid == 1102:
            out.append(_artifact(where, [("Log de auditoria (Security) apagado", 70, ("T1685.005",))], ch, when,
                                 detail=f"usuário: {d.get('SubjectUserName', '?')}"))
        elif ch == "System" and eid == 104:
            out.append(_artifact(where, [("Log do sistema apagado", 60, ("T1685.005",))], ch, when,
                                 detail=f"usuário: {d.get('SubjectUserName', '?')}"))
        elif ch == "Security" and eid == 4720:
            out.append(_artifact(where, [(f"Conta de usuário criada: {d.get('TargetUserName', '?')}", 40, ("T1136.001",))],
                                 ch, when, detail=f"criada por {d.get('SubjectUserName', '?')}"))
        elif ch == "Security" and eid == 4732 and d.get("TargetSid") == ADMINS_SID:
            out.append(_artifact(where, [("Membro adicionado ao grupo Administradores", 50, ("T1098",))], ch, when,
                                 detail=f"{d.get('MemberName') or d.get('MemberSid', '?')} por {d.get('SubjectUserName', '?')}"))
        elif ch == "Security" and eid == 4698:
            content = d.get("TaskContent", "")
            r = _check(content)
            if _suspect_dir(content):
                r.append(("Tarefa criada executa de diretório suspeito", 25))
            if r:
                out.append(_artifact(where, r, ch, when, attack=(att.SCHEDULED_TASK,),
                                     detail=f"tarefa {d.get('TaskName', '?')} criada por {d.get('SubjectUserName', '?')}"))
        elif ch == "System" and eid == 7045:
            image = d.get("ImagePath", "")
            r = _check(image)
            if _suspect_dir(image):
                r.append(("Serviço instalado executa de diretório suspeito", 25))
            if r:
                out.append(_artifact(where, r, ch, when, attack=(att.WINDOWS_SERVICE,),
                                     detail=f"{d.get('ServiceName', '?')}: {image[:160]}"))
        elif ch == PS_CHANNEL and eid == 4104:
            text = d.get("ScriptBlockText", "")[:20000]
            r = _check(text)
            if r:
                out.append(_artifact(where, r, "PowerShell", when, attack=("T1059.001",), detail=text[:200]))
        elif ch == "Security" and eid == 4625:
            ip = d.get("IpAddress", "")
            if ip not in ("", "-", "::1", "127.0.0.1"):
                failures[ip].append((dt, d.get("TargetUserName", "")))
        elif ch == "Security" and eid == 4624 and d.get("LogonType") in ("3", "10"):
            ip = d.get("IpAddress", "")
            if ip not in ("", "-", "::1", "127.0.0.1"):
                successes[ip].append((dt, d.get("TargetUserName", "")))
    return out + _bruteforce("Security", failures, successes, threshold)


def _decode(raw):
    """Com a saída em pipe, o wevtutil usa a página de código ANSI do sistema (ex.: cp1252), não a OEM do console
    (verificado: 'Informações' sai como cp1252). Tenta UTF-8 estrito e depois a ANSI."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        import ctypes
        return raw.decode(f"cp{ctypes.windll.kernel32.GetACP()}", errors="replace")
    except (AttributeError, OSError, LookupError):
        return raw.decode("utf-8", errors="replace")


def _xpath(ids, days, event_data=None):
    ms = int(days * 86400 * 1000)
    q = f"*[System[({' or '.join(f'EventID={i}' for i in ids)}) and TimeCreated[timediff(@SystemTime) <= {ms}]]"
    if event_data:
        q += f" and EventData[{event_data}]"
    return q + "]"


# (canal, ids, limite, filtro de EventData)
_QUERIES = [
    ("Security", (1102, 4720, 4732, 4698), 500, None),
    ("Security", (4625,), 5000, None),
    ("Security", (4624,), 3000, "Data[@Name='LogonType']='10' or Data[@Name='LogonType']='3'"),
    ("System", (104, 7045), 500, None),
    (PS_CHANNEL, (4104,), 2000, None),
]


def _query_events(channel, ids, days, limit, event_data=None):
    cmd = ["wevtutil", "qe", channel, f"/q:{_xpath(ids, days, event_data)}", f"/c:{limit}", "/rd:true", "/f:xml"]
    res = subprocess.run(cmd, capture_output=True, timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if res.returncode == 5:  # ERROR_ACCESS_DENIED
        raise PermissionError(channel)
    if res.returncode != 0:
        raise OSError((_decode(res.stderr or res.stdout)).strip()[:200] or f"wevtutil código {res.returncode}")
    text = _decode(res.stdout)
    return parse_events(text) if text.strip() else []


def windows_events(days=DEFAULT_DAYS, notes=None):
    """Consulta os logs de eventos com o wevtutil (nativo, sem dependências) e analisa o resultado."""
    notes = notes if notes is not None else []
    events, denied = [], set()
    for channel, ids, limit, extra in _QUERIES:
        if channel in denied:
            continue
        try:
            got = _query_events(channel, ids, days, limit, extra)
            events += got
            if len(got) >= limit:  # /rd:true traz os mais recentes primeiro
                notes.append(f"{channel}: limite de {limit} eventos atingido para {list(ids)}; os mais antigos ficaram de fora.")
        except PermissionError:
            denied.add(channel)
            notes.append(f"Log {channel} ilegível sem administrador"
                         + (": logons, contas, grupos, tarefas e limpeza de log não foram analisados." if channel == "Security" else "."))
        except (OSError, subprocess.SubprocessError, ET.ParseError) as e:
            notes.append(f"Log {channel}: {e}")
    return analyze_windows_events(events)


# ---------------------------------------------------------------- orquestração
def run_forensics(os_name, days=DEFAULT_DAYS, notes=None, cancelled=lambda: False):
    notes = notes if notes is not None else []
    if os_name == "windows":
        steps = [lambda: windows_events(days, notes), lambda: windows_history(notes=notes),
                 lambda: windows_prefetch(notes=notes)]
    else:
        steps = [lambda: linux_auth(days=days, notes=notes), lambda: linux_history(notes=notes)]
    out = []
    for step in steps:
        if cancelled():
            break
        out += step()
    return out


# ---------------------------------------------------------------- artefatos OFFLINE (arquivos exportados)
# Funções para analisar arquivos coletados (ex.: de uma imagem de disco ou de um KAPE) sem depender da máquina
# atual. Nada do arquivo é executado: só é lido. Dependências opcionais: python-evtx e regipy.
MAX_ARTIFACT_BYTES = 2 * 1024 ** 3
MAX_HISTORY_BYTES = 100 * 1024 ** 2  # históricos são lidos inteiros em memória
_EVTX_MAGIC = b"ElfFile\x00"
_HIVE_MAGIC = b"regf"
_NO_WINDOW = 36500  # "sem janela" para logs coletados: o corte de N dias contado de hoje descartaria tudo


def _too_big(path, notes, limit=None):
    limit = MAX_ARTIFACT_BYTES if limit is None else limit
    try:
        size = Path(path).stat().st_size
    except OSError as e:
        notes.append(f"Não foi possível ler {path}: {e}")
        return True
    if size > limit:
        notes.append(f"{Path(path).name}: {size / 1024 ** 3:.1f} GB excede o limite de {limit / 1024 ** 3:.1f} GB; ignorado.")
        return True
    return False


def _evtx_events(path, days=None, notes=None):
    """Registros do .evtx -> eventos no mesmo formato de `parse_events`. Tolera registros e chunks corrompidos."""
    notes = notes if notes is not None else []
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        notes.append("python-evtx não instalado (pip install python-evtx): arquivos .evtx não foram lidos.")
        return []
    p = Path(path)
    if _too_big(p, notes):
        return []
    try:
        with open(p, "rb") as f:
            if f.read(8) != _EVTX_MAGIC:
                notes.append(f"{p.name}: não é um arquivo .evtx válido (assinatura 'ElfFile' ausente).")
                return []
    except OSError as e:
        notes.append(f"Não foi possível ler {p}: {e}")
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days) if days else None  # o .evtx guarda UTC
    events, bad = [], 0
    try:
        with Evtx(str(p)) as log:
            chunks = iter(log.chunks())
            while True:
                try:
                    chunk = next(chunks)
                except StopIteration:
                    break
                except Exception:  # noqa - cabeçalho de chunk corrompido: o gerador não continua depois disso
                    bad += 1
                    break
                try:
                    for rec in chunk.records():
                        try:
                            if cutoff is not None:
                                ts = rec.timestamp()  # no python-evtx 0.8.1 vem COM fuso (UTC); tolera versões que devolvam naive
                                if (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)) < cutoff:
                                    continue
                            events += parse_events(rec.xml())
                        except Exception:  # noqa - registro ilegível: conta e segue
                            bad += 1
                except Exception:  # noqa - corpo do chunk corrompido: segue para o próximo chunk
                    bad += 1
    except Exception as e:  # noqa - não abriu (arquivo truncado/corrompido)
        notes.append(f"{p.name}: não foi possível ler o .evtx ({type(e).__name__}: {e}).")
        return events
    if bad:
        notes.append(f"{p.name}: {bad} registro(s) ou bloco(s) não puderam ser lidos e foram ignorados (arquivo corrompido ou "
                     "registro que o python-evtx não sabe renderizar; em logs reais ~5% dos eventos de hardware/WHEA falham assim).")
    return events


def evtx_file(path, days=None, notes=None):
    """Analisa um .evtx exportado com as mesmas regras dos logs ao vivo (`analyze_windows_events`).
    `days`: janela a partir de hoje (None = o arquivo inteiro).
    Desempenho: o python-evtx renderiza ~150-180 eventos/s (medido), então um .evtx de 20 MB leva ~2 min.
    Para logs grandes, prefira `days` (descarta registros antigos sem renderizar) ou exporte já filtrado:
    `wevtutil epl Security out.evtx /q:"*[System[(EventID=4625 or EventID=4624)]]"`."""
    out = analyze_windows_events(_evtx_events(path, days, notes))
    for f in out:
        f["origin"] = Path(path).name
    return out


# --- Amcache / Shimcache (via regipy)
@contextlib.contextmanager
def _quiet_regipy():
    """O regipy loga como ERROR chaves ausentes que são normais (ex.: \\Root\\File); silencia durante a leitura."""
    lg = logging.getLogger("regipy")
    old = lg.level
    lg.setLevel(logging.CRITICAL)
    try:
        yield
    finally:
        lg.setLevel(old)


def _hive_has(hive, key_path):
    try:
        hive.get_key(key_path)
        return True
    except Exception:  # noqa - RegistryKeyNotFoundException e erros de parsing: tratados como "não tem"
        return False


def _hive_kind(hive):
    """'amcache' | 'system' | None, pelas CHAVES (o nome no cabeçalho do hive nem sempre identifica o tipo)."""
    if _hive_has(hive, r"\Root\InventoryApplicationFile") or _hive_has(hive, r"\Root\File"):
        return "amcache"
    if _hive_has(hive, r"\Select") or _hive_has(hive, r"\ControlSet001"):
        return "system"
    return None


def _exe_reasons(path, name, source):
    """Razões comuns a Amcache/Shimcache: ferramenta conhecida (PREFETCH_TOOLS) ou pasta suspeita."""
    exe = (name or ntpath.basename(path)).lower()
    reasons = []
    for rx, desc, weight, techs in PREFETCH_TOOLS:
        if rx.match(exe):
            reasons.append((f"Registrado no {source}: {desc}", weight, techs))
            break
    if path and _suspect_dir(path):
        reasons.append((f"Executável registrado no {source} em diretório suspeito", 25))
    return reasons


def analyze_amcache_entries(entries):
    """`entries`: saída do plugin `amcache` do regipy com as_json=True (dicts; ver regipy/plugins/amcache/amcache.py).
    Chaves usadas: lower_case_long_path (InventoryApplicationFile) ou full_path (formato antigo), name, sha1,
    publisher, timestamp (última gravação da chave no hive, aproxima a 1ª execução/instalação)."""
    out = []
    for e in entries:
        if not isinstance(e, dict):  # o plugin também inclui chaves (NamedKey) de volume; não são arquivos
            continue
        path = e.get("full_path") or e.get("lower_case_long_path") or e.get("path") or ""
        name = e.get("name") or ntpath.basename(path)
        reasons = _exe_reasons(path, name, "Amcache")
        if not reasons:
            continue
        sha1 = e.get("sha1") or ""
        ts = e.get("timestamp") or e.get("last_modified_timestamp") or ""
        detail = f"{name}" + (f" · SHA-1 {sha1}" if sha1 else "") + (f" · publisher: {e['publisher']}" if e.get("publisher") else "")
        out.append(_artifact(f"Amcache · {path or name}", reasons, "Amcache", _when(_win_dt(str(ts))) if ts else "",
                             detail=detail, sha1=sha1))
    return out


def analyze_shimcache_entries(entries):
    """`entries`: saída do plugin `shimcache` do regipy com as_json=True. Chaves: path, last_mod_date
    (Win7+; no XP, last_mod_time), exec_flag (só Win7/8). ATENÇÃO: a data é a de MODIFICAÇÃO DO ARQUIVO, não a de
    execução, e no Windows 8+ estar no Shimcache não prova que o programa rodou."""
    out, seen = [], set()
    for e in entries:
        if not isinstance(e, dict):
            continue
        path = e.get("path") or ""
        ts = e.get("last_mod_date") or e.get("last_mod_time") or ""
        key = (path.lower(), str(ts))
        if key in seen:  # o plugin lê ControlSet001 e 002: o mesmo registro aparece duas vezes
            continue
        seen.add(key)
        reasons = _exe_reasons(path, "", "Shimcache")
        if not reasons:
            continue
        out.append(_artifact(f"Shimcache · {path}", reasons, "Shimcache", _when(_win_dt(str(ts))) if ts else "",
                             detail=f"{path} (data = última modificação do arquivo, não a execução)"))
    return out


def hive_file(path, notes=None):
    """Analisa um hive do registro exportado: Amcache.hve (arquivos registrados) ou SYSTEM (Shimcache)."""
    notes = notes if notes is not None else []
    try:
        from regipy.registry import RegistryHive
        from regipy.plugins.amcache.amcache import AmCachePlugin
        from regipy.plugins.system.shimcache import ShimCachePlugin
    except ImportError:
        notes.append("regipy não instalado (pip install regipy): hives (Amcache/Shimcache) não foram lidos.")
        return []
    p = Path(path)
    if _too_big(p, notes):
        return []
    out = []
    with _quiet_regipy():
        try:
            hive = RegistryHive(str(p))
        except PermissionError:
            notes.append(f"{p.name}: sem permissão para ler o hive.")
            return []
        except Exception as e:  # noqa - construct.ConstError e afins: não é um hive válido
            notes.append(f"{p.name}: hive inválido ou corrompido ({type(e).__name__}).")
            return []
        kind = _hive_kind(hive)
        if kind is None:
            notes.append(f"{p.name}: hive {hive.hive_type or 'desconhecido'} sem Amcache nem AppCompatCache (Shimcache); "
                         "nada a analisar. Informe Amcache.hve ou o hive SYSTEM.")
            return []
        try:
            plugin = AmCachePlugin(hive, as_json=True) if kind == "amcache" else ShimCachePlugin(hive, as_json=True)
            plugin.run()
        except Exception as e:  # noqa - o plugin levanta Exception genérica para formatos desconhecidos
            notes.append(f"{p.name}: não foi possível interpretar o {'Amcache' if kind == 'amcache' else 'Shimcache'}: {e}")
            return []
        entries = plugin.entries if isinstance(plugin.entries, list) else []
        if kind == "amcache":
            out = analyze_amcache_entries(entries)
        else:
            if not entries:
                notes.append(f"{p.name}: Shimcache sem entradas legíveis (vazio ou formato não reconhecido).")
            out = analyze_shimcache_entries(entries)
    for f in out:
        f["origin"] = p.name
    return out


# --- despacho
_HISTORY_NAMES = {".bash_history", "bash_history", ".zsh_history", "zsh_history", ".sh_history", "sh_history", "fish_history"}
_AUTH_NAME = re.compile(r"^(auth\.log|secure)([.\-].*)?$")


def analyze_artifact_file(path, days=None):
    """Analisa um arquivo de artefato exportado, escolhendo o analisador pelo conteúdo (magic bytes) e pelo nome.
    Devolve (achados, notas). `days=None` analisa o arquivo inteiro. Nunca executa nada do arquivo."""
    notes = []
    p = Path(path)
    if not p.is_file():
        return [], [f"{p}: arquivo não encontrado."]
    if _too_big(p, notes):
        return [], notes
    try:
        with open(p, "rb") as f:
            magic = f.read(8)
    except OSError as e:
        return [], [f"Não foi possível ler {p}: {e}"]
    name = p.name.lower()
    window = days if days is not None else _NO_WINDOW

    if magic == _EVTX_MAGIC or name.endswith(".evtx"):
        return evtx_file(p, days, notes), notes
    if magic[:4] == _HIVE_MAGIC:
        return hive_file(p, notes), notes
    if _AUTH_NAME.match(name):
        return linux_auth(paths=[p], days=window, notes=notes), notes
    if name in _HISTORY_NAMES or name == "consolehost_history.txt":
        if _too_big(p, notes, MAX_HISTORY_BYTES):
            return [], notes
        try:
            if name == "consolehost_history.txt":
                return _scan_history_file(p, "windows", "histórico do PowerShell"), notes
            return _scan_history_file(p, "linux", "histórico de shell"), notes
        except OSError as e:
            return [], notes + [f"Não foi possível ler {p}: {e}"]
    if name.endswith(".pf"):
        # windows_prefetch lê só o NOME dos .pf da pasta; aproveita filtrando o arquivo pedido
        found = [f for f in windows_prefetch(directory=p.parent, notes=[]) if f["where"] == str(p.parent / p.name)]
        if not found:
            notes.append(f"{p.name}: nome não corresponde a nenhuma ferramenta conhecida (o conteúdo do .pf não é interpretado).")
        return found, notes
    notes.append(f"{p.name}: tipo de artefato não reconhecido (esperado: .evtx, hive do registro, auth.log/secure, "
                 "histórico de shell/PowerShell ou .pf).")
    return [], notes
