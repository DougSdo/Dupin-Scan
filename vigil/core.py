"""Vigil - núcleo de varredura (sem dependência de interface)."""
import csv
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import stat
import subprocess
import time
import uuid
from datetime import datetime
from collections import Counter
from pathlib import Path
from typing import NamedTuple

from . import attack as att
from .attack import info as attack_info

try:
    import yara
except ImportError:
    yara = None
try:
    import psutil
except ImportError:
    psutil = None

# ---------------------------------------------------------------- constantes
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".rtf"}
EXEC_EXT = {
    "windows": {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com", ".lnk"},
    "linux": {".sh", ".elf", ".so", ".py", ".pl", ".bin", ".run"},
}
SUSPECT_DIRS = {
    "windows": ("\\temp\\", "\\appdata\\", "\\downloads\\", "\\programdata\\", "\\users\\public\\"),
    "linux": ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"),
}
PRUNE = {"linux": {"/proc", "/sys", "/dev", "/run", "/snap"}, "windows": set()}
MAX_SIZE = 100 * 1024 * 1024
ENTROPY_LIMIT = 7.2
# Variáveis externas que as regras YARA (inclusive as exportadas pelo Vigil) podem usar
# (inclui as usadas por repositórios públicos, como signature-base: extension, filetype, owner)
YARA_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}

class CmdRule(NamedTuple):
    rx: str            # regex aplicada ao comando em minúsculas
    desc: str
    weight: int
    attack: tuple = ()  # técnicas ATT&CK (ids); regras sem técnica não são exportadas como Sigma/YARA
    os: str = "any"     # "windows" | "linux" | "any" (usado só na exportação)


SUSPECT_CMD = [
    CmdRule(r"powershell.*(-enc\b|-encodedcommand|-w(indowstyle)?\s+hidden)",
            "PowerShell codificado/oculto", 50, ("T1059.001", "T1027.010"), "windows"),
    CmdRule(r"(curl|wget)[^|]*\|\s*(ba|z)?sh",
            "Download executado direto no shell", 60, ("T1105", "T1059.004"), "linux"),
    CmdRule(r"base64\s+(-d|--decode)", "Decodificação base64 em comando", 30, ("T1140",), "linux"),
    CmdRule(r"\bnc(at)?\b.*\s-e\s", "netcat com -e (possível reverse shell)", 70, ("T1059.004",), "linux"),
    CmdRule(r"bash\s+-i\s*>&?\s*/dev/tcp", "Reverse shell via /dev/tcp", 90, ("T1059.004",), "linux"),
    CmdRule(r"\bmshta\b", "LOLBin suspeito: mshta", 40, ("T1218.005",), "windows"),
    CmdRule(r"regsvr32.*scrobj", "LOLBin suspeito: regsvr32 com scrobj", 40, ("T1218.010",), "windows"),
    CmdRule(r"rundll32.*javascript", "LOLBin suspeito: rundll32 com javascript", 40, ("T1218.011",), "windows"),
    CmdRule(r"certutil.*-urlcache", "LOLBin suspeito: certutil -urlcache", 40, ("T1105",), "windows"),
    CmdRule(r"bitsadmin.*/transfer", "LOLBin suspeito: bitsadmin /transfer", 40, ("T1197",), "windows"),
    CmdRule(r"(/tmp/|/dev/shm/|/var/tmp/)", "Caminho temporário no comando", 20, (), "linux"),
    CmdRule(r"(\\temp\\|\\appdata\\local\\temp|\\users\\public\\)", "Caminho temporário no comando", 20, (), "windows"),
]


def check_cmd(text, rules=None):
    """Devolve [(descrição, peso, técnicas_attack)] das regras que casam com o comando.
    `rules`: lista de CmdRule alternativa (padrão: SUSPECT_CMD)."""
    low = text.lower()
    return [(r.desc, r.weight, r.attack) for r in (SUSPECT_CMD if rules is None else rules)
            if re.search(r.rx, low)]


def finding(kind, where, reasons, score=None, attack=(), **extra):
    """Monta um achado. `reasons`: (descrição, peso[, técnicas]) ou só texto.
    `attack`: técnicas do contexto (onde a persistência mora); as das razões são somadas, sem repetir."""
    if score is None:
        score = max(0, min(sum(r[1] for r in reasons if isinstance(r, tuple)), 100))  # pesos negativos = abatimentos
    names = [r[0] if isinstance(r, tuple) else r for r in reasons]
    techs = list(attack)
    for r in reasons:
        if isinstance(r, tuple) and len(r) > 2:
            techs += r[2]
    d = {"type": kind, "where": where, "score": score, "reasons": names,
         "attack": [attack_info(t) for t in dict.fromkeys(techs)]}
    d.update(extra)
    return d


# ---------------------------------------------------------------- arquivos
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


_SHA256_RX = re.compile(r"\b[a-fA-F0-9]{64}\b")


def load_hashes(path):
    """Lê SHA-256 de um arquivo de texto/CSV: extrai qualquer token de 64 hex por linha
    (aceita CSV com aspas, como o do MalwareBazaar) e ignora linhas de comentário (#)."""
    if not path:
        return set()
    out = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.lstrip().startswith("#"):
                continue
            out.update(h.lower() for h in _SHA256_RX.findall(line))
    return out


def load_yara(rules_dir, errors=None):
    """Compila as regras de uma pasta. Arquivos com erro são ignorados e descritos em `errors`."""
    if not (yara and rules_dir):
        return None
    good = {}
    for i, p in enumerate(sorted(Path(rules_dir).glob("*.yar*"))):
        try:
            yara.compile(filepath=str(p), externals=YARA_EXTERNALS)
        except Exception as e:  # noqa - yara.SyntaxError, yara.Error
            if errors is not None:
                errors.append(f"Regra YARA ignorada ({p.name}): {e}")
            continue
        good[f"{p.stem}_{i}"] = str(p)  # namespace único mesmo com nomes repetidos
    if not good:
        return None
    try:
        return yara.compile(filepaths=good, externals=YARA_EXTERNALS)
    except Exception as e:  # noqa
        if errors is not None:
            errors.append(f"Regras YARA não carregadas: {e}")
        return None


SCRIPT_EXT = {".ps1", ".psm1", ".vbs", ".js", ".bat", ".cmd", ".sh", ".py", ".pl", ".hta", ".wsf"}
STRONG_PREFIXES = ("Hash na lista", "Regra YARA")  # nunca abrandados por confiança no binário


class Ctx:
    """Contexto de uma varredura: fontes de detecção e cache de análises de binários (para a persistência e os
    processos analisarem o mesmo executável uma vez só)."""

    def __init__(self, os_name, bad_hashes=frozenset(), rules=None, check_trust=False):
        self.os_name, self.bad_hashes, self.rules, self.check_trust = os_name, bad_hashes, rules, check_trust
        self._cache = {}

    def analyze(self, path):
        key = _norm(path)
        if key not in self._cache:
            try:
                too_big = os.path.getsize(path) > MAX_SIZE
            except OSError:
                too_big = True
            self._cache[key] = None if too_big else analyze_file(path, self.os_name, self.bad_hashes, self.rules,
                                                                trust=self.check_trust)
        return self._cache[key]


def _decode_script(head):
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):  # PowerShell costuma salvar em UTF-16
        return head.decode("utf-16", errors="ignore")
    return head.decode("utf-8", errors="ignore")


def _mtime_iso(path):
    try:
        return datetime.fromtimestamp(os.stat(path).st_mtime).isoformat(timespec="seconds")
    except (OSError, OverflowError, ValueError):
        return ""


def analyze_file(path, os_name, bad_hashes, rules, trust=False):
    """Analisa um arquivo. `trust=True` consulta a assinatura digital (Windows) / o pacote (Linux) quando há
    achado em binário e abate heurísticas fracas de binários confiáveis."""
    p = Path(path)
    ext = p.suffix.lower()
    try:
        with open(path, "rb") as f:
            head = f.read(1024 * 1024)
        digest = sha256_file(path)
    except OSError:
        return None

    reasons = []
    if digest in bad_hashes:
        reasons.append(("Hash na lista de malware conhecido", 100))
    if rules:
        try:
            externals = {"filename": p.name, "filepath": str(p), "extension": p.suffix.lower(),
                         "filetype": p.suffix.lstrip(".").upper(), "owner": ""}
            for m in rules.match(str(path), timeout=10, externals=externals):
                reasons.append((f"Regra YARA: {m.rule}", 80))
        except Exception:
            pass

    is_pe = head[:2] == b"MZ"
    is_elf = head[:4] == b"\x7fELF"
    low = str(p).lower()
    in_suspect = any(d in low for d in SUSPECT_DIRS[os_name])

    if (is_pe or is_elf) and ext in DOC_EXT:
        reasons.append(("Binário executável disfarçado de documento", 40, ("T1036.008",)))

    parts = p.name.lower().split(".")
    if len(parts) > 2 and f".{parts[-1]}" in (EXEC_EXT["windows"] | EXEC_EXT["linux"]) and f".{parts[-2]}" in DOC_EXT:
        reasons.append(("Dupla extensão suspeita", 50, ("T1036.007",)))

    if (is_pe or is_elf) and entropy(head) > ENTROPY_LIMIT:
        reasons.append(("Entropia alta (possível empacotamento/criptografia)", 20, ("T1027.002",)))

    if (is_pe or is_elf) and in_suspect:
        reasons.append(("Binário em diretório comumente abusado", 15))

    if os_name == "linux" and is_elf and in_suspect:
        try:
            if os.stat(path).st_mode & 0o111:
                reasons.append(("ELF executável em /tmp, /dev/shm ou similar", 30))
        except OSError:
            pass

    if ext in SCRIPT_EXT and not (is_pe or is_elf):  # conteúdo de scripts pequenos (usa só o 1º MiB lido)
        for desc, w, techs in check_cmd(_decode_script(head), [r for r in SUSPECT_CMD if r.attack]):
            reasons.append((f"Script contém: {desc}", w, techs))

    if not reasons:
        return None
    extra = {}
    if trust and (is_pe or is_elf) and not any(r[0].startswith(STRONG_PREFIXES) for r in reasons):
        from . import trust as trust_mod  # import tardio: cada consulta cria um subprocesso
        info = trust_mod.check(path, os_name)
        if info:
            extra["trust"] = {k: info.get(k) for k in ("signed", "publisher", "package", "verified", "label")}
            if info["trusted"]:
                reasons.append((f"Binário confiável: {info['label']}", -30))
                if sum(r[1] for r in reasons) <= 0:
                    return None  # só heurísticas fracas e o binário é confiável: não vale o alarme
    return finding("file", str(p), reasons, sha256=digest, when=_mtime_iso(path), **extra)


def default_targets(os_name):
    home = Path.home()
    if os_name == "windows":
        cands = [home / "Downloads", home / "Desktop"]
        cands += [Path(os.environ[e]) for e in ("TEMP", "APPDATA") if os.environ.get(e)]
    else:
        cands = [home / "Downloads", home, Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")]
    return [str(c) for c in cands if str(c) and c.exists()]


def scan_files(targets, os_name, bad_hashes, rules, on_progress=None, on_finding=None, cancelled=lambda: False,
               trust=False):
    out, total, last = [], 0, 0.0
    prune = PRUNE[os_name]
    qdir = _norm(quarantine_path())  # nunca varre a própria quarentena
    for target in targets:
        # um alvo pode ser uma pasta ou um arquivo avulso
        walker = [(os.path.dirname(target), [], [os.path.basename(target)])] if os.path.isfile(target) else os.walk(target)
        for root, dirs, files in walker:
            if cancelled():
                return out, total
            dirs[:] = [d for d in dirs
                       if os.path.join(root, d) not in prune and _norm(os.path.join(root, d)) != qdir]
            for name in files:
                fp = os.path.join(root, name)
                try:
                    st = os.lstat(fp)
                except OSError:
                    continue
                # só arquivos regulares: FIFO/socket/dispositivo travariam o open(); links são ignorados
                if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SIZE:
                    continue
                total += 1
                r = analyze_file(fp, os_name, bad_hashes, rules, trust=trust)
                if r:
                    out.append(r)
                    if on_finding:
                        on_finding(r)
                now = time.monotonic()
                if on_progress and now - last > 0.1:
                    last = now
                    on_progress(fp, total)
                if cancelled():
                    return out, total
    return out, total


# ---------------------------------------------------------------- persistência e processos
# A lógica fica em persist.py; estes nomes continuam aqui por compatibilidade (testes, laboratório, quem importa o core).
def scan_text_file(path, technique=(), ctx=None):
    from . import persist
    return persist.scan_text_file(path, technique, ctx)


def linux_persistence(ctx=None, notes=None):
    from . import persist
    return persist.linux_persistence(ctx, notes)


def windows_persistence(ctx=None, notes=None):
    from . import persist
    return persist.windows_persistence(ctx, notes)


def scan_processes(os_name, ctx=None):
    from . import persist
    return persist.scan_processes(os_name, ctx)


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global  # exclui privados, loopback, link-local e CGNAT (100.64/10, ex.: Tailscale)
    except ValueError:
        return False


# ---------------------------------------------------------------- API
def host_os():
    return "windows" if platform.system() == "Windows" else "linux"


def level(score):
    return "ALTO" if score >= 80 else "MÉDIO" if score >= 40 else "BAIXO"


_MODULE_TYPES = {"files": "file", "persistence": "persistence", "processes": "process", "forensics": "artifact"}


def run_scan(os_name=None, modules=("files", "persistence", "processes", "forensics"), targets=None,
             hashes_path=None, yara_dir=None, on_progress=None, on_finding=None,
             cancelled=lambda: False, forensic_days=30, check_trust=False, track=False):
    """Executa a varredura e devolve o relatório (dict).

    check_trust: consulta assinatura digital (Windows) / pacote (Linux) dos binários que geraram achado.
    track: aplica a lista de ignorados e marca o que é novo desde a última varredura (grava em state.json).
           O padrão é False para a API não ter efeitos colaterais; a interface e a CLI ligam."""
    host = host_os()
    os_name = os_name or host
    modules = set(modules)
    notes = []
    live_ok = os_name == host
    if not live_ok:
        notes.append(f"Sistema escolhido ({os_name}) difere do host ({host}): só a varredura de arquivos foi executada.")

    def emit(msg, n=0):
        if on_progress:
            on_progress(msg, n)

    def report_findings(items):
        for x in items:
            if on_finding:
                on_finding(x)

    findings, total = [], 0
    started = datetime.now().isoformat(timespec="seconds")

    # Fontes de detecção, compartilhadas por arquivos, persistência e processos (que também analisam binários)
    rules = None
    if modules & {"files", "persistence", "processes"}:
        yara_errors = []
        rules = load_yara(yara_dir, yara_errors)
        notes += yara_errors
        if yara_dir and not rules and not yara_errors:
            notes.append("Regras YARA não carregadas (yara-python ausente ou pasta sem regras).")
    ctx = Ctx(os_name, load_hashes(hashes_path), rules, check_trust)

    if "files" in modules:
        tg = targets or default_targets(os_name)
        f, total = scan_files(load_targets(tg), os_name, ctx.bad_hashes, rules, on_progress, on_finding, cancelled,
                              trust=check_trust)
        findings += f
    if "persistence" in modules and live_ok and not cancelled():
        emit("Verificando persistência...", total)
        try:
            p = windows_persistence(ctx, notes) if os_name == "windows" else linux_persistence(ctx, notes)
        except Exception as e:  # noqa
            p = []
            notes.append(f"Persistência: {e}")
        report_findings(p)
        findings += p
    if "processes" in modules and live_ok and not cancelled():
        emit("Verificando processos...", total)
        if psutil is None:
            notes.append("psutil não instalado: módulo de processos ignorado.")
        else:
            try:
                p = scan_processes(os_name, ctx)
            except Exception as e:  # noqa
                p = []
                notes.append(f"Processos: {e}")
            report_findings(p)
            findings += p
    if "forensics" in modules and live_ok and not cancelled():
        emit("Analisando artefatos forenses...", total)
        from . import forensics  # import tardio: forensics importa o core
        try:
            p = forensics.run_forensics(os_name, forensic_days, notes, cancelled)
        except Exception as e:  # noqa
            p = []
            notes.append(f"Forense: {e}")
        report_findings(p)
        findings += p

    findings.sort(key=lambda x: x["score"], reverse=True)
    for x in findings:
        x["level"] = level(x["score"])

    ignored = []
    if track:
        from . import state  # import tardio: state importa o core
        scanned = {t for m, t in _MODULE_TYPES.items() if m in modules and (m == "files" or live_ok)}
        try:
            findings, ignored = state.annotate(findings, scanned, update=not cancelled())
        except OSError as e:
            notes.append(f"Não foi possível gravar o histórico de varreduras: {e}")
        for x in ignored:
            x["level"] = x.get("level") or level(x["score"])

    return {"os": os_name, "host": platform.platform(), "started": started,
            "finished": datetime.now().isoformat(timespec="seconds"),
            "cancelled": bool(cancelled()), "files_scanned": total,
            "notes": notes, "findings": findings, "ignored": ignored,
            "new": sum(1 for x in findings if x.get("new"))}


def make_report(findings, notes=(), os_name=None):
    """Relatório no formato de run_scan para achados que vieram de outro lugar (ex.: artefatos exportados)."""
    findings = sorted(findings, key=lambda x: x.get("score", 0), reverse=True)
    for x in findings:
        x.setdefault("level", level(x.get("score", 0)))
    now = datetime.now().isoformat(timespec="seconds")
    return {"os": os_name or host_os(), "host": platform.platform(), "started": now, "finished": now,
            "cancelled": False, "files_scanned": 0, "notes": list(notes), "findings": findings, "ignored": [], "new": 0}


def load_targets(targets):
    return [t for t in targets if t and os.path.exists(t)]


# ---------------------------------------------------------------- quarentena
def data_dir():
    if platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home()))
        return base / "Vigil"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "vigil"


def quarantine_path():
    """Pasta da quarentena (sem criá-la)."""
    return data_dir() / "quarantine"


def _norm(p):
    return os.path.normcase(os.path.abspath(str(p)))


def _qdir():
    d = quarantine_path()
    d.mkdir(parents=True, exist_ok=True)
    return d


def _index_path():
    return _qdir() / "index.json"


def list_quarantine():
    path = _index_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("índice inválido")
        return data
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        # Índice corrompido: preserva uma cópia em vez de deixá-lo ser sobrescrito pelo próximo salvamento.
        try:
            path.replace(path.with_name(f"index.corrompido-{datetime.now():%Y%m%d-%H%M%S}.json"))
        except OSError:
            pass
        return []


def _save_index(items):
    """Grava de forma atômica (arquivo temporário + rename) para não deixar um índice pela metade."""
    path = _index_path()
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def quarantine_file(path, sha256="", reasons=()):
    """Move o arquivo para a quarentena (sem permissão de execução). Nunca apaga."""
    qid = uuid.uuid4().hex[:12]
    dest = _qdir() / f"{qid}.quar"
    items = list_quarantine()  # lê antes de mover: se o índice estiver ilegível, nada foi movido ainda
    shutil.move(path, dest)
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    items.append({"id": qid, "original": str(path), "sha256": sha256, "reasons": list(reasons),
                  "date": datetime.now().isoformat(timespec="seconds")})
    try:
        _save_index(items)
    except OSError:
        shutil.move(dest, path)  # não deixa um arquivo órfão sem registro
        raise
    return qid


def restore_quarantine(qid):
    items = list_quarantine()
    item = next((i for i in items if i["id"] == qid), None)
    if not item:
        raise KeyError(qid)
    target = Path(item["original"])
    if target.exists():
        target = target.with_name(target.name + ".restaurado")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(_qdir() / f"{qid}.quar", target)
    _save_index([i for i in items if i["id"] != qid])
    return str(target)


def delete_quarantine(qid):
    items = list_quarantine()
    try:
        (_qdir() / f"{qid}.quar").unlink()
    except OSError:
        pass
    _save_index([i for i in items if i["id"] != qid])
