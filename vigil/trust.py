"""Vigil - confiança no binário: assinatura digital (Windows) e propriedade por pacote (Linux).

Serve para REDUZIR falsos positivos: um binário com assinatura válida (ou entregue e não modificado por um pacote
da distribuição) perde pontos de heurísticas fracas. Não é atestado de segurança: malware também é assinado, por
isso hash conhecido e regras YARA nunca são abrandados por aqui.

Só é consultado para arquivos que já geraram achado (poucos), porque cada consulta cria um subprocesso.
"""
import glob
import hashlib
import json
import os
import re
import subprocess

_cache = {}

_PS = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
       "$s=Get-AuthenticodeSignature -LiteralPath $env:VIGIL_TRUST_PATH;"
       "[pscustomobject]@{Status=[string]$s.Status;"
       "Subject=$(if($s.SignerCertificate){$s.SignerCertificate.Subject});"
       "OS=[bool]$s.IsOSBinary}|ConvertTo-Json -Compress")
_CN = re.compile(r'(?:^|,\s*)CN=(?:"([^"]+)"|([^,]+))')


def _ps_exe():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    p = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return p if os.path.exists(p) else "powershell"


def _publisher(subject):
    m = _CN.search(subject or "")
    return (m.group(1) or m.group(2)).strip() if m else ""


def windows_signature(path, timeout=30):
    """{"signed": bool, "status": str, "publisher": str, "os_binary": bool} ou None se não deu para consultar.
    Usa Get-AuthenticodeSignature, que entende assinaturas embutidas E de catálogo (arquivos do Windows)."""
    env = dict(os.environ, VIGIL_TRUST_PATH=str(path))
    try:
        res = subprocess.run([_ps_exe(), "-NoProfile", "-NonInteractive", "-Command", _PS], capture_output=True,
                             env=env, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if res.returncode != 0:
            return None
        data = json.loads(res.stdout.decode("utf-8", "replace").strip().lstrip("\ufeff"))
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return {"signed": data.get("Status") == "Valid", "status": data.get("Status") or "",
            "publisher": _publisher(data.get("Subject")), "os_binary": bool(data.get("OS"))}


# ---------------------------------------------------------------- Linux
def _run(cmd, timeout=20):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def _md5(path):
    h = hashlib.md5()  # só confere o md5sums do dpkg; não é uso de segurança
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _dpkg_verified(pkg, path):
    """True/False se o arquivo bate com o md5sums do pacote; None se não há como saber."""
    rel = os.path.realpath(path).lstrip("/")
    names = glob.glob(f"/var/lib/dpkg/info/{glob.escape(pkg)}.md5sums") + glob.glob(f"/var/lib/dpkg/info/{glob.escape(pkg)}:*.md5sums")
    for f in names:
        try:
            for line in open(f, encoding="utf-8", errors="replace"):
                digest, _, name = line.strip().partition("  ")
                if name == rel:
                    return _md5(path) == digest
        except OSError:
            continue
    return None


def linux_package(path):
    """{"package": nome, "verified": True/False/None} se o arquivo pertence a um pacote; senão None."""
    for candidate in dict.fromkeys((str(path), os.path.realpath(path))):
        res = _run(["dpkg", "-S", candidate])
        if res and res.returncode == 0 and res.stdout.strip():
            pkg = res.stdout.split(":", 1)[0].split(",")[0].strip()
            return {"package": pkg, "verified": _dpkg_verified(pkg, candidate)}
        res = _run(["rpm", "-qf", "--queryformat", "%{NAME}", candidate])
        if res and res.returncode == 0 and res.stdout.strip():
            return {"package": res.stdout.strip(), "verified": None}  # rpm: só propriedade (ver README)
    return None


# ---------------------------------------------------------------- interface
def check(path, os_name, use_cache=True):
    """Informação de confiança do binário, ou None se indisponível. Chaves: signed, publisher, package,
    verified, trusted (resumo booleano) e label (texto para o motivo do achado)."""
    try:
        st = os.stat(path)
        key = (os_name, os.path.normcase(str(path)), st.st_mtime_ns, st.st_size)
    except OSError:
        return None
    if use_cache and key in _cache:
        return _cache[key]
    info = windows_signature(path) if os_name == "windows" else linux_package(path)
    if info is not None:
        if os_name == "windows":
            info["trusted"] = bool(info["signed"])
            info["label"] = (("assinatura digital válida" + (f" ({info['publisher']})" if info["publisher"] else "")
                              + (", binário do Windows" if info.get("os_binary") else ""))
                             if info["signed"] else f"sem assinatura digital válida ({info['status'] or 'desconhecido'})")
        else:
            info["trusted"] = info["verified"] is not False
            info["label"] = f"pertence ao pacote {info['package']}" + (
                " e não foi modificado" if info["verified"] else "" if info["verified"] is None else " MAS FOI MODIFICADO")
    _cache[key] = info
    return info


def clear_cache():
    _cache.clear()
