"""Vigil - inteligência de ameaças (sem dependência de interface). TUDO AQUI É OPT-IN.

O Vigil funciona 100% offline. Este módulo só toca a rede quando o usuário pede explicitamente:

  update_hashes()  baixa uma lista pública de SHA-256 de malware (padrão: MalwareBazaar, que exige Auth-Key gratuita)
  update_yara()    baixa e VALIDA um pacote público de regras YARA (padrão: Neo23x0/signature-base)
  vt_lookup()      consulta UM hash na VirusTotal (nunca envia o arquivo, só o hash)

Garantias:
  - só HTTPS (inclusive em redirecionamentos); timeout e tetos de tamanho em tudo que é baixado;
  - nada que identifique o usuário/máquina vai na requisição (User-Agent genérico "Vigil");
  - chaves de API nunca aparecem em mensagens de erro, arquivos gravados nem metadados;
  - tudo é gravado só em intel_dir() e de forma atômica: uma atualização que falha preserva o que já existia;
  - todo acesso à rede passa por `_open`, para os testes o substituírem.

Verificado em 2026-11-11 (leituras limitadas a 4 KB): o antigo https://bazaar.abuse.ch/export/txt/sha256/recent/
devolve 410 Gone; a MalwareBazaar agora exige Auth-Key e documenta
https://mb-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv. O formato exato do CSV fica atrás de login e
NÃO foi verificado: o Vigil extrai qualquer token de 64 hex por linha (ignora linhas com '#'), como core.load_hashes.
"""
import io
import json
import os
import re
import shutil
import socket
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
import http.client
from datetime import datetime
from pathlib import Path

from . import core

# Exige Auth-Key gratuita (https://auth.abuse.ch/). {auth_key} é substituído em tempo de chamada.
DEFAULT_HASH_URL = "https://mb-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
DEFAULT_YARA_URL = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
VT_GUI = "https://www.virustotal.com/gui/file/{sha256}"
USER_AGENT = "Vigil"
TIMEOUT = 30
CHUNK = 64 * 1024

MAX_HASH_BYTES = 50 * 1024 * 1024       # lista de hashes
MAX_ZIP_BYTES = 100 * 1024 * 1024       # zip de regras baixado
MAX_VT_BYTES = 2 * 1024 * 1024          # resposta JSON da VirusTotal
MAX_ZIP_ENTRIES = 50_000                # entradas no zip (qualquer tipo)
MAX_YARA_FILES = 5_000                  # regras aceitas
MAX_YARA_MEMBER_BYTES = 5 * 1024 * 1024  # por arquivo de regra
MAX_YARA_TOTAL_BYTES = 200 * 1024 * 1024  # soma das regras extraídas (descomprimidas)

_SHA256_RX = re.compile(r"\b[a-fA-F0-9]{64}\b")  # igual à de core.load_hashes
_HEX64 = re.compile(r"^[a-fA-F0-9]{64}$")
_INCLUDE_RX = re.compile(r"^\s*include\s+\"", re.M)
_SECRET_HEADERS = {"auth-key", "x-apikey"}


class IntelError(Exception):
    """Falha de rede, de formato ou de segurança. A mensagem nunca contém chaves de API."""


class IntelHTTPError(IntelError):
    def __init__(self, code, message=""):
        super().__init__(message or f"HTTP {code}")
        self.code = code


# ---------------------------------------------------------------- utilidades
def intel_dir():
    """Pasta de trabalho do módulo (avaliada na hora: os testes trocam core.data_dir)."""
    return core.data_dir() / "intel"


def hashes_path():
    p = intel_dir() / "hashes.txt"
    return p if p.is_file() else None


def yara_dir():
    p = intel_dir() / "yara"
    return p if p.is_dir() else None


def _redact(text, secrets):
    for s in secrets:
        if s:
            text = text.replace(s, "***").replace(urllib.parse.quote(s, safe=""), "***")
    return text


def _now():
    return datetime.now().isoformat(timespec="seconds")


def _atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        if isinstance(data, str):
            tmp.write_text(data, encoding="utf-8", newline="\n")
        else:
            tmp.write_bytes(data)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _read_meta(base):
    try:
        data = json.loads((Path(base) / "meta.json").read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_meta(base, section, info):
    meta = _read_meta(base)
    meta[section] = info
    _atomic_write(Path(base) / "meta.json", json.dumps(meta, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------- rede
class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Recusa redirecionamento para fora de HTTPS e não leva cabeçalhos de chave a outro domínio."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise IntelError("Redirecionamento para endereço não HTTPS recusado.")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).hostname != urllib.parse.urlsplit(req.full_url).hostname:
            for store in (new.headers, new.unredirected_hdrs):
                for k in [k for k in store if k.lower() in _SECRET_HEADERS]:
                    del store[k]
        return new


def _require_https(url):
    if not str(url).lower().startswith("https://"):
        raise IntelError("Somente endereços HTTPS são aceitos.")


def _open(req_or_url, timeout=TIMEOUT):
    """Único ponto de rede do módulo. Devolve a resposta (2xx); erros viram IntelError/IntelHTTPError."""
    req = req_or_url
    if isinstance(req, str):
        req = urllib.request.Request(req, headers={"User-Agent": USER_AGENT})
    _require_https(req.full_url)
    try:
        return urllib.request.build_opener(_SafeRedirect()).open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        code = e.code
        e.close()
        raise IntelHTTPError(code, f"O servidor respondeu HTTP {code}.") from None
    except IntelError:
        raise
    except (urllib.error.URLError, socket.timeout, TimeoutError, ssl.SSLError, OSError, http.client.HTTPException) as e:
        reason = getattr(e, "reason", e)
        raise IntelError(f"Falha de rede: {type(reason).__name__}.") from None


def _request(url, headers=None):
    h = {"User-Agent": USER_AGENT}
    h.update(headers or {})
    return urllib.request.Request(url, headers=h, method="GET")


def _declared_length(resp):
    headers = getattr(resp, "headers", None)
    value = headers.get("Content-Length") if headers is not None else None
    return int(value) if value and str(value).isdigit() else None


def _read_limited(resp, limit, what):
    """Lê a resposta em blocos e aborta se passar do teto (também confere Content-Length)."""
    declared = _declared_length(resp)
    if declared is not None and declared > limit:
        raise IntelError(f"{what}: a resposta ({declared // 1024 // 1024} MB) passa do limite de {limit // 1024 // 1024} MB.")
    buf = io.BytesIO()
    while True:
        chunk = resp.read(CHUNK)
        if not chunk:
            break
        buf.write(chunk)
        if buf.tell() > limit:
            raise IntelError(f"{what}: a resposta passa do limite de {limit // 1024 // 1024} MB e foi descartada.")
    return buf.getvalue()


def _fetch(req, limit, what, secrets=()):
    try:
        resp = _open(req)
        try:
            return _read_limited(resp, limit, what)
        finally:
            close = getattr(resp, "close", None)
            if close:
                close()
    except IntelHTTPError as e:
        raise IntelHTTPError(e.code, _redact(str(e), secrets)) from None
    except IntelError as e:
        raise IntelError(_redact(str(e), secrets)) from None
    except OSError as e:  # falha no meio da leitura
        raise IntelError(_redact(f"Falha de rede: {type(e).__name__}.", secrets)) from None


# ---------------------------------------------------------------- hashes
def update_hashes(url=DEFAULT_HASH_URL, auth_key=None, dest=None):
    """Baixa uma lista de SHA-256 e grava em intel_dir()/hashes.txt (um por linha, minúsculos, sem duplicatas).

    `url` pode conter {auth_key} (padrão da MalwareBazaar). `auth_key` também vai no cabeçalho `Auth-Key`.
    `dest`: pasta de destino alternativa (padrão: intel_dir()). Devolve dict(count, path, source, date).
    """
    secrets = [auth_key] if auth_key else []
    if "{auth_key}" in url:
        if not auth_key:
            raise IntelError("A MalwareBazaar exige uma Auth-Key gratuita (https://auth.abuse.ch/). "
                             "Informe a chave para atualizar a lista de hashes.")
        url = url.replace("{auth_key}", urllib.parse.quote(auth_key, safe=""))
    _require_https(url)
    source = urllib.parse.urlsplit(url).hostname or "?"
    headers = {"Auth-Key": auth_key} if auth_key else {}

    try:
        raw = _fetch(_request(url, headers), MAX_HASH_BYTES, "Lista de hashes", secrets)
    except IntelHTTPError as e:
        if e.code in (401, 403):
            raise IntelError("O servidor recusou a Auth-Key (HTTP %d). Confira a chave em https://auth.abuse.ch/." % e.code) from None
        if e.code in (404, 410):
            raise IntelError(f"O endereço da lista não existe mais (HTTP {e.code}). Confira a URL nas configurações.") from None
        raise

    hashes = set()
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        if line.lstrip().startswith("#"):
            continue
        hashes.update(h.lower() for h in _SHA256_RX.findall(line))
    if not hashes:
        raise IntelError("A resposta não contém nenhum SHA-256: a chave pode estar inválida ou o formato mudou. "
                         "A lista anterior foi mantida.")

    base = Path(dest) if dest is not None else intel_dir()
    date = _now()
    path = base / "hashes.txt"
    body = f"# Vigil: {len(hashes)} hashes importados de {source} em {date}\n" + "\n".join(sorted(hashes)) + "\n"
    _atomic_write(path, body)
    _write_meta(base, "hashes", {"date": date, "source": source, "url": _redact(url, secrets), "count": len(hashes)})
    return {"count": len(hashes), "path": str(path), "source": source, "date": date}


# ---------------------------------------------------------------- YARA
def _swap_dir(new, final):
    """Troca `final` por `new` preservando o antigo se algo falhar no meio."""
    new, final = Path(new), Path(final)
    old = None
    if final.exists():
        old = final.with_name(f"{final.name}.old-{uuid.uuid4().hex[:8]}")
        os.rename(final, old)
    try:
        os.rename(new, final)
    except OSError:
        if old is not None:
            os.rename(old, final)  # restaura a pasta antiga
        raise
    if old is not None:
        shutil.rmtree(old, ignore_errors=True)


def _unique_name(name, taken):
    stem, ext = os.path.splitext(name)
    n, cand = 2, name
    while cand.lower() in taken:
        cand = f"{stem}_{n}{ext}"
        n += 1
    taken.add(cand.lower())
    return cand


def _suspicious_member(name):
    parts = re.split(r"[\\/]+", name)
    return name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name) is not None or ".." in parts


def update_yara(url=DEFAULT_YARA_URL, dest=None):
    """Baixa um zip de regras, valida cada uma com yara-python e troca intel_dir()/yara de uma vez.

    Só extrai .yar/.yara; nomes são achatados (nada é escrito fora da pasta de trabalho). Regras inválidas, com
    `include` ou acima dos tetos são descartadas e listadas. Devolve dict(files, skipped, errors, path, date).
    """
    if core.yara is None:
        raise IntelError("yara-python não está instalado: não dá para validar as regras, então nada foi baixado ou instalado "
                         "(pip install yara-python).")
    _require_https(url)
    base = Path(dest) if dest is not None else intel_dir()
    base.mkdir(parents=True, exist_ok=True)
    skipped, errors = [], []

    work = Path(tempfile.mkdtemp(prefix="yara-work-", dir=base))
    try:
        zpath = work / "regras.zip"
        try:
            resp = _open(_request(url))
        except IntelHTTPError as e:
            raise IntelError(f"Não foi possível baixar as regras (HTTP {e.code}).") from None
        try:
            declared = _declared_length(resp)
            if declared is not None and declared > MAX_ZIP_BYTES:
                raise IntelError("O pacote de regras passa do limite de tamanho e foi descartado.")
            total = 0
            with open(zpath, "wb") as f:
                while True:
                    chunk = resp.read(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ZIP_BYTES:
                        raise IntelError("O pacote de regras passa do limite de tamanho e foi descartado.")
                    f.write(chunk)
        finally:
            close = getattr(resp, "close", None)
            if close:
                close()

        staging = work / "novo"
        staging.mkdir()
        taken, total_unzipped, accepted = set(), 0, 0
        try:
            zf = zipfile.ZipFile(zpath)
        except zipfile.BadZipFile:
            raise IntelError("O arquivo baixado não é um zip válido.") from None
        with zf:
            infos = zf.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise IntelError("O pacote tem entradas demais e foi descartado.")
            for info in infos:
                name = info.filename
                if info.is_dir() or not name.lower().endswith((".yar", ".yara")):
                    continue
                if _suspicious_member(name):
                    skipped.append(f"{name}: caminho suspeito (possível zip-slip)")
                    continue
                if accepted >= MAX_YARA_FILES:
                    skipped.append(f"{name}: limite de {MAX_YARA_FILES} regras atingido")
                    continue
                try:
                    with zf.open(info) as src:
                        data = src.read(MAX_YARA_MEMBER_BYTES + 1)  # o tamanho DECLARADO não é confiável
                except (RuntimeError, NotImplementedError, zipfile.BadZipFile, EOFError, OSError) as e:
                    skipped.append(f"{name}: não foi possível ler ({type(e).__name__})")
                    continue
                if len(data) > MAX_YARA_MEMBER_BYTES:
                    skipped.append(f"{name}: arquivo grande demais (possível zip bomb)")
                    continue
                total_unzipped += len(data)
                if total_unzipped > MAX_YARA_TOTAL_BYTES:
                    skipped.append(f"{name}: limite do total descomprimido atingido")
                    continue
                if _INCLUDE_RX.search(data.decode("utf-8", errors="ignore")):
                    skipped.append(f"{name}: usa `include` (não aceito por segurança)")
                    continue
                target = staging / _unique_name(os.path.basename(name.replace("\\", "/")), taken)
                target.write_bytes(data)
                try:
                    core.yara.compile(filepath=str(target), externals=core.YARA_EXTERNALS)
                except Exception as e:  # noqa - yara.SyntaxError, yara.Error
                    target.unlink(missing_ok=True)
                    errors.append(f"{name}: {str(e)[:200]}")
                    continue
                accepted += 1

        if accepted == 0:
            raise IntelError("Nenhuma regra válida no pacote; as regras anteriores foram mantidas.")
        final = base / "yara"
        try:
            _swap_dir(staging, final)
        except OSError as e:
            raise IntelError(f"Não foi possível instalar as regras ({type(e).__name__}); as anteriores foram mantidas.") from None
    finally:
        shutil.rmtree(work, ignore_errors=True)

    date = _now()
    _write_meta(base, "yara", {"date": date, "source": urllib.parse.urlsplit(url).hostname or "?", "url": url,
                               "files": accepted})
    return {"files": accepted, "skipped": skipped, "errors": errors, "path": str(final), "date": date}


# ---------------------------------------------------------------- VirusTotal
def _vt_result(status, message="", stats=None, link=""):
    s = stats or {}
    return {"status": status, "malicious": s.get("malicious"), "suspicious": s.get("suspicious"),
            "harmless": s.get("harmless"), "undetected": s.get("undetected"), "link": link, "message": message}


def vt_lookup(sha256, api_key):
    """Consulta UM hash na VirusTotal. Só o hash sai da máquina (GET, sem corpo, sem parâmetros extras)."""
    if not isinstance(sha256, str) or not _HEX64.match(sha256):
        raise IntelError("Hash inválido: esperado um SHA-256 (64 caracteres hexadecimais).")
    sha256 = sha256.lower()
    link = VT_GUI.format(sha256=sha256)
    if not api_key:
        return _vt_result("unauthorized", "Chave da API da VirusTotal não informada.")
    secrets = [api_key]
    req = _request(VT_URL.format(sha256=sha256), {"x-apikey": api_key, "Accept": "application/json"})
    try:
        raw = _fetch(req, MAX_VT_BYTES, "VirusTotal", secrets)
    except IntelHTTPError as e:
        if e.code in (401, 403):
            return _vt_result("unauthorized", "A VirusTotal recusou a chave da API.")
        if e.code == 404:
            return _vt_result("not_found", "A VirusTotal não conhece este arquivo (isso não significa que seja seguro).", link=link)
        if e.code == 429:
            return _vt_result("rate_limited", "Limite de consultas da VirusTotal atingido: tente de novo mais tarde.")
        return _vt_result("error", _redact(str(e), secrets))
    except IntelError as e:
        return _vt_result("error", _redact(str(e), secrets))
    try:
        stats = json.loads(raw.decode("utf-8", errors="replace"))["data"]["attributes"]["last_analysis_stats"]
        if not isinstance(stats, dict):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        return _vt_result("error", "Resposta da VirusTotal em formato inesperado.")
    return _vt_result("found", f"{stats.get('malicious', 0)} mecanismo(s) marcaram como malicioso.", stats, link)


# ---------------------------------------------------------------- estado
def _count_lines(path):
    n = 0
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip() and not line.lstrip().startswith("#"):
                n += 1
    return n


def status():
    """Resumo do que existe em intel_dir(), tolerante a arquivos ausentes ou corrompidos."""
    base = intel_dir()
    meta = _read_meta(base)

    def section(name):
        s = meta.get(name)
        return s if isinstance(s, dict) else {}

    hs, ys = section("hashes"), section("yara")
    hp = hashes_path()
    count = hs.get("count") if isinstance(hs.get("count"), int) else None
    if hp is not None and count is None:
        try:
            count = _count_lines(hp)
        except OSError:
            count = None
    yd = yara_dir()
    files = None
    if yd is not None:
        try:
            files = sum(1 for p in yd.iterdir() if p.suffix.lower() in (".yar", ".yara"))
        except OSError:
            files = None
    return {
        "dir": str(base),
        "hashes": {"present": hp is not None, "count": count if hp is not None else None, "date": hs.get("date"),
                   "source": hs.get("source"), "path": str(hp) if hp else None},
        "yara": {"present": yd is not None, "files": files, "date": ys.get("date"),
                 "source": ys.get("source"), "path": str(yd) if yd else None},
    }
