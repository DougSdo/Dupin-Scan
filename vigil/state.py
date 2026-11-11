"""Vigil - estado entre varreduras: achados ignorados e histórico do que já foi visto (baseline).

Tudo fica em `<pasta de dados>/state.json`, gravado de forma atômica:

  ignore  achados que o usuário marcou como "esperados". A chave inclui o hash do arquivo, então um arquivo
          ignorado que for modificado volta a aparecer.
  seen    chave -> {first, last}. Um achado é "novo" se nunca foi visto antes, e isso só é afirmado para tipos
          (arquivo, persistência, processo, artefato) que já tiveram uma varredura completa anterior; na
          primeira varredura nada é marcado como novo, para não pintar tudo igual.
"""
import hashlib
import json
import os
import re
from datetime import datetime

from . import core

MAX_SEEN = 50_000
_PID = re.compile(r"^PID \d+ ")


def _path():
    return core.data_dir() / "state.json"


def fingerprint(f):
    """Chave estável de um achado (não depende de PID, contagens nem da ordem da lista)."""
    t = f.get("type", "")
    where = f.get("where", "")
    if t == "file":
        basis = (os.path.normcase(where), f.get("sha256", ""))
    elif t == "process":
        basis = (_PID.sub("", where), f.get("exe", ""), f.get("cmdline", ""))
    elif t == "persistence":
        basis = (where, f.get("detail", ""))
    else:  # artifact e futuros
        basis = (f.get("source", ""), where, f.get("detail", ""))
    raw = "\x1f".join((t,) + tuple(str(x) for x in basis))
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:24]


def _empty():
    return {"version": 1, "ignore": [], "seen": {}, "types": []}


def load():
    p = _path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("estado inválido")
        base = _empty()
        base.update({k: data[k] for k in base if k in data})
        if not isinstance(base["ignore"], list) or not isinstance(base["seen"], dict):
            raise ValueError("estado inválido")
        return base
    except FileNotFoundError:
        return _empty()
    except (OSError, ValueError):
        try:  # preserva o arquivo ruim em vez de sobrescrevê-lo no próximo salvamento
            p.replace(p.with_name(f"state.corrompido-{datetime.now():%Y%m%d-%H%M%S}.json"))
        except OSError:
            pass
        return _empty()


def save(state):
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    seen = state["seen"]
    if len(seen) > MAX_SEEN:  # mantém os vistos mais recentemente
        keep = sorted(seen.items(), key=lambda kv: kv[1].get("last", ""), reverse=True)[:MAX_SEEN]
        state["seen"] = dict(keep)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=1, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)


# ---------------------------------------------------------------- ignorados
def list_ignored():
    return load()["ignore"]


def ignore(finding, note=""):
    """Marca o achado como esperado. Devolve a chave."""
    key = fingerprint(finding)
    st = load()
    if not any(i.get("key") == key for i in st["ignore"]):
        st["ignore"].append({"key": key, "type": finding.get("type", ""), "where": finding.get("where", ""),
                             "reasons": list(finding.get("reasons", [])), "note": note,
                             "date": datetime.now().isoformat(timespec="seconds")})
        save(st)
    return key


def unignore(key):
    st = load()
    n = len(st["ignore"])
    st["ignore"] = [i for i in st["ignore"] if i.get("key") != key]
    if len(st["ignore"]) != n:
        save(st)
        return True
    return False


# ---------------------------------------------------------------- aplicação a uma varredura
def annotate(findings, scanned_types, update=True, now=None):
    """Separa os ignorados e marca o restante com `key`, `new` e `first_seen`.

    scanned_types: tipos de achado que esta varredura cobriu.
    update: grava o que foi visto (use False para varreduras canceladas/parciais).
    Devolve (mantidos, ignorados)."""
    st = load()
    now_s = (now or datetime.now()).isoformat(timespec="seconds")
    ignored_keys = {i.get("key") for i in st["ignore"]}
    seen, prior_types = st["seen"], set(st["types"])
    kept, ignored = [], []
    for f in findings:
        key = fingerprint(f)
        f["key"] = key
        if key in ignored_keys:
            ignored.append(f)
            continue
        entry = seen.get(key)
        f["new"] = None if f.get("type") not in prior_types else entry is None
        f["first_seen"] = entry["first"] if entry else now_s
        kept.append(f)
        if update:
            seen[key] = {"first": f["first_seen"], "last": now_s}
    if update:
        st["types"] = sorted(prior_types | set(scanned_types))
        save(st)
    return kept, ignored
