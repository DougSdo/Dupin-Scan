"""Vigil - linha do tempo e exportação CSV dos achados (sem dependência de interface).

Tudo aqui é tolerante a dados faltando ou malformados: os achados vêm de arquivos, logs e comandos que um
atacante pode controlar, então nenhuma função levanta exceção por causa do conteúdo de um achado.

    rows, sem_data = timeline.build(report["findings"])
    texto = timeline.to_csv(rows)                  # grave com encoding="utf-8-sig" (Excel abre acentos certo)
"""
import csv
import io
import re
from datetime import datetime

LEVELS = ("ALTO", "MÉDIO", "BAIXO")
TIMELINE_HEADERS = ["Quando", "Tipo", "Fonte", "Local", "Gravidade", "Pontos", "ATT&CK", "Resumo"]
FINDINGS_HEADERS = ["Gravidade", "Pontos", "Tipo", "Local", "ATT&CK", "Motivos", "Fonte", "Quando",
                    "Detalhe", "SHA-256", "Novo", "Confiança"]

# Fontes de artefato que são eventos de log (o restante é "Artefato": históricos, Prefetch, auth.log...)
_EVENT_SOURCES = {"security", "system", "powershell", "application"}

_WHEN = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2})?)(\.\d+)?\s*(Z|z|[+-]\d{2}(?::?\d{2})?)?)?$")
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


# ---------------------------------------------------------------- tolerância a dados ruins
def text(v, limit=None):
    """Qualquer valor -> str, sem levantar exceção (None vira '')."""
    if v is None:
        return ""
    try:
        s = v if isinstance(v, str) else str(v)
    except Exception:  # noqa - __str__ de objetos estranhos
        return ""
    if limit is not None and len(s) > limit:
        return s[:limit] + "…"
    return s


def as_list(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple, set, frozenset)):
        return list(v)
    return [v]


def clean_findings(findings):
    """Lista de achados válidos (dicts). Aceita também o relatório inteiro; qualquer outra coisa vira []."""
    if isinstance(findings, dict):
        findings = findings.get("findings")
    if not isinstance(findings, (list, tuple)):
        return []
    return [f for f in findings if isinstance(f, dict)]


def score_of(f):
    try:
        v = f.get("score")
        if isinstance(v, bool):
            return 0
        return max(0, min(int(float(v)), 100))
    except (TypeError, ValueError, OverflowError):
        return 0


def level_of(f):
    lv = f.get("level")
    if isinstance(lv, str) and lv in LEVELS:
        return lv
    s = score_of(f)
    return "ALTO" if s >= 80 else "MÉDIO" if s >= 40 else "BAIXO"


def attack_ids(f):
    """IDs ATT&CK do achado, sem repetir, como strings (não valida o formato: quem exibe valida)."""
    out = []
    for a in as_list(f.get("attack")):
        tid = a.get("id") if isinstance(a, dict) else a
        tid = text(tid).strip()
        if tid and tid not in out:
            out.append(tid)
    return out


def trust_text(trust):
    """{signed, publisher, package} -> texto curto; '' se não houver informação."""
    if not isinstance(trust, dict):
        return ""
    parts = []
    if trust.get("signed") is True:
        pub = text(trust.get("publisher")).strip()
        parts.append(f"assinado: {pub}" if pub else "assinado")
    elif trust.get("signed") is False:
        parts.append("não assinado")
    pkg = text(trust.get("package")).strip()
    if pkg:
        parts.append(f"pacote: {pkg}")
    return "; ".join(parts)


def kind_of(f):
    t = f.get("type")
    if t == "file":
        return "Arquivo modificado"
    if t == "process":
        return "Processo iniciado"
    if t == "persistence":
        return "Persistência"
    if t == "artifact":
        src = text(f.get("source")).strip().lower()
        return "Evento" if src in _EVENT_SOURCES or src.startswith("microsoft-windows") else "Artefato"
    return text(t) or "Achado"


# ---------------------------------------------------------------- datas
def parse_when(value):
    """'2026-11-10T12:00:00', com espaço, com fração, 'Z' ou deslocamento (+03:00 / -0300) -> datetime local
    sem fuso. Devolve None para vazio, não-texto ou formato inválido."""
    if not isinstance(value, str):
        return None
    m = _WHEN.match(value.strip())
    if not m:
        return None
    day, clock, frac, tz = m.groups()
    clock = clock or "00:00"
    if len(clock) == 5:
        clock += ":00"
    iso = f"{day}T{clock}"
    if frac:
        iso += "." + (frac[1:] + "000000")[:6]
    if tz:
        tz = "+00:00" if tz in ("Z", "z") else (tz if ":" in tz else (tz + ":00" if len(tz) == 3 else tz[:3] + ":" + tz[3:]))
        iso += tz
    try:
        dt = datetime.fromisoformat(iso)
        return dt.astimezone().replace(tzinfo=None) if dt.tzinfo else dt
    except (ValueError, OverflowError, OSError):
        return None


# ---------------------------------------------------------------- linha do tempo
def build(findings):
    """Ordena os achados por tempo crescente. Devolve (linhas, quantos_ficaram_sem_data_valida)."""
    keyed, untimed = [], 0
    for f in clean_findings(findings):
        dt = parse_when(f.get("when"))
        if dt is None:
            untimed += 1
            continue
        where = text(f.get("where"))
        row = {
            "when": dt.isoformat(timespec="seconds"),
            "kind": kind_of(f),
            "source": text(f.get("source")),
            "where": where,
            "level": level_of(f),
            "score": score_of(f),
            "attack": ", ".join(attack_ids(f)),
            "summary": "; ".join(text(r) for r in as_list(f.get("reasons"))),
        }
        keyed.append((dt, -row["score"], where, row))
    keyed.sort(key=lambda t: t[:3])  # empate: nota maior primeiro, depois local (ordem estável e determinística)
    return [k[3] for k in keyed], untimed


# ---------------------------------------------------------------- CSV
def csv_safe(v):
    """Neutraliza CSV/formula injection: células que o Excel/LibreOffice interpretariam como fórmula
    (começam com = + - @ tab ou CR) ganham um apóstrofo na frente. Nomes de arquivo e comandos são dados do atacante."""
    s = text(v)
    c = s.lstrip(" ")[:1]
    return "'" + s if c and c in "".join(_FORMULA_START) else s


def _csv(headers, table):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(headers)
    for r in table:
        w.writerow([csv_safe(c) if isinstance(c, str) else c for c in r])
    return buf.getvalue()


def to_csv(rows):
    """CSV da linha do tempo (str; grave com utf-8-sig)."""
    table = []
    for r in rows if isinstance(rows, (list, tuple)) else []:
        if not isinstance(r, dict):
            continue
        try:
            score = int(r.get("score") or 0)
        except (TypeError, ValueError, OverflowError):
            score = 0
        table.append([text(r.get("when")), text(r.get("kind")), text(r.get("source")), text(r.get("where")),
                      text(r.get("level")), score, text(r.get("attack")), text(r.get("summary"))])
    return _csv(TIMELINE_HEADERS, table)


def findings_to_csv(findings):
    """CSV dos achados, do mais grave ao menos grave."""
    fs = sorted(clean_findings(findings), key=lambda f: (-score_of(f), text(f.get("where"))))
    table = []
    for f in fs:
        new = f.get("new")
        table.append([level_of(f), score_of(f), kind_of(f), text(f.get("where")), ", ".join(attack_ids(f)),
                      "; ".join(text(r) for r in as_list(f.get("reasons"))), text(f.get("source")),
                      text(f.get("when")), text(f.get("detail") or f.get("cmdline")), text(f.get("sha256")),
                      "sim" if new is True else "não" if new is False else "", trust_text(f.get("trust"))])
    return _csv(FINDINGS_HEADERS, table)
