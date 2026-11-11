"""Vigil - relatórios (JSON, HTML autocontido e CSV), sem dependência de interface.

    report.write_report(rep, "saida.html")             # HTML (inclui a linha do tempo resumida)
    report.write_report(rep, "saida.json")             # relatório completo
    report.write_report(rep, "saida.csv")              # achados (CSV, utf-8-sig)
    report.write_report(rep, "saida.timeline.csv")     # linha do tempo (CSV, utf-8-sig)
    report.write_report(rep, "qualquer.nome", kind="html")   # força o formato: json | html | csv | timeline

Segurança do HTML: os valores vêm de arquivos, logs e linhas de comando que um atacante controla. Por isso tudo é
escapado com html.escape, não há JavaScript nem recurso externo (e uma CSP bloqueia ambos), e links ATT&CK só são
gerados a partir de IDs que casam `T\\d{4}(\\.\\d{3})?`, com o endereço montado aqui, nunca copiado do dado.
"""
import html
import json
import os
import re
from pathlib import Path

from . import timeline as tl

KINDS = ("json", "html", "csv", "timeline")
_TECH_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
_LEVEL_CLASS = {"ALTO": "hi", "MÉDIO": "mid", "BAIXO": "lo"}
_KIND_LABEL = {"file": "Arquivo", "persistence": "Persistência", "process": "Processo", "artifact": "Artefato"}
_TIMELINE_LIMIT = 200   # linhas da linha do tempo no HTML (o CSV traz tudo)
_LIST_LIMIT = 200       # itens por lista dentro de um achado / ignorados / quarentena
_CLIP = 4000            # tamanho máximo de um texto exibido

_CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1e293b;--muted:#5b6b82;--card:#f8fafc;--bd:#d9e1ec;--link:#1d4ed8;
--hi:#991b1b;--hi-bg:#fee2e2;--mid:#92400e;--mid-bg:#fef3c7;--lo:#1e40af;--lo-bg:#dbeafe;--ok:#166534;
--warn-bg:#fffbeb;--warn-bd:#d97706;--code-bg:#eef2f7}
@media (prefers-color-scheme:dark){:root{--bg:#0f172a;--fg:#e2e8f0;--muted:#94a3b8;--card:#131c31;--bd:#26344d;
--link:#7db1ff;--hi:#fecaca;--hi-bg:#5b1a1a;--mid:#fde68a;--mid-bg:#4a3510;--lo:#bfdbfe;--lo-bg:#1b2f55;--ok:#86efac;
--warn-bg:#2a2210;--warn-bd:#b7791f;--code-bg:#0b1222}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",Inter,"Noto Sans",Ubuntu,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.muted{color:var(--muted)}a{color:var(--link)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px}
.aviso{border-left:4px solid var(--warn-bd);background:var(--warn-bg)}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;margin:0}
dl.meta dt{color:var(--muted)}dl.meta dd{margin:0;word-break:break-word}
.chips{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0 0}
.chip{border-radius:999px;padding:5px 14px;font-weight:600}
.hi{background:var(--hi-bg);color:var(--hi)}.mid{background:var(--mid-bg);color:var(--mid)}
.lo{background:var(--lo-bg);color:var(--lo)}.tot{background:var(--code-bg);color:var(--fg)}
table{width:100%;border-collapse:collapse;border:1px solid var(--bd);border-radius:8px}
th,td{text-align:left;vertical-align:top;padding:7px 9px;border-bottom:1px solid var(--bd)}
th{color:var(--muted);background:var(--card);font-weight:600}th.num{text-align:right}
td.num{text-align:right;white-space:nowrap}td.nw{white-space:nowrap}
.badge{display:inline-block;border-radius:6px;padding:1px 8px;font-size:12px;font-weight:700}
.tag{display:inline-block;margin-left:6px;border:1px solid var(--bd);border-radius:6px;padding:0 6px;font-size:11px;color:var(--muted)}
.tag.new{color:var(--hi);border-color:var(--hi)}
details>summary{cursor:pointer;overflow-wrap:anywhere}
.tw{overflow-x:auto}td.loc{min-width:260px;width:100%}
.det{margin:8px 0 2px;padding:8px 10px;background:var(--code-bg);border-radius:8px}
.det ul{margin:4px 0 8px 18px;padding:0}.det dl{margin:0}
.det dt{color:var(--muted);font-size:12px;margin-top:8px}.det dd{margin:0;overflow-wrap:anywhere}
code,.mono{font-family:Consolas,"DejaVu Sans Mono",monospace;font-size:12.5px;overflow-wrap:anywhere}
.notes li{margin:3px 0}ul.plain{margin:6px 0 0 18px;padding:0}
footer{margin-top:32px;color:var(--muted);font-size:12px}
@media print{:root{--bg:#fff;--fg:#000;--muted:#444;--card:#fff;--bd:#bbb;--link:#000;--code-bg:#f2f2f2;--warn-bg:#fff;
--hi:#000;--mid:#000;--lo:#000;--hi-bg:#ddd;--mid-bg:#eee;--lo-bg:#f6f6f6}
body{font-size:11pt}main{max-width:none;padding:0}tr,.card{break-inside:avoid}
details::details-content{content-visibility:visible;display:block}}
"""


# ---------------------------------------------------------------- pequenos blocos
def _e(v, limit=_CLIP):
    """Texto -> HTML seguro (escapa < > & e aspas)."""
    return html.escape(tl.text(v, limit), quote=True)


def _lvl(f):
    lv = tl.level_of(f)
    return lv, _LEVEL_CLASS[lv]


def _badge(level):
    return f'<span class="badge {_LEVEL_CLASS.get(level, "lo")}">{_e(level)}</span>'


def _attack_link(a):
    """ID válido -> <a> para o MITRE (href montado aqui); inválido -> só texto escapado."""
    tid = tl.text(a.get("id") if isinstance(a, dict) else a)  # sem strip: o ID tem que casar exatamente
    name = tl.text(a.get("name")) if isinstance(a, dict) else ""
    label = _e(tid) + (f" · {_e(name)}" if name else "")
    if _TECH_ID.fullmatch(tid):
        href = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
        return f'<a href="{html.escape(href, quote=True)}" rel="noopener noreferrer" target="_blank">{label}</a>'
    return label


def _attack_cell(f):
    ids = [a for a in tl.as_list(f.get("attack"))][:_LIST_LIMIT]
    seen, parts = set(), []
    for a in ids:
        tid = tl.text(a.get("id") if isinstance(a, dict) else a)
        if tid.strip() and tid not in seen:
            seen.add(tid)
            parts.append(_attack_link({"id": tid}))
    return ", ".join(parts)


def _list(items, limit=_LIST_LIMIT, cls="plain"):
    items = tl.as_list(items)
    if not items:
        return ""
    more = f"<li class=\"muted\">… e mais {len(items) - limit}</li>" if len(items) > limit else ""
    return f'<ul class="{cls}">' + "".join(f"<li>{_e(i, 1000)}</li>" for i in items[:limit]) + more + "</ul>"


def _dl(pairs):
    body = "".join(f"<dt>{_e(k)}</dt><dd>{v}</dd>" for k, v in pairs if v)
    return f"<dl>{body}</dl>" if body else ""


def _target(t):
    if not isinstance(t, dict):
        return f"<code>{_e(t)}</code>" if tl.text(t) else ""
    bits = [f"<code>{_e(t.get('where'))}</code>"]
    if t.get("score") is not None:
        bits.append(f"{_badge(tl.level_of(t))} {tl.score_of(t)} pontos")
    r = _list(t.get("reasons"))
    sha = f'<div class="mono">SHA-256: {_e(t.get("sha256"))}</div>' if t.get("sha256") else ""
    return "<div>" + " ".join(bits) + "</div>" + r + sha


def _finding_row(f):
    lv, cls = _lvl(f)
    tags = ""
    if f.get("new") is True:
        tags += '<span class="tag new">novo</span>'
    tr = tl.trust_text(f.get("trust"))
    if tr:
        tags += f'<span class="tag">{_e(tr, 300)}</span>'
    if isinstance(f.get("target"), dict):
        tags += '<span class="tag">binário referenciado</span>'

    pairs = [
        ("Fonte", _e(f.get("source"))),
        ("Quando", _e(f.get("when"))),
        ("Detalhe", f"<code>{_e(f.get('detail'))}</code>" if f.get("detail") else ""),
        ("Executável", f"<code>{_e(f.get('exe'))}</code>" if f.get("exe") else ""),
        ("Linha de comando", f"<code>{_e(f.get('cmdline'))}</code>" if f.get("cmdline") else ""),
        ("SHA-256", f"<code>{_e(f.get('sha256'))}</code>" if f.get("sha256") else ""),
        ("Conexões externas", _list(f.get("remotes"))),
        ("Confiança", _e(tr, 300)),
    ]
    if f.get("failures"):
        pairs.append(("Tentativas falhas", str(_int(f.get("failures")))))
    if f.get("users"):
        pairs.append(("Usuários envolvidos", _list(f.get("users"))))
    if f.get("target") is not None:
        pairs.append(("Binário referenciado", _target(f.get("target"))))
    attacks = [_attack_link(a) for a in tl.as_list(f.get("attack"))[:_LIST_LIMIT]]
    pairs.append(("MITRE ATT&CK", "<ul class=\"plain\">" + "".join(f"<li>{a}</li>" for a in attacks) + "</ul>" if attacks else ""))

    reasons = _list(f.get("reasons"))
    det = f'<div class="det">{"<strong>Motivos</strong>" + reasons if reasons else ""}{_dl(pairs)}</div>'
    # ALTO já vem aberto: ao imprimir, o que importa aparece sem clicar
    opened = " open" if lv == "ALTO" else ""
    kind = _KIND_LABEL.get(f.get("type"), tl.text(f.get("type")) or "Achado")
    return (f'<tr><td class="nw">{_badge(lv)}</td><td class="nw">{_e(kind)}</td>'
            f'<td class="loc"><details{opened}><summary><code>{_e(f.get("where"), 1000)}</code>{tags}</summary>{det}</details></td>'
            f'<td class="nw">{_attack_cell(f)}</td><td class="num">{tl.score_of(f)}</td></tr>')


def _int(v):
    try:
        return max(0, int(float(v)))
    except (TypeError, ValueError, OverflowError):
        return 0


def _timeline_section(rows):
    rows = [r for r in rows if isinstance(r, dict)] if isinstance(rows, (list, tuple)) else []
    if not rows:
        return ""
    shown = rows[:_TIMELINE_LIMIT]
    body = "".join(
        f'<tr><td class="nw mono">{_e(r.get("when"))}</td><td class="nw">{_e(r.get("kind"))}</td>'
        f'<td><code>{_e(r.get("where"), 600)}</code></td><td class="nw">{_badge(tl.text(r.get("level")))}</td>'
        f'<td>{_e(r.get("summary"), 600)}</td></tr>' for r in shown)
    more = (f'<p class="muted">Mostrando {len(shown)} de {len(rows)} eventos; a exportação CSV traz todos.</p>'
            if len(rows) > len(shown) else "")
    return (f'<h2>Linha do tempo</h2><div class="tw"><table><thead><tr><th>Quando</th><th>Tipo</th><th>Local</th>'
            f"<th>Gravidade</th><th>Resumo</th></tr></thead><tbody>{body}</tbody></table></div>{more}")


def _path_list(title, items):
    items = tl.as_list(items)
    if not items:
        return ""
    texts = [tl.text(i.get("where")) if isinstance(i, dict) else tl.text(i) for i in items]
    return f"<h2>{_e(title)} ({len(texts)})</h2>" + _list(texts)


# ---------------------------------------------------------------- HTML
def to_html(report, rows=None):
    """Relatório HTML único e autocontido (sem JavaScript, sem recursos externos). `rows`: linha do tempo
    (saída de timeline.build) a resumir no relatório."""
    rep = report if isinstance(report, dict) else {}
    findings = sorted(tl.clean_findings(rep), key=lambda f: (-tl.score_of(f), tl.text(f.get("where"))))
    counts = {lv: 0 for lv in tl.LEVELS}
    for f in findings:
        counts[tl.level_of(f)] += 1
    new_n = sum(1 for f in findings if f.get("new") is True)

    meta = [("Computador", rep.get("host")), ("Sistema", rep.get("os")), ("Início", rep.get("started")),
            ("Fim", rep.get("finished")), ("Arquivos analisados", rep.get("files_scanned"))]
    meta_html = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in meta if v not in (None, ""))
    if rep.get("cancelled"):
        meta_html += "<dt>Situação</dt><dd><strong>Varredura cancelada: o resultado é parcial.</strong></dd>"

    chips = "".join(f'<span class="chip {_LEVEL_CLASS[lv]}">{counts[lv]} {_e(lv.capitalize())}</span>' for lv in tl.LEVELS)
    chips += f'<span class="chip tot">{len(findings)} no total</span>'
    if new_n:
        chips += f'<span class="chip tot">{new_n} novos</span>'

    notes = [n for n in tl.as_list(rep.get("notes")) if tl.text(n).strip()]
    notes_html = ""
    if notes:
        notes_html = ('<h2>Notas da varredura</h2><div class="card aviso"><ul class="notes">'
                      + "".join(f"<li>{_e(n, 2000)}</li>" for n in notes) + "</ul></div>")

    if findings:
        table = ('<div class="tw"><table><thead><tr><th>Gravidade</th><th>Tipo</th><th>Local</th><th>ATT&amp;CK</th>'
                 '<th class="num">Pontos</th></tr></thead><tbody>'
                 + "".join(_finding_row(f) for f in findings) + "</tbody></table></div>")
    else:
        table = '<div class="card"><strong style="color:var(--ok)">Nenhum achado nesta varredura.</strong></div>'

    return (
        '<!doctype html>\n<html lang="pt-BR"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="light dark">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
        f"<title>Vigil · Relatório de triagem</title><style>{_CSS}</style></head><body><main>"
        "<h1>Vigil · Relatório de triagem</h1>"
        '<p class="muted">Achados são indícios: confirme antes de agir. Falsos positivos são esperados.</p>'
        '<div class="card aviso"><strong>Triagem, não substitui antivírus/EDR.</strong> '
        "Um relatório sem achados não significa que o computador está limpo.</div>"
        f'<h2>Resumo</h2><div class="card"><dl class="meta">{meta_html}</dl><div class="chips">{chips}</div></div>'
        f"{notes_html}<h2>Achados</h2>{table}"
        f"{_timeline_section(rows)}"
        f'{_path_list("Enviados para a quarentena", rep.get("quarantined"))}'
        f'{_path_list("Ignorados", rep.get("ignored"))}'
        "<footer>Gerado pelo Vigil. Os textos acima vêm do computador analisado e foram escapados.</footer>"
        "</main></body></html>\n")


# ---------------------------------------------------------------- gravação
def _atomic_write(path, data):
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _kind_for(path, kind):
    if kind is not None:
        if kind not in KINDS:
            raise ValueError(f"formato desconhecido: {kind!r}; use um de {', '.join(KINDS)}")
        return kind
    name = path.name.lower()
    if name.endswith(".timeline.csv"):
        return "timeline"
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix in (".html", ".htm"):
        return "html"
    if suffix == ".csv":
        return "csv"
    raise ValueError(f"formato não suportado: {path.suffix or path.name!r}; "
                     "use .json, .html, .csv (achados) ou .timeline.csv (linha do tempo)")


def write_report(report, path, kind=None):
    """Grava o relatório no formato indicado pelo sufixo de `path` (ou por `kind`) e devolve o Path.
    A escrita é atômica (arquivo temporário + rename): o destino nunca fica pela metade."""
    p = Path(path)
    k = _kind_for(p, kind)
    rep = report if isinstance(report, dict) else {}
    if k == "json":
        data = json.dumps(rep, indent=2, ensure_ascii=False, default=str).encode("utf-8")
    elif k == "html":
        data = to_html(rep, tl.build(rep)[0]).encode("utf-8")
    elif k == "csv":
        data = tl.findings_to_csv(rep).encode("utf-8-sig")
    else:
        data = tl.to_csv(tl.build(rep)[0]).encode("utf-8-sig")
    _atomic_write(p, data)
    return p
