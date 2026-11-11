"""Vigil - linha de comando (sem interface gráfica, própria para agendar e automatizar).

    python -m vigil scan --out relatorio.json --fail-on ALTO
    python -m vigil scan --modules files,forensics --targets C:\\Users\\eu\\Downloads --out rel.html
    python -m vigil analyze Security.evtx auth.log.1.gz --out artefatos.html
    python -m vigil timeline relatorio.json --out linha-do-tempo.csv
    python -m vigil export-rules --out regras
    python -m vigil ignored list | remove CHAVE | add CHAVE --report relatorio.json
    python -m vigil intel status | update-hashes | update-yara | vt SHA256

Códigos de saída: 0 sem achados no limite pedido, 1 erro, 2 há achados em --fail-on ou acima.
Chaves de API só por variável de ambiente (ABUSECH_AUTH_KEY, VT_API_KEY): argumentos aparecem na lista de processos.
Qualquer acesso à rede é um comando explícito (`intel ...`); `scan` nunca usa a rede.
"""
import argparse
import json
import os
import platform
import sys
from datetime import datetime
from pathlib import Path

from . import core

COMMANDS = ("scan", "analyze", "timeline", "export-rules", "ignored", "intel")
MODULES = ("files", "persistence", "processes", "forensics")
_RANK = {"BAIXO": 1, "MÉDIO": 2, "ALTO": 3}


def _err(msg):
    print(f"vigil: {msg}", file=sys.stderr)
    return 1


def _progress(quiet):
    if quiet or not sys.stderr.isatty():
        return None

    def cb(msg, n):
        text = f"{n:,} arquivos · {msg}".replace(",", ".")
        sys.stderr.write("\r" + text[-100:].ljust(100))
        sys.stderr.flush()

    return cb


def summarize(rep, limit=25, out=None):
    out = out or sys.stdout  # resolvido na chamada: um padrão fixado no import ignoraria redirecionamentos
    f = rep.get("findings", [])
    n = {lv: sum(1 for x in f if x.get("level") == lv) for lv in ("ALTO", "MÉDIO", "BAIXO")}
    extra = []
    if rep.get("new"):
        extra.append(f"{rep['new']} novos")
    if rep.get("ignored"):
        extra.append(f"{len(rep['ignored'])} ignorados")
    print(f"Vigil: {len(f)} achados ({n['ALTO']} alto, {n['MÉDIO']} médio, {n['BAIXO']} baixo)"
          + (" · " + ", ".join(extra) if extra else "") + f" · {rep.get('files_scanned', 0)} arquivos varridos", file=out)
    for x in f[:limit]:
        ids = ",".join(t["id"] for t in x.get("attack", []))
        mark = " [NOVO]" if x.get("new") else ""
        print(f" {x.get('level', '?'):6} {x.get('score', 0):3}  {x.get('type', ''):12} {x.get('where', '')[:90]}{mark}"
              + (f"  [{ids}]" if ids else ""), file=out)
        print(f"            {'; '.join(x.get('reasons', []))[:150]}", file=out)
    if len(f) > limit:
        print(f" ... e mais {len(f) - limit} (use --out para o relatório completo)", file=out)
    for note in rep.get("notes", []):
        print(f" nota: {note}", file=out)


def _write(rep, out_path, quiet):
    from . import report
    if out_path == "-":
        print(json.dumps(rep, indent=2, ensure_ascii=False, default=str))
        return
    p = report.write_report(rep, out_path)
    if not quiet:
        print(f"Relatório gravado em {p}", file=sys.stderr)


def _exit_code(rep, fail_on):
    if not fail_on:
        return 0
    need = _RANK[fail_on]
    return 2 if any(_RANK.get(x.get("level"), 0) >= need for x in rep.get("findings", [])) else 0


def _report_from(findings, notes, os_name=None):
    findings.sort(key=lambda x: x.get("score", 0), reverse=True)
    for x in findings:
        x.setdefault("level", core.level(x.get("score", 0)))
    now = datetime.now().isoformat(timespec="seconds")
    return {"os": os_name or core.host_os(), "host": platform.platform(), "started": now, "finished": now,
            "cancelled": False, "files_scanned": 0, "notes": notes, "findings": findings, "ignored": [], "new": 0}


# ---------------------------------------------------------------- comandos
def cmd_scan(a):
    modules = [m.strip() for m in a.modules.split(",") if m.strip()]
    bad = [m for m in modules if m not in MODULES]
    if bad:
        return _err(f"módulo desconhecido: {', '.join(bad)} (válidos: {', '.join(MODULES)})")
    hashes, yara_dir = a.hashes, a.yara
    if a.use_intel:
        from . import intel
        hashes = hashes or (str(intel.hashes_path()) if intel.hashes_path() else None)
        yara_dir = yara_dir or (str(intel.yara_dir()) if intel.yara_dir() else None)
    rep = core.run_scan(os_name=a.os, modules=modules, targets=a.targets or None, hashes_path=hashes, yara_dir=yara_dir,
                        on_progress=_progress(a.quiet), forensic_days=a.days, check_trust=not a.no_trust, track=a.track)
    if sys.stderr.isatty() and not a.quiet:
        sys.stderr.write("\r" + " " * 100 + "\r")
    if a.out:
        _write(rep, a.out, a.quiet)
    if not a.quiet and a.out != "-":
        summarize(rep, a.limit)
    return _exit_code(rep, a.fail_on)


def cmd_analyze(a):
    from . import forensics
    fn = getattr(forensics, "analyze_artifact_file", None)
    if fn is None:
        return _err("esta versão não tem análise de artefatos exportados")
    findings, notes = [], []
    for path in a.files:
        try:
            f, n = fn(path, a.days)
        except OSError as e:
            notes.append(f"{path}: {e}")
            continue
        findings += f
        notes += n
    rep = _report_from(findings, notes)
    if a.out:
        _write(rep, a.out, a.quiet)
    if not a.quiet and a.out != "-":
        summarize(rep, a.limit)
    return _exit_code(rep, a.fail_on)


def cmd_timeline(a):
    from . import timeline
    try:
        rep = json.loads(Path(a.report).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return _err(f"não consegui ler {a.report}: {e}")
    rows, untimed = timeline.build(rep)
    data = timeline.to_csv(rows)
    if a.out in (None, "-"):
        sys.stdout.write(data)
    else:
        Path(a.out).write_text(data, encoding="utf-8-sig", newline="")
        print(f"{len(rows)} eventos na linha do tempo ({untimed} achados sem data) em {a.out}", file=sys.stderr)
    return 0


def cmd_export_rules(a):
    from . import export_rules
    for p in export_rules.write_all(a.out, a.format):
        print(p)
    return 0


def cmd_ignored(a):
    from . import state
    if a.action == "list":
        items = state.list_ignored()
        for i in items:
            print(f"{i['key']}  {i.get('type', ''):12} {i.get('where', '')[:80]}  ({i.get('date', '')})"
                  + (f"  # {i['note']}" if i.get("note") else ""))
        if not items:
            print("Nenhum item ignorado.")
        return 0
    if not a.key:
        return _err("informe a CHAVE")
    if a.action == "remove":
        ok = state.unignore(a.key)
        print("Removido." if ok else "Chave não encontrada.")
        return 0 if ok else 1
    if not a.report:
        return _err("`ignored add` precisa de --report relatorio.json (de onde sai o achado)")
    try:
        rep = json.loads(Path(a.report).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return _err(f"não consegui ler {a.report}: {e}")
    for f in rep.get("findings", []):
        if state.fingerprint(f) == a.key or f.get("key") == a.key:
            state.ignore(f, a.note or "")
            print(f"Ignorado: {f.get('where')}")
            return 0
    return _err("chave não encontrada no relatório")


def cmd_intel(a):
    from . import intel
    try:
        if a.action == "status":
            print(json.dumps(intel.status(), indent=2, ensure_ascii=False))
        elif a.action == "update-hashes":
            r = intel.update_hashes(auth_key=os.environ.get("ABUSECH_AUTH_KEY") or None)
            print(f"{r['count']} hashes em {r['path']}")
        elif a.action == "update-yara":
            r = intel.update_yara()
            skipped = list(r.get("skipped", [])) + list(r.get("errors", []))
            print(f"{r['files']} regras aceitas, {len(skipped)} descartadas")
            for e in skipped[:20]:
                print(f" - {e}")
        elif a.action == "vt":
            if not a.sha256:
                return _err("informe o SHA-256")
            r = intel.vt_lookup(a.sha256, os.environ.get("VT_API_KEY") or None)
            print(json.dumps(r, indent=2, ensure_ascii=False))
            return 0 if r["status"] in ("found", "not_found") else 1
    except intel.IntelError as e:
        return _err(str(e))
    return 0


# ---------------------------------------------------------------- argumentos
def build_parser():
    ap = argparse.ArgumentParser(prog="vigil", description="Vigil: triagem de ameaças (modo linha de comando).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="varredura do computador")
    s.add_argument("--modules", default=",".join(MODULES), help=f"separados por vírgula ({', '.join(MODULES)})")
    s.add_argument("--targets", nargs="*", help="pastas ou arquivos (padrão: Downloads, Desktop, Temp...)")
    s.add_argument("--os", choices=("windows", "linux"), help="padrão: o do computador")
    s.add_argument("--hashes", help="arquivo com SHA-256 maliciosos")
    s.add_argument("--yara", help="pasta com regras YARA")
    s.add_argument("--use-intel", action="store_true", help="usa hashes/regras baixados com `intel update-*`")
    s.add_argument("--days", type=int, default=30, help="janela da análise forense (dias)")
    s.add_argument("--no-trust", action="store_true", help="não consulta assinatura digital / pacotes")
    s.add_argument("--track", action="store_true", help="aplica a lista de ignorados e marca o que é novo")
    s.add_argument("--out", help="relatório: .json, .html, .csv, .timeline.csv ou - (JSON na tela)")
    s.add_argument("--fail-on", choices=tuple(_RANK), help="código de saída 2 se houver achado neste nível ou acima")
    s.add_argument("--limit", type=int, default=25, help="achados mostrados na tela")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("analyze", help="analisa artefatos exportados (.evtx, hives, auth.log, históricos...)")
    s.add_argument("files", nargs="+")
    s.add_argument("--days", type=int, default=None)
    s.add_argument("--out")
    s.add_argument("--fail-on", choices=tuple(_RANK))
    s.add_argument("--limit", type=int, default=25)
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(fn=cmd_analyze)

    s = sub.add_parser("timeline", help="linha do tempo (CSV) a partir de um relatório JSON")
    s.add_argument("report")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_timeline)

    s = sub.add_parser("export-rules", help="exporta as detecções como regras Sigma/YARA")
    s.add_argument("--out", default="vigil-rules")
    s.add_argument("--format", choices=("all", "sigma", "yara"), default="all")
    s.set_defaults(fn=cmd_export_rules)

    s = sub.add_parser("ignored", help="lista de achados ignorados")
    s.add_argument("action", choices=("list", "add", "remove"))
    s.add_argument("key", nargs="?")
    s.add_argument("--report")
    s.add_argument("--note")
    s.set_defaults(fn=cmd_ignored)

    s = sub.add_parser("intel", help="atualizações e consultas externas (única parte que usa a rede)")
    s.add_argument("action", choices=("status", "update-hashes", "update-yara", "vt"))
    s.add_argument("sha256", nargs="?")
    s.set_defaults(fn=cmd_intel)
    return ap


def _ensure_streams():
    """Num executável sem console (PyInstaller --windowed) sys.stdout/sys.stderr são None: sem isto, o primeiro
    sys.stderr.isatty() ou .write() derruba a CLI. O resultado continua indo para --out e para o código de saída."""
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


def main(argv=None):
    _ensure_streams()
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args) or 0
    except KeyboardInterrupt:
        return _err("interrompido")
    except (OSError, ValueError) as e:
        return _err(str(e))


if __name__ == "__main__":
    sys.exit(main())
