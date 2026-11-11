"""Exporta as detecções do Vigil como regras Sigma (YAML) e YARA.

    python -m vigil.export_rules --out vigil-rules

As regras saem das mesmas tabelas que o scanner usa (core.SUSPECT_CMD, extensões, limite de entropia),
então não divergem do comportamento do app. Só viram regra as detecções que têm técnica ATT&CK associada:
heurísticas puramente de "pasta suspeita" são ruído demais para caça de ameaças.

São pontos de partida: ajuste ao seu ambiente e teste contra tráfego limpo antes de produção.
"""
import argparse
import re
import unicodedata
import uuid
from datetime import date
from pathlib import Path

from . import attack as att
from . import core

_NS = uuid.UUID("3b1f3c52-8a0e-4d62-9f1b-5a1c7e2d9b10")  # ids estáveis entre exportações
AUTHOR = "Vigil"
# Tags de tática que o Sigma conhece. "Stealth" (antiga Defense Evasion) fica sem tag de tática:
# as tags de técnica (attack.tNNNN) já carregam a informação.
_TACTIC_TAGS = {"Persistence": "persistence", "Privilege Escalation": "privilege_escalation",
                "Execution": "execution", "Command and Control": "command_and_control",
                "Initial Access": "initial_access"}
_FP = ["Administração legítima, scripts de implantação e ferramentas de TI"]


def _slug(text):
    ascii_ = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "_", ascii_.lower()).strip("_")


def _level(weight):
    return "high" if weight >= 80 else "medium" if weight >= 40 else "low"


# ---------------------------------------------------------------- Sigma
_BARE = re.compile(r"^[A-Za-z0-9_.\-]+$")
_RESERVED = {"true", "false", "yes", "no", "on", "off", "null", "y", "n"}


def _scalar(v):
    s = str(v)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):  # data: o Sigma espera sem aspas
        return s
    if _BARE.match(s) and s.lower() not in _RESERVED and not re.fullmatch(r"[0-9.\-]+", s):
        return s
    return "'" + s.replace("'", "''") + "'"  # aspas simples YAML: barra invertida é literal


def _emit(obj, ind=0):
    pad = "  " * ind
    lines = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}{k}:")
                lines += _emit(v, ind + 1)
            else:
                lines.append(f"{pad}{k}: {_scalar(v)}")
    else:
        lines += [f"{pad}- {_scalar(v)}" for v in obj]
    return lines


def _rule(title, key, description, ids, logsource, detection, level):
    tactics = []
    for i in ids:
        for t in att.TECHNIQUES[i][1]:
            tag = _TACTIC_TAGS.get(t)
            if tag and f"attack.{tag}" not in tactics:
                tactics.append(f"attack.{tag}")
    tags = tactics + [f"attack.{i.lower()}" for i in ids]
    doc = {
        "title": title,
        "id": str(uuid.uuid5(_NS, key)),
        "status": "experimental",
        "description": f"{description}. Derivada de uma heurística do Vigil: ponto de partida para "
                       "caça de ameaças, precisa de ajuste ao ambiente.",
        "references": [att.url(i) for i in ids],
        "author": AUTHOR,
        "date": date.today().isoformat(),
        "tags": tags,
        "logsource": logsource,
        "detection": detection,
        "falsepositives": _FP,
        "level": level,
    }
    return "\n".join(_emit(doc)) + "\n"


def _command_rules():
    for r in core.SUSPECT_CMD:
        if not r.attack:
            continue
        for product in (("windows", "linux") if r.os == "any" else (r.os,)):
            yield (f"vigil_cmd_{_slug(r.desc)}_{product}.yml",
                   _rule(f"Vigil - {r.desc}", f"cmd:{r.rx}:{product}", r.desc, r.attack,
                         {"category": "process_creation", "product": product},
                         {"selection": {"CommandLine|re|i": r.rx}, "condition": "selection"},
                         _level(r.weight)))


def _structural_rules():
    """Detecções do Vigil que não são só 'comando suspeito': onde a persistência é gravada."""
    win_regex = [r.rx for r in core.SUSPECT_CMD if r.attack and r.os in ("windows", "any")]
    win_dirs = list(core.SUSPECT_DIRS["windows"])
    yield ("vigil_persistencia_chave_run_windows.yml", _rule(
        "Vigil - Chave Run/RunOnce com comando suspeito", "struct:run-key",
        "Valor gravado em chave Run/RunOnce que executa comando suspeito ou de pasta comumente abusada",
        (att.RUN_KEYS,), {"category": "registry_set", "product": "windows"},
        {"selection_key": {"TargetObject|contains": ["\\CurrentVersion\\Run\\", "\\CurrentVersion\\RunOnce\\"]},
         "selection_cmd": {"Details|re|i": win_regex},
         "selection_dir": {"Details|contains": win_dirs},
         "condition": "selection_key and (selection_cmd or selection_dir)"}, "medium"))
    yield ("vigil_persistencia_pasta_startup_windows.yml", _rule(
        "Vigil - Executável criado na pasta Startup", "struct:startup",
        "Arquivo executável ou script criado na pasta Startup do menu Iniciar",
        (att.RUN_KEYS,), {"category": "file_event", "product": "windows"},
        {"selection_dir": {"TargetFilename|contains": "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"},
         "selection_ext": {"TargetFilename|endswith": sorted(core.EXEC_EXT["windows"])},
         "condition": "all of selection_*"}, "low"))
    yield ("vigil_persistencia_tarefa_agendada_windows.yml", _rule(
        "Vigil - Tarefa agendada apontando para pasta suspeita", "struct:schtask",
        "schtasks /create cuja ação aponta para pasta comumente abusada (temp, AppData, Public...)",
        (att.SCHEDULED_TASK,), {"category": "process_creation", "product": "windows"},
        {"selection_img": {"Image|endswith": "\\schtasks.exe"},
         "selection_create": {"CommandLine|contains": " /create "},
         "selection_dir": {"CommandLine|contains": win_dirs},
         "condition": "all of selection_*"}, "low"))
    yield ("vigil_persistencia_ld_so_preload_linux.yml", _rule(
        "Vigil - Escrita em /etc/ld.so.preload", "struct:ld-preload",
        "Alteração de /etc/ld.so.preload, técnica de rootkit em userland",
        (att.LD_PRELOAD,), {"category": "file_event", "product": "linux"},
        {"selection": {"TargetFilename": "/etc/ld.so.preload"}, "condition": "selection"}, "medium"))


def sigma_rules():
    """[(nome_do_arquivo, texto_yaml)]"""
    return list(_command_rules()) + list(_structural_rules())


# ---------------------------------------------------------------- YARA
def _meta(description, ids):
    d = description.replace("\\", "\\\\").replace('"', '\\"')
    return (f'    meta:\n        description = "{d}"\n        author = "{AUTHOR}"\n'
            f'        mitre_attack = "{", ".join(ids)}"\n')


def _alt(exts):
    return "|".join(sorted(e.lstrip(".") for e in exts))


def yara_text():
    docs = _alt(core.DOC_EXT)
    execs = _alt(core.EXEC_EXT["windows"] | core.EXEC_EXT["linux"])
    magic = "(uint16(0) == 0x5A4D or uint32(0) == 0x464C457F)"  # PE (MZ) ou ELF
    lim = core.ENTROPY_LIMIT
    out = [
        "// Regras exportadas pelo Vigil (ponto de partida: ajuste e teste antes de usar em produção).",
        "// As regras de nome de arquivo usam a variável externa `filename`; declare-a ao compilar:",
        '//   yara-python:  yara.compile(filepath=..., externals={"filename": ""})',
        '//   CLI:          yara -d filename=<nome> regras.yar alvo   (o CLI não infere o nome sozinho)',
        'import "math"', "",
        "rule vigil_executavel_disfarcado_de_documento", "{", _meta(
            "Binário executável (PE/ELF) com extensão de documento", ("T1036.008",)) +
        f"    condition:\n        {magic} and\n        filename matches /\\.({docs})$/i", "}", "",
        "rule vigil_dupla_extensao_suspeita", "{", _meta(
            "Documento seguido de extensão executável (ex.: fatura.pdf.exe)", ("T1036.007",)) +
        f"    condition:\n        filename matches /\\.({docs})\\.({execs})$/i", "}", "",
        "rule vigil_binario_alta_entropia", "{", _meta(
            "Binário PE/ELF com entropia alta no primeiro 1 MiB (possível empacotamento)", ("T1027.002",)) +
        f"    condition:\n        {magic} and (\n"
        f"            (filesize <= 1048576 and math.entropy(0, filesize) > {lim}) or\n"
        f"            (filesize > 1048576 and math.entropy(0, 1048576) > {lim})\n        )", "}", "",
    ]
    seen = set()
    for r in core.SUSPECT_CMD:
        if not r.attack:
            continue
        name = f"vigil_cmd_{_slug(r.desc)}"
        while name in seen:
            name += "_2"
        seen.add(name)
        rx = r.rx.replace("/", "\\/")
        out += [f"rule {name}", "{", _meta(r.desc + f" (SO: {r.os})", r.attack) +
                f"    strings:\n        $r = /{rx}/ nocase ascii wide\n"
                "    condition:\n        filesize < 1MB and $r", "}", ""]
    return "\n".join(out)


# ---------------------------------------------------------------- saída
def write_all(out_dir, fmt="all"):
    """Grava as regras em out_dir (sigma/*.yml e vigil.yar). Devolve a lista de arquivos criados."""
    out = Path(out_dir)
    written = []
    if fmt in ("all", "sigma"):
        (out / "sigma").mkdir(parents=True, exist_ok=True)
        for name, text in sigma_rules():
            p = out / "sigma" / name
            p.write_text(text, encoding="utf-8", newline="\n")
            written.append(p)
    if fmt in ("all", "yara"):
        out.mkdir(parents=True, exist_ok=True)
        p = out / "vigil.yar"
        p.write_text(yara_text(), encoding="utf-8", newline="\n")
        written.append(p)
    return written


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m vigil.export_rules",
                                 description="Exporta as detecções do Vigil como regras Sigma e/ou YARA.")
    ap.add_argument("--out", default="vigil-rules", help="pasta de saída (padrão: vigil-rules)")
    ap.add_argument("--format", choices=("all", "sigma", "yara"), default="all")
    args = ap.parse_args(argv)
    for p in write_all(args.out, args.format):
        print(p)


if __name__ == "__main__":
    main()
