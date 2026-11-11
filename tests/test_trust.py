"""Confiança no binário (assinatura digital / pacote) e seu efeito sobre as notas."""
import os
import subprocess
from types import SimpleNamespace

import pytest

from dupin_scan import core, trust


@pytest.fixture(autouse=True)
def limpa_cache(monkeypatch):
    # A pasta temporária do pytest fica em \temp\ ou /tmp/: sem isto a heurística de "diretório suspeito" somaria
    # pontos e as contas dos testes dependeriam do sistema operacional.
    monkeypatch.setitem(core.SUSPECT_DIRS, "windows", ())
    monkeypatch.setitem(core.SUSPECT_DIRS, "linux", ())
    trust.clear_cache()
    yield
    trust.clear_cache()


def binario_entropico(tmp_path, nome="pacote.bin"):
    p = tmp_path / nome
    p.write_bytes(b"MZ" + os.urandom(8192))  # PE + entropia alta: só uma heurística fraca (20)
    return p


# ------------------------------------------------------------ publisher
@pytest.mark.parametrize("subject,esperado", [
    ('CN=Microsoft Windows, O=Microsoft Corporation, C=US', "Microsoft Windows"),
    ('CN="Empresa, Ltda", O=Empresa', "Empresa, Ltda"),
    ("O=Sem CN", ""), ("", ""), (None, ""),
])
def test_publisher(subject, esperado):
    assert trust._publisher(subject) == esperado


# ------------------------------------------------------------ Windows (subprocesso simulado)
def _ps(monkeypatch, stdout=b"", code=0):
    monkeypatch.setattr(trust.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=code, stdout=stdout, stderr=b""))


def test_windows_signature_valida(monkeypatch):
    _ps(monkeypatch, b'\xef\xbb\xbf{"Status":"Valid","Subject":"CN=Acme, O=Acme","OS":false}')
    assert trust.windows_signature("x.exe") == {"signed": True, "status": "Valid", "publisher": "Acme", "os_binary": False}


def test_windows_signature_ausente(monkeypatch):
    _ps(monkeypatch, b'{"Status":"NotSigned","Subject":null,"OS":false}')
    r = trust.windows_signature("x.exe")
    assert r["signed"] is False and r["publisher"] == ""


@pytest.mark.parametrize("stdout,code", [(b"", 1), (b"nao e json", 0)])
def test_windows_signature_falha_devolve_none(monkeypatch, stdout, code):
    _ps(monkeypatch, stdout, code)
    assert trust.windows_signature("x.exe") is None


def test_windows_signature_timeout_devolve_none(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("ps", 1)

    monkeypatch.setattr(trust.subprocess, "run", boom)
    assert trust.windows_signature("x.exe") is None


def test_o_caminho_vai_por_variavel_de_ambiente_e_nao_no_comando(monkeypatch):
    visto = {}

    def spy(cmd, **k):
        visto.update(cmd=cmd, env=k["env"])
        return SimpleNamespace(returncode=0, stdout=b'{"Status":"Valid"}', stderr=b"")

    monkeypatch.setattr(trust.subprocess, "run", spy)
    nome = "C:\\a'; Remove-Item x #\\b.exe"  # aspas e ; num nome não podem virar código
    trust.windows_signature(nome)
    assert visto["env"]["DUPIN_SCAN_TRUST_PATH"] == nome and nome not in " ".join(visto["cmd"])


@pytest.mark.skipif(os.name != "nt", reason="Authenticode só no Windows")
def test_assinatura_real_de_binarios_do_windows():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    r = trust.check(os.path.join(root, "System32", "notepad.exe"), "windows")
    assert r and r["signed"] and r["trusted"] and "Microsoft" in r["publisher"] and r["os_binary"]


@pytest.mark.skipif(os.name != "nt", reason="Authenticode só no Windows")
def test_arquivo_sem_assinatura_nao_e_confiavel(tmp_path):
    r = trust.check(binario_entropico(tmp_path), "windows")
    assert r and r["signed"] is False and r["trusted"] is False and "sem assinatura" in r["label"]


def test_check_arquivo_inexistente():
    assert trust.check("/nao/existe.exe", "windows") is None


def test_check_usa_cache(tmp_path, monkeypatch):
    chamadas = []
    monkeypatch.setattr(trust, "windows_signature", lambda p: chamadas.append(p) or
                        {"signed": True, "status": "Valid", "publisher": "A", "os_binary": False})
    f = binario_entropico(tmp_path)
    trust.check(f, "windows")
    trust.check(f, "windows")
    assert len(chamadas) == 1
    f.write_bytes(b"MZ" + os.urandom(100))  # mudou: a entrada do cache deixa de valer
    trust.check(f, "windows")
    assert len(chamadas) == 2


# ------------------------------------------------------------ Linux (dpkg/rpm simulados)
def _run_stub(monkeypatch, respostas):
    def fake(cmd, timeout=20):
        for prefixo, (code, out) in respostas.items():
            if cmd[0] == prefixo:
                return SimpleNamespace(returncode=code, stdout=out, stderr="")
        return None

    monkeypatch.setattr(trust, "_run", fake)


def test_pacote_dpkg_nao_modificado(tmp_path, monkeypatch):
    f = tmp_path / "ls"
    f.write_bytes(b"conteudo original")
    md5 = trust.hashlib.md5(b"conteudo original").hexdigest()
    info = tmp_path / "coreutils.md5sums"
    info.write_text(f"{md5}  {os.path.realpath(f).lstrip('/')}\n")
    _run_stub(monkeypatch, {"dpkg": (0, f"coreutils: {f}\n")})
    monkeypatch.setattr(trust.glob, "glob", lambda pat: [str(info)] if pat.endswith("coreutils.md5sums") else [])
    assert trust.linux_package(f) == {"package": "coreutils", "verified": True}


def test_pacote_dpkg_modificado_nao_e_confiavel(tmp_path, monkeypatch):
    f = tmp_path / "ls"
    f.write_bytes(b"trocado pelo atacante")
    info = tmp_path / "coreutils.md5sums"
    info.write_text(f"{'0' * 32}  {os.path.realpath(f).lstrip('/')}\n")
    _run_stub(monkeypatch, {"dpkg": (0, f"coreutils: {f}\n")})
    monkeypatch.setattr(trust.glob, "glob", lambda pat: [str(info)] if pat.endswith("coreutils.md5sums") else [])
    monkeypatch.setattr(trust, "_cache", {})
    r = trust.check(f, "linux")
    assert r["verified"] is False and r["trusted"] is False and "MODIFICADO" in r["label"]


def test_pacote_sem_md5sums_e_confiavel_mas_nao_verificado(tmp_path, monkeypatch):
    f = tmp_path / "x"
    f.write_bytes(b"1")
    _run_stub(monkeypatch, {"dpkg": (0, f"pkg: {f}\n")})
    monkeypatch.setattr(trust.glob, "glob", lambda pat: [])
    r = trust.check(f, "linux")
    assert r["verified"] is None and r["trusted"] is True and "pkg" in r["label"]


def test_rpm_so_propriedade(tmp_path, monkeypatch):
    f = tmp_path / "x"
    f.write_bytes(b"1")
    _run_stub(monkeypatch, {"dpkg": (1, ""), "rpm": (0, "bash")})
    assert trust.linux_package(f) == {"package": "bash", "verified": None}


def test_arquivo_fora_de_pacote(tmp_path, monkeypatch):
    f = tmp_path / "x"
    f.write_bytes(b"1")
    _run_stub(monkeypatch, {"dpkg": (1, ""), "rpm": (1, "")})
    assert trust.linux_package(f) is None
    monkeypatch.setattr(trust, "_run", lambda *a, **k: None)  # nem dpkg nem rpm instalados
    assert trust.linux_package(f) is None


# ------------------------------------------------------------ efeito nas notas (analyze_file)
def _info(trusted, **k):
    return {"signed": trusted, "publisher": "Acme", "package": None, "verified": None, "trusted": trusted,
            "label": "assinatura digital válida (Acme)" if trusted else "sem assinatura", **k}


def test_binario_confiavel_com_so_heuristica_fraca_nao_gera_achado(tmp_path, monkeypatch):
    f = binario_entropico(tmp_path)
    assert core.analyze_file(f, "windows", set(), None)["score"] == 20  # sem consulta de confiança: alerta
    monkeypatch.setattr(trust, "check", lambda p, o: _info(True))
    assert core.analyze_file(f, "windows", set(), None, trust=True) is None


def test_binario_nao_confiavel_continua_e_guarda_o_resultado(tmp_path, monkeypatch):
    monkeypatch.setattr(trust, "check", lambda p, o: _info(False))
    r = core.analyze_file(binario_entropico(tmp_path), "windows", set(), None, trust=True)
    assert r["score"] == 20 and r["trust"]["signed"] is False


def test_hash_conhecido_nunca_e_abrandado_pela_confianca(tmp_path, monkeypatch):
    f = binario_entropico(tmp_path)
    digest = core.sha256_file(f)
    monkeypatch.setattr(trust, "check", lambda p, o: pytest.fail("não deveria consultar a confiança"))
    assert core.analyze_file(f, "windows", {digest}, None, trust=True)["score"] == 100


def test_confianca_abate_mas_mantem_quando_ha_mais_indicios(tmp_path, monkeypatch):
    p = tmp_path / "fatura.pdf"  # PE com extensão de documento (40) + entropia (20) = 60
    p.write_bytes(b"MZ" + os.urandom(8192))
    monkeypatch.setattr(trust, "check", lambda p_, o: _info(True))
    r = core.analyze_file(p, "windows", set(), None, trust=True)
    assert r["score"] == 30 and any("confiável" in x for x in r["reasons"])


def test_falha_da_consulta_nao_derruba_a_analise(tmp_path, monkeypatch):
    monkeypatch.setattr(trust, "check", lambda p, o: None)
    assert core.analyze_file(binario_entropico(tmp_path), "windows", set(), None, trust=True)["score"] == 20


def test_confianca_so_para_binarios(tmp_path, monkeypatch):
    monkeypatch.setattr(trust, "check", lambda p, o: pytest.fail("script não deveria consultar assinatura"))
    s = tmp_path / "a.ps1"
    s.write_text("powershell -w hidden -enc AAAA")
    assert core.analyze_file(s, "windows", set(), None, trust=True)["score"] >= 50
