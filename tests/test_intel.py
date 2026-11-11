"""Inteligência de ameaças (opt-in): toda a rede é simulada, nenhum teste acessa a internet."""
import io
import json
import os
import urllib.request
import zipfile

import pytest

from vigil import core, intel

REAL_OPEN = intel._open  # a fixture autouse troca intel._open por um bloqueador de rede
KEY = "SEGREDO-ABC-123"
H1, H2 = "a" * 64, "B" * 64
GOOD_RULE = 'rule boa { strings: $a = "abc" condition: $a }'
EXT_RULE = 'rule usa_externas { condition: filetype == "exe" or extension == ".dll" or owner == "x" }'


class FakeResp(io.BytesIO):
    def __init__(self, data=b"", headers=None):
        super().__init__(data)
        self.headers = headers or {}
        self.status = 200


class Endless:
    """Resposta sem fim: se o código não respeitar o teto, o teste trava/estoura memória."""
    headers = {}

    def __init__(self):
        self.lidos = 0

    def read(self, n=-1):
        self.lidos += n
        return b"a" * n

    def close(self):
        pass


@pytest.fixture(autouse=True)
def isolado(tmp_path, monkeypatch):
    """Dados em pasta temporária e rede bloqueada por padrão."""
    monkeypatch.setattr(core, "data_dir", lambda: tmp_path / "vigil_data")

    def sem_rede(*a, **k):
        raise AssertionError("tentou acessar a rede")

    monkeypatch.setattr(intel, "_open", sem_rede)
    return tmp_path / "vigil_data"


def rede(monkeypatch, responder):
    """Troca _open; `responder(req)` devolve uma resposta ou levanta. Devolve a lista de requisições feitas."""
    vistos = []

    def fake(req, timeout=intel.TIMEOUT):
        vistos.append(req)
        return responder(req)

    monkeypatch.setattr(intel, "_open", fake)
    return vistos


def zip_bytes(membros):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for nome, dado in membros:
            z.writestr(nome, dado)
    return buf.getvalue()


def erro_http(code):
    def f(req):
        raise intel.IntelHTTPError(code, f"O servidor respondeu HTTP {code}.")
    return f


# ------------------------------------------------------------ geral
def test_intel_dir_segue_data_dir_na_hora(tmp_path, monkeypatch):
    assert intel.intel_dir() == tmp_path / "vigil_data" / "intel"
    monkeypatch.setattr(core, "data_dir", lambda: tmp_path / "outra")
    assert intel.intel_dir() == tmp_path / "outra" / "intel"


# ------------------------------------------------------------ hashes
CSV = (f'# comentário {"d" * 64}\n'
       f'"2026-11-10 10:00:00", "{H1}", "{"e" * 32}", "{"f" * 40}", "rep"\n'
       f'{H2}\n{H1}\nlinha sem hash\n')


def test_update_hashes_extrai_dedupe_e_grava(monkeypatch):
    vistos = rede(monkeypatch, lambda req: FakeResp(CSV.encode()))
    r = intel.update_hashes(auth_key=KEY)
    p = intel.intel_dir() / "hashes.txt"
    assert r["count"] == 2 and r["path"] == str(p) and r["source"] == "mb-api.abuse.ch" and r["date"]
    assert core.load_hashes(str(p)) == {H1, H2.lower()}  # o arquivo é lido pelo próprio Vigil
    meta = json.loads((intel.intel_dir() / "meta.json").read_text(encoding="utf-8"))["hashes"]
    assert meta["count"] == 2 and meta["source"] == "mb-api.abuse.ch"
    req = vistos[0]
    assert req.full_url == f"https://mb-api.abuse.ch/v2/files/exports/{KEY}/recent.csv"
    assert req.get_header("Auth-key") == KEY and req.get_method() == "GET" and req.data is None
    assert req.get_header("User-agent") == "Vigil"


def test_regex_de_hash_igual_a_do_core(tmp_path, monkeypatch):
    f = tmp_path / "t.txt"
    f.write_text(CSV, encoding="utf-8")
    rede(monkeypatch, lambda req: FakeResp(CSV.encode()))
    intel.update_hashes(auth_key=KEY)
    assert core.load_hashes(str(intel.intel_dir() / "hashes.txt")) == core.load_hashes(str(f))


def test_update_hashes_recusa_nao_https(monkeypatch):
    for url in ("http://exemplo.org/h.txt", "ftp://exemplo.org/h.txt", "file:///etc/passwd"):
        with pytest.raises(intel.IntelError, match="HTTPS"):
            intel.update_hashes(url=url)


def test_update_hashes_modelo_exige_chave():
    with pytest.raises(intel.IntelError, match="Auth-Key"):
        intel.update_hashes()


def test_update_hashes_url_sem_modelo_nao_exige_chave(monkeypatch):
    vistos = rede(monkeypatch, lambda req: FakeResp(H1.encode()))
    assert intel.update_hashes(url="https://exemplo.org/h.txt")["count"] == 1
    assert vistos[0].get_header("Auth-key") is None


def test_update_hashes_zero_hash_mantem_a_lista_anterior(monkeypatch):
    rede(monkeypatch, lambda req: FakeResp(H1.encode()))
    intel.update_hashes(auth_key=KEY)
    antes = (intel.intel_dir() / "hashes.txt").read_text(encoding="utf-8")
    rede(monkeypatch, lambda req: FakeResp(b"<html>chave invalida</html>"))
    with pytest.raises(intel.IntelError, match="nenhum SHA-256"):
        intel.update_hashes(auth_key=KEY)
    assert (intel.intel_dir() / "hashes.txt").read_text(encoding="utf-8") == antes


def test_update_hashes_resposta_gigante_e_descartada(monkeypatch):
    monkeypatch.setattr(intel, "MAX_HASH_BYTES", 1000)
    fim = Endless()
    rede(monkeypatch, lambda req: fim)
    with pytest.raises(intel.IntelError, match="limite"):
        intel.update_hashes(auth_key=KEY)
    assert fim.lidos < 10 * intel.CHUNK  # parou logo, sem ler "tudo"
    assert not (intel.intel_dir() / "hashes.txt").exists()


def test_update_hashes_content_length_gigante_nem_le(monkeypatch):
    class R(Endless):
        headers = {"Content-Length": str(10 ** 12)}

    r = R()
    rede(monkeypatch, lambda req: r)
    with pytest.raises(intel.IntelError, match="limite"):
        intel.update_hashes(auth_key=KEY)
    assert r.lidos == 0


@pytest.mark.parametrize("code,trecho", [(401, "recusou a Auth-Key"), (403, "recusou a Auth-Key"), (410, "não existe mais"),
                                         (404, "não existe mais")])
def test_update_hashes_erros_http_com_mensagem_clara(monkeypatch, code, trecho):
    rede(monkeypatch, erro_http(code))
    with pytest.raises(intel.IntelError, match=trecho) as e:
        intel.update_hashes(auth_key=KEY)
    assert KEY not in str(e.value)


def test_update_hashes_chave_nunca_vaza(monkeypatch):
    rede(monkeypatch, lambda req: FakeResp(H1.encode()))
    intel.update_hashes(auth_key=KEY)
    for arq in intel.intel_dir().iterdir():
        assert KEY not in arq.read_text(encoding="utf-8"), arq.name

    def eco(req):  # servidor/biblioteca que "devolve" a chave na mensagem
        raise intel.IntelError(f"falha ao acessar https://x/{KEY}/recent.csv")

    rede(monkeypatch, eco)
    with pytest.raises(intel.IntelError) as e:
        intel.update_hashes(auth_key=KEY)
    assert KEY not in str(e.value) and "***" in str(e.value)


def test_update_hashes_chave_com_caracteres_especiais(monkeypatch):
    vistos = rede(monkeypatch, lambda req: FakeResp(H1.encode()))
    intel.update_hashes(auth_key="a/b c?d")
    assert "a%2Fb%20c%3Fd" in vistos[0].full_url
    assert "a/b c?d" not in (intel.intel_dir() / "meta.json").read_text(encoding="utf-8")


def test_update_hashes_gravacao_atomica(monkeypatch):
    rede(monkeypatch, lambda req: FakeResp(H1.encode()))
    intel.update_hashes(auth_key=KEY)
    antes = (intel.intel_dir() / "hashes.txt").read_text(encoding="utf-8")
    rede(monkeypatch, lambda req: FakeResp(H2.encode()))

    def falha(src, dst):
        raise OSError("disco cheio")

    monkeypatch.setattr(intel.os, "replace", falha)
    with pytest.raises(OSError):
        intel.update_hashes(auth_key=KEY)
    assert (intel.intel_dir() / "hashes.txt").read_text(encoding="utf-8") == antes
    assert not list(intel.intel_dir().glob("*.tmp"))


def test_update_hashes_dest_alternativo(tmp_path, monkeypatch):
    rede(monkeypatch, lambda req: FakeResp(H1.encode()))
    r = intel.update_hashes(auth_key=KEY, dest=tmp_path / "x")
    assert r["path"] == str(tmp_path / "x" / "hashes.txt") and not intel.intel_dir().exists()


# ------------------------------------------------------------ camada de rede real (sem internet)
def test_open_recusa_http():
    with pytest.raises(intel.IntelError, match="HTTPS"):
        REAL_OPEN("http://exemplo.org/")  # recusa antes de qualquer conexão


def test_redirecionamento_para_http_e_recusado():
    h = intel._SafeRedirect()
    req = urllib.request.Request("https://a.example/x", headers={"Auth-Key": KEY})
    with pytest.raises(intel.IntelError, match="não HTTPS"):
        h.redirect_request(req, None, 302, "Found", {}, "http://a.example/y")


def test_redirecionamento_para_outro_dominio_nao_leva_a_chave():
    h = intel._SafeRedirect()
    req = urllib.request.Request("https://a.example/x", headers={"Auth-Key": KEY, "X-apikey": KEY, "User-Agent": "Vigil"})
    novo = h.redirect_request(req, None, 302, "Found", {}, "https://b.example/y")
    assert not {k.lower() for k in novo.headers} & {"auth-key", "x-apikey"} and novo.get_header("User-agent") == "Vigil"
    mesmo = h.redirect_request(req, None, 302, "Found", {}, "https://a.example/z")
    assert mesmo.get_header("Auth-key") == KEY  # mesmo domínio: mantém


# ------------------------------------------------------------ YARA
pytestmark_yara = pytest.mark.skipif(core.yara is None, reason="yara-python não instalado")


@pytestmark_yara
def test_update_yara_instala_valida_e_descarta(monkeypatch):
    z = zip_bytes([
        ("sb-master/", ""),
        ("sb-master/yara/boa.yar", GOOD_RULE),
        ("sb-master/yara/externas.yara", EXT_RULE),
        ("sb-master/yara/quebrada.yar", "rule x { isto nao e yara }"),
        ("sb-master/yara/inclui.yar", 'include "/etc/passwd"\nrule y { condition: true }'),
        ("sb-master/README.md", "# nada"),
        ("sb-master/iocs/hashes.txt", H1),
    ])
    vistos = rede(monkeypatch, lambda req: FakeResp(z))
    r = intel.update_yara()
    assert r["files"] == 2 and len(r["errors"]) == 1 and "quebrada.yar" in r["errors"][0]
    assert any("inclui.yar" in s and "include" in s for s in r["skipped"])
    d = intel.intel_dir() / "yara"
    assert sorted(p.name for p in d.iterdir()) == ["boa.yar", "externas.yara"]
    assert core.load_yara(str(d)) is not None  # o Vigil consegue carregar o resultado
    assert vistos[0].full_url == intel.DEFAULT_YARA_URL and vistos[0].get_header("User-agent") == "Vigil"
    assert not list(intel.intel_dir().glob("yara-work-*"))
    assert json.loads((intel.intel_dir() / "meta.json").read_text(encoding="utf-8"))["yara"]["files"] == 2


@pytestmark_yara
def test_update_yara_zip_slip_nada_e_escrito_fora(tmp_path, monkeypatch):
    z = zip_bytes([("../evil.yar", GOOD_RULE), ("..\\evil2.yar", GOOD_RULE), ("/abs/evil3.yar", GOOD_RULE),
                   ("C:/evil4.yar", GOOD_RULE), ("ok/boa.yar", GOOD_RULE)])
    rede(monkeypatch, lambda req: FakeResp(z))
    r = intel.update_yara()
    assert r["files"] == 1 and len([s for s in r["skipped"] if "zip-slip" in s]) == 4
    nomes = {p.name for p in tmp_path.rglob("*") if p.is_file()}
    assert not {n for n in nomes if n.startswith("evil")}
    assert [p.name for p in (intel.intel_dir() / "yara").iterdir()] == ["boa.yar"]


@pytestmark_yara
def test_update_yara_nomes_repetidos_nao_se_sobrescrevem(monkeypatch):
    z = zip_bytes([("a/regra.yar", 'rule um { condition: true }'), ("b/regra.yar", 'rule dois { condition: true }')])
    rede(monkeypatch, lambda req: FakeResp(z))
    assert intel.update_yara()["files"] == 2
    assert sorted(p.name for p in (intel.intel_dir() / "yara").iterdir()) == ["regra.yar", "regra_2.yar"]


@pytestmark_yara
def test_update_yara_zip_bomb_por_arquivo(monkeypatch):
    monkeypatch.setattr(intel, "MAX_YARA_MEMBER_BYTES", 1000)
    bomba = GOOD_RULE + "\n// " + "A" * 200_000  # comprime a quase nada, descomprime enorme
    z = zip_bytes([("bomba.yar", bomba), ("boa.yar", GOOD_RULE)])
    assert len(z) < 2000
    rede(monkeypatch, lambda req: FakeResp(z))
    r = intel.update_yara()
    assert r["files"] == 1 and any("bomba.yar" in s and "zip bomb" in s for s in r["skipped"])


@pytestmark_yara
def test_update_yara_limites_de_quantidade_e_total(monkeypatch):
    regras = [(f"r{i}.yar", f"rule r{i} {{ condition: true }}") for i in range(5)]
    rede(monkeypatch, lambda req: FakeResp(zip_bytes(regras)))
    monkeypatch.setattr(intel, "MAX_YARA_FILES", 2)
    r = intel.update_yara()
    assert r["files"] == 2 and len(r["skipped"]) == 3
    monkeypatch.setattr(intel, "MAX_YARA_FILES", 100)
    monkeypatch.setattr(intel, "MAX_YARA_TOTAL_BYTES", 60)
    r = intel.update_yara()
    assert r["files"] < 5 and any("total descomprimido" in s for s in r["skipped"])


@pytestmark_yara
def test_update_yara_entradas_demais(monkeypatch):
    monkeypatch.setattr(intel, "MAX_ZIP_ENTRIES", 3)
    rede(monkeypatch, lambda req: FakeResp(zip_bytes([(f"x{i}.txt", "x") for i in range(10)])))
    with pytest.raises(intel.IntelError, match="entradas demais"):
        intel.update_yara()


@pytestmark_yara
def test_update_yara_download_gigante(monkeypatch):
    monkeypatch.setattr(intel, "MAX_ZIP_BYTES", 1000)
    fim = Endless()
    rede(monkeypatch, lambda req: fim)
    with pytest.raises(intel.IntelError, match="limite"):
        intel.update_yara()
    assert fim.lidos < 10 * intel.CHUNK
    assert not list(intel.intel_dir().glob("yara-work-*")) and not (intel.intel_dir() / "yara").exists()


@pytestmark_yara
def test_update_yara_nao_e_zip_e_sem_regra_valida_mantem_as_antigas(monkeypatch):
    rede(monkeypatch, lambda req: FakeResp(zip_bytes([("boa.yar", GOOD_RULE)])))
    intel.update_yara()
    rede(monkeypatch, lambda req: FakeResp(b"isto nao e um zip"))
    with pytest.raises(intel.IntelError, match="zip válido"):
        intel.update_yara()
    rede(monkeypatch, lambda req: FakeResp(zip_bytes([("ruim.yar", "lixo")])))
    with pytest.raises(intel.IntelError, match="Nenhuma regra válida"):
        intel.update_yara()
    assert [p.name for p in (intel.intel_dir() / "yara").iterdir()] == ["boa.yar"]


@pytestmark_yara
def test_update_yara_troca_atomica_preserva_a_pasta_antiga(monkeypatch):
    rede(monkeypatch, lambda req: FakeResp(zip_bytes([("antiga.yar", GOOD_RULE)])))
    intel.update_yara()
    rede(monkeypatch, lambda req: FakeResp(zip_bytes([("nova.yar", GOOD_RULE)])))
    real = os.rename

    def falha_na_segunda(src, dst):
        if os.path.basename(str(src)) == "novo":  # a hora de colocar a pasta nova no lugar
            raise OSError("falha simulada")
        return real(src, dst)

    monkeypatch.setattr(intel.os, "rename", falha_na_segunda)
    with pytest.raises(intel.IntelError, match="anteriores foram mantidas"):
        intel.update_yara()
    assert [p.name for p in (intel.intel_dir() / "yara").iterdir()] == ["antiga.yar"]
    assert not list(intel.intel_dir().glob("yara.old-*")) and not list(intel.intel_dir().glob("yara-work-*"))
    monkeypatch.setattr(intel.os, "rename", real)
    intel.update_yara()  # e depois disso uma atualização normal funciona
    assert [p.name for p in (intel.intel_dir() / "yara").iterdir()] == ["nova.yar"]


def test_update_yara_sem_yara_python_nao_baixa_nada(monkeypatch):
    monkeypatch.setattr(core, "yara", None)
    with pytest.raises(intel.IntelError, match="yara-python"):
        intel.update_yara()  # a rede está bloqueada pela fixture: se tentasse baixar, o teste falharia


@pytestmark_yara
def test_update_yara_recusa_nao_https():
    with pytest.raises(intel.IntelError, match="HTTPS"):
        intel.update_yara(url="http://exemplo.org/r.zip")


@pytestmark_yara
def test_update_yara_http_erro_vira_mensagem(monkeypatch):
    rede(monkeypatch, erro_http(404))
    with pytest.raises(intel.IntelError, match="HTTP 404"):
        intel.update_yara()


# ------------------------------------------------------------ VirusTotal
HASH = "ab" * 32


def vt_ok(stats=None):
    corpo = {"data": {"attributes": {"last_analysis_stats": stats or {"malicious": 7, "suspicious": 1, "harmless": 0,
                                                                          "undetected": 60, "timeout": 0}}}}
    return lambda req: FakeResp(json.dumps(corpo).encode())


def test_vt_encontrado_e_so_o_hash_sai(monkeypatch):
    vistos = rede(monkeypatch, vt_ok())
    r = intel.vt_lookup(HASH.upper(), KEY)
    assert r == {"status": "found", "malicious": 7, "suspicious": 1, "harmless": 0, "undetected": 60,
                 "link": f"https://www.virustotal.com/gui/file/{HASH}", "message": r["message"]}
    req = vistos[0]
    assert req.full_url == f"https://www.virustotal.com/api/v3/files/{HASH}"  # sem query, em minúsculas
    assert req.get_method() == "GET" and req.data is None
    assert {k.lower() for k in req.headers} == {"user-agent", "accept", "x-apikey"}
    assert req.get_header("X-apikey") == KEY and req.get_header("User-agent") == "Vigil"


@pytest.mark.parametrize("code,status", [(401, "unauthorized"), (403, "unauthorized"), (404, "not_found"),
                                         (429, "rate_limited"), (500, "error")])
def test_vt_codigos_http(monkeypatch, code, status):
    rede(monkeypatch, erro_http(code))
    r = intel.vt_lookup(HASH, KEY)
    assert r["status"] == status and KEY not in json.dumps(r)
    assert set(r) == {"status", "malicious", "suspicious", "harmless", "undetected", "link", "message"}


def test_vt_nao_encontrado_nao_diz_que_e_seguro(monkeypatch):
    rede(monkeypatch, erro_http(404))
    r = intel.vt_lookup(HASH, KEY)
    assert "não significa que seja seguro" in r["message"] and r["malicious"] is None


@pytest.mark.parametrize("ruim", ["", "abc", "g" * 64, "a" * 63, "a" * 65, " " + "a" * 63, None, 123, "../../etc/passwd"])
def test_vt_hash_invalido_nao_toca_a_rede(ruim):
    with pytest.raises(intel.IntelError, match="Hash inválido"):
        intel.vt_lookup(ruim, KEY)  # a fixture bloqueia a rede: se tentasse, falharia


@pytest.mark.parametrize("chave", ["", None])
def test_vt_sem_chave_nao_toca_a_rede(chave):
    assert intel.vt_lookup(HASH, chave)["status"] == "unauthorized"


def test_vt_resposta_malformada(monkeypatch):
    for corpo in (b"nao e json", b"{}", b'{"data": {"attributes": {}}}', b'{"data": {"attributes": {"last_analysis_stats": 5}}}'):
        rede(monkeypatch, lambda req, c=corpo: FakeResp(c))
        assert intel.vt_lookup(HASH, KEY)["status"] == "error"


def test_vt_resposta_gigante(monkeypatch):
    monkeypatch.setattr(intel, "MAX_VT_BYTES", 100)
    rede(monkeypatch, lambda req: Endless())
    assert intel.vt_lookup(HASH, KEY)["status"] == "error"


def test_vt_erro_de_rede_nunca_mostra_a_chave(monkeypatch):
    def eco(req):
        raise intel.IntelError(f"falhou com x-apikey={KEY}")

    rede(monkeypatch, eco)
    r = intel.vt_lookup(HASH, KEY)
    assert r["status"] == "error" and KEY not in json.dumps(r) and "***" in r["message"]


# ------------------------------------------------------------ status
def test_status_vazio():
    s = intel.status()
    assert s["hashes"]["present"] is False and s["yara"]["present"] is False
    assert s["hashes"]["count"] is None and s["yara"]["files"] is None and s["dir"] == str(intel.intel_dir())


def test_status_apos_atualizar(monkeypatch):
    rede(monkeypatch, lambda req: FakeResp(f"{H1}\n{H2}\n".encode()))
    intel.update_hashes(auth_key=KEY)
    s = intel.status()["hashes"]
    assert s["present"] and s["count"] == 2 and s["source"] == "mb-api.abuse.ch" and s["date"]
    assert intel.hashes_path() == intel.intel_dir() / "hashes.txt"


@pytestmark_yara
def test_status_yara(monkeypatch):
    rede(monkeypatch, lambda req: FakeResp(zip_bytes([("a.yar", GOOD_RULE), ("b.yara", EXT_RULE)])))
    intel.update_yara()
    s = intel.status()["yara"]
    assert s["present"] and s["files"] == 2 and s["source"] == "github.com"
    assert intel.yara_dir() == intel.intel_dir() / "yara"


def test_status_tolera_meta_e_arquivos_corrompidos():
    d = intel.intel_dir()
    (d / "yara").mkdir(parents=True)
    (d / "meta.json").write_text("{ lixo", encoding="utf-8")
    (d / "hashes.txt").write_bytes(b"# c\n" + H1.encode() + b"\n\xff\xfe\x00 lixo\n" + H2.encode() + b"\n")
    s = intel.status()
    assert s["hashes"]["present"] and s["hashes"]["count"] == 3 and s["hashes"]["date"] is None  # conta linhas úteis
    assert s["yara"]["present"] and s["yara"]["files"] == 0


@pytest.mark.parametrize("meta", ["[]", '"texto"', '{"hashes": "x", "yara": 3}', '{"hashes": {"count": "muitos"}}'])
def test_status_tolera_meta_com_formato_errado(meta):
    d = intel.intel_dir()
    d.mkdir(parents=True)
    (d / "meta.json").write_text(meta, encoding="utf-8")
    (d / "hashes.txt").write_text(H1 + "\n")
    assert intel.status()["hashes"]["count"] == 1
