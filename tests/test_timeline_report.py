"""Linha do tempo, CSV e relatórios (JSON/HTML/CSV). Dados de achados são tratados como hostis."""
import csv
import io
import json
import time
from html.parser import HTMLParser

import pytest

from vigil import report as rp
from vigil import timeline as tl

XSS = "<script>alert(1)</script>"
IMG = '"><img src=x onerror=alert(1)>'
JS = "javascript:alert(1)"


def f(where="C:\\a.exe", score=50, **kw):
    d = {"type": "file", "where": where, "score": score, "reasons": ["motivo"], "attack": []}
    d.update(kw)
    return d


class Scan(HTMLParser):
    """Coleta tags e atributos do HTML gerado, para provar que nada executável escapou."""

    def __init__(self):
        super().__init__()
        self.tags, self.attrs = [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs += [(tag, k, v) for k, v in attrs]


def scan(html_text):
    p = Scan()
    p.feed(html_text)
    return p


# ------------------------------------------------------------ datas
@pytest.mark.parametrize("valor", ["2026-11-10T12:00:00", "2026-11-10 12:00:00", "2026-11-10T12:00",
                                   "2026-11-10T12:00:00.123456789", "2026-11-10T12:00:00.5",
                                   "2026-11-10T12:00:00Z", "2026-11-10T12:00:00z", "2026-11-10T12:00:00+03:00",
                                   "2026-11-10T12:00:00-0300", "2026-11-10T12:00:00+03", "2026-11-10", "  2026-11-10T12:00:00  "])
def test_parse_when_formatos_validos(valor):
    assert tl.parse_when(valor) is not None


@pytest.mark.parametrize("valor", [None, "", "   ", "ontem", "2026-13-40T99:99:99", "2026-11-10T12:00:00+99:99x",
                                   "10/11/2026", 1700000000, ["2026-11-10"], {"a": 1}, "2026-11-10T12:00:00\n; DROP"])
def test_parse_when_invalidos_viram_none(valor):
    assert tl.parse_when(valor) is None


def test_parse_when_fusos_diferentes_sao_o_mesmo_instante():
    a = tl.parse_when("2026-11-10T12:00:00+00:00")
    b = tl.parse_when("2026-11-10T09:00:00-03:00")
    c = tl.parse_when("2026-11-10T15:00:00+03:00")
    z = tl.parse_when("2026-11-10T12:00:00Z")
    assert a == b == c == z


def test_parse_when_fracao_vira_microssegundos():
    assert tl.parse_when("2026-11-10T12:00:00.5").microsecond == 500000
    assert tl.parse_when("2026-11-10T12:00:00.8995939Z") is not None


# ------------------------------------------------------------ build
def test_build_ordena_e_separa_sem_data():
    fs = [f("c", when="2026-11-10T12:00:03"), f("a", when="2026-11-10T12:00:01"), f("b", when="2026-11-10T12:00:02"),
          f("x"), f("y", when=""), f("z", when="lixo"), f("w", when=123)]
    rows, untimed = tl.build(fs)
    assert [r["where"] for r in rows] == ["a", "b", "c"] and untimed == 4


def test_build_formatos_mistos_em_ordem_cronologica():
    fs = [f("tarde", when="2026-11-10T15:00:00+00:00"), f("cedo", when="2026-11-10T06:00:00-03:00"),
          f("meio", when="2026-11-10T12:00:00Z")]
    # 06:00-03:00 = 09:00Z < 12:00Z < 15:00Z
    assert [r["where"] for r in tl.build(fs)[0]] == ["cedo", "meio", "tarde"]


def test_build_empate_mostra_a_nota_maior_primeiro():
    fs = [f("baixa", 10, when="2026-11-10T12:00:00"), f("alta", 90, when="2026-11-10T12:00:00")]
    assert [r["where"] for r in tl.build(fs)[0]] == ["alta", "baixa"]


def test_build_campos_da_linha():
    a = f("x", 85, when="2026-11-10T12:00:00.9Z", reasons=["um", "dois"], attack=[{"id": "T1110"}, {"id": "T1078"}, {"id": "T1110"}])
    [r], _ = tl.build([a])
    assert r["level"] == "ALTO" and r["score"] == 85 and r["summary"] == "um; dois" and r["attack"] == "T1110, T1078"
    assert r["when"].count(":") == 2 and "." not in r["when"]  # normalizado, sem fração


@pytest.mark.parametrize("achado,esperado", [
    (f(type="file"), "Arquivo modificado"), (f(type="process"), "Processo iniciado"),
    (f(type="persistence"), "Persistência"), (f(type="artifact", source="Security"), "Evento"),
    (f(type="artifact", source="System"), "Evento"), (f(type="artifact", source="PowerShell"), "Evento"),
    (f(type="artifact", source="auth.log"), "Artefato"), (f(type="artifact", source="Prefetch"), "Artefato"),
    (f(type="artifact"), "Artefato"), (f(type="novo-tipo"), "novo-tipo"), (f(type=None), "Achado")])
def test_kind_of(achado, esperado):
    assert tl.kind_of(achado) == esperado


def test_build_tolera_tudo_faltando_ou_malformado():
    sujo = [None, 1, "x", [], {}, {"when": "2026-11-10T12:00:00"}, {"when": "2026-11-10T12:00:00", "score": "abc", "reasons": 5,
            "attack": "T1", "where": None, "level": 99}, {"when": "2026-11-10T12:00:01", "reasons": None, "attack": [None, 3, {"id": None}]}]
    rows, untimed = tl.build(sujo)
    assert len(rows) == 3 and untimed == 1  # só o {} (dict sem when) conta como sem data; não-dicts são ignorados
    assert all(isinstance(r["score"], int) for r in rows)
    for entrada in (None, 5, "x", {}, {"findings": None}, {"findings": [None]}):
        assert tl.build(entrada) == ([], 0)


def test_build_aceita_o_relatorio_inteiro():
    rows, _ = tl.build({"findings": [f(when="2026-11-10T12:00:00")]})
    assert len(rows) == 1


def test_score_e_nivel_tolerantes():
    assert tl.score_of({"score": "85"}) == 85 and tl.score_of({"score": True}) == 0
    assert tl.score_of({"score": float("nan")}) == 0 and tl.score_of({"score": float("inf")}) == 0
    assert tl.score_of({"score": -5}) == 0 and tl.score_of({"score": 1000}) == 100
    assert tl.level_of({"level": "ALTO", "score": 0}) == "ALTO"
    assert tl.level_of({"level": "<script>", "score": 85}) == "ALTO"  # nível inválido é recalculado pela nota
    assert tl.level_of({"score": 40}) == "MÉDIO" and tl.level_of({}) == "BAIXO"


def test_text_nao_levanta_com_objetos_estranhos():
    class Ruim:
        def __str__(self):
            raise RuntimeError("boom")

    assert tl.text(Ruim()) == "" and tl.text(None) == "" and tl.text("a" * 10, 3) == "aaa…"


# ------------------------------------------------------------ CSV
@pytest.mark.parametrize("valor", ["=1+1", "+1", "-1", "@SUM(A1)", "\t=1", "\r=1", "  =1+1", "=cmd|' /C calc'!A0"])
def test_csv_safe_neutraliza_formulas(valor):
    assert tl.csv_safe(valor).startswith("'")


@pytest.mark.parametrize("valor", ["normal", "", "a=b", "C:\\x\\-y", "1+1", "olá"])
def test_csv_safe_nao_mexe_no_resto(valor):
    assert tl.csv_safe(valor) == valor


def test_csv_da_linha_do_tempo_neutraliza_e_faz_round_trip():
    fs = [f("=HYPERLINK(\"http://evil\")", when="2026-11-10T12:00:00", reasons=["+cmd", "ok, com vírgula\nquebra"],
            source="@x", attack=[{"id": "T1110"}])]
    rows, _ = tl.build(fs)
    out = tl.to_csv(rows)
    lido = list(csv.reader(io.StringIO(out)))
    assert lido[0] == tl.TIMELINE_HEADERS and len(lido) == 2
    quando, tipo, fonte, local, grav, pts, att, resumo = lido[1]
    assert local.startswith("'=") and fonte == "'@x" and resumo.startswith("'+cmd")
    assert "ok, com vírgula\nquebra" in resumo and att == "T1110" and tipo == "Arquivo modificado"


def test_csv_dos_achados():
    fs = [f("baixo", 10), f("=x", 90, new=True, trust={"signed": True, "publisher": "ACME"}, sha256="ab", detail="-cmd"),
          f("meio", 50, new=False)]
    lido = list(csv.reader(io.StringIO(tl.findings_to_csv(fs))))
    assert lido[0] == tl.FINDINGS_HEADERS
    assert [r[3] for r in lido[1:]] == ["'=x", "meio", "baixo"]  # do mais grave ao menos grave
    top = dict(zip(tl.FINDINGS_HEADERS, lido[1]))
    assert top["Novo"] == "sim" and top["Confiança"] == "assinado: ACME" and top["Detalhe"] == "'-cmd"
    assert dict(zip(tl.FINDINGS_HEADERS, lido[2]))["Novo"] == "não"
    assert dict(zip(tl.FINDINGS_HEADERS, lido[3]))["Novo"] == ""


def test_csv_vazio_e_entradas_ruins():
    assert tl.to_csv([]).count("\n") == 1 and tl.to_csv(None).count("\n") == 1
    assert tl.to_csv([None, 3, {}]).count("\r\n") == 2  # cabeçalho + a linha vazia do {}
    assert tl.findings_to_csv(None).count("\n") == 1
    assert "0" in tl.to_csv([{"score": "abc"}]).splitlines()[1]


def test_trust_text():
    assert tl.trust_text({"signed": False}) == "não assinado"
    assert tl.trust_text({"signed": True}) == "assinado"
    assert tl.trust_text({"package": "coreutils"}) == "pacote: coreutils"
    assert tl.trust_text({"signed": True, "publisher": "X", "package": "p"}) == "assinado: X; pacote: p"
    assert tl.trust_text("lixo") == "" and tl.trust_text(None) == ""


# ------------------------------------------------------------ HTML: segurança
def hostil():
    carga = [XSS, IMG, JS, "</td><script>x</script>", "'><svg onload=alert(1)>", "&lt;ja escapado&gt;"]
    return {
        "host": XSS, "os": IMG, "started": JS, "finished": XSS, "files_scanned": XSS,
        "notes": [XSS, IMG, JS],
        "findings": [f(
            where=c, score=95, reasons=[c, XSS], detail=c, cmdline=IMG, exe=XSS, sha256=JS, source=c,
            users=[c, XSS], remotes=[IMG], when=c, failures=XSS, new=True,
            trust={"signed": True, "publisher": c, "package": XSS},
            target={"where": c, "score": 90, "reasons": [XSS, IMG], "sha256": JS},
            attack=[{"id": "T1059.001", "name": c, "url": "javascript:alert(1)"}, {"id": c, "name": XSS, "url": JS}],
        ) for c in carga],
        "ignored": [XSS, {"where": IMG}], "quarantined": [JS, {"where": XSS}],
    }


def test_html_nenhum_payload_sai_cru():
    rep = hostil()
    rows = [{"when": XSS, "kind": IMG, "where": JS, "level": XSS, "summary": IMG, "score": 5}]
    out = rp.to_html(rep, rows)
    for cru in (XSS, IMG, "</td><script>", "<svg onload", "<img", "onerror=alert(1)>"):
        assert cru not in out, cru
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "&amp;lt;ja escapado&amp;gt;" in out  # texto que já parecia escapado é exibido literalmente (escapa o &)


def test_html_estrutura_nao_tem_nada_executavel():
    s = scan(rp.to_html(hostil(), [{"when": "2026-11-10T12:00:00", "where": XSS}]))
    assert not {"script", "img", "svg", "iframe", "object", "embed", "link", "form", "input", "base"} & set(s.tags)
    assert not [a for a in s.attrs if a[1].startswith("on")]
    assert not [a for a in s.attrs if a[1] in ("src", "srcdoc", "style", "action", "formaction")]
    assert "meta" in s.tags  # a CSP está presente
    csp = [v for t, k, v in s.attrs if t == "meta" and k == "content" and v and "default-src" in v]
    assert csp and "script-src" not in csp[0] and "default-src 'none'" in csp[0]


def test_html_so_links_para_o_mitre_com_id_valido():
    s = scan(rp.to_html(hostil()))
    hrefs = [v for t, k, v in s.attrs if k == "href"]
    assert hrefs and all(h.startswith("https://attack.mitre.org/techniques/T") for h in hrefs)
    assert set(hrefs) == {"https://attack.mitre.org/techniques/T1059/001/"}
    assert {v for t, k, v in s.attrs if t == "a" and k == "rel"} == {"noopener noreferrer"}


@pytest.mark.parametrize("tid", ['"><script>x</script>', "javascript:alert(1)", "T1059.001\n", "T1059.0011", "t1059", "T12",
                                 "T1059/../../x", "T1059.001 ", "../T1059", ""])
def test_id_attack_malicioso_nao_vira_link(tid):
    out = rp.to_html({"findings": [f(attack=[{"id": tid, "name": "n"}])]})
    assert "<a " not in out and "href=" not in out


def test_id_attack_valido_vira_link_montado_localmente():
    out = rp.to_html({"findings": [f(attack=[{"id": "T1547.001", "url": "https://evil.example/x"}, "T1110"])]})
    assert 'href="https://attack.mitre.org/techniques/T1547/001/"' in out and "evil.example" not in out
    assert 'href="https://attack.mitre.org/techniques/T1110/"' in out


def test_html_tamanho_dos_campos_e_limitado():
    out = rp.to_html({"findings": [f(where="W" * 50000, detail="D" * 50000, users=[str(i) for i in range(5000)])]})
    assert len(out) < 80000 and "…" in out and "… e mais" in out


# ------------------------------------------------------------ HTML: conteúdo
def test_html_vazio_e_parcial():
    for rep in (None, {}, {"findings": []}, {"findings": None}, {"notes": "uma nota"}, 5, "x", [], {"findings": [None, 1]}):
        out = rp.to_html(rep)
        assert "Nenhum achado" in out and "<!doctype html>" in out
    assert "uma nota" in rp.to_html({"notes": "uma nota"})


def test_html_resumo_e_ordem_por_gravidade():
    rep = {"findings": [f("baixo", 10), f("alto", 95), f("medio", 50), f("alto2", 85, new=True)], "cancelled": True,
           "host": "PC1", "os": "windows", "files_scanned": 1234}
    out = rp.to_html(rep)
    assert out.index("alto") < out.index("alto2") < out.index("medio") < out.index("baixo")
    for esperado in ("2 Alto", "1 Médio", "1 Baixo", "4 no total", "1 novos", "PC1", "windows", "1234", "cancelada",
                     "não substitui antivírus/EDR"):
        assert esperado in out, esperado


def test_html_marca_novo_confianca_e_alvo():
    out = rp.to_html({"findings": [f("p", 60, type="persistence", new=True, trust={"signed": False},
                                     target={"where": "C:\\bin\\x.exe", "score": 85, "reasons": ["Entropia"], "sha256": "ff00"})]})
    for esperado in ("novo", "não assinado", "binário referenciado", "C:\\bin\\x.exe", "Entropia", "ff00", "Persistência"):
        assert esperado in out, esperado
    sem = rp.to_html({"findings": [f("p", 60, new=False)]})
    assert 'tag new' not in sem and "binário referenciado" not in sem


def test_html_alto_vem_aberto_e_o_resto_fechado():
    s = scan(rp.to_html({"findings": [f("a", 90), f("b", 20)]}))
    abertos = [1 for t, k, v in s.attrs if t == "details" and k == "open"]
    assert s.tags.count("details") == 2 and len(abertos) == 1


def test_html_notas_ignorados_e_quarentena():
    out = rp.to_html({"findings": [], "notes": ["Log Security ilegível"], "ignored": ["C:\\i.exe", {"where": "C:\\j.exe"}],
                      "quarantined": ["C:\\q.exe"]})
    for esperado in ("Notas da varredura", "Log Security ilegível", "Ignorados (2)", "C:\\i.exe", "C:\\j.exe",
                     "Enviados para a quarentena (1)", "C:\\q.exe"):
        assert esperado in out, esperado
    assert "Ignorados" not in rp.to_html({"findings": []})


def test_html_linha_do_tempo_resumida():
    rows = [{"when": f"2026-11-10T12:{i // 60:02d}:{i % 60:02d}", "kind": "Evento", "where": f"w{i}", "level": "BAIXO", "summary": "s"}
            for i in range(300)]
    out = rp.to_html({"findings": []}, rows)
    assert "Linha do tempo" in out and "Mostrando 200 de 300" in out and "w199" in out and "w200" not in out
    assert "Linha do tempo" not in rp.to_html({"findings": []}) and "Linha do tempo" not in rp.to_html({"findings": []}, [None, 3])


def test_html_tem_tema_claro_escuro_impressao_e_nada_externo():
    out = rp.to_html({"findings": [f()]})
    assert "prefers-color-scheme:dark" in out and "@media print" in out and "color-scheme" in out
    for externo in ("http://", "@import", "url(", "<script", "src="):
        assert externo not in out, externo
    assert out.count("https://") == 0  # sem achados com ATT&CK, nenhum link


# ------------------------------------------------------------ write_report
def rep_exemplo():
    return {"os": "windows", "host": "PC", "notes": ["n"], "files_scanned": 2,
            "findings": [f("a", 90, when="2026-11-10T12:00:00", attack=[{"id": "T1110", "name": "Brute Force"}]),
                         f("b", 30, when="2026-11-10T11:00:00"), f("c", 70)]}


def test_write_report_json_round_trip(tmp_path):
    rep = rep_exemplo()
    p = rp.write_report(rep, tmp_path / "r.json")
    assert json.loads(p.read_text(encoding="utf-8")) == rep
    rep2 = {"host": "açaí ✓", "findings": []}
    p = rp.write_report(rep2, tmp_path / "u.JSON")
    assert "açaí ✓" in p.read_text(encoding="utf-8")  # ensure_ascii=False


def test_write_report_json_tolera_valores_estranhos(tmp_path):
    from datetime import datetime
    p = rp.write_report({"started": datetime(2026, 1, 1), "x": {1, 2}.__class__}, tmp_path / "r.json")
    assert json.loads(p.read_text(encoding="utf-8"))["started"].startswith("2026-01-01")


def test_write_report_html(tmp_path):
    p = rp.write_report(rep_exemplo(), tmp_path / "r.html")
    t = p.read_text(encoding="utf-8")
    assert t.startswith("<!doctype html>") and "Linha do tempo" in t and "Brute Force" in t
    assert rp.write_report(rep_exemplo(), tmp_path / "r.htm").read_text(encoding="utf-8").startswith("<!doctype html>")


def test_write_report_csv_achados_e_timeline(tmp_path):
    raw = rp.write_report(rep_exemplo(), tmp_path / "r.csv").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # BOM do utf-8-sig: o Excel abre os acentos certo
    achados = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
    assert achados[0] == tl.FINDINGS_HEADERS and len(achados) == 4
    tempo = list(csv.reader(io.StringIO(rp.write_report(rep_exemplo(), tmp_path / "r.timeline.csv").read_bytes().decode("utf-8-sig"))))
    assert tempo[0] == tl.TIMELINE_HEADERS and [r[3] for r in tempo[1:]] == ["b", "a"]  # só os com data, em ordem


def test_write_report_kind_explicito(tmp_path):
    p = rp.write_report(rep_exemplo(), tmp_path / "saida.dados", kind="html")
    assert p.read_text(encoding="utf-8").startswith("<!doctype html>")
    with pytest.raises(ValueError, match="formato desconhecido"):
        rp.write_report(rep_exemplo(), tmp_path / "x", kind="pdf")


@pytest.mark.parametrize("nome", ["r.pdf", "r", "r.txt", "r.json.bak", "r.xml"])
def test_write_report_sufixo_desconhecido(tmp_path, nome):
    with pytest.raises(ValueError, match="não suportado"):
        rp.write_report(rep_exemplo(), tmp_path / nome)
    assert list(tmp_path.iterdir()) == []  # nada criado


def test_write_report_atomico_nao_deixa_temporario_nem_destroi_o_destino(tmp_path, monkeypatch):
    destino = tmp_path / "r.json"
    destino.write_text("ANTIGO")
    import os

    def falha(src, dst):
        raise OSError("disco cheio")

    monkeypatch.setattr(os, "replace", falha)
    with pytest.raises(OSError, match="disco cheio"):
        rp.write_report(rep_exemplo(), destino)
    assert destino.read_text() == "ANTIGO" and [p.name for p in tmp_path.iterdir()] == ["r.json"]


def test_write_report_pasta_inexistente_da_erro_claro(tmp_path):
    with pytest.raises(OSError):
        rp.write_report(rep_exemplo(), tmp_path / "nao" / "existe" / "r.json")


def test_write_report_com_relatorio_ruim(tmp_path):
    for i, rep in enumerate((None, 5, "x", {}, {"findings": [None]})):
        for ext in ("json", "html", "csv", "timeline.csv"):
            assert rp.write_report(rep, tmp_path / f"r{i}.{ext}").exists()


# ------------------------------------------------------------ desempenho
def _grande(n):
    return {"findings": [f(f"C:\\pasta\\{i}.exe", i % 100, when=f"2026-11-{1 + i % 28:02d}T{i % 24:02d}:{i % 60:02d}:00",
                           reasons=["a", "b"], attack=[{"id": "T1110", "name": "x"}], detail="d" * 50) for i in range(n)]}


def _tempo(fn, *a):
    melhor = float("inf")
    for _ in range(2):
        t = time.perf_counter()
        fn(*a)
        melhor = min(melhor, time.perf_counter() - t)
    return melhor


def test_milhares_de_achados_nao_sao_quadraticos():
    pequeno, grande = _grande(2000), _grande(8000)

    def tudo(rep):
        rows, _ = tl.build(rep)
        tl.to_csv(rows)
        tl.findings_to_csv(rep)
        rp.to_html(rep, rows)

    t1, t2 = _tempo(tudo, pequeno), _tempo(tudo, grande)
    assert t2 < 10, f"8000 achados levaram {t2:.1f}s"
    assert t2 / max(t1, 1e-6) < 10, f"cresceu {t2 / t1:.1f}x para 4x mais dados (linear ≈ 4x, quadrático ≈ 16x)"


def test_build_com_dez_mil_achados_e_rapido():
    rows, untimed = tl.build(_grande(10000)["findings"])
    assert len(rows) == 10000 and untimed == 0
    assert [r["when"] for r in rows] == sorted(r["when"] for r in rows)
