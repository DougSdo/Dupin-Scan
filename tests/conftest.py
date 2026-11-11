"""Isolamento global: nenhum teste pode tocar nos dados reais do usuário.

`core.data_dir()` agora MIGRA a pasta antiga (Vigil) para a nova na primeira chamada. Sem este isolamento, qualquer
teste que chamasse `data_dir()` sem simular (ex.: uma varredura que calcula o caminho da quarentena) moveria a pasta
de dados verdadeira de quem roda a suíte. Aqui a base de dados vai para uma pasta temporária em TODOS os testes;
os que precisam de outra base (ex.: test_migration) redefinem as variáveis por conta própria.
"""
import pytest


@pytest.fixture(autouse=True)
def _dados_do_usuario_isolados(tmp_path_factory, monkeypatch):
    base = tmp_path_factory.mktemp("dados_isolados")
    monkeypatch.setenv("LOCALAPPDATA", str(base))
    monkeypatch.setenv("XDG_DATA_HOME", str(base))
