"""Exercise native build layouts independently of the host OS."""
from pathlib import Path

import pytest


@pytest.mark.parametrize('name', ['mamlscan', 'mamlpipe'])
@pytest.mark.parametrize('layout', ['build/{name}', 'build/{name}.exe',
                                  'build/Release/{name}.exe', 'build/Debug/{name}.exe'])
def test_native_build_layout(cli_executable, tmp_path, monkeypatch, name, layout):
    monkeypatch.delenv('MAML_SCAN', raising=False)
    monkeypatch.delenv('MAML_PIPE', raising=False)
    binary = tmp_path / layout.format(name=name)
    binary.parent.mkdir(parents=True)
    binary.touch()
    assert Path(cli_executable(name, root=tmp_path)) == binary


@pytest.mark.parametrize('name,variable', [('mamlscan', 'MAML_SCAN'), ('mamlpipe', 'MAML_PIPE')])
def test_explicit_cli_override(cli_executable, tmp_path, monkeypatch, name, variable):
    binary = tmp_path / 'custom.exe'
    binary.touch()
    monkeypatch.setenv(variable, str(binary))
    assert Path(cli_executable(name, root=tmp_path)) == binary
    binary.unlink()
    with pytest.raises(AssertionError, match=f'Invalid {variable} override'):
        cli_executable(name, root=tmp_path)


def test_missing_build_reports_skip_reason(cli_executable, tmp_path, monkeypatch):
    monkeypatch.delenv('MAML_PIPE', raising=False)
    with pytest.raises(pytest.skip.Exception, match='Build mamlpipe.*searched:'):
        cli_executable('mamlpipe', root=tmp_path)
