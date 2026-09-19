"""Shared discovery of native CLI builds for integration tests."""
import os
from pathlib import Path

import pytest


@pytest.fixture
def cli_executable():
    def locate(name, *, root=Path(__file__).resolve().parents[2]):
        variable = {'mamlscan': 'MAML_SCAN', 'mamlpipe': 'MAML_PIPE'}[name]
        override = os.environ.get(variable)
        if override:
            assert Path(override).is_file(), f'Invalid {variable} override: {override}'
            return str(override)
        candidates = [
            root / 'build' / name,
            root / 'build' / (name + '.exe'),
            root / 'build' / 'Release' / (name + '.exe'),
            root / 'build' / 'Debug' / (name + '.exe'),
        ]
        found = next((path for path in candidates if path.is_file()), None)
        if found is None:
            pytest.skip(f'Build {name} to run native CLI integration; searched: '
                        + ', '.join(map(str, candidates)))
        return str(found)
    return locate
