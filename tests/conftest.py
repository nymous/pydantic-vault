import pytest
from pyfakefs.fake_filesystem import FakeFilesystem
from pytest import MonkeyPatch


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
    monkeypatch.delenv("VAULT_SECRET_ID", raising=False)
    monkeypatch.delenv("VAULT_KUBERNETES_ROLE", raising=False)


@pytest.fixture(autouse=True)
def mock_filesystem(fs: FakeFilesystem) -> None:
    pass
