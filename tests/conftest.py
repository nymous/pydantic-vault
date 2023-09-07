import logging

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem
from pytest import LogCaptureFixture, MonkeyPatch


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
    monkeypatch.delenv("VAULT_SECRET_ID", raising=False)
    monkeypatch.delenv("VAULT_KUBERNETES_ROLE", raising=False)
    monkeypatch.delenv("VAULT_CA_BUNDLE", raising=False)


@pytest.fixture(autouse=True)
def mock_filesystem(fs: FakeFilesystem) -> None:
    pass


@pytest.fixture(autouse=True)
def set_log_level(caplog: LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
