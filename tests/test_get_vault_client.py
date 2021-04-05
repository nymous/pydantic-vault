from pathlib import Path

from pydantic import BaseSettings, SecretStr
import pytest
from pytest import MonkeyPatch
from pytest_mock import MockerFixture

from pydantic_vault import VaultParameterError
from pydantic_vault.vault_settings import _get_authenticated_vault_client


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.delenv("VAULT_ADDR", raising=False)


@pytest.fixture(autouse=True)
def mock_home_dir(monkeypatch: MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


@pytest.fixture
def mock_vault_token_from_file(mock_home_dir: Path) -> str:
    """Return the token written in the .vault-token file"""
    vault_token = "token-from-file"
    with open(mock_home_dir / ".vault-token", "w") as token_file:
        token_file.write(vault_token)
    return vault_token


def test_get_vault_client_with_namespace_in_config(mocker: MockerFixture) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: str = "fake-token"
            vault_namespace: str = "some/namespace"

    settings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", namespace="some/namespace", token="fake-token"
    )


def test_get_vault_client_with_namespace_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    monkeypatch.setenv("VAULT_NAMESPACE", "some/namespace")

    settings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", namespace="some/namespace"
    )


def test_get_vault_client_namespace_priority(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    """
    Environment variable VAULT_NAMESPACE should be preferred over value in Config class
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_namespace: str = "some/namespace/from/config"

    monkeypatch.setenv("VAULT_NAMESPACE", "some/namespace/from/environment")

    settings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", namespace="some/namespace/from/environment"
    )


def test_get_vault_client_with_vault_token_in_config(mocker: MockerFixture) -> None:
    # vault_token is a str
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: str = "fake-token"

    settings: BaseSettings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld", token="fake-token")

    # vault_token is a SecretStr, we need to unwrap it
    class SettingsWithSecretToken(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: SecretStr = SecretStr("fake-token")

    settings = SettingsWithSecretToken()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld", token="fake-token")


def test_get_vault_client_reads_from_token_file(
    mocker: MockerFixture, mock_vault_token_from_file: str
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    settings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", token=mock_vault_token_from_file
    )


def test_get_vault_client_with_vault_token_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    monkeypatch.setenv("VAULT_TOKEN", "fake-token")

    settings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld", token="fake-token")


def test_get_vault_client_vault_token_priority_env_config(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    """
    Environment variable VAULT_TOKEN should be preferred over value in Config class
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: str = "fake-token-from-config"

    monkeypatch.setenv("VAULT_TOKEN", "fake-token-from-environment")

    settings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", token="fake-token-from-environment"
    )


def test_get_vault_client_vault_token_priority_env_file(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, mock_vault_token_from_file: str
) -> None:
    """
    Environment variable VAULT_TOKEN should be preferred over .vault-token file
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    monkeypatch.setenv("VAULT_TOKEN", "fake-token-from-environment")

    settings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", token="fake-token-from-environment"
    )


def test_get_vault_client_vault_token_priority_file_config(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, mock_vault_token_from_file: str
) -> None:
    """
    .vault-token file should be preferred over value in Config class
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: str = "fake-token-from-config"

    settings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", token=mock_vault_token_from_file
    )


def test_get_vault_client_with_vault_url_in_config(mocker: MockerFixture) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    settings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")


def test_get_vault_client_with_vault_url_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    class Settings(BaseSettings):
        pass

    monkeypatch.setenv("VAULT_ADDR", "https://vault.tld")

    settings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")


def test_get_vault_client_vault_url_priority(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    """
    Environment variable VAULT_ADDR should be preferred over value in Config class
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault-from-config.tld"

    monkeypatch.setenv("VAULT_ADDR", "https://vault-from-environment.tld")

    settings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault-from-environment.tld")


def test_get_vault_client_with_no_vault_url_fails() -> None:
    class Settings(BaseSettings):
        pass

    settings = Settings()

    with pytest.raises(VaultParameterError) as e:
        _get_authenticated_vault_client(settings)
    assert "URL" in str(e)
