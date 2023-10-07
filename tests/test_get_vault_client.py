import logging
from pathlib import Path
from unittest import mock

import pytest
from pydantic import BaseSettings, SecretStr
from pyfakefs.fake_filesystem import FakeFilesystem
from pytest import LogCaptureFixture, MonkeyPatch
from pytest_mock import MockerFixture

from pydantic_vault import VaultParameterError
from pydantic_vault.vault_settings import _get_authenticated_vault_client


@pytest.fixture
def mock_vault_token_from_file(fs: FakeFilesystem) -> str:
    """Return the token written in the .vault-token file"""
    vault_token = "token-from-file"
    vault_token_path = Path.home() / ".vault-token"
    fs.create_file(vault_token_path, contents=vault_token)
    return vault_token


@pytest.fixture
def mock_kubernetes_token_from_file(fs: FakeFilesystem) -> str:
    kubernetes_token = "fake-kubernetes-token"
    kubernetes_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    fs.create_file(kubernetes_token_path, contents=kubernetes_token)
    return kubernetes_token


def test_get_vault_client_with_namespace_in_config(
    mocker: MockerFixture, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: str = "fake-token"
            vault_namespace: str = "some/namespace"

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", namespace="some/namespace", token="fake-token"
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Namespace 'some/namespace' in Config") in caplog.record_tuples
    assert ("pydantic-vault", logging.INFO, "Connecting to Vault 'https://vault.tld' on namespace 'some/namespace' with method 'Vault Token'") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_with_namespace_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    monkeypatch.setenv("VAULT_NAMESPACE", "some/namespace")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", namespace="some/namespace"
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Namespace 'some/namespace' in environment variables") in caplog.record_tuples
    # fmt: on


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

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", namespace="some/namespace/from/environment"
    )


def test_get_vault_client_with_vault_token_in_config(caplog: LogCaptureFixture) -> None:
    # vault_token is a str
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: str = "fake-token"

    settings: BaseSettings = Settings()

    with mock.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    ) as vault_client_mock:
        _get_authenticated_vault_client(settings)
        vault_client_mock.assert_called_once_with(
            "https://vault.tld", token="fake-token"
        )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Token in Config") in caplog.record_tuples
    # fmt: on

    caplog.clear()

    # vault_token is a SecretStr, we will need to unwrap it
    class SettingsWithSecretToken(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: SecretStr = SecretStr("fake-token")

    settings = SettingsWithSecretToken()

    with mock.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    ) as vault_client_mock:
        _get_authenticated_vault_client(settings)
        vault_client_mock.assert_called_once_with(
            "https://vault.tld", token="fake-token"
        )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Token in Config") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_with_vault_token_in_token_file(
    mocker: MockerFixture, mock_vault_token_from_file: str, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", token=mock_vault_token_from_file
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Token in file '~/.vault-token'") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_with_vault_token_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    monkeypatch.setenv("VAULT_TOKEN", "fake-token")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld", token="fake-token")
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Token in environment variables") in caplog.record_tuples
    # fmt: on


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

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", token="fake-token-from-environment"
    )


def test_get_vault_client_vault_token_priority_env_file(
    mocker: MockerFixture,
    monkeypatch: MonkeyPatch,
    mock_vault_token_from_file: str,
) -> None:
    """
    Environment variable VAULT_TOKEN should be preferred over .vault-token file
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    monkeypatch.setenv("VAULT_TOKEN", "fake-token-from-environment")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", token="fake-token-from-environment"
    )


def test_get_vault_client_vault_token_priority_file_config(
    mocker: MockerFixture,
    mock_vault_token_from_file: str,
) -> None:
    """
    Value in Config class should be preferred over .vault-token file
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: str = "fake-token-from-config"

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", token="fake-token-from-config"
    )


def test_get_vault_client_approle_in_config(caplog: LogCaptureFixture) -> None:
    # vault_secret_id is a str
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_role_id: str = "fake-role-id"
            vault_secret_id: str = "fake-secret-id"

    settings: BaseSettings = Settings()

    with mock.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    ) as vault_client_mock:
        _get_authenticated_vault_client(settings)
        vault_client_mock.assert_called_once_with("https://vault.tld")
        vault_client_mock.return_value.auth.approle.login.assert_called_once_with(
            role_id="fake-role-id", secret_id="fake-secret-id"
        )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Role ID 'fake-role-id' in Config") in caplog.record_tuples
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Secret ID in Config") in caplog.record_tuples
    assert ("pydantic-vault", logging.INFO, "Connecting to Vault 'https://vault.tld' with method 'Approle' ({'role_id': 'fake-role-id'})") in caplog.record_tuples
    # fmt: on

    # vault_secret_id is a SecretStr, we will need to unwrap it
    class SettingsWithSecretSecretId(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_role_id: str = "fake-role-id"
            vault_secret_id: SecretStr = SecretStr("fake-secret-id")

    settings = SettingsWithSecretSecretId()

    with mock.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    ) as vault_client_mock:
        _get_authenticated_vault_client(settings)
        vault_client_mock.assert_called_once_with("https://vault.tld")
        vault_client_mock.return_value.auth.approle.login.assert_called_once_with(
            role_id="fake-role-id", secret_id="fake-secret-id"
        )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Role ID 'fake-role-id' in Config") in caplog.record_tuples
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Secret ID in Config") in caplog.record_tuples
    assert ("pydantic-vault", logging.INFO, "Connecting to Vault 'https://vault.tld' with method 'Approle' ({'role_id': 'fake-role-id'})") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_approle_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    monkeypatch.setenv("VAULT_ROLE_ID", "fake-role-id")
    monkeypatch.setenv("VAULT_SECRET_ID", "fake-secret-id")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.approle.login.assert_called_once_with(
        role_id="fake-role-id", secret_id="fake-secret-id"
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Role ID 'fake-role-id' in environment variables") in caplog.record_tuples
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Secret ID in environment variables") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_approle_in_environment_and_config(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_role_id: str = "fake-role-id"

    monkeypatch.setenv("VAULT_SECRET_ID", "fake-secret-id")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.approle.login.assert_called_once_with(
        role_id="fake-role-id", secret_id="fake-secret-id"
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Role ID 'fake-role-id' in Config") in caplog.record_tuples
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Secret ID in environment variables") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_approle_priority_env_config(
    mocker: MockerFixture,
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Environment variables VAULT_ROLE_ID and VAULT_SECRET_ID should be preferred over values in Config class
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_role_id: str = "fake-role-id-from-config"
            vault_secret_id: SecretStr = SecretStr("fake-secret-id-from-config")

    monkeypatch.setenv("VAULT_ROLE_ID", "fake-role-id-from-env")
    monkeypatch.setenv("VAULT_SECRET_ID", "fake-secret-id-from-env")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.approle.login.assert_called_once_with(
        role_id="fake-role-id-from-env", secret_id="fake-secret-id-from-env"
    )


def test_get_vault_client_approle_custom_auth_mount_point_in_config(
    mocker: MockerFixture, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_role_id: str = "fake-role-id"
            vault_secret_id: SecretStr = SecretStr("fake-secret-id")
            vault_auth_mount_point: str = "custom-approle-from-config"

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.approle.login.assert_called_once_with(
        role_id="fake-role-id",
        secret_id="fake-secret-id",
        mount_point="custom-approle-from-config",
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Auth mount point 'custom-approle-from-config' in Config") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_approle_custom_auth_mount_point_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_role_id: str = "fake-role-id"
            vault_secret_id: SecretStr = SecretStr("fake-secret-id")

    monkeypatch.setenv("VAULT_AUTH_MOUNT_POINT", "custom-approle-from-env")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.approle.login.assert_called_once_with(
        role_id="fake-role-id",
        secret_id="fake-secret-id",
        mount_point="custom-approle-from-env",
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Auth mount point 'custom-approle-from-env' in environment variables") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_approle_custom_auth_mount_point_priority_env_config(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    """
    Environment variable VAULT_AUTH_MOUNT_POINT should be preferred over value in Config class
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_role_id: str = "fake-role-id"
            vault_secret_id: SecretStr = SecretStr("fake-secret-id")
            vault_auth_mount_point: str = "custom-approle-from-config"

    monkeypatch.setenv("VAULT_AUTH_MOUNT_POINT", "custom-approle-from-env")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.approle.login.assert_called_once_with(
        role_id="fake-role-id",
        secret_id="fake-secret-id",
        mount_point="custom-approle-from-env",
    )


def test_get_vault_client_with_vault_url_in_config(
    mocker: MockerFixture, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Address 'https://vault.tld' in Config") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_with_vault_url_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        pass

    monkeypatch.setenv("VAULT_ADDR", "https://vault.tld")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Address 'https://vault.tld' in environment variables") in caplog.record_tuples
    # fmt: on


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

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault-from-environment.tld")


def test_get_vault_client_with_no_vault_url_fails() -> None:
    class Settings(BaseSettings):
        pass

    settings = Settings()

    with pytest.raises(VaultParameterError) as e:
        _get_authenticated_vault_client(settings)
    assert "URL" in str(e)


def test_get_vault_client_with_kubernetes_token_role_in_config(
    mock_kubernetes_token_from_file: str, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_kubernetes_role: str = "my-role"

    settings = Settings()

    with mock.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    ) as vault_client_mock:
        _get_authenticated_vault_client(settings)
        vault_client_mock.assert_called_once_with("https://vault.tld")
        vault_client_mock.return_value.auth.kubernetes.login.assert_called_once_with(
            "my-role", mock_kubernetes_token_from_file
        )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Kubernetes JWT Token in file '/var/run/secrets/kubernetes.io/serviceaccount/token'") in caplog.record_tuples
    assert ("pydantic-vault", logging.DEBUG, "Found Kubernetes role 'my-role' in Config") in caplog.record_tuples
    assert ("pydantic-vault", logging.INFO, "Connecting to Vault 'https://vault.tld' with method 'Kubernetes' ({'kubernetes_role': 'my-role'})") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_with_kubernetes_token_role_in_environment(
    mocker: MockerFixture,
    mock_kubernetes_token_from_file: str,
    monkeypatch: MonkeyPatch,
    caplog: LogCaptureFixture,
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    monkeypatch.setenv("VAULT_KUBERNETES_ROLE", "my-role-from-env")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.kubernetes.login.assert_called_once_with(
        "my-role-from-env", mock_kubernetes_token_from_file
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Kubernetes JWT Token in file '/var/run/secrets/kubernetes.io/serviceaccount/token'") in caplog.record_tuples
    assert ("pydantic-vault", logging.DEBUG, "Found Kubernetes role 'my-role-from-env' in environment variables") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_with_kubernetes_token_role_priority_env_config(
    mocker: MockerFixture,
    mock_kubernetes_token_from_file: str,
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Environment variable VAULT_KUBERNETES_ROLE should be preferred over value in Config class
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_kubernetes_role: str = "my-role-from-config"

    monkeypatch.setenv("VAULT_KUBERNETES_ROLE", "my-role-from-env")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.kubernetes.login.assert_called_once_with(
        "my-role-from-env", mock_kubernetes_token_from_file
    )


def test_get_vault_client_kubernetes_custom_auth_mount_point_in_config(
    mocker: MockerFixture,
    mock_kubernetes_token_from_file: str,
    caplog: LogCaptureFixture,
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_kubernetes_role: str = "my-role"
            vault_auth_mount_point: str = "custom-kubernetes-from-config"

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.kubernetes.login.assert_called_once_with(
        "my-role",
        mock_kubernetes_token_from_file,
        mount_point="custom-kubernetes-from-config",
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Auth mount point 'custom-kubernetes-from-config' in Config") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_kubernetes_custom_auth_mount_point_in_environment(
    mocker: MockerFixture,
    mock_kubernetes_token_from_file: str,
    monkeypatch: MonkeyPatch,
    caplog: LogCaptureFixture,
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_kubernetes_role: str = "my-role"

    monkeypatch.setenv("VAULT_AUTH_MOUNT_POINT", "custom-kubernetes-from-env")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.kubernetes.login.assert_called_once_with(
        "my-role",
        mock_kubernetes_token_from_file,
        mount_point="custom-kubernetes-from-env",
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault Auth mount point 'custom-kubernetes-from-env' in environment variables") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_kubernetes_custom_auth_mount_point_priority_env_config(
    mocker: MockerFixture,
    mock_kubernetes_token_from_file: str,
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Environment variable VAULT_AUTH_MOUNT_POINT should be preferred over value in Config class
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_kubernetes_role: str = "my-role"
            vault_auth_mount_point: str = "custom-kubernetes-from-config"

    monkeypatch.setenv("VAULT_AUTH_MOUNT_POINT", "custom-kubernetes-from-env")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.kubernetes.login.assert_called_once_with(
        "my-role",
        mock_kubernetes_token_from_file,
        mount_point="custom-kubernetes-from-env",
    )


def test_get_vault_client_kubernetes_approle_priority(
    mocker: MockerFixture,
    mock_kubernetes_token_from_file: str,
    caplog: LogCaptureFixture,
) -> None:
    """
    Kubernetes should be preferred over Approle
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_kubernetes_role: str = "my-role"
            vault_role_id: str = "fake-role-id"
            vault_secret_id: str = "fake-secret-id"

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.kubernetes.login.assert_called_once_with(
        "my-role", mock_kubernetes_token_from_file
    )
    vault_client_mock.return_value.auth.approle.login.assert_not_called()

    # fmt: off
    assert ("pydantic-vault", logging.INFO, "Connecting to Vault 'https://vault.tld' with method 'Kubernetes' ({'kubernetes_role': 'my-role'})") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_token_kubernetes_priority(
    mocker: MockerFixture,
    mock_kubernetes_token_from_file: str,
    caplog: LogCaptureFixture,
) -> None:
    """
    Vault token should be preferred over Kubernetes
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: str = "fake-token"
            vault_kubernetes_role: str = "my-role"

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld", token="fake-token")
    vault_client_mock.return_value.auth.kubernetes.login.assert_not_called()

    # fmt: off
    assert ("pydantic-vault", logging.INFO, "Connecting to Vault 'https://vault.tld' with method 'Vault Token'") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_token_approle_priority(
    mocker: MockerFixture,
    caplog: LogCaptureFixture,
) -> None:
    """
    Vault token should be preferred over Approle
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: str = "fake-token"
            vault_role_id: str = "fake-role-id"
            vault_secret_id: str = "fake-secret-id"

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld", token="fake-token")
    vault_client_mock.return_value.auth.approle.login.assert_not_called()

    # fmt: off
    assert ("pydantic-vault", logging.INFO, "Connecting to Vault 'https://vault.tld' with method 'Vault Token'") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_with_disabled_ssl_verify_in_config(
    mocker: MockerFixture, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_certificate_verify: bool = False

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld",
        verify=False,
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault CA bundle 'False' in Config") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_with_custom_ssl_verify_in_config(
    mocker: MockerFixture, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_certificate_verify: str = "/path/to/ca.crt"

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld",
        verify="/path/to/ca.crt",
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault CA bundle '/path/to/ca.crt' in Config") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_with_disabled_ssl_verify_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    monkeypatch.setenv("VAULT_CA_BUNDLE", "False")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld",
        verify=False,
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault CA bundle 'False' in environment variables") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_with_custom_ssl_verify_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    monkeypatch.setenv("VAULT_CA_BUNDLE", "/path/to/ca.crt")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld",
        verify="/path/to/ca.crt",
    )
    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault CA bundle '/path/to/ca.crt' in environment variables") in caplog.record_tuples
    # fmt: on


def test_get_vault_client_custom_ssl_priority(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    """
    Environment variable VAULT_CA_BUNDLE should be preferred over value in Config class
    """

    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_certificate_verify: bool = False

    monkeypatch.setenv("VAULT_CA_BUNDLE", "/path/to/ca.crt")

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld",
        verify="/path/to/ca.crt",
    )

    # fmt: off
    assert ("pydantic-vault", logging.DEBUG, "Found Vault CA bundle '/path/to/ca.crt' in environment variables") in caplog.record_tuples
    assert ("pydantic-vault", logging.DEBUG, "Found Vault CA bundle 'False' in Config") in caplog.record_tuples
    # fmt: on
