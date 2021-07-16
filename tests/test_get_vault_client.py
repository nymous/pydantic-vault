from pathlib import Path
from unittest import mock

import pytest
from pydantic import BaseSettings, SecretStr
from pyfakefs.fake_filesystem import FakeFilesystem
from pytest import MonkeyPatch
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


def test_get_vault_client_with_namespace_in_config(mocker: MockerFixture) -> None:
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


def test_get_vault_client_with_namespace_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
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


def test_get_vault_client_namespace_priority(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    """
    Value in Config class should be preferred over environment variable VAULT_NAMESPACE
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
        "https://vault.tld", namespace="some/namespace/from/config"
    )


def test_get_vault_client_with_vault_token_in_config(mocker: MockerFixture) -> None:
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


def test_get_vault_client_with_vault_token_in_token_file(
    mocker: MockerFixture, mock_vault_token_from_file: str
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


def test_get_vault_client_with_vault_token_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
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


def test_get_vault_client_vault_token_priority_env_config(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    """
    Value in Config class should be preferred over environment variable VAULT_TOKEN
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
        "https://vault.tld", token="fake-token-from-config"
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

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with(
        "https://vault.tld", token="fake-token-from-environment"
    )


def test_get_vault_client_vault_token_priority_file_config(
    mocker: MockerFixture, mock_vault_token_from_file: str
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


def test_get_vault_client_approle_in_config(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    # vault_secret_id is a str
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_role_id: str = "fake-role-id"
            vault_secret_id: str = "fake-secret-id"

    settings: BaseSettings = Settings()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.approle.login.assert_called_once_with(
        role_id="fake-role-id", secret_id="fake-secret-id"
    )

    # vault_secret_id is a SecretStr, we will need to unwrap it
    class SettingsWithSecretSecretId(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_role_id: str = "fake-role-id"
            vault_secret_id: SecretStr = SecretStr("fake-secret-id")

    settings = SettingsWithSecretSecretId()

    vault_client_mock = mocker.patch("pydantic_vault.vault_settings.HvacClient")

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")
    vault_client_mock.return_value.auth.approle.login.assert_called_once_with(
        role_id="fake-role-id", secret_id="fake-secret-id"
    )


def test_get_vault_client_approle_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
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


def test_get_vault_client_approle_in_environment_and_config(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
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


def test_get_vault_client_approle_priority_env_config(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    """
    Values in Config class should be preferred over environment variables VAULT_ROLE_ID and VAULT_SECRET_ID
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
        role_id="fake-role-id-from-config", secret_id="fake-secret-id-from-config"
    )


def test_get_vault_client_approle_custom_auth_mount_point_in_config(
    mocker: MockerFixture,
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


def test_get_vault_client_approle_custom_auth_mount_point_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
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


def test_get_vault_client_approle_custom_auth_mount_point_priority_env_config(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    """
    Value in Config class should be preferred over environment variable VAULT_AUTH_MOUNT_POINT
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
        mount_point="custom-approle-from-config",
    )


def test_get_vault_client_with_vault_url_in_config(mocker: MockerFixture) -> None:
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"

    settings = Settings()

    vault_client_mock = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )

    _get_authenticated_vault_client(settings)
    vault_client_mock.assert_called_once_with("https://vault.tld")


def test_get_vault_client_with_vault_url_in_environment(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
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


def test_get_vault_client_vault_url_priority(
    mocker: MockerFixture, monkeypatch: MonkeyPatch
) -> None:
    """
    Value in Config class should be preferred over environment variable VAULT_ADDR
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
    vault_client_mock.assert_called_once_with("https://vault-from-config.tld")


def test_get_vault_client_with_no_vault_url_fails() -> None:
    class Settings(BaseSettings):
        pass

    settings = Settings()

    with pytest.raises(VaultParameterError) as e:
        _get_authenticated_vault_client(settings)
    assert "URL" in str(e)


def test_get_vault_client_with_kubernetes_token_role_in_config(
    mocker: MockerFixture, mock_kubernetes_token_from_file: str
) -> None:
    # vault_kubernetes_role is a str
    class Settings(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_kubernetes_role: str = "my-role"

    settings: BaseSettings = Settings()

    with mock.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    ) as vault_client_mock:

        _get_authenticated_vault_client(settings)
        vault_client_mock.assert_called_once_with("https://vault.tld")
        vault_client_mock.return_value.auth_kubernetes.assert_called_once_with(
            "my-role", mock_kubernetes_token_from_file
        )

    # vault_kubernetes_role is a SecretStr, we will need to unwrap it
    class SettingsWithSecretStr(BaseSettings):
        class Config:
            vault_url: str = "https://vault.tld"
            vault_kubernetes_role: SecretStr = SecretStr("my-role")

    settings = SettingsWithSecretStr()

    with mock.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    ) as vault_client_mock:
        _get_authenticated_vault_client(settings)
        vault_client_mock.assert_called_once_with("https://vault.tld")
        vault_client_mock.return_value.auth_kubernetes.assert_called_once_with(
            "my-role", mock_kubernetes_token_from_file
        )


def test_get_vault_client_with_kubernetes_token_role_in_environment(
    mocker: MockerFixture,
    mock_kubernetes_token_from_file: str,
    monkeypatch: MonkeyPatch,
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
    vault_client_mock.return_value.auth_kubernetes.assert_called_once_with(
        "my-role-from-env", mock_kubernetes_token_from_file
    )


def test_get_vault_client_with_kubernetes_token_role_priority_env_config(
    mocker: MockerFixture,
    mock_kubernetes_token_from_file: str,
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Value in Config class should be preferred over environment variable VAULT_KUBERNETES_ROLE
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
    vault_client_mock.return_value.auth_kubernetes.assert_called_once_with(
        "my-role-from-config", mock_kubernetes_token_from_file
    )


def test_get_vault_client_kubernetes_approle_priority(
    mocker: MockerFixture, mock_kubernetes_token_from_file: str
) -> None:
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
    vault_client_mock.return_value.auth_kubernetes.assert_called_once_with(
        "my-role", mock_kubernetes_token_from_file
    )
    vault_client_mock.return_value.auth.approle.login.assert_not_called()


def test_get_vault_client_kubernetes_custom_auth_mount_point_in_config(
    mocker: MockerFixture, mock_kubernetes_token_from_file: str
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
    vault_client_mock.return_value.auth_kubernetes.assert_called_once_with(
        "my-role",
        mock_kubernetes_token_from_file,
        mount_point="custom-kubernetes-from-config",
    )


def test_get_vault_client_kubernetes_custom_auth_mount_point_in_environment(
    mocker: MockerFixture,
    mock_kubernetes_token_from_file: str,
    monkeypatch: MonkeyPatch,
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
    vault_client_mock.return_value.auth_kubernetes.assert_called_once_with(
        "my-role",
        mock_kubernetes_token_from_file,
        mount_point="custom-kubernetes-from-env",
    )


def test_get_vault_client_kubernetes_custom_auth_mount_point_priority_env_config(
    mocker: MockerFixture,
    mock_kubernetes_token_from_file: str,
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Value in Config class should be preferred over environment variable VAULT_AUTH_MOUNT_POINT
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
    vault_client_mock.return_value.auth_kubernetes.assert_called_once_with(
        "my-role",
        mock_kubernetes_token_from_file,
        mount_point="custom-kubernetes-from-config",
    )
