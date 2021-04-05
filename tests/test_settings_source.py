from typing import Any, Dict
from unittest.mock import MagicMock

from hvac.exceptions import VaultError
from pydantic import BaseSettings, Field, SecretStr
import pytest
from pytest_mock import MockerFixture

from pydantic_vault import vault_config_settings_source

VaultStructure = Dict[str, Dict[str, Any]]
VaultResponseDict = Dict[str, Dict[str, Dict[str, Any]]]


def fake_vault(path: str, mount_point: str = "secrets") -> VaultResponseDict:
    vault: VaultStructure = {
        "first_level_key": {
            "username": "my_user",
            "password": "my_password",
            "complex_value": {
                "inner": "value",
                "int_key": 12,
                "list_key": ["first", "second", "third"],
            },
        },
        "nested/path": {"username": "my_nested_username"},
    }
    try:
        return {"data": {"data": vault[path]}}
    except KeyError:
        raise VaultError(f"Key {path} not found in Vault")


@pytest.fixture(autouse=True, name="fake_hvac_client")
def bypass_hvac_client(mocker: MockerFixture) -> MagicMock:
    mock_hvac_client = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )
    return mock_hvac_client.return_value


def test_get_vault_secrets(fake_hvac_client: MagicMock) -> None:
    fake_hvac_client.secrets.kv.v2.read_secret_version.side_effect = fake_vault

    class Settings(BaseSettings):
        username: str = Field(
            "doesn't matter",
            vault_secret_path="first_level_key",
            vault_secret_key="username",
        )
        password: SecretStr = Field(
            "doesn't matter",
            vault_secret_path="first_level_key",
            vault_secret_key="password",
        )

        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: SecretStr = SecretStr("fake-token")

    settings = Settings()

    vault_settings_dict = vault_config_settings_source(settings)
    assert vault_settings_dict == {"username": "my_user", "password": "my_password"}


def test_do_not_search_vault_for_keys_not_configured() -> None:
    class Settings(BaseSettings):
        simple_field: str = "doesn't matter"
        field_from_vault: str = Field(
            "doesn't matter",
            vault_secret_path="first_level_key",
            vault_secret_key="password",
        )

        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: SecretStr = SecretStr("fake-token")

    settings = Settings()

    vault_settings_dict = vault_config_settings_source(settings)
    assert "field_from_vault" in vault_settings_dict
    assert "simple_field" not in vault_settings_dict
