from typing import Any, Dict

from hvac.exceptions import VaultError
from pydantic import BaseSettings, Field, SecretStr
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


def test_get_vault_secrets(mocker: MockerFixture) -> None:
    mock_hvac_client = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )
    mock_hvac_client.return_value.secrets.kv.v2.read_secret_version.side_effect = (
        fake_vault
    )

    class Settings(BaseSettings):
        username: str = Field(
            ..., vault_secret_path="first_level_key", vault_secret_key="username"
        )
        password: SecretStr = Field(
            ..., vault_secret_path="first_level_key", vault_secret_key="password"
        )

        class Config:
            vault_url: str = "https://vault.tld"
            vault_token: SecretStr = SecretStr("fake-token")

    settings = Settings(username="doesn't matter", password=SecretStr("doesn't matter"))

    vault_settings_dict = vault_config_settings_source(settings)
    assert vault_settings_dict == {"username": "my_user", "password": "my_password"}
