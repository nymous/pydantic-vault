import logging
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
from hvac.exceptions import VaultError
from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings
from pydantic_settings.sources import SettingsError
from pytest import LogCaptureFixture
from pytest_mock import MockerFixture
from typing_extensions import TypedDict

from pydantic_vault import VaultSettingsSource


class VaultDataWrapper(TypedDict):
    data: Dict[str, Any]


VaultStructure = Dict[str, VaultDataWrapper]


def fake_vault(path: str) -> VaultDataWrapper:
    vault: VaultStructure = {
        # Database secret engine
        "database/creds/db_role": {
            "data": {"username": "db_username", "password": "db_password"}
        },
        # KV v1 secret engine
        "kv/normal_secret": {"data": {"kvv1_key": "kvv1_value"}},
        "kv/secret_with_data_key": {
            "data": {
                "kvv1_key": "kvv1_value",
                "data": {"kvv1_nested_key": "kvv1_nested_value"},
            }
        },
        # KV v2 secret engine
        "secret/data/first_level_key": {
            "data": {
                "metadata": {},
                "data": {
                    "username": "kvv2_user",
                    "password": "kvv2_password",
                    "complex_value": {
                        "inner": "value",
                        "int_key": 12,
                        "list_key": ["first", "second", "third"],
                    },
                    "json_in_string": '{"key": "value", "list": [1, 2, 3]}',
                },
            }
        },
        "secret/data/first_level_key/not_found": None,  # type: ignore[dict-item]
        "secret/data/secret_with_data_key": {
            "data": {
                "metadata": {},
                "data": {"data": {"kvv2_nested_key": "kvv2_nested_value"}},
            }
        },
        "secret/data/nested/path": {
            "data": {"metadata": {}, "data": {"username": "kvv2_nested_username"}}
        },
        "secret/data/bad_json": {
            "data": {"metadata": {}, "data": {"bad_json": "{this is not a valid JSON}"}}
        },
    }
    try:
        return vault[path]
    except KeyError:
        raise VaultError(f"Key {path} not found in Vault")


@pytest.fixture(autouse=True, name="fake_hvac_client")
def bypass_hvac_client(mocker: MockerFixture) -> MagicMock:
    mock_hvac_client_constructor = mocker.patch(
        "pydantic_vault.vault_settings.HvacClient", autospec=True
    )
    mock_hvac_client = mock_hvac_client_constructor.return_value
    mock_hvac_client.read.side_effect = fake_vault

    return mock_hvac_client


def test_get_vault_secrets() -> None:
    class Settings(BaseSettings):
        username: str = Field(
            "doesn't matter",
            vault_secret_path="secret/data/first_level_key",
            vault_secret_key="username",
        )
        password: SecretStr = Field(  # type: ignore
            "doesn't matter",
            vault_secret_path="secret/data/first_level_key",
            vault_secret_key="password",
        )

        model_config = {  # type: ignore
            "vault_url": "https://vault.tld",
            "vault_token": SecretStr("fake-token"),
        }

    vault_settings_dict = VaultSettingsSource(Settings)()
    assert vault_settings_dict == {"username": "kvv2_user", "password": "kvv2_password"}


def test_do_not_search_vault_for_keys_not_configured() -> None:
    class Settings(BaseSettings):
        simple_field: str = "doesn't matter"
        field_from_vault: str = Field(
            "doesn't matter",
            vault_secret_path="secret/data/first_level_key",
            vault_secret_key="password",
        )

        model_config = {  # type: ignore
            "vault_url": "https://vault.tld",
            "vault_token": SecretStr("fake-token"),
        }

    vault_settings_dict = VaultSettingsSource(Settings)()
    assert vault_settings_dict == {"field_from_vault": "kvv2_password"}


def test_do_not_override_default_value_if_secret_is_not_found() -> None:
    class Settings(BaseSettings):
        field_from_vault: str = Field(
            "doesn't matter",
            vault_secret_path="secret/data/first_level_key",
            vault_secret_key="password",
        )
        path_not_found: str = Field(
            "default_value",
            vault_secret_path="not/found",
            vault_secret_key="does_not_matter",
        )
        path_almost_found: str = Field(
            "default_value",
            vault_secret_path="secret/data/first_level_key/not_found",
            vault_secret_key="does_not_exist",
        )
        key_not_found: str = Field(
            "default_value",
            vault_secret_path="secret/data/first_level_key",
            vault_secret_key="does_not_exist",
        )

        model_config = {  # type: ignore
            "vault_url": "https://vault.tld",
            "vault_token": SecretStr("fake-token"),
        }

    settings = Settings()

    vault_settings_dict = VaultSettingsSource(Settings)()
    assert "field_from_vault" in vault_settings_dict
    assert "path_not_found" not in vault_settings_dict
    assert "path_almost_found" not in vault_settings_dict
    assert "key_not_found" not in vault_settings_dict

    assert settings.path_not_found == "default_value"
    assert settings.path_almost_found == "default_value"
    assert settings.key_not_found == "default_value"


def test_get_secret_without_key() -> None:
    class DbCredentials(BaseModel):
        username: str
        password: SecretStr

    class Settings(BaseSettings):
        db_credentials: DbCredentials = Field(  # type: ignore
            {"username": "doesn't matter", "password": "doesn't matter"},
            vault_secret_path="database/creds/db_role",
        )
        kvv2_secret: Dict[str, Any] = Field(
            {}, vault_secret_path="secret/data/first_level_key"
        )

        model_config = {  # type: ignore
            "vault_url": "https://vault.tld",
            "vault_token": SecretStr("fake-token"),
        }

    vault_settings_dict = VaultSettingsSource(Settings)()
    assert vault_settings_dict == {
        "db_credentials": {"username": "db_username", "password": "db_password"},
        "kvv2_secret": {
            "username": "kvv2_user",
            "password": "kvv2_password",
            "complex_value": {
                "inner": "value",
                "int_key": 12,
                "list_key": ["first", "second", "third"],
            },
            "json_in_string": '{"key": "value", "list": [1, 2, 3]}',
        },
    }


def test_get_secrets_from_different_mount_points() -> None:
    class Settings(BaseSettings):
        field_from_kvv1: str = Field(
            "doesn't matter",
            vault_secret_path="kv/normal_secret",
            vault_secret_key="kvv1_key",
        )

        field_from_kvv2: str = Field(
            "doesn't matter",
            vault_secret_path="secret/data/first_level_key",
            vault_secret_key="username",
        )

        model_config = {  # type: ignore
            "vault_url": "https://vault.tld",
            "vault_token": SecretStr("fake-token"),
        }

    vault_settings_dict = VaultSettingsSource(Settings)()
    assert vault_settings_dict == {
        "field_from_kvv1": "kvv1_value",
        "field_from_kvv2": "kvv2_user",
    }


def test_get_secret_jsonified() -> None:
    class JsonField(BaseModel):
        key: str
        list: List[int]

    class Settings(BaseSettings):
        json_field: JsonField = Field(  # type: ignore
            {"key": "doesn't matter", "list": []},
            vault_secret_path="secret/data/first_level_key",
            vault_secret_key="json_in_string",
        )

        model_config = {  # type: ignore
            "vault_url": "https://vault.tld",
            "vault_token": SecretStr("fake-token"),
        }

    vault_settings_dict = VaultSettingsSource(Settings)()
    assert vault_settings_dict == {"json_field": JsonField(key="value", list=[1, 2, 3])}


def test_get_secret_in_data_key() -> None:
    class Settings(BaseSettings):
        kvv1_data_with_key: Dict[str, Any] = Field(
            {}, vault_secret_path="kv/secret_with_data_key", vault_secret_key="data"
        )
        # FIXME: KV v1 secret with a `data` key and configured without a
        #        vault_secret_key is currently not supported
        kvv2_data_with_key: Dict[str, Any] = Field(
            {},
            vault_secret_path="secret/data/secret_with_data_key",
            vault_secret_key="data",
        )
        kvv2_data_without_key: Dict[str, Any] = Field(
            {},
            vault_secret_path="secret/data/secret_with_data_key",
        )

        model_config = {  # type: ignore
            "vault_url": "https://vault.tld",
            "vault_token": SecretStr("fake-token"),
        }

    vault_settings_dict = VaultSettingsSource(Settings)()
    assert vault_settings_dict == {
        "kvv1_data_with_key": {"kvv1_nested_key": "kvv1_nested_value"},
        "kvv2_data_with_key": {"kvv2_nested_key": "kvv2_nested_value"},
        "kvv2_data_without_key": {"data": {"kvv2_nested_key": "kvv2_nested_value"}},
    }


def test_get_secret_bad_json() -> None:
    class Settings(BaseSettings):
        bad_json: Dict[str, Any] = Field(
            {}, vault_secret_path="secret/data/bad_json", vault_secret_key="bad_json"
        )

        model_config = {  # type: ignore
            "vault_url": "https://vault.tld",
            "vault_token": SecretStr("fake-token"),
        }

    with pytest.raises(SettingsError):
        VaultSettingsSource(Settings)()


def test_log_warning_if_no_authentication_found(caplog: LogCaptureFixture) -> None:
    class Settings(BaseSettings):
        username: str = Field(
            "doesn't matter",
            vault_secret_path="secret/data/first_level_key",
            vault_secret_key="username",
        )

        model_config = {"vault_url": "https://vault.tld"}  # type: ignore

    VaultSettingsSource(Settings)()

    # fmt: off
    assert ("pydantic-vault", logging.WARNING, "Could not find a suitable authentication method for Vault") in caplog.record_tuples
    # fmt: on
