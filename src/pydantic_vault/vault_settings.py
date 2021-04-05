import logging
import os
from contextlib import suppress
from pathlib import Path
from typing import Dict, Optional, Any

from hvac import Client as HvacClient
from hvac.exceptions import VaultError
from pydantic import BaseSettings, SecretStr
from pydantic.env_settings import SettingsError
from typing_extensions import TypedDict


class HvacClientParameters(TypedDict, total=False):
    namespace: str
    token: str


class HvacReadSecretParameters(TypedDict, total=False):
    path: str
    mount_point: str


class PydanticVaultException(BaseException):
    ...


class VaultParameterError(PydanticVaultException, ValueError):
    ...


def _get_authenticated_vault_client(settings: BaseSettings) -> HvacClient:
    hvac_parameters: HvacClientParameters = {}

    # URL
    _vault_url: Optional[str] = None
    if getattr(settings.__config__, "vault_url", None) is not None:
        _vault_url = settings.__config__.vault_url  # type: ignore
    if "VAULT_ADDR" in os.environ:
        _vault_url = os.environ["VAULT_ADDR"]
    if _vault_url is None:
        raise VaultParameterError("No URL provided to connect to Vault")

    # Namespace
    _vault_namespace: str
    if getattr(settings.__config__, "vault_namespace", None) is not None:
        _vault_namespace = settings.__config__.vault_namespace  # type: ignore
        hvac_parameters.update({"namespace": _vault_namespace})
    if "VAULT_NAMESPACE" in os.environ:
        _vault_namespace = os.environ["VAULT_NAMESPACE"]
        hvac_parameters.update({"namespace": _vault_namespace})

    # Vault token
    _vault_token: str
    if getattr(settings.__config__, "vault_token", None) is not None:
        if isinstance(settings.__config__.vault_token, SecretStr):  # type: ignore
            _vault_token = settings.__config__.vault_token.get_secret_value()  # type: ignore
        else:
            _vault_token = settings.__config__.vault_token  # type: ignore
        hvac_parameters.update({"token": _vault_token})
    with suppress(FileNotFoundError):
        with open(Path.home() / ".vault-token") as token_file:
            _vault_token = token_file.read().strip()
            hvac_parameters.update({"token": _vault_token})
    if "VAULT_TOKEN" in os.environ:
        _vault_token = os.environ["VAULT_TOKEN"]
        hvac_parameters.update({"token": _vault_token})

    return HvacClient(_vault_url, **hvac_parameters)


def vault_config_settings_source(settings: BaseSettings) -> Dict[str, Any]:
    d: Dict[str, Optional[str]] = {}

    vault_client = _get_authenticated_vault_client(settings)

    # Get secrets
    for field in settings.__fields__.values():
        vault_val: Optional[str] = None

        vault_secret_path = field.field_info.extra.get("vault_secret_path")
        vault_secret_key = field.field_info.extra.get("vault_secret_key")

        if vault_secret_path is None or vault_secret_key is None:
            logging.debug(f"Skipping field {field.name}")
            continue

        vault_secret_mount_point = getattr(
            settings.__config__, "vault_secret_mount_point", None
        )

        read_secret_parameters: HvacReadSecretParameters = {"path": vault_secret_path}
        if vault_secret_mount_point is not None:
            read_secret_parameters["mount_point"] = vault_secret_mount_point

        try:
            vault_val = vault_client.secrets.kv.v2.read_secret_version(
                **read_secret_parameters
            )["data"]["data"][vault_secret_key]
        except VaultError:
            logging.info(
                f'could not get secret "{vault_secret_path}:{vault_secret_key}"'
            )

        if field.is_complex():
            try:
                vault_val = settings.__config__.json_loads(vault_val)  # type: ignore
            except ValueError as e:
                raise SettingsError(
                    f'error parsing JSON for "{vault_secret_path}:{vault_secret_key}'
                ) from e

        d[field.alias] = vault_val

    return d
