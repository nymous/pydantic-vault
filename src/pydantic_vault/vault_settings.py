import logging
import os
from contextlib import suppress
from pathlib import Path
from typing import Dict, Optional, Any, NamedTuple

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

    _vault_token = _extract_vault_token(settings)
    if _vault_token is not None:
        hvac_parameters.update({"token": _vault_token.get_secret_value()})
        hvac_client = HvacClient(_vault_url, **hvac_parameters)
        return hvac_client

    hvac_client = HvacClient(_vault_url, **hvac_parameters)

    _vault_approle = _extract_approle(settings)
    if _vault_approle is not None:
        hvac_client.auth.approle.login(
            role_id=_vault_approle.role_id,
            secret_id=_vault_approle.secret_id.get_secret_value(),
        )
        return hvac_client


class Approle(NamedTuple):
    role_id: str
    secret_id: SecretStr


def _extract_approle(settings: BaseSettings) -> Optional[Approle]:
    """Extract Approle information from environment or from BaseSettings.Config"""
    _vault_role_id: Optional[str] = None
    _vault_secret_id: Optional[SecretStr] = None

    # Load from BaseSettings.Config
    if getattr(settings.__config__, "vault_role_id", None) is not None:
        _vault_role_id = settings.__config__.vault_role_id  # type: ignore
    if getattr(settings.__config__, "vault_secret_id", None) is not None:
        if isinstance(settings.__config__.vault_secret_id, SecretStr):  # type: ignore
            _vault_secret_id = settings.__config__.vault_secret_id  # type: ignore
        else:
            _vault_secret_id = SecretStr(settings.__config__.vault_secret_id)  # type: ignore

    # Load (and eventually override) from environment
    if "VAULT_ROLE_ID" in os.environ:
        _vault_role_id = os.environ["VAULT_ROLE_ID"]
    if "VAULT_SECRET_ID" in os.environ:
        _vault_secret_id = SecretStr(os.environ["VAULT_SECRET_ID"])

    if _vault_role_id is not None and _vault_secret_id is not None:
        return Approle(role_id=_vault_role_id, secret_id=_vault_secret_id)

    return None


def _extract_vault_token(settings: BaseSettings) -> Optional[SecretStr]:
    """Extract Vault token from environment, from .vault-token file or from BaseSettings.Config"""
    _vault_token: SecretStr
    if "VAULT_TOKEN" in os.environ:
        _vault_token = SecretStr(os.environ["VAULT_TOKEN"])
        return _vault_token

    with suppress(FileNotFoundError):
        with open(Path.home() / ".vault-token") as token_file:
            _vault_token = SecretStr(token_file.read().strip())
            return _vault_token

    if getattr(settings.__config__, "vault_token", None) is not None:
        if isinstance(settings.__config__.vault_token, SecretStr):  # type: ignore
            _vault_token = settings.__config__.vault_token  # type: ignore
        else:
            _vault_token = SecretStr(settings.__config__.vault_token)  # type: ignore
        return _vault_token

    return None


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
