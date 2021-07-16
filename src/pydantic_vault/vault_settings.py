import logging
import os
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, NamedTuple, Optional, Union

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


class AuthMethodParameters(TypedDict, total=False):
    mount_point: str


class PydanticVaultException(BaseException):
    ...


class VaultParameterError(PydanticVaultException, ValueError):
    ...


def _get_authenticated_vault_client(settings: BaseSettings) -> HvacClient:
    hvac_parameters: HvacClientParameters = {}

    # URL
    _vault_url: Optional[str] = None
    if "VAULT_ADDR" in os.environ:
        _vault_url = os.environ["VAULT_ADDR"]
    if getattr(settings.__config__, "vault_url", None) is not None:
        _vault_url = settings.__config__.vault_url  # type: ignore
    if _vault_url is None:
        raise VaultParameterError("No URL provided to connect to Vault")

    # Namespace
    _vault_namespace: str
    if "VAULT_NAMESPACE" in os.environ:
        _vault_namespace = os.environ["VAULT_NAMESPACE"]
        hvac_parameters.update({"namespace": _vault_namespace})
    if getattr(settings.__config__, "vault_namespace", None) is not None:
        _vault_namespace = settings.__config__.vault_namespace  # type: ignore
        hvac_parameters.update({"namespace": _vault_namespace})

    # Auth method parameters
    _vault_auth_method_parameters: AuthMethodParameters = {}
    if "VAULT_AUTH_MOUNT_POINT" in os.environ:
        _vault_auth_method_parameters["mount_point"] = os.environ[
            "VAULT_AUTH_MOUNT_POINT"
        ]
    if getattr(settings.__config__, "vault_auth_mount_point", None) is not None:
        _vault_auth_method_parameters["mount_point"] = settings.__config__.vault_auth_mount_point  # type: ignore

    _vault_token = _extract_vault_token(settings)
    if _vault_token is not None:
        hvac_parameters.update({"token": _vault_token.get_secret_value()})
        hvac_client = HvacClient(_vault_url, **hvac_parameters)
        return hvac_client

    hvac_client = HvacClient(_vault_url, **hvac_parameters)

    _vault_kubernetes_jwt = _extract_kubernetes()
    if _vault_kubernetes_jwt is not None:
        # Kubernetes role
        kubernetes_role: Optional[SecretStr] = None
        if "VAULT_KUBERNETES_ROLE" in os.environ:
            kubernetes_role = SecretStr(os.environ["VAULT_KUBERNETES_ROLE"])

        if getattr(settings.__config__, "vault_kubernetes_role", None) is not None:
            if isinstance(settings.__config__.vault_kubernetes_role, SecretStr):  # type: ignore
                kubernetes_role = settings.__config__.vault_kubernetes_role  # type: ignore
            else:
                kubernetes_role = SecretStr(settings.__config__.vault_kubernetes_role)  # type: ignore

        if kubernetes_role is not None:
            hvac_client.auth_kubernetes(
                kubernetes_role.get_secret_value(),
                _vault_kubernetes_jwt.get_secret_value(),
                **_vault_auth_method_parameters,
            )
            return hvac_client

    _vault_approle = _extract_approle(settings)
    if _vault_approle is not None:
        hvac_client.auth.approle.login(
            role_id=_vault_approle.role_id,
            secret_id=_vault_approle.secret_id.get_secret_value(),
            **_vault_auth_method_parameters,
        )
        return hvac_client


class Approle(NamedTuple):
    role_id: str
    secret_id: SecretStr


def _extract_approle(settings: BaseSettings) -> Optional[Approle]:
    """Extract Approle information from environment or from BaseSettings.Config"""
    _vault_role_id: Optional[str] = None
    _vault_secret_id: Optional[SecretStr] = None

    # Load from environment
    if "VAULT_ROLE_ID" in os.environ:
        _vault_role_id = os.environ["VAULT_ROLE_ID"]
    if "VAULT_SECRET_ID" in os.environ:
        _vault_secret_id = SecretStr(os.environ["VAULT_SECRET_ID"])

    # Load (and eventually override) from BaseSettings.Config
    if getattr(settings.__config__, "vault_role_id", None) is not None:
        _vault_role_id = settings.__config__.vault_role_id  # type: ignore
    if getattr(settings.__config__, "vault_secret_id", None) is not None:
        if isinstance(settings.__config__.vault_secret_id, SecretStr):  # type: ignore
            _vault_secret_id = settings.__config__.vault_secret_id  # type: ignore
        else:
            _vault_secret_id = SecretStr(settings.__config__.vault_secret_id)  # type: ignore

    if _vault_role_id is not None and _vault_secret_id is not None:
        return Approle(role_id=_vault_role_id, secret_id=_vault_secret_id)

    return None


def _extract_vault_token(settings: BaseSettings) -> Optional[SecretStr]:
    """Extract Vault token from environment, from .vault-token file or from BaseSettings.Config"""
    _vault_token: SecretStr
    if getattr(settings.__config__, "vault_token", None) is not None:
        if isinstance(settings.__config__.vault_token, SecretStr):  # type: ignore
            _vault_token = settings.__config__.vault_token  # type: ignore
        else:
            _vault_token = SecretStr(settings.__config__.vault_token)  # type: ignore
        return _vault_token

    if "VAULT_TOKEN" in os.environ:
        _vault_token = SecretStr(os.environ["VAULT_TOKEN"])
        return _vault_token

    with suppress(FileNotFoundError):
        with open(Path.home() / ".vault-token") as token_file:
            _vault_token = SecretStr(token_file.read().strip())
            return _vault_token

    return None


def _extract_kubernetes() -> Optional[SecretStr]:
    """Extract Kubernetes token from default file"""
    _kubernetes_jwt: SecretStr
    with suppress(FileNotFoundError):
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as token_file:
            _kubernetes_jwt = SecretStr(token_file.read().strip())
            return _kubernetes_jwt

    return None


def vault_config_settings_source(settings: BaseSettings) -> Dict[str, Any]:
    d: Dict[str, Any] = {}

    vault_client = _get_authenticated_vault_client(settings)

    # Get secrets
    for field in settings.__fields__.values():
        vault_val: Union[str, Dict[str, Any]]

        vault_secret_path: Optional[str] = field.field_info.extra.get(
            "vault_secret_path"
        )
        vault_secret_key: Optional[str] = field.field_info.extra.get("vault_secret_key")

        if vault_secret_path is None:
            logging.debug(f"Skipping field {field.name}")
            continue

        try:
            vault_api_response = vault_client.read(vault_secret_path)["data"]
        except VaultError:
            logging.info(f'could not get secret "{vault_secret_path}"')
            continue

        if vault_secret_key is None:
            try:
                vault_val = vault_api_response["data"]
            except KeyError:
                vault_val = vault_api_response
        else:
            try:
                vault_val = vault_api_response["data"][vault_secret_key]
            except KeyError:
                try:
                    vault_val = vault_api_response[vault_secret_key]
                except KeyError:
                    logging.info(
                        f'could not get key "{vault_secret_key}" in secret "{vault_secret_path}"'
                    )
                    continue

        if field.is_complex() and not isinstance(
            vault_val, dict
        ):  # If it is already a dict we can load it in Pydantic
            try:
                vault_val = settings.__config__.json_loads(vault_val)  # type: ignore
            except ValueError as e:
                secret_full_path = vault_secret_path
                if vault_secret_key is not None:
                    secret_full_path += f":{vault_secret_key}"
                raise SettingsError(
                    f'error parsing JSON for "{secret_full_path}"'
                ) from e

        d[field.alias] = vault_val

    return d
