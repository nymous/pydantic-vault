import logging
import os
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, NamedTuple, Optional, Union, cast

from hvac import Client as HvacClient
from hvac.exceptions import VaultError
from pydantic import BaseSettings, SecretStr
from pydantic.env_settings import SettingsError
from typing_extensions import TypedDict

logger = logging.getLogger("pydantic-vault")
logger.addHandler(logging.NullHandler())


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


def _format_vault_client_auth_log(
    vault_url: str,
    vault_auth_method: str,
    vault_namespace: Optional[str] = None,
    additional_parameters: Optional[Dict[str, str]] = None,
) -> str:
    message = f"Connecting to Vault '{vault_url}'"

    if vault_namespace is not None:
        message += f" on namespace '{vault_namespace}'"

    message += f" with method '{vault_auth_method}'"

    if additional_parameters is not None:
        message += f" ({additional_parameters})"

    return message


def _get_authenticated_vault_client(settings: BaseSettings) -> Optional[HvacClient]:
    hvac_parameters: HvacClientParameters = {}

    # URL
    _vault_url: Optional[str] = None
    if "VAULT_ADDR" in os.environ:
        _vault_url = os.environ["VAULT_ADDR"]
        logger.debug(f"Found Vault Address '{_vault_url}' in environment variables")
    if getattr(settings.__config__, "vault_url", None) is not None:
        _vault_url = settings.__config__.vault_url  # type: ignore
        logger.debug(f"Found Vault Address '{_vault_url}' in Config")
    if _vault_url is None:
        raise VaultParameterError("No URL provided to connect to Vault")

    # Namespace
    _vault_namespace: Optional[str] = None
    if "VAULT_NAMESPACE" in os.environ:
        _vault_namespace = os.environ["VAULT_NAMESPACE"]
        hvac_parameters.update({"namespace": _vault_namespace})
        logger.debug(
            f"Found Vault Namespace '{_vault_namespace}' in environment variables"
        )
    if getattr(settings.__config__, "vault_namespace", None) is not None:
        _vault_namespace = cast(str, settings.__config__.vault_namespace)  # type: ignore
        hvac_parameters.update({"namespace": _vault_namespace})
        logger.debug(f"Found Vault Namespace '{_vault_namespace}' in Config")

    # Auth method parameters
    _vault_auth_method_parameters: AuthMethodParameters = {}
    if "VAULT_AUTH_MOUNT_POINT" in os.environ:
        _vault_auth_mount_point = os.environ["VAULT_AUTH_MOUNT_POINT"]
        _vault_auth_method_parameters["mount_point"] = _vault_auth_mount_point
        logger.debug(
            f"Found Vault Auth mount point '{_vault_auth_mount_point}' in environment variables"
        )
    if getattr(settings.__config__, "vault_auth_mount_point", None) is not None:
        _vault_auth_mount_point: str = settings.__config__.vault_auth_mount_point  # type: ignore
        _vault_auth_method_parameters["mount_point"] = _vault_auth_mount_point
        logger.debug(
            f"Found Vault Auth mount point '{_vault_auth_mount_point}' in Config"
        )

    _vault_token = _extract_vault_token(settings)
    if _vault_token is not None:
        hvac_parameters.update({"token": _vault_token.get_secret_value()})
        hvac_client = HvacClient(_vault_url, **hvac_parameters)
        logger.info(
            _format_vault_client_auth_log(_vault_url, "Vault Token", _vault_namespace)
        )
        return hvac_client

    hvac_client = HvacClient(_vault_url, **hvac_parameters)

    _vault_kubernetes = _extract_kubernetes(settings)
    if _vault_kubernetes is not None:
        hvac_client.auth.kubernetes.login(
            _vault_kubernetes.role,
            _vault_kubernetes.jwt_token.get_secret_value(),
            **_vault_auth_method_parameters,
        )
        logger.info(
            _format_vault_client_auth_log(
                _vault_url,
                "Kubernetes",
                _vault_namespace,
                {"kubernetes_role": _vault_kubernetes.role},
            )
        )
        return hvac_client

    _vault_approle = _extract_approle(settings)
    if _vault_approle is not None:
        hvac_client.auth.approle.login(
            role_id=_vault_approle.role_id,
            secret_id=_vault_approle.secret_id.get_secret_value(),
            **_vault_auth_method_parameters,
        )
        logger.info(
            _format_vault_client_auth_log(
                _vault_url,
                "Approle",
                _vault_namespace,
                {"role_id": _vault_approle.role_id},
            )
        )
        return hvac_client

    # We couldn't find suitable information to authenticate against Vault
    return None


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
        logger.debug(f"Found Vault Role ID '{_vault_role_id}' in environment variables")
    if "VAULT_SECRET_ID" in os.environ:
        _vault_secret_id = SecretStr(os.environ["VAULT_SECRET_ID"])
        logger.debug("Found Vault Secret ID in environment variables")

    # Load (and eventually override) from BaseSettings.Config
    if getattr(settings.__config__, "vault_role_id", None) is not None:
        _vault_role_id = settings.__config__.vault_role_id  # type: ignore
        logger.debug(f"Found Vault Role ID '{_vault_role_id}' in Config")
    if getattr(settings.__config__, "vault_secret_id", None) is not None:
        if isinstance(settings.__config__.vault_secret_id, SecretStr):  # type: ignore
            _vault_secret_id = settings.__config__.vault_secret_id  # type: ignore
        else:
            _vault_secret_id = SecretStr(settings.__config__.vault_secret_id)  # type: ignore
        logger.debug(f"Found Vault Secret ID in Config")

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
        logger.debug("Found Vault Token in Config")
        return _vault_token

    if "VAULT_TOKEN" in os.environ:
        _vault_token = SecretStr(os.environ["VAULT_TOKEN"])
        logger.debug("Found Vault Token in environment variables")
        return _vault_token

    with suppress(FileNotFoundError):
        with open(Path.home() / ".vault-token") as token_file:
            _vault_token = SecretStr(token_file.read().strip())
            logger.debug("Found Vault Token in file '~/.vault-token'")
            return _vault_token

    return None


class Kubernetes(NamedTuple):
    role: str
    jwt_token: SecretStr


def _extract_kubernetes(settings: BaseSettings) -> Optional[Kubernetes]:
    """Extract Kubernetes token from default file, and role from environment or from BaseSettings.Config"""
    _kubernetes_jwt: SecretStr
    with suppress(FileNotFoundError):
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as token_file:
            _kubernetes_jwt = SecretStr(token_file.read().strip())
            logger.debug(
                "Found Kubernetes JWT Token in file '/var/run/secrets/kubernetes.io/serviceaccount/token'"
            )

        # Kubernetes role
        kubernetes_role: Optional[str] = None
        if "VAULT_KUBERNETES_ROLE" in os.environ:
            kubernetes_role = os.environ["VAULT_KUBERNETES_ROLE"]
            logger.debug(
                f"Found Kubernetes role '{kubernetes_role}' in environment variables"
            )
        if getattr(settings.__config__, "vault_kubernetes_role", None) is not None:
            kubernetes_role = settings.__config__.vault_kubernetes_role  # type: ignore
            logger.debug(f"Found Kubernetes role '{kubernetes_role}' in Config")

        if kubernetes_role is not None:
            return Kubernetes(role=kubernetes_role, jwt_token=_kubernetes_jwt)

    return None


def vault_config_settings_source(settings: BaseSettings) -> Dict[str, Any]:
    d: Dict[str, Any] = {}

    vault_client = _get_authenticated_vault_client(settings)
    if vault_client is None:
        logger.warning("Could not find a suitable authentication method for Vault")
        return {}

    # Get secrets
    for field in settings.__fields__.values():
        vault_val: Union[str, Dict[str, Any]]

        vault_secret_path: Optional[str] = field.field_info.extra.get(
            "vault_secret_path"
        )
        vault_secret_key: Optional[str] = field.field_info.extra.get("vault_secret_key")

        if vault_secret_path is None:
            logger.debug(f"Skipping field {field.name}")
            continue

        try:
            vault_api_response = vault_client.read(vault_secret_path)["data"]
        except VaultError:
            logger.info(f'could not get secret "{vault_secret_path}"')
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
                    logger.info(
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
