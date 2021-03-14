import logging
from typing import Dict, Optional, Any

from hvac import Client as HvacClient
from hvac.exceptions import VaultError
from pydantic import BaseSettings
from pydantic.env_settings import SettingsError
from typing_extensions import TypedDict


class HvacClientParameters(TypedDict, total=False):
    namespace: str
    token: str


class HvacReadSecretParameters(TypedDict, total=False):
    path: str
    mount_point: str


def vault_config_settings_source(settings: BaseSettings) -> Dict[str, Any]:
    d: Dict[str, Optional[str]] = {}

    # Login
    hvac_parameters: HvacClientParameters = {}
    if getattr(settings.__config__, "vault_namespace", None) is not None:
        hvac_parameters.update({"namespace": settings.__config__.vault_namespace})  # type: ignore
    if getattr(settings.__config__, "vault_token", None) is not None:
        hvac_parameters.update({"token": settings.__config__.vault_token})  # type: ignore

    vault_client = HvacClient(settings.__config__.vault_url, **hvac_parameters)  # type: ignore

    # Get secrets
    for field in settings.__fields__.values():
        vault_val: Optional[str] = None

        vault_secret_path = field.field_info.extra["vault_secret_path"]
        vault_secret_key = field.field_info.extra["vault_secret_key"]
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
