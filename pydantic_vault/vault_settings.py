import logging
from pathlib import Path
from typing import Dict, Optional, Any, Union

import hvac
from hvac.exceptions import VaultError
from pydantic import BaseSettings
from pydantic.env_settings import SettingsError
from pydantic.utils import deep_update
from typing_extensions import TypedDict


class HvacClientParameters(TypedDict, total=False):
    namespace: str
    token: str


class HvacReadSecretParameters(TypedDict, total=False):
    path: str
    mount_point: str


class VaultBaseSettings(BaseSettings):
    def _build_values(
        self, init_kwargs: Dict[str, Any], _env_file: Union[Path, str, None] = None
    ) -> Dict[str, Any]:
        return deep_update(
            deep_update(self._build_vault(), self._build_environ(_env_file)),
            init_kwargs,
        )

    def _build_vault(self) -> Dict[str, Optional[str]]:
        d: Dict[str, Optional[str]] = {}

        # Login
        hvac_parameters: HvacClientParameters = {}
        if self.__config__.vault_namespace is not None:
            hvac_parameters.update({"namespace": self.__config__.vault_namespace})
        if self.__config__.vault_token is not None:
            hvac_parameters.update({"token": self.__config__.vault_token})

        vault_client = hvac.Client(self.__config__.vault_url, **hvac_parameters)

        # Get secrets
        for field in self.__fields__.values():
            vault_val: Optional[str] = None

            vault_secret_path = field.field_info.extra["vault_secret_path"]
            vault_secret_key = field.field_info.extra["vault_secret_key"]
            vault_secret_mount_point = self.__config__.vault_secret_mount_point

            read_secret_parameters: HvacReadSecretParameters = {
                "path": vault_secret_path
            }
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
                    vault_val = self.__config__.json_loads(vault_val)  # type: ignore
                except ValueError as e:
                    raise SettingsError(
                        f'error parsing JSON for "{vault_secret_path}:{vault_secret_key}'
                    ) from e

            d[field.alias] = vault_val

        return d

    class Config(BaseSettings.Config):
        vault_url: str
        vault_namespace: Optional[str] = None
        vault_token: str
        vault_secret_mount_point: Optional[str] = None

    __config__: Config
