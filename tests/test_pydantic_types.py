import datetime
import logging
from pathlib import Path
from typing import Any, Callable

import pytest
from pydantic import AfterValidator, Json
from pydantic_settings import BaseSettings
from pytest import LogCaptureFixture
from typing_extensions import Annotated, Dict

from pydantic_vault.vault_settings import FileInfo, StoredSecret


class TestStoredSecret:
    def test_save_secret(self) -> None:
        # arrange
        path = Path("service-account.json")
        path_is_exist = path.exists()

        service_account_raw = '{"key": "value", "some_key": "some_value"}'

        class Settings(BaseSettings):
            google_ads_service_account: Annotated[
                StoredSecret[Json[Dict[str, str]]],
                AfterValidator(FileInfo(path)),
            ]
            model_config = {  # type: ignore
                "vault_url": "https://vault.tld",
                "vault_token": "fake-token",
            }

        # act
        settings = Settings(google_ads_service_account=service_account_raw)  # type: ignore[arg-type]

        # assert
        assert settings.google_ads_service_account.get_value() == {
            "key": "value",
            "some_key": "some_value",
        }
        assert settings.google_ads_service_account.get_file_info().path == path  # type: ignore[union-attr]
        assert (
            settings.google_ads_service_account.get_file_info().path.read_text()  # type: ignore[union-attr]
            == service_account_raw
        )
        assert path_is_exist is False

    def test_save_not_serializable_object__raise_error(
        self,
        caplog: LogCaptureFixture,
    ) -> None:
        # arrange
        secret = StoredSecret[datetime.datetime](datetime.datetime.now())
        file_info = FileInfo(Path("filename"))
        secret.set_file_info(file_info)

        # act
        with pytest.raises(TypeError):
            secret.save_to_disk()

        # assert
        assert (
            "pydantic-vault",
            logging.ERROR,
            f"Failed to save secret to disk: {str(file_info.path)}",
        ) in caplog.record_tuples

    def test_raise_error_is_false__no_error_occurs(
        self,
        caplog: LogCaptureFixture,
    ) -> None:
        # arrange
        secret = StoredSecret[datetime.datetime](datetime.datetime.now())
        file_info = FileInfo(Path("filename"), raise_error=False)
        secret.set_file_info(file_info)

        # act
        secret.save_to_disk()

        # assert
        assert (
            "pydantic-vault",
            logging.ERROR,
            f"Failed to save secret to disk: {str(file_info.path)}",
        ) in caplog.record_tuples

    def test_file_info_not_injected__raise_value_error(self) -> None:
        # arrange
        secret = StoredSecret[str]("data")

        # act & assert
        with pytest.raises(ValueError):
            secret.save_to_disk()

    @pytest.mark.parametrize("to_str", [str, repr])
    def test_display(self, to_str: Callable[[Any], str]) -> None:
        # arrange
        secret = StoredSecret[str]("data")

        # act
        result = to_str(secret)

        # assert
        assert result == "StoredSecret(data, path=None, encoding=None)"


def test_file_info__send_wrong_type__raise_error() -> None:
    # arrange
    file_info = FileInfo(Path("filename"))

    # act & assert
    with pytest.raises(TypeError):
        file_info("wrong type")  # type: ignore[arg-type]
