from typing import NamedTuple, Union

from pydantic import SecretStr
from typing_extensions import TypedDict


class HvacClientParameters(TypedDict, total=False):
    namespace: str
    token: str
    verify: Union[bool, str]


class HvacReadSecretParameters(TypedDict, total=False):
    path: str
    mount_point: str


class AuthMethodParameters(TypedDict, total=False):
    mount_point: str


class Approle(NamedTuple):
    role_id: str
    secret_id: SecretStr


class Kubernetes(NamedTuple):
    role: str
    jwt_token: SecretStr
