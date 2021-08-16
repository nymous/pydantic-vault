from typing import Any, Dict, Optional, Union

class ApproleStub:
    @staticmethod
    def login(
        role_id: str,
        secret_id: Optional[str] = None,
        use_token: bool = True,
        mount_point: str = "approle",
    ) -> Dict[str, Any]:
        raise NotImplementedError()

class KubernetesStub:
    @staticmethod
    def login(
        role: str,
        jwt: str,
        use_token: bool = True,
        mount_point: str = "kubernetes",
    ) -> Dict[str, Any]:
        raise NotImplementedError()

class AuthStub:
    approle: ApproleStub
    kubernetes: KubernetesStub

class Client:
    auth: AuthStub
    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        verify: Union[bool, str] = True,
        timeout: int = 30,
        allow_redirects: bool = True,
        namespace: Optional[str] = None,
    ) -> None:
        raise NotImplementedError()
    def read(self, path: str) -> Dict[str, Any]:
        raise NotImplementedError()
