from typing import List, Optional

class VaultError(Exception):
    def __init__(
        self, message: Optional[str] = None, errors: Optional[List[str]] = None
    ) -> None:
        raise NotImplementedError()
