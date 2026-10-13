"""Shared exception definition; publicly re-exported from cf_access_auth."""


class AccessError(Exception):
    # Preserve the original public exception identity for inspection and pickling.
    __module__ = "cf_access_auth"

    def __init__(self, code: str, status: int = 401):
        self.code = code
        self.status = status
        super().__init__(
            {401: "Unauthorized", 403: "Forbidden", 503: "Authentication unavailable"}[
                status
            ]
        )
