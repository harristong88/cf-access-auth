"""Cloudflare Access verification, independent of application persistence."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
import jwt

from ._errors import AccessError
from ._jwks import _JwksCache

MAX_TOKEN_BYTES = 16384


@dataclass(frozen=True)
class AccessIdentity:
    issuer: str
    subject: str
    email: str
    expires_at: int


def normalize_email(email: str) -> str:
    return email.strip().lower()


def assertion_from_headers(headers: Iterable[tuple[bytes, bytes]]) -> str:
    values = [
        value for name, value in headers if name.lower() == b"cf-access-jwt-assertion"
    ]
    if len(values) != 1:
        raise AccessError("ASSERTION_HEADER")
    try:
        token = values[0].decode("ascii")
    except (UnicodeError, AttributeError):
        raise AccessError("MALFORMED_TOKEN") from None
    _validate_token(token)
    return token


def _validate_token(token: str) -> None:
    if (
        not isinstance(token, str)
        or len(token.encode()) > MAX_TOKEN_BYTES
        or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)
    ):
        raise AccessError("MALFORMED_TOKEN")


class AccessVerifier:
    def __init__(
        self,
        team_domain: str,
        audience: str | Iterable[str],
        *,
        cache_ttl: float = 600,
        timeout: float = 5,
        cooldown: float = 30,
        on_diagnostic: Callable[[dict], None] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        url = urlsplit(team_domain)
        if (
            url.scheme != "https"
            or not re.fullmatch(r"[a-z0-9-]+\.cloudflareaccess\.com", url.netloc)
            or url.path not in ("", "/")
            or url.query
            or url.fragment
        ):
            raise ValueError(
                "team_domain must be an HTTPS Cloudflare Access team origin"
            )
        audiences = [audience] if isinstance(audience, str) else list(audience)
        if not audiences or any(
            not isinstance(a, str) or not a.strip() or a != a.strip() for a in audiences
        ):
            raise ValueError("audience is required")
        if (
            any(not math.isfinite(v) or v < 0 for v in (cache_ttl, cooldown))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Invalid JWKS timing")
        self.audience = audiences
        self.on_diagnostic = on_diagnostic
        self._cache = _JwksCache(f"https://{url.netloc}", cache_ttl, timeout, cooldown, transport)

    # These settings were public mutable attributes before cache extraction.
    @property
    def issuer(self) -> str:
        return self._cache.issuer

    @issuer.setter
    def issuer(self, value: str) -> None:
        self._cache.issuer = value

    @property
    def cache_ttl(self) -> float:
        return self._cache.cache_ttl

    @cache_ttl.setter
    def cache_ttl(self, value: float) -> None:
        self._cache.cache_ttl = value

    @property
    def cooldown(self) -> float:
        return self._cache.cooldown

    @cooldown.setter
    def cooldown(self, value: float) -> None:
        self._cache.cooldown = value

    async def aclose(self) -> None:
        await self._cache.aclose()

    def _report(self, error: AccessError) -> None:
        if self.on_diagnostic:
            try:
                self.on_diagnostic({"code": error.code, "status": error.status})
            except Exception:
                pass

    async def verify_token(self, token: str) -> AccessIdentity:
        try:
            _validate_token(token)
            header = jwt.get_unverified_header(token)
            if (
                "crit" in header
                or header.get("b64", True) is not True
                or header.get("alg") != "RS256"
                or not isinstance(header.get("kid"), str)
                or not header["kid"]
            ):
                raise AccessError("INVALID_TOKEN")
            key = await self._cache.key(header["kid"])
            payload = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
                leeway=0,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "exp",
                        "iat",
                        "nbf",
                        "sub",
                        "email",
                        "type",
                    ]
                },
            )
            if (
                payload["type"] != "app"
                or any(type(payload[k]) is not int for k in ("exp", "iat", "nbf"))
                or any(
                    abs(payload[k]) > 9007199254740991 for k in ("exp", "iat", "nbf")
                )
                or payload["iat"] > int(time.time())
                or payload["exp"] <= payload["iat"]
                or not isinstance(payload["sub"], str)
                or not payload["sub"].strip()
                or not isinstance(payload["email"], str)
                or not payload["email"].strip()
            ):
                raise AccessError("INVALID_CLAIMS")
            return AccessIdentity(
                self.issuer, payload["sub"], payload["email"].strip(), payload["exp"]
            )
        except (jwt.PyJWTError, TypeError, ValueError, OverflowError):
            error = AccessError("INVALID_TOKEN")
            self._report(error)
            raise error from None
        except AccessError as error:
            self._report(error)
            raise

    async def authenticate_request(
        self, headers: Iterable[tuple[bytes, bytes]]
    ) -> AccessIdentity:
        try:
            token = assertion_from_headers(headers)
        except AccessError as error:
            self._report(error)
            raise
        return await self.verify_token(token)
