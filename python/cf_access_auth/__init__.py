"""Cloudflare Access verification, independent of application persistence."""

from __future__ import annotations

import asyncio
import math
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
import jwt

MAX_TOKEN_BYTES = 16384


@dataclass(frozen=True)
class AccessIdentity:
    issuer: str
    subject: str
    email: str
    expires_at: int


class AccessError(Exception):
    def __init__(self, code: str, status: int = 401):
        self.code = code
        self.status = status
        super().__init__(
            {401: "Unauthorized", 403: "Forbidden", 503: "Authentication unavailable"}[
                status
            ]
        )


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
        self.issuer = f"https://{url.netloc}"
        self.audience = audiences
        self.cache_ttl, self.cooldown = cache_ttl, cooldown
        self.on_diagnostic = on_diagnostic
        self._client = httpx.AsyncClient(
            timeout=timeout, transport=transport, follow_redirects=False
        )
        self._keys: dict[str, object] = {}
        self._expires = 0.0
        self._last_fetch = -math.inf
        self._generation = 0
        self._last_error = False
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._client.aclose()

    def _report(self, error: AccessError) -> None:
        if self.on_diagnostic:
            try:
                self.on_diagnostic({"code": error.code, "status": error.status})
            except Exception:
                pass

    async def _key(self, kid: str):
        now = time.monotonic()
        if now < self._expires and kid in self._keys:
            return self._keys[kid]
        generation = self._generation
        async with self._lock:
            now = time.monotonic()
            if now < self._expires and kid in self._keys:
                return self._keys[kid]
            # A waiter shares the completed fetch, including a failed fetch.
            if self._generation != generation or now - self._last_fetch < self.cooldown:
                if self._last_error or now >= self._expires:
                    raise AccessError("JWKS_UNAVAILABLE", 503)
                raise AccessError("INVALID_TOKEN")
            self._last_fetch = now
            self._generation += 1
            try:
                response = await self._client.get(self.issuer + "/cdn-cgi/access/certs")
                response.raise_for_status()
                document = response.json()
                keys = {}
                for raw in document["keys"]:
                    if (
                        raw.get("kty") != "RSA"
                        or raw.get("use", "sig") != "sig"
                        or raw.get("alg", "RS256") != "RS256"
                    ):
                        continue
                    key_id = raw.get("kid")
                    if not isinstance(key_id, str) or not key_id or key_id in keys:
                        raise ValueError("Invalid key ID")
                    keys[key_id] = jwt.algorithms.RSAAlgorithm.from_jwk(raw)
                if not keys:
                    raise ValueError("No signing keys")
                self._keys = keys
                self._expires = time.monotonic() + self.cache_ttl
                self._last_error = False
            except Exception:
                self._last_error = True
                raise AccessError("JWKS_UNAVAILABLE", 503) from None
            if kid not in self._keys:
                raise AccessError("INVALID_TOKEN")
            return self._keys[kid]

    async def verify_token(self, token: str) -> AccessIdentity:
        try:
            _validate_token(token)
            header = jwt.get_unverified_header(token)
            if (
                header.get("crit")
                or header.get("b64", True) is not True
                or header.get("alg") != "RS256"
                or not isinstance(header.get("kid"), str)
                or not header["kid"]
            ):
                raise AccessError("INVALID_TOKEN")
            key = await self._key(header["kid"])
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
