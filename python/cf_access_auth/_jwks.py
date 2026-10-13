"""Private signing-key parsing, HTTP lifecycle, and refresh coordination."""
import asyncio
import math
import time
from typing import Any

import httpx
import jwt

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from ._errors import AccessError

SigningKey = RSAPublicKey | RSAPrivateKey


def _parse_signing_keys(document: dict[str, Any]) -> dict[str, SigningKey]:
    keys: dict[str, SigningKey] = {}
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
    return keys


class _JwksCache:
    """Own the HTTP client, cached keys, and refresh coordination for one issuer."""

    def __init__(self, issuer: str, cache_ttl: float, timeout: float, cooldown: float,
                 transport: httpx.AsyncBaseTransport | None):
        self.issuer = issuer
        self.cache_ttl, self.cooldown = cache_ttl, cooldown
        self._client = httpx.AsyncClient(
            timeout=timeout, transport=transport, follow_redirects=False
        )
        self._keys: dict[str, SigningKey] = {}
        self._expires = 0.0
        self._last_fetch = -math.inf
        self._generation = 0
        self._last_error = False
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def key(self, kid: str) -> SigningKey:
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
                self._keys = _parse_signing_keys(document)
                self._expires = time.monotonic() + self.cache_ttl
                self._last_error = False
            except Exception:
                self._last_error = True
                raise AccessError("JWKS_UNAVAILABLE", 503) from None
            if kid not in self._keys:
                raise AccessError("INVALID_TOKEN")
            return self._keys[kid]
