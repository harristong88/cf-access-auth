"""Private parsing of the key documents accepted by the Python verifier."""
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

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
