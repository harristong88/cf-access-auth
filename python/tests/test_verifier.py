import asyncio
import json
from pathlib import Path

import httpx
import pytest
from cf_access_auth import AccessError, AccessVerifier, assertion_from_headers

FIXTURE = json.loads((Path(__file__).parents[2] / "fixtures/tokens.json").read_text())


def verifier(handler=None, **kwargs):
    return AccessVerifier(
        FIXTURE["issuer"],
        FIXTURE["audience"],
        transport=httpx.MockTransport(
            handler or (lambda req: httpx.Response(200, json=FIXTURE["jwks"]))
        ),
        **kwargs,
    )


@pytest.mark.parametrize("name,scenario", list(FIXTURE["cases"].items()))
async def test_shared_fixtures(name, scenario):
    v = verifier(
        lambda req: httpx.Response(
            200, json=FIXTURE["rotatedJwks"] if name == "rotated" else FIXTURE["jwks"]
        )
    )
    try:
        if scenario["status"] == 200:
            identity = await v.verify_token(scenario["token"])
            assert identity.issuer == FIXTURE["issuer"]
            assert identity.expires_at == 4102444800
        else:
            with pytest.raises(AccessError) as exc:
                await v.verify_token(scenario["token"])
            assert exc.value.status == 401
    finally:
        await v.aclose()


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [(b"cookie", b"CF_Authorization=x")],
        [(b"cf-access-authenticated-user-email", b"alice@example.com")],
        [
            (b"cf-access-jwt-assertion", b"a.b.c"),
            (b"Cf-Access-Jwt-Assertion", b"a.b.c"),
        ],
        [(b"cf-access-jwt-assertion", b"a.b.c, a.b.c")],
        [(b"cf-access-jwt-assertion", b"x" * 16385)],
        [(b"cf-access-jwt-assertion", b"\xff")],
    ],
)
def test_headers_rejected(headers):
    with pytest.raises(AccessError):
        assertion_from_headers(headers)


async def test_rotation_and_coalescing():
    calls = []

    async def fetch(req):
        calls.append(req.url)
        await asyncio.sleep(0.01)
        return httpx.Response(
            200, json=FIXTURE["jwks"] if len(calls) == 1 else FIXTURE["rotatedJwks"]
        )

    v = verifier(fetch, cooldown=0)
    try:
        await asyncio.gather(
            *(v.verify_token(FIXTURE["cases"]["valid"]["token"]) for _ in range(10))
        )
        assert len(calls) == 1
        await asyncio.gather(
            *(v.verify_token(FIXTURE["cases"]["rotated"]["token"]) for _ in range(10))
        )
        assert len(calls) == 2
    finally:
        await v.aclose()


async def test_outage_and_expired_cache():
    available = True

    def fetch(req):
        if not available:
            raise httpx.ConnectError("offline")
        return httpx.Response(200, json=FIXTURE["jwks"])

    v = verifier(fetch, cooldown=0)
    try:
        token = FIXTURE["cases"]["valid"]["token"]
        await v.verify_token(token)
        available = False
        await v.verify_token(token)
        v._expires = 0
        with pytest.raises(AccessError) as exc:
            await v.verify_token(token)
        assert exc.value.status == 503
    finally:
        await v.aclose()


async def test_cold_outage_coalesced():
    calls = 0

    async def fetch(req):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        raise httpx.ConnectError("offline")

    v = verifier(fetch)
    results = await asyncio.gather(
        *(v.verify_token(FIXTURE["cases"]["valid"]["token"]) for _ in range(10)),
        return_exceptions=True,
    )
    assert calls == 1
    assert all(isinstance(e, AccessError) and e.status == 503 for e in results)
    await v.aclose()


async def test_bad_signature_does_not_refresh():
    calls = 0

    def fetch(req):
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=FIXTURE["jwks"])

    v = verifier(fetch)
    await v.verify_token(FIXTURE["cases"]["valid"]["token"])
    bad = FIXTURE["cases"]["valid"]["token"][:-5] + "AAAAA"
    with pytest.raises(AccessError):
        await v.verify_token(bad)
    assert calls == 1
    await v.aclose()
