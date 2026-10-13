import asyncio
import json
import time
from dataclasses import asdict
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
            expected = dict(scenario["identity"])
            expected["expires_at"] = expected.pop("expiresAt")
            assert asdict(identity) == expected
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


async def test_outage_and_expired_cache(monkeypatch):
    available = True
    clock = [time.monotonic()]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])

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
        clock[0] += 601
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


@pytest.mark.parametrize("domain", ["http://fixture.cloudflareaccess.com", "https://evil.test", "https://fixture.cloudflareaccess.com/path", "https://fixture.cloudflareaccess.com?x=y", "https://FIXTURE.cloudflareaccess.com"])
def test_invalid_domains(domain):
    with pytest.raises(ValueError):
        AccessVerifier(domain, FIXTURE["audience"])


@pytest.mark.parametrize("audience", ["", " ", " aud", [], ["aud", " "], [42]])
def test_invalid_audiences(audience):
    with pytest.raises(ValueError):
        AccessVerifier(FIXTURE["issuer"], audience)


@pytest.mark.parametrize("settings", [{"cache_ttl":-1}, {"cooldown":-1}, {"timeout":0}, {"timeout":-1}, {"cache_ttl":float("nan")}, {"timeout":float("inf")}])
def test_invalid_timings(settings):
    with pytest.raises(ValueError):
        verifier(**settings)


async def test_valid_configuration_and_audience_transition():
    v = AccessVerifier(FIXTURE["issuer"] + "/", ["old", FIXTURE["audience"]], cache_ttl=0, cooldown=0,
        transport=httpx.MockTransport(lambda req:httpx.Response(200,json=FIXTURE["jwks"])))
    try:
        assert (await v.verify_token(FIXTURE["cases"]["valid"]["token"])).subject == "user-1"
    finally:
        await v.aclose()


async def test_sequential_failure_backoff_and_recovery(monkeypatch):
    clock = [time.monotonic()]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    calls = 0
    available = False
    def fetch(req):
        nonlocal calls
        calls += 1
        if not available:
            raise httpx.ConnectError("offline")
        return httpx.Response(200,json=FIXTURE["jwks"])
    v = verifier(fetch)
    try:
        for _ in range(5):
            with pytest.raises(AccessError) as exc:
                await v.verify_token(FIXTURE["cases"]["valid"]["token"])
            assert exc.value.status == 503
        assert calls == 1
        available = True
        clock[0] += 31
        await v.verify_token(FIXTURE["cases"]["valid"]["token"])
        assert calls == 2
    finally:
        await v.aclose()


async def test_fresh_keys_during_stalled_refresh():
    started, release = asyncio.Event(), asyncio.Event()
    calls = 0
    async def fetch(req):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(200,json=FIXTURE["jwks"])
        started.set()
        await release.wait()
        raise httpx.ConnectError("offline")
    v = verifier(fetch, cooldown=0)
    await v.verify_token(FIXTURE["cases"]["valid"]["token"])
    refresh = asyncio.create_task(v.verify_token(FIXTURE["cases"]["rotated"]["token"]))
    try:
        await asyncio.wait_for(started.wait(), 1)
        identity = await asyncio.wait_for(v.verify_token(FIXTURE["cases"]["valid"]["token"]), 1)
        assert identity.subject == "user-1"
    finally:
        release.set()
        results = await asyncio.gather(refresh, return_exceptions=True)
        await v.aclose()
    assert isinstance(results[0], AccessError) and results[0].status == 503
    assert calls == 2


async def test_diagnostics_are_safe_and_do_not_affect_rejection():
    events = []
    def diagnostic(event):
        events.append(event)
        raise RuntimeError("logger failed")
    def fetch(req):
        raise httpx.ConnectError("offline")
    v = verifier(fetch, on_diagnostic=diagnostic)
    try:
        with pytest.raises(AccessError) as exc:
            await v.verify_token(FIXTURE["cases"]["valid"]["token"])
        assert exc.value.status == 503
        assert events == [{"code":"JWKS_UNAVAILABLE", "status":503}]
    finally:
        await v.aclose()


async def test_python_ignores_unsupported_keys():
    jwks = {"keys":[*FIXTURE["jwks"]["keys"], {"kty":"EC", "kid":"unused"}]}
    v = verifier(lambda req:httpx.Response(200,json=jwks))
    try:
        assert (await v.verify_token(FIXTURE["cases"]["valid"]["token"])).subject == "user-1"
    finally:
        await v.aclose()


async def test_public_settings_and_shutdown_remain_compatible():
    calls = []
    class Transport(httpx.MockTransport):
        closes = 0
        async def aclose(self):
            self.closes += 1
            await super().aclose()
    transport = Transport(lambda req:(calls.append(str(req.url)) or httpx.Response(200,json=FIXTURE["jwks"])))
    v = AccessVerifier(FIXTURE["issuer"],FIXTURE["audience"],cache_ttl=0,cooldown=0,transport=transport)
    try:
        await v.verify_token(FIXTURE["cases"]["valid"]["token"])
        v.cache_ttl = 600
        await v.verify_token(FIXTURE["cases"]["valid"]["token"])
        assert len(calls) == 2
        v.cooldown = 30
        with pytest.raises(AccessError) as exc:
            await v.verify_token(FIXTURE["cases"]["rotated"]["token"])
        assert exc.value.status == 401
        assert len(calls) == 2
        v.cooldown = 0
        v.issuer = "https://other.cloudflareaccess.com"
        with pytest.raises(AccessError) as exc:
            await v.verify_token(FIXTURE["cases"]["rotated"]["token"])
        assert exc.value.status == 401
        assert calls[-1] == v.issuer + "/cdn-cgi/access/certs"
        assert AccessError.__module__ == "cf_access_auth"
    finally:
        await v.aclose()
        await v.aclose()
    assert transport.closes == 1


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
