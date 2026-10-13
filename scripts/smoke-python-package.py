"""Exercise an installed wheel in a new environment outside the checkout."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = """
import asyncio, json
from dataclasses import asdict
from pathlib import Path
import httpx
import cf_access_auth
from cf_access_auth import AccessError, AccessIdentity, AccessVerifier, normalize_email
assert Path(cf_access_auth.__file__).is_relative_to(Path.cwd())
f = json.loads(Path(FIXTURES).read_text())
async def check():
    v = AccessVerifier(f['issuer'], f['audience'], transport=httpx.MockTransport(lambda req:httpx.Response(200,json=f['jwks'])))
    try:
        expected = dict(f['cases']['valid']['identity'])
        expected['expires_at'] = expected.pop('expiresAt')
        identity = await v.verify_token(f['cases']['valid']['token'])
        assert isinstance(identity, AccessIdentity) and asdict(identity) == expected
        try:
            await v.authenticate_request([])
        except AccessError as error:
            assert error.status == 401
        else:
            raise AssertionError('Missing assertion accepted')
        assert normalize_email(' Alice@Example.com ') == 'alice@example.com'
    finally:
        await v.aclose()
asyncio.run(check())
"""
with tempfile.TemporaryDirectory(prefix="cf-access-wheel-consumer-") as temporary:
    directory = Path(temporary)
    subprocess.run([sys.executable, "-m", "build", str(ROOT / "python"), "--wheel", "--outdir", str(directory / "wheels")], check=True)
    venv.create(directory / "env", with_pip=True)
    executable = directory / "env" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    wheel, = (directory / "wheels").glob("*.whl")
    subprocess.run([str(executable), "-m", "pip", "install", str(wheel)], check=True, cwd=directory)
    subprocess.run([str(executable), "-I", "-c", "FIXTURES = " + repr(str(ROOT / "fixtures/tokens.json")) + "\n" + PROGRAM], check=True, cwd=directory)
print("Packaged Python wheel consumer passed")
