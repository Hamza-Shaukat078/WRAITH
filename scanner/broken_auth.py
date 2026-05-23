import base64
import json
from .capture import get, build

PROBE_PATHS = ["", "/api/me", "/profile", "/account", "/api/user"]


def _first_responding(base, paths, headers):
    for p in paths:
        r, req, res = get(base + p, headers)
        if r and r.status_code not in (0, 404, 405):
            return base + p, r, req, res
    url = base + paths[0]
    r, req, res = get(url, headers)
    return url, r, req, res


REMEDIATIONS = {
    "missing_auth": (
        "Every protected endpoint must validate the Authorization header before processing the request. "
        "Return HTTP 401 immediately if the header is absent.",
        """\
# FastAPI dependency example
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer

security = HTTPBearer()

@app.get("/api/me")
async def get_me(credentials = Security(security)):
    # credentials.credentials contains the token
    user = verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user"""
    ),
    "empty_token": (
        "Reject tokens that are empty strings or whitespace-only. "
        "Validate token length and format before any signature check.",
        """\
def verify_token(token: str):
    if not token or not token.strip():
        raise HTTPException(status_code=401, detail="Token must not be empty")
    # proceed with JWT validation..."""
    ),
    "malformed_token": (
        "Use a strict JWT library that rejects tokens not conforming to the "
        "header.payload.signature format before attempting any decoding.",
        """\
import jwt
try:
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
except jwt.exceptions.DecodeError:
    raise HTTPException(status_code=401, detail="Malformed token")
except jwt.exceptions.InvalidTokenError:
    raise HTTPException(status_code=401, detail="Invalid token")"""
    ),
    "expired_token": (
        "Enable expiry validation in your JWT library (it is usually off by default "
        "or can be bypassed with options). Never disable exp claim verification.",
        """\
import jwt
# options={} means ALL validations ON (default)
payload = jwt.decode(
    token,
    SECRET_KEY,
    algorithms=["HS256"],
    options={"verify_exp": True},   # explicitly enforce
)"""
    ),
    "cross_user": (
        "After authenticating the token, check that the resource being accessed belongs "
        "to the authenticated user or that the user has an explicit permission grant.",
        """\
@app.get("/users/{user_id}")
async def get_user(user_id: int, current_user = Depends(get_current_user)):
    if user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return fetch_user(user_id)"""
    ),
}


def run(target_url: str, token: str) -> list[dict]:
    findings = []
    base = target_url.rstrip("/")
    auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

    probe_url, _, _, _ = _first_responding(base, PROBE_PATHS, auth_headers)

    # 1 — Missing auth header
    r, req, res = get(probe_url, {})
    if r and r.status_code == 200:
        rem, code = REMEDIATIONS["missing_auth"]
        findings.append(build(
            title="Broken Auth — Missing Authorization Header Accepted",
            severity="CRITICAL",
            description=(
                "The endpoint returned HTTP 200 with no Authorization header present. "
                "Authentication is not enforced — any anonymous caller can access protected data."
            ),
            evidence={"url": probe_url, "status_code": r.status_code},
            cvss_score=9.8,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            remediation=rem, remediation_code=code,
            req=req, res=res,
        ))

    # 2 — Empty token
    r, req, res = get(probe_url, {"Authorization": "Bearer "})
    if r and r.status_code == 200:
        rem, code = REMEDIATIONS["empty_token"]
        findings.append(build(
            title="Broken Auth — Empty Bearer Token Accepted",
            severity="CRITICAL",
            description="The server accepted an empty Bearer token string and returned HTTP 200.",
            evidence={"url": probe_url, "status_code": r.status_code},
            cvss_score=9.8,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            remediation=rem, remediation_code=code,
            req=req, res=res,
        ))

    # 3 — Malformed token
    r, req, res = get(probe_url, {"Authorization": "Bearer not.a.jwt"})
    if r and r.status_code == 200:
        rem, code = REMEDIATIONS["malformed_token"]
        findings.append(build(
            title="Broken Auth — Malformed Token Accepted",
            severity="HIGH",
            description="The server accepted a clearly malformed (non-JWT) Bearer token without rejection.",
            evidence={"url": probe_url, "token_sent": "not.a.jwt"},
            cvss_score=7.5,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            remediation=rem, remediation_code=code,
            req=req, res=res,
        ))

    # 4 — Expired token
    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    pay = base64.urlsafe_b64encode(
        json.dumps({"sub": "1", "exp": 1000000}).encode()
    ).rstrip(b"=").decode()
    fake_exp = f"{hdr}.{pay}.fakesig"
    r, req, res = get(probe_url, {"Authorization": f"Bearer {fake_exp}"})
    if r and r.status_code == 200:
        rem, code = REMEDIATIONS["expired_token"]
        findings.append(build(
            title="Broken Auth — Expired Token Accepted",
            severity="HIGH",
            description=(
                "The server accepted a JWT with exp=1000000 (January 1970). "
                "Expiry validation is disabled or not enforced."
            ),
            evidence={"url": probe_url, "exp_used": 1000000},
            cvss_score=7.5,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            remediation=rem, remediation_code=code,
            req=req, res=res,
        ))

    # 5 — Cross-user resource access
    if token:
        cross_url = base + "/users/2"
        r, req, res = get(cross_url, auth_headers)
        if r and r.status_code == 200:
            rem, code = REMEDIATIONS["cross_user"]
            findings.append(build(
                title="Broken Auth — Cross-User Resource Access",
                severity="HIGH",
                description=(
                    "The provided token accessed /users/2. If this token belongs to user 1, "
                    "another user's data is exposed — no ownership check was performed."
                ),
                evidence={"url": cross_url, "status_code": r.status_code},
                cvss_score=8.1,
                cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                remediation=rem, remediation_code=code,
                req=req, res=res,
            ))

    if not findings:
        findings.append(build(
            title="Broken Auth — No Obvious Vulnerabilities Detected",
            severity="INFO",
            description="All authentication checks passed for tested patterns.",
            evidence={"url_probed": probe_url},
            cvss_score=0.0, cvss_vector="N/A",
            remediation="Maintain strict token validation: reject missing, empty, malformed, and expired tokens.",
        ))

    return findings
