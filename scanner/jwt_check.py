import base64
import hashlib
import hmac
import json
import time
from .capture import get, build

WEAK_SECRETS = ["secret", "password", "123456", "admin", "test", "qwerty", "letmein", "token"]

REMEDIATIONS = {
    "alg_none": (
        "Explicitly whitelist the allowed algorithms in your JWT library and never permit 'none'. "
        "Reject any token whose header specifies an algorithm outside the whitelist.",
        """\
import jwt

ALLOWED_ALGORITHMS = ["HS256"]  # never include "none"

def verify(token: str):
    # PyJWT raises InvalidAlgorithmError if alg not in algorithms list
    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=ALLOWED_ALGORITHMS,
    )
    return payload"""
    ),
    "weak_secret": (
        "Use a cryptographically random secret of at least 256 bits (32 bytes). "
        "Store it in an environment variable or secrets manager — never in source code.",
        """\
import secrets, os

# Generate a strong secret (run once, store securely)
SECRET_KEY = secrets.token_hex(32)   # 64-char hex = 256 bits

# Load from environment in production
SECRET_KEY = os.environ["JWT_SECRET_KEY"]"""
    ),
    "expired": (
        "Enable expiry validation in your JWT library. "
        "Set short-lived access tokens (15 min) and use refresh tokens for longer sessions.",
        """\
import jwt
from datetime import datetime, timedelta

# Issue tokens with short expiry
def create_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(minutes=15),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Validate — PyJWT checks exp by default
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])"""
    ),
    "no_sig": (
        "Never accept tokens with an empty or missing signature. "
        "Always verify the signature before trusting any claim in the payload.",
        """\
import jwt

def verify(token: str):
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        raise ValueError("Token must have a valid signature")
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])"""
    ),
}


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _parse_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(_b64url_decode(parts[0])), json.loads(_b64url_decode(parts[1])), parts[2]
    except Exception:
        return None


def _sign_hs256(h64: str, p64: str, secret: str) -> str:
    msg = f"{h64}.{p64}".encode()
    return _b64url_encode(hmac.new(secret.encode(), msg, hashlib.sha256).digest())


def run(target_url: str, token: str) -> list[dict]:
    findings = []

    if not token or "." not in token:
        findings.append(build(
            title="JWT Check — No Valid JWT Provided",
            severity="INFO",
            description="No JWT token was provided or the token is not in JWT format. Skipping JWT-specific checks.",
            evidence={}, cvss_score=0.0, cvss_vector="N/A",
            remediation="Provide a JWT Bearer token in the Auth Token field to enable JWT attack checks.",
        ))
        return findings

    parsed = _parse_jwt(token)
    if not parsed:
        findings.append(build(
            title="JWT Check — Token Unparseable",
            severity="INFO",
            description="Could not parse the provided token as a JWT.",
            evidence={"token_preview": token[:40]}, cvss_score=0.0, cvss_vector="N/A",
            remediation="Ensure the token follows the header.payload.signature format.",
        ))
        return findings

    header, payload, orig_sig = parsed
    parts = token.split(".")
    h64, p64 = parts[0], parts[1]

    # 1 — alg:none attack
    none_h = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    for none_tok, label in [
        (f"{none_h}.{p64}.", "empty signature"),
        (f"{none_h}.{p64}.{orig_sig}", "original signature retained"),
    ]:
        r, req, res = get(target_url, {"Authorization": f"Bearer {none_tok}"})
        if r and r.status_code == 200:
            rem, code = REMEDIATIONS["alg_none"]
            findings.append(build(
                title="JWT — Algorithm None Attack Accepted",
                severity="CRITICAL",
                description=(
                    f"Server accepted a JWT with alg:none and {label}. "
                    "Signature verification is completely bypassed — an attacker can forge "
                    "arbitrary claims without knowing the secret key."
                ),
                evidence={"crafted_token": none_tok[:80] + "…", "response_code": r.status_code},
                cvss_score=9.8,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                remediation=rem, remediation_code=code,
                req=req, res=res,
            ))
            break

    # 2 — Weak secret brute-force
    for secret in WEAK_SECRETS:
        try:
            sig = _sign_hs256(h64, p64, secret)
            crafted = f"{h64}.{p64}.{sig}"
            r, req, res = get(target_url, {"Authorization": f"Bearer {crafted}"})
            if r and r.status_code == 200:
                rem, code = REMEDIATIONS["weak_secret"]
                findings.append(build(
                    title="JWT — Weak Secret Accepted",
                    severity="CRITICAL",
                    description=(
                        f"The server accepted a JWT signed with the common weak secret '{secret}'. "
                        "An attacker can enumerate weak secrets offline and forge tokens for any user."
                    ),
                    evidence={"secret_cracked": secret},
                    cvss_score=9.8,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    remediation=rem, remediation_code=code,
                    req=req, res=res,
                ))
                break
        except Exception:
            continue

    # 3 — Expired token
    exp_payload = {**payload, "exp": int(time.time()) - 86400}
    exp_p64 = _b64url_encode(json.dumps(exp_payload).encode())
    exp_tok = f"{h64}.{exp_p64}.{orig_sig}"
    r, req, res = get(target_url, {"Authorization": f"Bearer {exp_tok}"})
    if r and r.status_code == 200:
        rem, code = REMEDIATIONS["expired"]
        findings.append(build(
            title="JWT — Expired Token Accepted",
            severity="HIGH",
            description=(
                "The server accepted a JWT whose exp claim was set to 24 hours in the past. "
                "Stolen tokens remain valid indefinitely, enabling session hijacking attacks."
            ),
            evidence={"exp_used": exp_payload["exp"], "hours_past": 24},
            cvss_score=7.5,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            remediation=rem, remediation_code=code,
            req=req, res=res,
        ))

    # 4 — No signature
    no_sig = f"{h64}.{p64}."
    r, req, res = get(target_url, {"Authorization": f"Bearer {no_sig}"})
    if r and r.status_code == 200:
        rem, code = REMEDIATIONS["no_sig"]
        findings.append(build(
            title="JWT — Token Without Signature Accepted",
            severity="CRITICAL",
            description=(
                "The server accepted a JWT with an empty signature field. "
                "An attacker can craft tokens with any claims without needing the secret key."
            ),
            evidence={"crafted_token": no_sig[:80] + "…"},
            cvss_score=9.8,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            remediation=rem, remediation_code=code,
            req=req, res=res,
        ))

    if not findings:
        findings.append(build(
            title="JWT — No Obvious Vulnerabilities Detected",
            severity="INFO",
            description="alg:none, weak secret, expired token, and no-signature attacks were all rejected.",
            evidence={"algorithm": header.get("alg"), "claims": list(payload.keys())},
            cvss_score=0.0, cvss_vector="N/A",
            remediation="JWT implementation appears sound. Consider also testing for kid injection and jwks confusion.",
        ))

    return findings
