import json
from .capture import make_request, build

PROBE_PATHS = [
    "/api/users", "/api/user", "/users", "/user",
    "/api/register", "/register", "/api/profile", "/profile",
    "/api/account", "/account", "/api/me", "/me",
]

PRIVILEGED_FIELDS = [
    {"role": "admin"},
    {"isAdmin": True},
    {"is_admin": True},
    {"admin": True},
    {"role": "superuser"},
    {"privilege": "admin"},
    {"permissions": ["admin", "write", "read"]},
    {"balance": 999999},
    {"credit": 999999},
    {"verified": True},
    {"email_verified": True},
    {"status": "active"},
    {"subscription": "premium"},
    {"plan": "enterprise"},
]

DUMMY_USER = {
    "username": "wraith_probe_user",
    "email": "probe@wraith-scanner.local",
    "password": "Wr41th!Probe#2024",
    "name": "WRAITH Probe",
}


def _post(url, payload, headers):
    return make_request(
        "POST", url, headers,
        json=payload,
    )


def _put(url, payload, headers):
    return make_request(
        "PUT", url, headers,
        json=payload,
    )


def _find_endpoint(base, paths, headers):
    for p in paths:
        r, req, res = _post(base + p, DUMMY_USER, headers)
        if r and r.status_code in (200, 201, 400, 422):
            return base + p, r.status_code
    return None, None


def _field_reflected(response_body: str, field: str, value) -> bool:
    try:
        body = json.loads(response_body)
        if isinstance(body, dict):
            val = body.get(field)
            return val == value or str(val).lower() == str(value).lower()
    except Exception:
        pass
    return str(value).lower() in response_body.lower()


def run(target_url: str, token: str) -> list[dict]:
    findings = []
    base = target_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"} if token else {"Content-Type": "application/json"}

    endpoint, base_status = _find_endpoint(base, PROBE_PATHS, headers)

    if not endpoint:
        endpoint = base
        base_status = None

    confirmed = []

    for field_dict in PRIVILEGED_FIELDS:
        payload = {**DUMMY_USER, **field_dict}
        field_name = list(field_dict.keys())[0]
        field_value = list(field_dict.values())[0]

        r, req, res = _post(endpoint, payload, headers)
        if r and r.status_code in (200, 201):
            if _field_reflected(res.get("body", ""), field_name, field_value):
                confirmed.append((field_name, field_value, "POST", endpoint, req, res, r.status_code))
                continue

        r, req, res = _put(endpoint, payload, headers)
        if r and r.status_code in (200, 201, 204):
            if _field_reflected(res.get("body", ""), field_name, field_value):
                confirmed.append((field_name, field_value, "PUT", endpoint, req, res, r.status_code))

    for field_name, field_value, method, url, req, res, status in confirmed:
        findings.append(build(
            title=f"Mass Assignment — Privileged Field '{field_name}' Accepted",
            severity="HIGH",
            description=(
                f"The server accepted and reflected '{field_name}={field_value}' in a {method} request to {url} "
                f"(HTTP {status}). An attacker can escalate privileges, modify billing, or activate premium features "
                "by injecting undocumented fields into the request body."
            ),
            evidence={
                "url": url,
                "method": method,
                "injected_field": field_name,
                "injected_value": str(field_value),
                "response_code": status,
            },
            cvss_score=8.8,
            cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            remediation=(
                "Use an explicit allowlist (DTO / schema) that only permits fields the user is authorised to set. "
                "Never bind raw request bodies directly to data models."
            ),
            remediation_code=(
                "# Pydantic example — only allow safe fields\n"
                "class UserUpdate(BaseModel):\n"
                "    name: str\n"
                "    email: str\n"
                "    # role, isAdmin etc. are NOT here — they cannot be set via this schema\n\n"
                "@app.put('/api/me')\n"
                "async def update_me(data: UserUpdate, current_user = Depends(get_current_user)):\n"
                "    update_user(current_user.id, data.dict())"
            ),
            req=req, res=res,
        ))

    if not confirmed:
        r, req, res = _post(endpoint, {**DUMMY_USER, "role": "admin", "isAdmin": True}, headers)
        if r and r.status_code in (200, 201):
            findings.append(build(
                title="Mass Assignment — Privileged Fields Not Reflected (Possible Silent Accept)",
                severity="LOW",
                description=(
                    f"POST to {endpoint} with privileged fields (role, isAdmin) returned {r.status_code} "
                    "but fields were not reflected in the response. The server may silently accept and store them."
                ),
                evidence={"url": endpoint, "status_code": r.status_code},
                cvss_score=3.5,
                cvss_vector="AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
                remediation="Verify via database inspection that privileged fields are not persisted even if not echoed.",
                req=req, res=res,
            ))

    if not findings:
        findings.append(build(
            title="Mass Assignment — No Privileged Field Injection Detected",
            severity="INFO",
            description="Tested 14 privileged field injection payloads. None were reflected in responses.",
            evidence={"endpoint_probed": endpoint, "fields_tested": len(PRIVILEGED_FIELDS)},
            cvss_score=0.0, cvss_vector="N/A",
            remediation="Continue enforcing strict input schemas (DTOs/allowlists) on all write endpoints.",
        ))

    return findings
