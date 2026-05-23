from .capture import get, build

ENDPOINTS = [
    "/users/{id}", "/api/users/{id}", "/account/{id}",
    "/profile/{id}", "/orders/{id}", "/items/{id}",
]

REM_IDOR = (
    "Implement object-level authorization on every endpoint that accesses a resource by ID. "
    "Validate that the authenticated user owns or has permission to access the requested object "
    "before returning data."
)
REM_IDOR_CODE = """\
# Python / FastAPI example
@app.get("/users/{user_id}")
async def get_user(user_id: int, current_user: User = Depends(get_current_user)):
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
    return db.get_user(user_id)"""

REM_SEQ = (
    "Replace sequential integer IDs with UUIDs or opaque tokens so resources cannot be "
    "enumerated by simply incrementing a number."
)
REM_SEQ_CODE = """\
import uuid
# Generate non-guessable IDs
resource_id = str(uuid.uuid4())  # e.g. "550e8400-e29b-41d4-a716-446655440000"
# Store and reference by UUID, not integer sequence"""


def run(target_url: str, token: str) -> list[dict]:
    findings = []
    base = target_url.rstrip("/")
    auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

    for tpl in ENDPOINTS:
        results_auth, results_noauth = [], []

        for id_val in range(1, 6):
            url = base + tpl.replace("{id}", str(id_val))
            r_a, req_a, res_a = get(url, auth_headers)
            r_n, req_n, res_n = get(url, {})
            if r_a:
                results_auth.append((id_val, r_a.status_code, len(r_a.text), req_a, res_a))
            if r_n:
                results_noauth.append((id_val, r_n.status_code, len(r_n.text), req_n, res_n))

        if not results_auth:
            continue

        vuln_ids = []
        sample_req, sample_res = {}, {}
        for (id_a, sta, la, rqa, rsa), (id_n, stn, ln, rqn, rsn) in zip(results_auth, results_noauth):
            if stn == 200 and sta == 200 and ln > 0:
                vuln_ids.append(id_a)
                if not sample_req:
                    sample_req, sample_res = rqn, rsn

        if vuln_ids:
            findings.append(build(
                title=f"IDOR — Unauthenticated Access on {tpl}",
                severity="CRITICAL",
                description=(
                    f"Resource IDs {vuln_ids} on {tpl} returned HTTP 200 without authentication, "
                    "the same as with a valid token. This is a Broken Object Level Authorization "
                    "(BOLA/IDOR) vulnerability — any unauthenticated caller can read arbitrary resources."
                ),
                evidence={"endpoint": tpl, "vulnerable_ids": vuln_ids},
                cvss_score=9.1,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                remediation=REM_IDOR,
                remediation_code=REM_IDOR_CODE,
                req=sample_req, res=sample_res,
            ))

        successful_auth = [r for r in results_auth if r[1] == 200]
        if len(successful_auth) >= 3:
            _, _, _, rq, rs = successful_auth[0]
            findings.append(build(
                title=f"IDOR — Sequential ID Enumeration on {tpl}",
                severity="MEDIUM",
                description=(
                    f"Sequential integer IDs on {tpl} return valid responses, making resource "
                    "enumeration trivial. An attacker can iterate IDs to harvest data at scale."
                ),
                evidence={"endpoint": tpl, "successful_ids": [r[0] for r in successful_auth]},
                cvss_score=5.3,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                remediation=REM_SEQ,
                remediation_code=REM_SEQ_CODE,
                req=rq, res=rs,
            ))

    if not findings:
        findings.append(build(
            title="IDOR — No Obvious Vulnerabilities Detected",
            severity="INFO",
            description="Common IDOR patterns were not detected on tested endpoints.",
            evidence={"endpoints_tested": ENDPOINTS},
            cvss_score=0.0, cvss_vector="N/A",
            remediation="Continue using object-level authorization checks on all resource endpoints.",
        ))

    return findings
