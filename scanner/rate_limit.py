import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from .capture import build

TIMEOUT = 10
REQUEST_COUNT = 50

REM_NO_LIMIT = (
    "Implement rate limiting at the API gateway or application layer. "
    "Return HTTP 429 with a Retry-After header when the limit is exceeded. "
    "Use sliding window or token bucket algorithms for fairness."
)
REM_NO_LIMIT_CODE = """\
# Express.js (Node) — express-rate-limit
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,                   // max 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

# Python / FastAPI — slowapi
from slowapi import Limiter
from slowapi.util import get_remote_address
limiter = Limiter(key_func=get_remote_address)
@app.get("/api/resource")
@limiter.limit("100/minute")
async def resource(request: Request): ..."""


def _send(url: str, headers: dict) -> dict:
    try:
        t0 = time.time()
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        return {
            "status_code": r.status_code,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "rate_limit_headers": {
                k: v for k, v in r.headers.items()
                if any(k.lower().startswith(p) for p in ("x-ratelimit", "retry-after", "ratelimit"))
            },
        }
    except requests.exceptions.RequestException as e:
        return {"status_code": 0, "elapsed_ms": 0, "error": str(e), "rate_limit_headers": {}}


def run(target_url: str, token: str) -> list[dict]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    results = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(_send, target_url, headers) for _ in range(REQUEST_COUNT)]
        for f in as_completed(futures):
            results.append(f.result())

    ok = sum(1 for r in results if r["status_code"] == 200)
    blocked = sum(1 for r in results if r["status_code"] in (429, 503))
    all_rl_headers: dict = {}
    for r in results:
        all_rl_headers.update(r.get("rate_limit_headers", {}))

    # Sample request/response for display
    sample_req = {"method": "GET", "url": target_url, "headers": {
        k: ("***redacted***" if k.lower() == "authorization" else v)
        for k, v in headers.items()
    }}
    sample_res = {
        "status_code": results[0]["status_code"] if results else 0,
        "note": f"Sent {REQUEST_COUNT} rapid concurrent requests",
        "rate_limit_headers_observed": all_rl_headers,
    }

    findings = []

    if blocked == 0 and ok >= 45:
        findings.append(build(
            title="Rate Limiting — Not Enforced",
            severity="HIGH",
            description=(
                f"All {ok}/{REQUEST_COUNT} rapid concurrent requests returned HTTP 200. "
                "No rate limiting is in place. This exposes the API to brute-force, credential "
                "stuffing, and application-layer DoS attacks."
            ),
            evidence={"requests_sent": REQUEST_COUNT, "ok": ok, "blocked": blocked,
                      "rate_limit_headers_seen": all_rl_headers},
            cvss_score=7.5,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            remediation=REM_NO_LIMIT, remediation_code=REM_NO_LIMIT_CODE,
            req=sample_req, res=sample_res,
        ))
    elif blocked > 0:
        findings.append(build(
            title="Rate Limiting — Enforced",
            severity="INFO",
            description=f"{blocked}/{REQUEST_COUNT} requests were blocked (HTTP 429/503). Rate limiting is active.",
            evidence={"requests_sent": REQUEST_COUNT, "ok": ok, "blocked": blocked,
                      "rate_limit_headers_seen": all_rl_headers},
            cvss_score=0.0, cvss_vector="N/A",
            remediation="Rate limiting is active. Verify limits are appropriate for your threat model.",
            req=sample_req, res=sample_res,
        ))
    elif all_rl_headers:
        findings.append(build(
            title="Rate Limiting — Headers Present, Enforcement Unconfirmed",
            severity="MEDIUM",
            description=(
                "Rate limit headers were observed but no requests were blocked during the test. "
                "The limit threshold may be higher than the test volume or enforcement may be inconsistent."
            ),
            evidence={"requests_sent": REQUEST_COUNT, "ok": ok,
                      "rate_limit_headers_seen": all_rl_headers},
            cvss_score=3.7,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            remediation="Verify rate limit thresholds are set low enough to prevent abuse.",
            req=sample_req, res=sample_res,
        ))
    else:
        findings.append(build(
            title="Rate Limiting — No Headers or Blocking Detected",
            severity="MEDIUM",
            description=(
                f"Sent {REQUEST_COUNT} rapid requests. No rate-limit headers and no blocking observed. "
                "Rate limiting may be absent or enforced at a network layer not visible to this scanner."
            ),
            evidence={"requests_sent": REQUEST_COUNT, "ok": ok, "blocked": blocked},
            cvss_score=5.3,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            remediation=REM_NO_LIMIT, remediation_code=REM_NO_LIMIT_CODE,
            req=sample_req, res=sample_res,
        ))

    return findings
