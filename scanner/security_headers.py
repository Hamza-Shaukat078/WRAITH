from .capture import get, build, make_request

REQUIRED_HEADERS = [
    (
        "Strict-Transport-Security",
        "HSTS not enforced",
        "MEDIUM",
        5.3,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'",
    ),
    (
        "X-Content-Type-Options",
        "MIME sniffing not disabled",
        "LOW",
        3.1,
        "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "Add: X-Content-Type-Options: nosniff to all responses.",
        "response.headers['X-Content-Type-Options'] = 'nosniff'",
    ),
    (
        "X-Frame-Options",
        "Clickjacking protection missing",
        "MEDIUM",
        4.3,
        "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "Add: X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
        "response.headers['X-Frame-Options'] = 'DENY'",
    ),
    (
        "Content-Security-Policy",
        "No Content Security Policy set",
        "MEDIUM",
        5.3,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "Define a strict CSP. Minimum: Content-Security-Policy: default-src 'self'",
        "response.headers['Content-Security-Policy'] = \"default-src 'self'\"",
    ),
    (
        "X-XSS-Protection",
        "XSS filter header absent",
        "LOW",
        3.1,
        "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "Add: X-XSS-Protection: 1; mode=block (legacy browsers). Use CSP as primary defence.",
        "response.headers['X-XSS-Protection'] = '1; mode=block'",
    ),
    (
        "Referrer-Policy",
        "Referrer-Policy not set",
        "LOW",
        3.1,
        "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "Add: Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
        "response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'",
    ),
    (
        "Permissions-Policy",
        "Permissions-Policy header missing",
        "LOW",
        2.7,
        "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "Add: Permissions-Policy: geolocation=(), microphone=(), camera=() to restrict browser features.",
        "response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'",
    ),
]


def _check_cors(url, headers):
    findings = []
    r, req, res = make_request(
        "OPTIONS", url,
        {**(headers or {}), "Origin": "https://evil.com",
         "Access-Control-Request-Method": "GET"},
    )
    if not r:
        return findings
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao == "*":
        findings.append(build(
            title="Security Headers — CORS Wildcard Origin",
            severity="MEDIUM",
            description=(
                "Access-Control-Allow-Origin: * allows any domain to read responses. "
                "If cookies or sensitive data are returned this becomes a data theft vector."
            ),
            evidence={"acao_header": acao, "url": url},
            cvss_score=5.3,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            remediation="Restrict CORS to an explicit whitelist of trusted origins. Never use * on authenticated endpoints.",
            remediation_code="response.headers['Access-Control-Allow-Origin'] = 'https://trusted-origin.com'",
            req=req, res=res,
        ))
    if acao == "https://evil.com" and acac == "true":
        findings.append(build(
            title="Security Headers — CORS Origin Reflection with Credentials",
            severity="HIGH",
            description=(
                "Server reflects the request Origin verbatim and sets Access-Control-Allow-Credentials: true. "
                "An attacker's site can make credentialed cross-origin requests and read the responses."
            ),
            evidence={"acao_header": acao, "acac_header": acac},
            cvss_score=8.1,
            cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            remediation="Validate Origin against a strict whitelist before reflecting it. Never combine wildcard/reflection with credentials.",
            remediation_code=(
                "ALLOWED = {'https://app.example.com'}\n"
                "origin = request.headers.get('Origin', '')\n"
                "if origin in ALLOWED:\n"
                "    response.headers['Access-Control-Allow-Origin'] = origin"
            ),
            req=req, res=res,
        ))
    return findings


def run(target_url: str, token: str) -> list[dict]:
    findings = []
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r, req, res = get(target_url, headers)
    if not r:
        findings.append(build(
            title="Security Headers — Target Unreachable",
            severity="INFO",
            description=f"Could not connect to {target_url} to inspect response headers.",
            evidence={"url": target_url},
            cvss_score=0.0, cvss_vector="N/A",
            remediation="Ensure the target URL is reachable.",
        ))
        return findings

    resp_headers = {k.lower(): v for k, v in r.headers.items()}

    for hdr, label, sev, cvss, vector, rem, code in REQUIRED_HEADERS:
        if hdr.lower() not in resp_headers:
            findings.append(build(
                title=f"Security Headers — {label}",
                severity=sev,
                description=(
                    f"The response does not include the '{hdr}' header. "
                    f"{rem.split('.')[0]}."
                ),
                evidence={"missing_header": hdr, "url": target_url},
                cvss_score=cvss,
                cvss_vector=vector,
                remediation=rem,
                remediation_code=code,
                req=req, res=res,
            ))

    findings.extend(_check_cors(target_url, headers))

    server = resp_headers.get("server", "")
    powered = resp_headers.get("x-powered-by", "")
    if server or powered:
        findings.append(build(
            title="Security Headers — Server Version Disclosure",
            severity="LOW",
            description=(
                f"Response reveals technology fingerprint via headers: "
                f"Server='{server}' X-Powered-By='{powered}'. "
                "Attackers use this to target version-specific exploits."
            ),
            evidence={"server": server, "x-powered-by": powered},
            cvss_score=2.7,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            remediation="Remove or genericise Server and X-Powered-By headers in your web server config.",
            remediation_code=(
                "# Nginx: server_tokens off;\n"
                "# FastAPI/Uvicorn middleware:\n"
                "@app.middleware('http')\n"
                "async def remove_headers(request, call_next):\n"
                "    response = await call_next(request)\n"
                "    response.headers.pop('server', None)\n"
                "    response.headers.pop('x-powered-by', None)\n"
                "    return response"
            ),
            req=req, res=res,
        ))

    if not findings:
        findings.append(build(
            title="Security Headers — All Key Headers Present",
            severity="INFO",
            description="All checked security headers are present and CORS is configured correctly.",
            evidence={"url": target_url, "headers_checked": len(REQUIRED_HEADERS)},
            cvss_score=0.0, cvss_vector="N/A",
            remediation="Continue auditing headers periodically as the stack evolves.",
        ))

    return findings
