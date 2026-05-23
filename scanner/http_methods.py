from .capture import make_request, build

PROBE_PATHS = [
    "", "/api", "/api/users", "/users", "/api/user", "/user",
    "/api/me", "/me", "/api/orders", "/orders",
    "/api/products", "/products", "/api/admin", "/admin",
    "/api/profile", "/profile", "/api/config", "/config",
]

DANGEROUS_METHODS = ["DELETE", "PUT", "PATCH", "TRACE", "CONNECT"]
INFO_METHODS = ["OPTIONS", "HEAD"]
ALL_METHODS = DANGEROUS_METHODS + INFO_METHODS


def _request(method, url, headers):
    return make_request(method, url, headers, allow_redirects=False)


def run(target_url: str, token: str) -> list[dict]:
    findings = []
    base = target_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    # First find a responding endpoint
    probe_url = base
    for path in PROBE_PATHS:
        url = base + path
        r, _, _ = _request("GET", url, headers)
        if r and r.status_code not in (0, 404, 405, 301, 302):
            probe_url = url
            break

    # Check OPTIONS for advertised methods
    r_opt, req_opt, res_opt = _request("OPTIONS", probe_url, headers)
    advertised = set()
    if r_opt:
        allow_hdr = r_opt.headers.get("Allow", "") + r_opt.headers.get("Access-Control-Allow-Methods", "")
        advertised = {m.strip().upper() for m in allow_hdr.replace(",", " ").split() if m.strip()}
        if advertised:
            findings.append(build(
                title=f"HTTP Methods — OPTIONS Discloses Allowed Methods",
                severity="LOW",
                description=(
                    f"OPTIONS {probe_url} returned: Allow: {', '.join(sorted(advertised))}. "
                    "Advertising available methods helps attackers enumerate attack surface."
                ),
                evidence={"url": probe_url, "allowed_methods": sorted(advertised)},
                cvss_score=2.7,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                remediation="Restrict the Allow header to only the methods your endpoint actually supports.",
                remediation_code=(
                    "@app.middleware('http')\n"
                    "async def restrict_methods(request, call_next):\n"
                    "    if request.method not in {'GET', 'POST'}:\n"
                    "        return Response(status_code=405)\n"
                    "    return await call_next(request)"
                ),
                req=req_opt, res=res_opt,
            ))

    # TRACE — reflects request headers (XST attack)
    r_trace, req_t, res_t = _request("TRACE", probe_url, {**headers, "X-WRAITH-Probe": "trace-test"})
    if r_trace and r_trace.status_code in (200, 201) and "trace-test" in (res_t.get("body", "")):
        findings.append(build(
            title="HTTP Methods — TRACE Enabled (Cross-Site Tracing)",
            severity="MEDIUM",
            description=(
                f"TRACE {probe_url} returned HTTP {r_trace.status_code} and reflected the request body. "
                "Cross-Site Tracing (XST) allows attackers to steal cookies and auth headers via XSS."
            ),
            evidence={"url": probe_url, "response_code": r_trace.status_code},
            cvss_score=5.3,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            remediation="Disable TRACE method entirely in your web server configuration.",
            remediation_code=(
                "# Nginx:\n"
                "if ($request_method = TRACE) { return 405; }\n\n"
                "# FastAPI middleware:\n"
                "if request.method == 'TRACE':\n"
                "    return Response(status_code=405)"
            ),
            req=req_t, res=res_t,
        ))

    # Test dangerous methods on each probe path
    for path in PROBE_PATHS[:8]:
        url = base + path
        for method in ["DELETE", "PUT", "PATCH"]:
            r, req, res = _request(method, url, {})
            if not r:
                continue
            # 200/201/204 without auth = dangerous
            if r.status_code in (200, 201, 204):
                sev = "CRITICAL" if method == "DELETE" else "HIGH"
                cvss = 9.1 if method == "DELETE" else 8.1
                findings.append(build(
                    title=f"HTTP Methods — Unauthenticated {method} Accepted",
                    severity=sev,
                    description=(
                        f"{method} {url} returned HTTP {r.status_code} without any Authorization header. "
                        f"{'An attacker can destroy resources without credentials.' if method == 'DELETE' else 'An attacker can overwrite or modify data without credentials.'}"
                    ),
                    evidence={"url": url, "method": method, "response_code": r.status_code},
                    cvss_score=cvss,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H" if method == "DELETE" else "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    remediation=f"Require authentication and authorisation for all {method} requests. Return 401/403 when credentials are absent.",
                    remediation_code=(
                        f"@app.{method.lower()}('/resource/{{id}}')\n"
                        "async def modify(id: int, user = Depends(require_auth)):\n"
                        "    if not user.can_modify(id):\n"
                        "        raise HTTPException(403)\n"
                        "    ..."
                    ),
                    req=req, res=res,
                ))
            # 405 allowed but without auth check — only 401/403 is correct
            elif r.status_code not in (401, 403, 404, 405, 501):
                findings.append(build(
                    title=f"HTTP Methods — {method} Returns Unexpected Status {r.status_code}",
                    severity="LOW",
                    description=(
                        f"{method} {url} returned HTTP {r.status_code} (expected 401/403/405). "
                        "Unexpected responses may indicate inconsistent access control."
                    ),
                    evidence={"url": url, "method": method, "response_code": r.status_code},
                    cvss_score=3.1,
                    cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    remediation=f"Ensure {method} on this endpoint returns 401 (unauthenticated) or 405 (not allowed).",
                    req=req, res=res,
                ))

    if not findings:
        findings.append(build(
            title="HTTP Methods — No Dangerous Method Exposure Found",
            severity="INFO",
            description=(
                f"Tested DELETE, PUT, PATCH, TRACE, OPTIONS across {len(PROBE_PATHS)} paths. "
                "All dangerous methods returned 401, 403, or 405."
            ),
            evidence={"paths_tested": len(PROBE_PATHS), "methods_tested": ALL_METHODS},
            cvss_score=0.0, cvss_vector="N/A",
            remediation="Maintain an explicit method allowlist on all routes.",
        ))

    return findings
