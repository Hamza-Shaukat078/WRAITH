import re
import json
from .capture import get, build

PROBE_PATHS = [
    "", "/api/users", "/api/user", "/users", "/user",
    "/api/me", "/me", "/profile", "/api/profile",
    "/api/orders", "/orders", "/api/payments", "/payments",
    "/api/accounts", "/accounts", "/api/config", "/config",
    "/api/keys", "/api/tokens", "/api/logs",
]

PATTERNS = [
    (
        "Email Address",
        re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
        "MEDIUM", 4.3,
        "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "Strip PII from API responses. Return only fields the client actually needs.",
    ),
    (
        "Phone Number",
        re.compile(r'(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)(\d{3}[\s.\-]?\d{4})'),
        "MEDIUM", 4.3,
        "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "Remove phone numbers from API responses unless explicitly required by the client view.",
    ),
    (
        "Credit Card Number",
        re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
        "CRITICAL", 9.1,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "Never return full card numbers. Store only last 4 digits and always use tokenisation (Stripe, Braintree).",
    ),
    (
        "AWS Access Key",
        re.compile(r'(?:AKIA|AIPA|ABIA|ACCA)[A-Z0-9]{16}'),
        "CRITICAL", 9.8,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Rotate the key immediately. Use IAM roles instead of static keys. Never embed credentials in responses.",
    ),
    (
        "AWS Secret Key",
        re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']?[A-Za-z0-9/+=]{40}'),
        "CRITICAL", 9.8,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Rotate immediately. Use AWS Secrets Manager or environment variables. Audit all response payloads.",
    ),
    (
        "Generic API Key / Secret",
        re.compile(r'(?i)(?:api[_\-]?key|apikey|secret[_\-]?key|auth[_\-]?token|access[_\-]?token)["\s:=]+["\']?([A-Za-z0-9\-_]{20,})'),
        "HIGH", 7.5,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "Never return secret keys or tokens in API responses. Move secrets to server-side environment variables.",
    ),
    (
        "Private Key / Certificate",
        re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
        "CRITICAL", 9.8,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Revoke and regenerate the key immediately. Private keys must never appear in API responses.",
    ),
    (
        "Password in Response",
        re.compile(r'(?i)["\']?password["\']?\s*[=:]\s*["\']?(?!null|undefined|\*+|\\u|\$)[^\s,"\'}{]{4,}'),
        "HIGH", 8.1,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "Never return password fields in any response, even hashed. Exclude password from all serialisers.",
    ),
    (
        "Social Security Number",
        re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'),
        "CRITICAL", 9.1,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "SSNs are highly regulated PII. Apply field-level encryption and restrict access via RBAC.",
    ),
    (
        "JWT Token in Response Body",
        re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
        "MEDIUM", 5.3,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "Tokens returned in response bodies may be logged. Use secure cookies (HttpOnly, Secure, SameSite) instead.",
    ),
    (
        "IPv4 Internal Address",
        re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'),
        "LOW", 3.1,
        "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "Internal IPs in responses reveal network topology. Strip infrastructure details from all API error messages and responses.",
    ),
]


def _scan_body(body: str) -> list[tuple]:
    hits = []
    for label, pattern, sev, cvss, vector, rem in PATTERNS:
        matches = pattern.findall(body)
        if matches:
            sample = str(matches[0])[:80]
            hits.append((label, sev, cvss, vector, rem, sample, len(matches)))
    return hits


def run(target_url: str, token: str) -> list[dict]:
    findings = []
    base = target_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    seen_labels = set()

    for path in PROBE_PATHS:
        url = base + path
        r, req, res = get(url, headers)
        if not r or r.status_code not in (200, 201):
            continue

        body = res.get("body", "")
        if not body:
            continue

        hits = _scan_body(body)
        for label, sev, cvss, vector, rem, sample, count in hits:
            key = (label, url)
            if key in seen_labels:
                continue
            seen_labels.add(key)

            findings.append(build(
                title=f"Sensitive Data Exposure — {label} Leaked in Response",
                severity=sev,
                description=(
                    f"The response from {url} contains what appears to be a {label}. "
                    f"{count} match(es) found. Sample: '{sample}{'…' if len(sample)==80 else ''}'. "
                    "Leaking this data violates GDPR, PCI-DSS, and OWASP API3:2023."
                ),
                evidence={
                    "url": url,
                    "data_type": label,
                    "match_count": count,
                    "sample": sample,
                    "http_status": r.status_code,
                },
                cvss_score=cvss,
                cvss_vector=vector,
                remediation=rem,
                req=req, res=res,
            ))

    if not findings:
        findings.append(build(
            title="Sensitive Data Exposure — No Obvious Leaks Detected",
            severity="INFO",
            description=(
                f"Scanned {len(PROBE_PATHS)} endpoints for {len(PATTERNS)} sensitive data patterns. "
                "No obvious PII, credentials, or secrets found in responses."
            ),
            evidence={"paths_scanned": len(PROBE_PATHS), "patterns_checked": len(PATTERNS)},
            cvss_score=0.0, cvss_vector="N/A",
            remediation="Continue auditing with authenticated tokens and deeper endpoint coverage.",
        ))

    return findings
