import time
import requests

TIMEOUT = 10


def make_request(method: str, url: str, headers: dict | None = None, **kwargs):
    headers = headers or {}
    req_captured = {
        "method": method.upper(),
        "url": url,
        "headers": {k: ("***redacted***" if k.lower() == "authorization" else v)
                    for k, v in headers.items()},
    }
    try:
        t0 = time.time()
        r = requests.request(method, url, headers=headers, timeout=TIMEOUT, **kwargs)
        elapsed = int((time.time() - t0) * 1000)
        res_captured = {
            "status_code": r.status_code,
            "reason": r.reason,
            "headers": dict(r.headers),
            "body": r.text[:800] if r.text else "",
            "elapsed_ms": elapsed,
        }
        return r, req_captured, res_captured
    except requests.exceptions.RequestException as e:
        return None, req_captured, {"error": str(e), "status_code": 0, "reason": "Connection Error"}


def get(url: str, headers: dict | None = None, **kwargs):
    return make_request("GET", url, headers, **kwargs)


def build(title, severity, description, evidence,
          cvss_score, cvss_vector, remediation, remediation_code="",
          req=None, res=None):
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "remediation": remediation,
        "remediation_code": remediation_code,
        "request": req or {},
        "response": res or {},
    }
