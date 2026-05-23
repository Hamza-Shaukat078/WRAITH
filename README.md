```
 █████╗ ██████╗ ██╗███████╗███████╗ ██████╗
██╔══██╗██╔══██╗██║██╔════╝██╔════╝██╔════╝
███████║██████╔╝██║███████╗█████╗  ██║
██╔══██║██╔═══╝ ██║╚════██║██╔══╝  ██║
██║  ██║██║     ██║███████║███████╗╚██████╗
╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝
 ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

> **For authorized security testing only.**

APISec Scanner is a FastAPI-powered web tool that automates common API vulnerability checks with a live-streaming terminal UI.

---

## Vulnerability Checks

| Module | What It Tests | OWASP Reference |
|--------|--------------|-----------------|
| **IDOR** | Sequential ID enumeration, unauthenticated resource access | [API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) |
| **Broken Auth** | Missing/empty/malformed tokens, expired tokens, cross-user access | [API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/) |
| **Rate Limiting** | 50-request burst, checks for 429 responses and rate-limit headers | [API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) |
| **JWT Attacks** | alg:none, weak secret brute-force, expired token, no-signature token | [API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/) |

---

## Installation

```bash
git clone <repo>
cd api-tester
pip install -r requirements.txt
python main.py
```

Then open [http://localhost:8000](http://localhost:8000).

### Docker

```bash
docker build -t apisec-scanner .
docker run -p 8000:8000 apisec-scanner
```

---

## Usage

1. Enter the **Target URL** (e.g. `https://api.example.com`)
2. Paste an optional **Auth Token** (JWT or Bearer)
3. Select which checks to run
4. Click **Run Scan** — results stream live in the terminal
5. Export as **JSON** or **PDF** when done

---

## Screenshot

```
┌─────────────────────────────────────────────┐
│         APISec Scanner  [cyan glow]         │
├─────────────────────────────────────────────┤
│  Target URL: [ https://api.example.com    ] │
│  Auth Token: [ eyJhbGci...               ] │
│  ☑ IDOR  ☑ Broken Auth  ☑ Rate Limit  ☑ JWT│
│  [ ▶ Run Scan ]                             │
├─────────────────────────────────────────────┤
│ ⟳ [idor] running                           │
│   [CRITICAL] IDOR — Unauthenticated Access │
│   [HIGH]     Sequential ID Enumeration     │
│ ✓ [idor] done                              │
│ ⟳ [jwt_check] running                     │
│   [CRITICAL] JWT — Algorithm None Attack   │
│ ✓ [jwt_check] done                        │
│ ■ Scan complete — 4 finding(s)             │
└─────────────────────────────────────────────┘
```

---

## Disclaimer

This tool is intended **exclusively for use on systems you own or have explicit written permission to test**. Unauthorized security testing is illegal. The authors accept no liability for misuse.
