import json
from .capture import make_request, build

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/gql", "/api/gql",
    "/v1/graphql", "/v2/graphql", "/query", "/api/query",
    "/graphql/v1", "/graphql/v2",
]

INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name } } } }"}'

DEPTH_QUERY = '{"query":"{ user { friends { friends { friends { friends { friends { id name } } } } } } }"}'

BATCH_QUERY = json.dumps([
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
])

FIELD_SUGGESTION_QUERY = '{"query":"{ usr { id } }"}'

ALIAS_OVERLOAD = json.dumps({"query": " ".join(
    [f'a{i}: __typename' for i in range(100)]
    + ["{", "}"],
)})


def _post_graphql(url, body, headers):
    h = {**headers, "Content-Type": "application/json"}
    return make_request("POST", url, h, data=body)


def _get_graphql(url, headers):
    return make_request("GET", url + "?query={__typename}", headers)


def _is_graphql_response(body: str) -> bool:
    try:
        d = json.loads(body)
        return "data" in d or "errors" in d
    except Exception:
        return False


def _find_endpoint(base, headers):
    for path in GRAPHQL_PATHS:
        url = base + path
        r, req, res = _post_graphql(url, '{"query":"{ __typename }"}', headers)
        if r and r.status_code in (200, 400) and _is_graphql_response(res.get("body", "")):
            return url, req, res
        r, req, res = _get_graphql(url, headers)
        if r and r.status_code in (200, 400) and _is_graphql_response(res.get("body", "")):
            return url, req, res
    return None, None, None


def run(target_url: str, token: str) -> list[dict]:
    findings = []
    base = target_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    endpoint, disc_req, disc_res = _find_endpoint(base, headers)

    if not endpoint:
        findings.append(build(
            title="GraphQL — No GraphQL Endpoint Detected",
            severity="INFO",
            description=(
                f"Probed {len(GRAPHQL_PATHS)} common GraphQL paths on {base}. "
                "No GraphQL endpoint was found."
            ),
            evidence={"paths_probed": GRAPHQL_PATHS},
            cvss_score=0.0, cvss_vector="N/A",
            remediation="No action required. This target does not appear to expose a GraphQL API.",
        ))
        return findings

    findings.append(build(
        title="GraphQL — Endpoint Discovered",
        severity="INFO",
        description=f"GraphQL endpoint found at {endpoint}. Running attack checks.",
        evidence={"endpoint": endpoint},
        cvss_score=0.0, cvss_vector="N/A",
        remediation="Ensure the GraphQL endpoint requires authentication and has depth/complexity limits.",
        req=disc_req, res=disc_res,
    ))

    # 1 — Introspection enabled
    r, req, res = _post_graphql(endpoint, INTROSPECTION_QUERY, headers)
    if r and r.status_code == 200:
        body = res.get("body", "")
        try:
            data = json.loads(body)
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            type_count = len(types)
        except Exception:
            types = []
            type_count = 0

        if type_count > 0:
            type_names = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")][:10]
            findings.append(build(
                title="GraphQL — Introspection Enabled in Production",
                severity="MEDIUM",
                description=(
                    f"GraphQL introspection is enabled at {endpoint}. "
                    f"Schema reveals {type_count} types including: {', '.join(type_names)}. "
                    "Attackers use introspection to map the entire API surface and find hidden mutations."
                ),
                evidence={
                    "endpoint": endpoint,
                    "type_count": type_count,
                    "sample_types": type_names,
                },
                cvss_score=5.3,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                remediation="Disable introspection in production. Allow only in development environments.",
                remediation_code=(
                    "# Apollo Server:\n"
                    "ApolloServer({ introspection: process.env.NODE_ENV !== 'production' })\n\n"
                    "# Strawberry (Python):\n"
                    "from strawberry.extensions import DisableIntrospection\n"
                    "schema = strawberry.Schema(query=Query, extensions=[DisableIntrospection])"
                ),
                req=req, res=res,
            ))

    # 2 — Query depth attack
    r, req, res = _post_graphql(endpoint, DEPTH_QUERY, headers)
    if r and r.status_code == 200:
        body = res.get("body", "")
        if '"data"' in body and '"errors"' not in body:
            findings.append(build(
                title="GraphQL — No Query Depth Limit (DoS Risk)",
                severity="HIGH",
                description=(
                    f"A deeply nested query (6 levels) at {endpoint} returned HTTP 200 with data. "
                    "Without depth limits an attacker can craft exponentially expensive queries causing DoS."
                ),
                evidence={"endpoint": endpoint, "depth_tested": 6},
                cvss_score=7.5,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                remediation="Enforce maximum query depth (recommend ≤ 5) and complexity limits.",
                remediation_code=(
                    "# graphql-core (Python) — add depth limit validation:\n"
                    "from graphql import validate, parse\n"
                    "from graphql.validation import NoUnusedVariablesRule\n\n"
                    "# Use graphene-django with depth limiter:\n"
                    "from graphene_django.views import GraphQLView\n"
                    "from graphql_depth_limit import depth_limit_validator\n"
                    "schema.execute(query, validation_rules=[depth_limit_validator(5)])"
                ),
                req=req, res=res,
            ))

    # 3 — Batch query attack
    r, req, res = _post_graphql(endpoint, BATCH_QUERY, headers)
    if r and r.status_code == 200:
        body = res.get("body", "")
        try:
            data = json.loads(body)
            if isinstance(data, list) and len(data) >= 5:
                findings.append(build(
                    title="GraphQL — Batching Enabled (Brute-Force Risk)",
                    severity="HIGH",
                    description=(
                        f"The server accepted and processed a batch of 5 queries in a single request to {endpoint}. "
                        "Batching can be abused to brute-force credentials, bypass rate limits, "
                        "or enumerate IDs by sending thousands of queries per HTTP request."
                    ),
                    evidence={"endpoint": endpoint, "batch_size": 5, "responses": len(data)},
                    cvss_score=7.5,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
                    remediation="Disable query batching or limit batch size to 1-5 queries per request.",
                    remediation_code=(
                        "# Apollo Server:\n"
                        "ApolloServer({ allowBatchedHttpRequests: false })\n\n"
                        "# Manual middleware check:\n"
                        "if isinstance(request.json(), list) and len(request.json()) > 3:\n"
                        "    raise HTTPException(400, 'Batch too large')"
                    ),
                    req=req, res=res,
                ))
        except Exception:
            pass

    # 4 — Field suggestion / schema leakage
    r, req, res = _post_graphql(endpoint, FIELD_SUGGESTION_QUERY, headers)
    if r and r.status_code in (200, 400):
        body = res.get("body", "")
        if "Did you mean" in body or "suggestion" in body.lower():
            findings.append(build(
                title="GraphQL — Field Suggestions Leak Schema Information",
                severity="LOW",
                description=(
                    f"Sending a typo query to {endpoint} returned a 'Did you mean...' suggestion. "
                    "Suggestions reveal valid field names and help attackers enumerate the schema without introspection."
                ),
                evidence={"endpoint": endpoint, "trigger_query": "{ usr { id } }"},
                cvss_score=3.1,
                cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                remediation="Disable field suggestions in production.",
                remediation_code=(
                    "# Apollo Server:\n"
                    "ApolloServer({ formatError: (err) => { delete err.extensions?.exception; return err; } })\n\n"
                    "# Strawberry:\n"
                    "schema = strawberry.Schema(query=Query, config=StrawberryConfig(relay_max_results=100))"
                ),
                req=req, res=res,
            ))

    # 5 — Alias overloading
    r, req, res = _post_graphql(endpoint, ALIAS_OVERLOAD, headers)
    if r and r.status_code == 200:
        body = res.get("body", "")
        try:
            data = json.loads(body).get("data", {})
            if len(data) >= 50:
                findings.append(build(
                    title="GraphQL — Alias Overloading Accepted (DoS Risk)",
                    severity="MEDIUM",
                    description=(
                        f"A query with 100 aliases was processed by {endpoint}. "
                        "Alias overloading multiplies resolver execution cost without depth increase, "
                        "bypassing naive depth limiters and enabling resource exhaustion."
                    ),
                    evidence={"endpoint": endpoint, "aliases_sent": 100, "aliases_returned": len(data)},
                    cvss_score=5.3,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    remediation="Implement query complexity analysis that counts aliases, not just depth.",
                    remediation_code=(
                        "# Use graphql-query-complexity (JS) or equivalent:\n"
                        "from graphql_query_complexity import (\n"
                        "    QueryComplexity, SimpleEstimator\n"
                        ")\n"
                        "schema.execute(query, validation_rules=[\n"
                        "    QueryComplexity(max_complexity=100, estimators=[SimpleEstimator(1)])\n"
                        "])"
                    ),
                    req=req, res=res,
                ))
        except Exception:
            pass

    return findings
