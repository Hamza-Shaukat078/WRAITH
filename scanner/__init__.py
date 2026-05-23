from .idor import run as run_idor
from .broken_auth import run as run_broken_auth
from .rate_limit import run as run_rate_limit
from .jwt_check import run as run_jwt_check
from .security_headers import run as run_security_headers
from .mass_assignment import run as run_mass_assignment
from .sensitive_data import run as run_sensitive_data
from .http_methods import run as run_http_methods
from .graphql import run as run_graphql

MODULES = {
    "idor": run_idor,
    "broken_auth": run_broken_auth,
    "rate_limit": run_rate_limit,
    "jwt_check": run_jwt_check,
    "security_headers": run_security_headers,
    "mass_assignment": run_mass_assignment,
    "sensitive_data": run_sensitive_data,
    "http_methods": run_http_methods,
    "graphql": run_graphql,
}
