from .idor import run as run_idor
from .broken_auth import run as run_broken_auth
from .rate_limit import run as run_rate_limit
from .jwt_check import run as run_jwt_check

MODULES = {
    "idor": run_idor,
    "broken_auth": run_broken_auth,
    "rate_limit": run_rate_limit,
    "jwt_check": run_jwt_check,
}
