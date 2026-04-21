"""
access_control.py — Access Control Module
Secret: the exact role-permission matrix and which commands require re-authentication.
Callers ask yes/no questions; the policy encoding is opaque.
"""

# ── Permission tables (hidden from all callers) ───────────────────────────────

# Admin can manage users and audit; CANNOT touch address records (BR-2)
_ADMIN_ALLOWED = frozenset({
    'LIN', 'LOU', 'CHP', 'HLP', 'EXT',
    'ADU', 'DEU', 'LSU', 'RPW', 'DAL',
})

# Regular user can manage their own records; CANNOT do user management or view audit (BR-1)
_USER_ALLOWED = frozenset({
    'LIN', 'LOU', 'CHP', 'HLP', 'EXT',
    'ADR', 'DER', 'EDR', 'RER', 'IMD', 'EXD',
})

# Commands that require re-authentication even within an active session (SR-6)
_REAUTH_REQUIRED = frozenset({'ADU', 'DEU', 'LSU', 'RPW'})

# Commands that do NOT require an active session
_NO_AUTH_REQUIRED = frozenset({'LIN', 'HLP', 'EXT'})


# ── Public interface ──────────────────────────────────────────────────────────

def acl_can_perform(role: str, operation: str) -> bool:
    """Return True if the given role is permitted to execute the operation."""
    if role == 'admin':
        return operation in _ADMIN_ALLOWED
    if role == 'user':
        return operation in _USER_ALLOWED
    return False


def acl_requires_reauth(operation: str) -> bool:
    """Return True if this operation requires password re-entry even mid-session."""
    return operation in _REAUTH_REQUIRED


def acl_requires_auth(operation: str) -> bool:
    """Return True if this operation requires an active session."""
    return operation not in _NO_AUTH_REQUIRED


def acl_get_role(user_id: str) -> str:
    """Derive role from user_id. 'none' if user_id is falsy."""
    if not user_id:
        return 'none'
    return 'admin' if user_id == 'admin' else 'user'