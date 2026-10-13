"""Authorization rules for human decisions.

The twin has two different write paths:

* ``memory.write`` may approve a packet, which makes it executable.
* ``asset_twin.veto`` may stop a packet with ``hold`` or ``veto``.  This is
  intentionally narrower than a general write permission so a read-only token
  cannot mutate the gate, while an emergency operator does not need approval
  rights just to stop an unsafe action.

The HTTP/authentication layer is outside this extracted package.  Callers at a
trust boundary should construct a :class:`Principal` from the verified token
and pass it to ``service.decide_human``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MEMORY_READ = "memory.read"
MEMORY_WRITE = "memory.write"
ASSET_TWIN_VETO = "asset_twin.veto"
ASSET_TWIN_WRITER = "asset_twin.writer"
ASSET_TWIN_SAFETY = "asset_twin.safety"


class AuthorizationError(PermissionError):
    """The principal is not allowed to change a decision gate."""


@dataclass(frozen=True)
class Principal:
    """Verified caller identity and capabilities.

    ``tenant`` binds the principal to one tenant.  ``None`` is reserved for a
    trusted in-process caller and should not be used for an HTTP request.
    """

    name: str
    tenant: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def internal(cls, tenant: str, name: str | None = None) -> "Principal":
        """Compatibility identity for trusted in-process service callers."""
        return cls(name=name or tenant, tenant=tenant, scopes=frozenset({MEMORY_WRITE}))

    @classmethod
    def read_only(cls, name: str, tenant: str) -> "Principal":
        return cls(name=name, tenant=tenant, scopes=frozenset({MEMORY_READ}))

    @classmethod
    def veto_only(cls, name: str, tenant: str) -> "Principal":
        return cls(name=name, tenant=tenant, scopes=frozenset({ASSET_TWIN_VETO}))

    @classmethod
    def writer(cls, name: str, tenant: str) -> "Principal":
        return cls(name=name, tenant=tenant, scopes=frozenset({MEMORY_WRITE}))


class AuthorizationPolicy:
    """Policy for the three human verdicts accepted by the gate."""

    def authorize_write(self, tenant: str, principal: Principal) -> None:
        if principal.tenant is not None and principal.tenant != tenant:
            raise AuthorizationError("principal is not authorized for this tenant")
        if MEMORY_WRITE not in principal.scopes and ASSET_TWIN_WRITER not in principal.roles:
            raise AuthorizationError("operation requires memory.write authorization")

    def authorize(self, tenant: str, verdict: str, principal: Principal) -> None:
        self._authorize_tenant(tenant, principal)

        can_write = MEMORY_WRITE in principal.scopes or ASSET_TWIN_WRITER in principal.roles
        can_stop = can_write or ASSET_TWIN_VETO in principal.scopes or ASSET_TWIN_SAFETY in principal.roles

        if verdict == "approve" and not can_write:
            raise AuthorizationError("approval requires memory.write authorization")
        if verdict in {"hold", "veto"} and not can_stop:
            raise AuthorizationError("hold/veto requires asset_twin.veto authorization")
        if verdict not in {"approve", "hold", "veto"}:
            raise AuthorizationError(f"unsupported verdict: {verdict}")

    @staticmethod
    def _authorize_tenant(tenant: str, principal: Principal) -> None:
        if principal.tenant is not None and principal.tenant != tenant:
            raise AuthorizationError("principal is not authorized for this tenant")


DEFAULT_POLICY = AuthorizationPolicy()
