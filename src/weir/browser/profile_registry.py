from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Protocol

from weir.browser.protocol import SessionSpec
from weir.contract import validate_identifier
from weir.engines.base import EnginePolicyBlocked


@dataclass(frozen=True, slots=True)
class VerifiedProfileBinding:
    """Non-secret registry metadata used for host-global credential fencing."""

    profile_id: str
    credential_binding_id: str
    site_profile_id: str
    credential_scope: str

    def validate(self) -> None:
        validate_identifier(self.profile_id, "profile_id")
        validate_identifier(self.credential_binding_id, "credential_binding_id")
        validate_identifier(self.site_profile_id, "site_profile_id")
        validate_identifier(self.credential_scope, "credential_scope")
        if self.credential_scope != "read_only":
            raise ValueError("profile registry currently accepts read-only credentials")

    def validate_for(self, spec: SessionSpec) -> None:
        self.validate()
        if self.profile_id != spec.profile_id:
            raise EnginePolicyBlocked("profile registry returned a different profile ID")
        if self.credential_binding_id != spec.credential_binding_id:
            raise EnginePolicyBlocked(
                "browser credential binding changed after session admission"
            )
        if self.site_profile_id != spec.site_profile_id:
            raise EnginePolicyBlocked(
                "browser credential is not registered for the selected site profile"
            )
        if self.credential_scope != spec.credential_scope:
            raise EnginePolicyBlocked("browser credential scope changed after admission")


@dataclass(frozen=True, slots=True)
class VerifiedProfileState:
    """Worker-private credential state and its host-attested binding metadata."""

    profile_id: str
    credential_binding_id: str
    site_profile_id: str
    credential_scope: str
    storage_state: dict[str, Any]

    @property
    def binding(self) -> VerifiedProfileBinding:
        binding = VerifiedProfileBinding(
            profile_id=self.profile_id,
            credential_binding_id=self.credential_binding_id,
            site_profile_id=self.site_profile_id,
            credential_scope=self.credential_scope,
        )
        binding.validate()
        return binding

    def validate_for(self, spec: SessionSpec) -> dict[str, Any]:
        try:
            self.binding.validate_for(spec)
        except ValueError as exc:
            raise EnginePolicyBlocked(
                "browser credential registry does not attest read-only scope"
            ) from exc
        return _copy_storage_state(self.storage_state)


class ProfileBindingProvider(Protocol):
    """Resolve only non-secret binding metadata in the broker trust boundary."""

    def binding_for(self, profile_id: str) -> VerifiedProfileBinding | None: ...


class ProfileStateProvider(ProfileBindingProvider, Protocol):
    """Resolve private browser state inside the worker trust boundary."""

    def state_for(self, profile_id: str) -> VerifiedProfileState | None: ...


class EmptyProfileStateProvider:
    def binding_for(self, profile_id: str) -> VerifiedProfileBinding | None:
        return None

    def state_for(self, profile_id: str) -> VerifiedProfileState | None:
        return None


class StaticProfileStateRegistry:
    """Host-owned registry populated from an ACL-protected configuration source.

    The registry retains defensive in-memory copies only. It never derives identity
    from cookie bytes and never persists credentials. A deployment provisioner owns
    the stable ``credential_binding_id`` and must reuse it for aliases that expose the
    same real credential state.
    """

    def __init__(self, states: Iterable[VerifiedProfileState]) -> None:
        state_list = list(states)
        for state in state_list:
            if not isinstance(state, VerifiedProfileState):
                raise TypeError("profile registry entries must be VerifiedProfileState")
            state.binding.validate()
            _copy_storage_state(state.storage_state)
        if len({state.profile_id for state in state_list}) != len(state_list):
            raise ValueError("profile registry IDs must be unique")
        self._states = {
            state.profile_id: VerifiedProfileState(
                profile_id=state.profile_id,
                credential_binding_id=state.credential_binding_id,
                site_profile_id=state.site_profile_id,
                credential_scope=state.credential_scope,
                storage_state=_copy_storage_state(state.storage_state),
            )
            for state in state_list
        }

    def binding_for(self, profile_id: str) -> VerifiedProfileBinding | None:
        state = self._states.get(profile_id)
        return None if state is None else state.binding

    def state_for(self, profile_id: str) -> VerifiedProfileState | None:
        state = self._states.get(profile_id)
        if state is None:
            return None
        return VerifiedProfileState(
            profile_id=state.profile_id,
            credential_binding_id=state.credential_binding_id,
            site_profile_id=state.site_profile_id,
            credential_scope=state.credential_scope,
            storage_state=_copy_storage_state(state.storage_state),
        )


def _copy_storage_state(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("browser storage state must be an object")
    try:
        copied = json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "browser storage state must be a JSON-compatible object"
        ) from exc
    if not isinstance(copied, dict):  # pragma: no cover - defensive JSON guard
        raise ValueError("browser storage state must remain an object")
    return copied


__all__ = [
    "EmptyProfileStateProvider",
    "ProfileBindingProvider",
    "ProfileStateProvider",
    "StaticProfileStateRegistry",
    "VerifiedProfileBinding",
    "VerifiedProfileState",
]
