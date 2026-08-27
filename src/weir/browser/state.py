from __future__ import annotations

from weir.browser.models import SessionState

ALLOWED_TRANSITIONS: dict[SessionState, frozenset[SessionState]] = {
    SessionState.OPENING: frozenset(
        {SessionState.ACTIVE, SessionState.LOST, SessionState.CLOSED}
    ),
    SessionState.ACTIVE: frozenset(
        {SessionState.PAUSED, SessionState.LOST, SessionState.CLOSED}
    ),
    SessionState.PAUSED: frozenset(
        {SessionState.ACTIVE, SessionState.LOST, SessionState.CLOSED}
    ),
    SessionState.LOST: frozenset({SessionState.OPENING, SessionState.CLOSED}),
    SessionState.CLOSED: frozenset(),
}


class InvalidSessionTransition(RuntimeError):
    pass


def require_transition(current: SessionState, target: SessionState) -> None:
    if target not in ALLOWED_TRANSITIONS[current]:
        raise InvalidSessionTransition(
            f"browser session cannot transition from {current.value} to {target.value}"
        )
