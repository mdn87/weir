from __future__ import annotations

from weir.browser.models import Observation, ResolvedTarget, SemanticLocator


class LocatorResolutionError(RuntimeError):
    code = "locator_resolution_failed"

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(f"{self.code}: {detail}")


class LocatorNotFoundError(LocatorResolutionError):
    code = "locator_not_found"


class LocatorAmbiguousError(LocatorResolutionError):
    code = "locator_ambiguous"

    def __init__(self, match_count: int):
        self.match_count = match_count
        super().__init__(f"{match_count} elements matched; add constraints or an ordinal")


class StaleObservationError(LocatorResolutionError):
    code = "stale_observation"


def resolve_locator(
    locator: SemanticLocator,
    observation: Observation,
    *,
    expected_session_id: str | None = None,
    expected_revision: int | None = None,
    expected_epoch: int | None = None,
) -> ResolvedTarget:
    """Resolve a semantic locator against one immutable, freshness-checked observation.

    Candidate order is the accessibility/DOM order retained by ``Observation``.
    ``ordinal`` is zero-based within the filtered candidate list.
    """

    locator.validate()
    observation.validate()
    _check_freshness(
        observation,
        expected_session_id=expected_session_id,
        expected_revision=expected_revision,
        expected_epoch=expected_epoch,
    )

    candidates = []
    for element in observation.elements:
        if locator.role is not None and element.role != locator.role:
            continue
        if locator.name is not None:
            if locator.name_match.value == "casefold":
                name_matches = (
                    element.name is not None
                    and element.name.casefold() == locator.name.casefold()
                )
            else:
                name_matches = element.name == locator.name
            if not name_matches:
                continue
        if locator.test_id is not None and element.test_id != locator.test_id:
            continue
        if locator.required_state is not None and element.state != locator.required_state:
            continue
        candidates.append(element)

    if locator.ordinal is not None:
        if locator.ordinal >= len(candidates):
            raise LocatorNotFoundError(
                f"ordinal {locator.ordinal} is outside {len(candidates)} matched elements"
            )
        matched = candidates[locator.ordinal]
    elif not candidates:
        raise LocatorNotFoundError("no element matched the semantic locator")
    elif len(candidates) > 1:
        raise LocatorAmbiguousError(len(candidates))
    else:
        matched = candidates[0]

    target = ResolvedTarget(
        observation_id=observation.observation_id,
        session_id=observation.session_id,
        session_revision=observation.session_revision,
        session_epoch=observation.session_epoch,
        element_ref=matched.ref,
        role=matched.role,
        name=matched.name,
        test_id=matched.test_id,
        state=matched.state,
        locator_hash=locator.locator_hash,
    )
    target.validate()
    return target


def _check_freshness(
    observation: Observation,
    *,
    expected_session_id: str | None,
    expected_revision: int | None,
    expected_epoch: int | None,
) -> None:
    if expected_session_id is not None and observation.session_id != expected_session_id:
        raise StaleObservationError(
            f"expected session {expected_session_id!r}, got {observation.session_id!r}"
        )
    if expected_revision is not None and observation.session_revision != expected_revision:
        raise StaleObservationError(
            f"expected revision {expected_revision}, got {observation.session_revision}"
        )
    if expected_epoch is not None and observation.session_epoch != expected_epoch:
        raise StaleObservationError(
            f"expected epoch {expected_epoch}, got {observation.session_epoch}"
        )


resolve = resolve_locator


__all__ = [
    "LocatorAmbiguousError",
    "LocatorNotFoundError",
    "LocatorResolutionError",
    "StaleObservationError",
    "resolve",
    "resolve_locator",
]
