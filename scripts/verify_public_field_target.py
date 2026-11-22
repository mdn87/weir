"""Qualify the public test document in the isolated reader and a read-only Chromium session."""

import argparse
import ipaddress
import json
from dataclasses import asdict
from datetime import datetime, timezone

from weir.browser.effect_driver import FADE_AUTHORITY_ID
from weir.browser.enrolled_document import EnrolledTab
from weir.browser.enrolled_fill import EnrolledField
from weir.contract import canonical_digest
from weir.linux_field.review import page_template
from weir.linux_field.runtime import browser_service, read_in_service

URL = "https://lugos-host.tail099c37.ts.net:8443/weir-field/"


def observe(peer: str, certificate_digest: str) -> dict:
    address = ipaddress.ip_address(peer)
    if not address.is_global or address.is_multicast or address.is_unspecified:
        raise ValueError("The test needs the public ingress address.")
    template = page_template()
    profile = {"id": "public-field-test", "url": URL, "scope": "anonymous-enrolled-field"}
    field = EnrolledField(
        url=URL, name=template["name"], test_id=template["test_id"], profile_id=profile["id"],
        profile_digest=canonical_digest(profile), credential_binding_id="public-field-anonymous",
        body_digest=template["body_digest"], headers_digest=template["headers_digest"],
        tls_fingerprint=certificate_digest, peer_address=str(address),
    )
    field.validate()
    document = read_in_service(field)
    with browser_service() as (browser, witness):
        tab = EnrolledTab(browser, field, document)
        witness.pin_document()
        witness.evidence().require_current(datetime.now(timezone.utc), caller_id=FADE_AUTHORITY_ID,
                                           expected_platform="linux")
        observation = tab.read()
        if observation["value"] != "" or observation["enrollment_digest"] != field.digest:
            raise RuntimeError("The browser did not see the pinned empty textbox.")
    closed = witness.verify_exit()
    if not closed["cgroup_removed"] or closed["unexpected_deliveries"] or not closed["exited_pidfds"]:
        raise RuntimeError("Isolated browser shutdown was not verified.")
    return {
        "observed_at": datetime.now(timezone.utc).isoformat(), "candidate": asdict(field),
        "candidate_digest": field.digest, "document_bytes": len(document.body),
        "textbox_value": observation["value"], "document_identity": observation["document_identity"],
        "browser_processes_exited": len(closed["exited_lifetimes"]), "cgroup_removed": closed["cgroup_removed"],
        "unit_policy_digest": closed["unit_policy_digest"], "controlled_receivers": closed["controlled_receivers"],
        "unexpected_deliveries": closed["unexpected_deliveries"], "action_dispatched": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", required=True, help="One publicly advertised HTTPS ingress IP")
    parser.add_argument("--certificate-digest", required=True, help="Pinned SHA-256 digest of the public TLS leaf")
    args = parser.parse_args()
    print(json.dumps(observe(args.peer, args.certificate_digest), indent=2))
