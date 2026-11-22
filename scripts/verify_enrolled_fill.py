"""Exercise the enrolled field adapter against disposable authority and a private HTTPS fixture."""

import argparse
import base64
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from weir.linux_field import runtime as linux_field_runtime
from weir.linux_field.runtime import _launch_peer, browser_service, field_peer, read_in_service
from weir.linux_field.review import REHEARSAL_AUDIENCE, accept_rehearsal_review, owner_review, page_template, publish_review
from weir.browser.effect_driver import FADE_AUTHORITY_ID
from weir.browser.enrolled_document import EnrolledDocument, HEADERS, byte_digest, inert_page
from weir.browser.enrolled_fill import DecisionTrust, ENROLL_ACTION, EnrolledField, GRANT, LinuxFillAuthority
from weir.browser.field_controller import LinuxFieldController
from weir.browser.field_service import prepare_enrolled_fill
from weir.browser.store import SQLiteSessionStore
from weir.contract import canonical_digest
from weir.engines.base import EnginePolicyBlocked
from weir.models import DataClass
from weir.persistence import CaptureStore
from weir.proposals import ActionProposalStore
from weir.remote_decision import RemoteDecision, RemoteDecisionCapsule
from weir.service import (ACTION_EXECUTE_SCOPE, ACTION_STATUS_SCOPE, PROPOSAL_READ_FULL_SCOPE, ClientCredential,
                          ClientRegistry, WeirService)
from weir.work_context import WorkContext, WorkContextSource


def utc():
    return datetime.now(timezone.utc)


class QualificationAuthority:
    """Trusted fixture signer. The deployed service contains only a pinned public key."""

    def __init__(self, directory, *, source=None, owner_trust=None, field_name="Fixture value", test_id="fixture-value"):
        self.key = None if owner_trust else Ed25519PrivateKey.generate()
        self.trust = owner_trust or DecisionTrust("fixture-issuer", "fixture-key", "fixture-device", "fixture-owner",
                                                  "fixture-enrolled-action", self.key.public_key())
        auth_dir, witness = directory / "authority", directory / "witness"
        auth_dir.mkdir(mode=0o700)
        witness.mkdir(mode=0o700)
        (witness / "grant.jsonl").write_text(json.dumps({"grant": GRANT, "state": "available"}) + "\n")
        (witness / "grant.jsonl").chmod(0o600)
        self.authority = LinuxFillAuthority(auth_dir, witness, self.trust)
        body = inert_page(field_name, test_id)
        self.document = EnrolledDocument(body, tuple(HEADERS.items()), canonical_digest("fixture-peer-cert"))
        self.field = EnrolledField(source[0] if source else "https://offline.example/field", field_name, test_id,
                                   "fixture-enrollment", canonical_digest("profile"), "fixture-exclusive",
                                   byte_digest(body), canonical_digest(HEADERS),
                                   source[1] if source else self.document.peer_fingerprint, "127.0.0.1")
        if owner_trust is None:
            enroll = self.capsule("fixture-enroll", ENROLL_ACTION, self.field.digest,
                                  canonical_digest({"grant": GRANT, "operation": "enroll"}), enrollment=True)
            self.authority.accept_enrollment(self.field, enroll, enroll.step_up_ref, utc())
            self.refresh()

    def refresh(self):
        self.authority.record_revocations(self.field.digest, utc(), [])

    def capsule(self, command, action, proposal, context, *, enrollment=False, owner=None):
        now = utc()
        return RemoteDecisionCapsule.create(
            key_id=self.trust.key_id, issuer_id=self.trust.issuer, capsule_id="decision-" + secrets.token_hex(12),
            command_id=command, actor_id=owner or self.trust.owner,
            audience=self.trust.audience + (".enrollment" if enrollment else ""), device_id=self.trust.device,
            decision=RemoteDecision.APPROVE, proposal_hash=proposal, action_id=action, work_context_hash=context,
            issued_at=now.isoformat(), expires_at=(now + timedelta(seconds=90)).isoformat(),
            nonce=secrets.token_urlsafe(16), step_up_ref=canonical_digest(secrets.token_hex(32)), private_key=self.key)


@contextmanager
def tls_fixture(directory, body):
    """An actual HTTPS peer. Only the disposable reader namespace trusts this CA."""
    now = utc()
    ca_key, leaf_key = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
    ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "WEIR qualification CA")])
    leaf_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "field.test")])
    def cert(name, key):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(hours=1)))
    ca = cert(ca_name, ca_key).add_extension(x509.BasicConstraints(ca=True, path_length=0), True).sign(ca_key, hashes.SHA256())
    leaf = (cert(leaf_name, leaf_key).add_extension(x509.SubjectAlternativeName([x509.DNSName("field.test")]),False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    ca_file, leaf_file, key_file = [directory / n for n in ("ca.pem","peer.pem","peer.key")]
    ca_file.write_bytes(ca.public_bytes(pem))
    ca_file.chmod(0o444)
    leaf_file.write_bytes(leaf.public_bytes(pem))
    key_file.write_bytes(leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(leaf_file, key_file)
    requests = []
    class Page(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.command,self.path))
            self.send_response(200)
            for key, val in HEADERS.items():
                self.send_header(key,val)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_):
            pass
    with ThreadingHTTPServer(("127.0.0.1",0), Page) as server:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            yield (f"https://field.test:{server.server_port}/field", byte_digest(leaf.public_bytes(serialization.Encoding.DER))), ca_file, requests
        finally:
            server.shutdown()
            thread.join(3)


def wrong_role_peer(role):
    with socket.socket(fileno=os.dup(0)) as sock:
        sock.send(b"ready")
        job = json.loads(sock.recv(2048))
        sock.send(json.dumps({"method": "fill" if role == "read" else "read", **job}).encode())


def check_witness_volume(directory):
    """Qualify live trust loading and the append-only check on an expendable mounted image."""
    pid = os.fork()
    if pid == 0:
        try:
            os.unshare(os.CLONE_NEWNS)
            subprocess.run(["/usr/bin/mount", "--make-rprivate", "/"], check=True)
            directory.mkdir(mode=0o700)
            qa = QualificationAuthority(directory)
            store = SQLiteSessionStore(directory / "commissioning-check.sqlite3")
            volume = directory / "witness.img"
            with volume.open("xb") as out:
                out.truncate(16 * 1024 * 1024)
            subprocess.run(["/usr/sbin/mkfs.ext4", "-q", str(volume)], check=True)
            mounted = directory / "witness-volume"
            mounted.mkdir()
            subprocess.run(["/usr/bin/mount", "-o", "loop,nodev,nosuid,noexec", str(volume), str(mounted)], check=True)
            mounted.chmod(0o700)
            config_dir = directory / "live-shaped-trust"
            config_dir.mkdir(mode=0o700)
            signer = Ed25519PrivateKey.generate()
            key = signer.public_key()
            config = {"machine_digest": canonical_digest(Path("/etc/machine-id").read_text().strip()),
                      "audience": "weir.production.first-fill", "grant": GRANT, "key_id": "disposable-sealed-key",
                      "issuer": "qualification-issuer", "owner": "qualification-human", "device": "qualification-device",
                      "profile_id": "qualification-public", "profile_digest": canonical_digest("profile"),
                      "credential_binding_id": "qualification-anonymous",
                      "public_key": base64.b64encode(key.public_bytes_raw()).decode()}
            (config_dir / "deployment.json").write_text(json.dumps(config))
            journal = mounted / "grant.jsonl"
            journal.write_text(json.dumps({"grant": GRANT, "state": "available",
                                           "deployment": canonical_digest(config)}) + "\n")
            with patch.multiple(linux_field_runtime, _CONFIG=config_dir, _WITNESS=mounted, _INGRESS=qa.authority.ingress):
                try:
                    linux_field_runtime.commissioned_authority(store)
                except EnginePolicyBlocked:
                    pass
                else:
                    raise AssertionError("Live trust accepted a rewindable witness")
                subprocess.run(["/usr/bin/chattr", "+a", str(journal)], check=True)
                authority = linux_field_runtime.commissioned_authority(store)
                for signing_key, audience in ((qa.key, config["audience"]), (signer, qa.trust.audience)):
                    probe = RemoteDecisionCapsule.create(key_id=config["key_id"], issuer_id=config["issuer"],
                        capsule_id="qualification-decision", command_id="qa-command", actor_id=config["owner"],
                        device_id=config["device"], audience=audience, decision=RemoteDecision.APPROVE,
                        proposal_hash=qa.field.digest, action_id="qa-action", work_context_hash=qa.field.digest,
                        issued_at=utc().isoformat(), expires_at=(utc()+timedelta(seconds=50)).isoformat(),
                        nonce=secrets.token_urlsafe(16), step_up_ref=canonical_digest("qa-step-up"), private_key=signing_key)
                    try:
                        authority.trust.verify(probe, utc())
                    except (ValueError, EnginePolicyBlocked):
                        pass
                    else:
                        raise AssertionError("The sealed trust accepted a fixture key or audience")
            os._exit(0)
        except Exception:
            import traceback
            traceback.print_exc()
            os._exit(1)
    if os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) != 0:
        raise RuntimeError("Independent grant volume qualification failed")


def check_reaped_thread():
    """Read an actual creation event after the short-lived test thread has exited."""
    trace = Path("/sys/kernel/tracing/instances") / ("weir-thread-check-" + secrets.token_hex(8))
    trace.mkdir()
    try:
        (trace / "tracing_on").write_text("0")
        (trace / "options/pause-on-trace").write_text("0")
        (trace / "set_event_pid").write_text(str(os.getpid()))
        (trace / "events/task/task_newtask/enable").write_text("1")
        (trace / "tracing_on").write_text("1")
        thread = Thread(target=lambda: None)
        thread.start()
        thread.join(3)
        recorded = (trace / "trace").read_text()
        if thread.is_alive() or "task_newtask:" not in recorded:
            raise RuntimeError("The trace missed the short-lived qualification thread")
        linux_field_runtime.verify_task_events(recorded)
    finally:
        (trace / "tracing_on").write_text("0")
        trace.rmdir()


class RehearsalExchange:
    """Read both independent decisions for a private fixture. No live deployment accepts this audience."""

    def __init__(self, directory):
        from fade.field_review import FieldPins, protected_json

        self.directory = directory
        root = directory.stat()
        if directory != directory.resolve() or root.st_uid != 0 or root.st_mode & 0o022:
            raise ValueError("The rehearsal exchange must be in a protected root-owned directory")
        config = protected_json(directory / "config" / "pins.json", 0)
        self.issuer_uid, self.web_uid = config["issuer_uid"], config["web_uid"]
        if (type(self.issuer_uid) is not int or type(self.web_uid) is not int or
                min(self.issuer_uid, self.web_uid) < 1 or self.issuer_uid == self.web_uid):
            raise ValueError("The web application and issuer need separate unprivileged accounts")
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(config["public_key"], validate=True))
        self.pins = FieldPins(config["actor_id"], config["device_id"], config["issuer"], config["key_id"], key)
        self.trust = DecisionTrust(self.pins.issuer, self.pins.key_id, self.pins.device, self.pins.actor,
                                   REHEARSAL_AUDIENCE, key)
        self.stepups = []

    def decide(self, qa, *, proposal=None, proposals=None, coordinator=None):
        from fade.field_review import deliver_field_decision, protected_decision, verify_field_decision

        card = owner_review(qa.field, self.trust, proposal=proposal, proposals=proposals)
        publish_review(self.directory / "review", card)
        while utc() < datetime.fromisoformat(card["expires_at"]):
            try:
                sealed = protected_decision(self.directory / "decisions", card["review_hash"], self.issuer_uid)
                step = protected_decision(self.directory / "stepups", card["review_hash"], self.web_uid)
                break
            except FileNotFoundError:
                time.sleep(0.25)
        else:
            raise TimeoutError("The owner review expired before both independent records arrived")
        verified = verify_field_decision(card, sealed, self.pins)
        if step["step_up_ref"] in self.stepups:
            raise ValueError("Enrollment and fill require different passkey ceremonies")
        def accept(event):
            if proposal is not None:
                qa.refresh()
            ack = accept_rehearsal_review(qa.authority, qa.field, card, event, step,
                                          proposal=proposal, proposals=proposals)
            if proposal is None:
                qa.refresh()
            return ack
        result = deliver_field_decision(card, sealed, self.pins, accept=accept, coordinator=coordinator)
        self.stepups.append(step["step_up_ref"])
        return result, verified.command


def run(directory, fade_source=None, owner_exchange=None, page_copy=None):
    if fade_source is not None:
        sys.path.insert(0, str(fade_source))
    from fade.weir_authority import (AmbiguousWeirTransportError, AuthorityRunStore, HttpWeirActionClient,
                                     WeirAuthorityCoordinator)
    from fade.weir_contract import WeirApprovalCommand
    from run_fade_weir_action_canary import DropFirstExecuteResponseClient

    field_name, test_id = "Fixture value", "fixture-value"
    body = inert_page(field_name, test_id)
    if page_copy is not None:
        template = page_template()
        with page_copy.open("rb") as stream:
            body = stream.read(8193)
        if body != template["html"].encode("ascii"):
            raise ValueError("The copy must exactly match the public field template.")
        field_name, test_id = template["name"], template["test_id"]

    os.umask(0o077)
    directory.mkdir(mode=0o700, exist_ok=False)
    check_reaped_thread()
    check_witness_volume(directory / "volume-check")
    token = secrets.token_urlsafe(40)
    clients = ClientRegistry([ClientCredential(FADE_AUTHORITY_ID, token,
                              frozenset({ACTION_EXECUTE_SCOPE, ACTION_STATUS_SCOPE, PROPOSAL_READ_FULL_SCOPE}),
                              frozenset({DataClass.PUBLIC}))])
    ident = secrets.token_hex(12)
    context = WorkContext.create(context_id="context-" + ident, run_id="run-" + ident, correlation_id="corr-" + ident,
                                 assignment_id="qa-" + ident, source=WorkContextSource.AUTOWORK, created_at=utc().isoformat())
    with ExitStack() as stack:
        source, ca_file, received = stack.enter_context(tls_fixture(directory, body))
        exchange = RehearsalExchange(owner_exchange) if owner_exchange else None
        qa = QualificationAuthority(directory, source=source, owner_trust=exchange.trust if exchange else None,
                                    field_name=field_name, test_id=test_id)
        if exchange:
            enrolled, command = exchange.decide(qa)
            if enrolled["state"] != "enrolled" or command is not None:
                raise RuntimeError("Field enrollment unexpectedly authorized a fill")
        try:
            read_in_service(qa.field)
        except EnginePolicyBlocked:
            pass
        else:
            raise RuntimeError("The default system trust accepted the disposable TLS CA")
        if received:
            raise RuntimeError("The invalid TLS peer received an HTTP request")
        original_command = linux_field_runtime._reader_command
        def test_reader(field):
            args = original_command(field)
            args.insert(args.index("--"), f"--property=BindReadOnlyPaths={ca_file}:/etc/ssl/certs/ca-certificates.crt")
            return args
        stack.enter_context(patch.object(linux_field_runtime, "_reader_command", test_reader))
        store = stack.enter_context(SQLiteSessionStore(directory / "session.sqlite3"))
        proposals = ActionProposalStore(directory / "proposals", CaptureStore(directory / "captures"), store)
        reader, effect = [stack.enter_context(field_peer(role)) for role in ("read", "fill")]
        for role in ("read", "fill"):
            with _launch_peer(role, wrong_role_peer) as adversary:
                try:
                    adversary.serve(role, qa.field.digest, lambda _: (_ for _ in ()).throw(
                        AssertionError("Cross-role operation reached the browser")))
                except EnginePolicyBlocked:
                    pass
                else:
                    raise AssertionError("Cross-role operation was admitted")
        def open_controller(field):
            controller = LinuxFieldController(field, browser_service=browser_service,
                                             read_source=read_in_service, observer=reader, effect=effect)
            stack.callback(controller.contain)
            return controller
        app, p = prepare_enrolled_fill(store=store, proposals=proposals, context=context, authority=qa.authority,
                                       clients=clients, backend=object(), open_controller=open_controller)
        with WeirService(app) as service:
            client = HttpWeirActionClient(f"http://{service.address[0]}:{service.address[1]}", credential=token)
            dropped = DropFirstExecuteResponseClient(client, AmbiguousWeirTransportError)
            class Events:
                def post(self, event):
                    pass
            coordinator = WeirAuthorityCoordinator(AuthorityRunStore(directory / "fade"), dropped, event_sink=Events(),
                                                   sleeper=lambda _: None)
            if exchange:
                first, command = exchange.decide(qa, proposal=p, proposals=proposals, coordinator=coordinator)
            else:
                command = WeirApprovalCommand(command_id="cmd-" + ident, proposal_hash=p.proposal_hash,
                    action_id=p.action_id, work_context_hash=p.work_context_hash, decision="approved",
                    reason="Fixed offline acceptance")
                proof = qa.capsule(command.command_id, p.action_id, p.proposal_hash, p.work_context_hash)
                ref = "approval-" + command.decision_digest(qa.trust.owner).removeprefix("sha256:")[:32]
                qa.authority.accept_approval(ref, proof, proof.step_up_ref, utc())
                qa.refresh()
                first = coordinator.decide(command, actor_id=qa.trust.owner)
            if first["state"] != "completed":
                raise RuntimeError("WEIR did not verify the enrolled fill: " + str(first["state"]))
            second = coordinator.decide(command, actor_id=qa.trust.owner)
            if first != second or dropped.execute_calls != 1 or dropped.dropped_responses != 1:
                raise RuntimeError("Fade's status recovery changed the receipt or repeated dispatch")
        with qa.authority.journal() as (_, rows):
            if [x["state"] for x in rows] != ["available", "reserved", "dispatch"]:
                raise RuntimeError("Deployment grant history is incomplete")
        restarted, next_proposal = prepare_enrolled_fill(store=store, proposals=proposals, context=context,
            authority=qa.authority, clients=clients, backend=object(),
            open_controller=lambda _: (_ for _ in ()).throw(AssertionError("A spent grant reopened Chromium")))
        with WeirService(restarted) as service:
            client = HttpWeirActionClient(f"http://{service.address[0]}:{service.address[1]}", credential=token)
            full_receipt = store.load_receipt(p.action_id)
            status = client.get_action_status(command_id=command.command_id, permit_id=full_receipt["permit_id"])
            if next_proposal is not None or status.receipt.receipt_hash != first["receipt"]["receipt_hash"]:
                raise RuntimeError("Restart failed to return the original verified receipt")
        ref = full_receipt["verification"]["supporting_evidence_refs"][-1]
        retained = json.loads((qa.authority.ingress / ("lifecycle-" + ref.split(":")[1] + ".json")).read_text())
        if canonical_digest(retained) != ref or retained["command"] != command.command_id:
            raise RuntimeError("Saved shutdown evidence differs from the receipt")
        if received != [("GET", "/field"), ("GET", "/field")]:
            raise RuntimeError("The HTTPS fixture received unexpected requests")
        return {"schema": "weir-enrolled-fill-qualification/v1", "run_id": context.run_id,
                "observed_at": utc().isoformat(), "receipt_hash": first["receipt"]["receipt_hash"],
                "fade_execute_calls": dropped.execute_calls, "lost_responses_reconciled": dropped.dropped_responses,
                "same_receipt_on_replay": True, "cross_role_denials": 2, "grant_states": [x["state"] for x in rows],
                "signed_disposable_enrollment_and_approval": True, "separate_browser_discard": True,
                "fixture_https_gets": len(received), "ordinary_trust_rejected_fixture_ca": True,
                "separate_append_only_volume_checked": True, "commissioned_trust_rejected_fixture_signature": True,
                "kernel_observed_reaped_thread": True,
                "same_receipt_after_weir_restart": True, "exit_evidence_digest": ref,
                "browser_exits": [{"invocation": item["invocation"], "cgroup_removed": item["cgroup_removed"],
                                   "pinned_pidfds_exited": item["exited_pidfds"], "processes_exited": len(item["exited_lifetimes"]),
                                   "receivers": item["controlled_receivers"], "unexpected_deliveries": item["unexpected_deliveries"]}
                                  for item in retained["evidence"].values()],
                "live_website_accessed": False, "page_body_digest": byte_digest(body),
                "independent_owner_records": len(exchange.stepups) if exchange else 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--fade-source", type=Path, help="Optional checkout for development builds")
    parser.add_argument("--owner-exchange", type=Path, help="Use the protected Mission Control rehearsal exchange")
    parser.add_argument("--page-copy", type=Path, help="Serve the exact published field bytes on the private test origin")
    args = parser.parse_args()
    print(json.dumps(run(args.directory.resolve(), args.fade_source, args.owner_exchange, args.page_copy), indent=2))
