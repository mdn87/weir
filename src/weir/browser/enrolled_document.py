"""One anonymous HTTPS read and a network-free Chromium view of the enrolled bytes."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from weir.browser.enrolled_fill import EnrolledField, MARKER, require
from weir.contract import canonical_digest


CSP = "default-src 'none'; base-uri 'none'; form-action 'none'"
HEADERS = {"content-type": "text/html; charset=utf-8", "content-security-policy": CSP,
           "cache-control": "no-store"}


def byte_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def inert_page(name, test_id):
    from html import escape

    return (f'<!doctype html><html><head><title>WEIR field</title></head><body>'
            f'<input type="text" aria-label="{escape(name, quote=True)}" '
            f'data-testid="{escape(test_id, quote=True)}"></body></html>').encode()


@dataclass(frozen=True)
class EnrolledDocument:
    body: bytes
    headers: tuple[tuple[str, str], ...]
    peer_fingerprint: str

    def verify(self, field: EnrolledField):
        field.validate()
        keys = [k.lower() for k, _ in self.headers]
        values = {k.lower(): v for k, v in self.headers}
        require(len(set(keys)) == len(keys)
                and set(keys) <= (set(HEADERS) | {"date", "server", "content-length", "connection"})
                and all(values.get(k) == v for k, v in HEADERS.items())
                and values.get("content-length", str(len(self.body))) == str(len(self.body))
                and canonical_digest({k: values[k] for k in HEADERS}) == field.headers_digest
                and self.peer_fingerprint == field.tls_fingerprint and byte_digest(self.body) == field.body_digest
                and self.body == inert_page(field.name, field.test_id),
                "The fetched response differs from the enrolled inert page")


def read_connected(field: EnrolledField, upstream):
    """Read exactly once on the supervisor's already connected TCP descriptor."""
    field.validate()
    url = urlsplit(field.url)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Use the installed Linux system bundle, independent of process environment overrides.
    tls.load_verify_locations(cafile="/etc/ssl/certs/ca-certificates.crt")
    address, port, *_ = upstream.getpeername()
    require(ipaddress.ip_address(address) == ipaddress.ip_address(field.peer_address) and port == (url.port or 443),
            "The inherited reader connection differs from the enrolled destination")
    conn = http.client.HTTPConnection(url.hostname, url.port or 443, timeout=5)
    try:
        conn.sock = tls.wrap_socket(upstream, server_hostname=url.hostname)
        fingerprint = byte_digest(conn.sock.getpeercert(binary_form=True))
        require(fingerprint == field.tls_fingerprint, "The enrolled TLS peer certificate changed")
        conn.request("GET", url.path, headers={"Host": url.netloc, "Accept": "text/html", "Connection": "close"})
        result = conn.getresponse()
        require(result.status == 200, "The enrolled document must return HTTP 200 directly")
        document = EnrolledDocument(result.read(8193), tuple(result.getheaders()), fingerprint)
        document.verify(field)
        return document
    finally:
        conn.close()


class FieldObserver:
    """A controller-owned CDP session exposing only frame and DOM snapshot reads."""

    def __init__(self, session, url, name, test_id):
        self._session = session
        self._url, self._name, self._id = url, name, test_id
        self.identity = None

    def value(self):
        tree = self._session.send("Page.getFrameTree")["frameTree"]
        frame = tree["frame"]
        snap = self._session.send("DOMSnapshot.captureSnapshot", {"computedStyles": []})
        strings = snap["strings"]
        doc, = snap["documents"]
        nodes = doc["nodes"]
        index, = [i for i, name in enumerate(nodes["nodeName"]) if strings[name] == "INPUT"]
        attrs = [strings[i] for i in nodes["attributes"][index]]
        require(dict(zip(attrs[::2], attrs[1::2])) ==
                {"type": "text", "aria-label": self._name, "data-testid": self._id}
                and not tree.get("childFrames") and frame["url"] == self._url
                and strings[doc["documentURL"]] == self._url and strings[doc["frameId"]] == frame["id"],
                "The observed document or field differs from enrollment")
        identity = (frame["id"], frame["loaderId"], nodes["backendNodeId"][index])
        require(self.identity in (None, identity), "The enrolled document or its field was replaced")
        self.identity = identity
        values = nodes["inputValue"]
        value = dict(zip(values["index"], values["value"]))[index]
        if value == -1:
            return ""
        require(0 <= value < len(strings), "Unknown snapshot value")
        return strings[value]


class EnrolledTab:
    """Only the trusted controller has this object. Peers receive fixed operations."""

    def __init__(self, browser, field, document):
        document.verify(field)
        self.field = field
        self._count = 0
        self._filled = False
        ctx = browser.new_context(offline=True, java_script_enabled=False, service_workers="block",
                                  accept_downloads=False)
        ctx.set_default_timeout(5000)
        page = ctx.new_page()

        def serve(route):
            self._count += 1
            req = route.request
            if (self._count != 1 or req.url != field.url or req.method != "GET"
                    or not req.is_navigation_request() or req.frame != page.main_frame):
                return route.abort()
            route.fulfill(status=200, headers=HEADERS, body=document.body)

        ctx.route("**/*", serve)
        page.goto(field.url, wait_until="load", timeout=15000)
        self._observer = FieldObserver(ctx.new_cdp_session(page), field.url, field.name, field.test_id)
        self._effect = ctx.new_cdp_session(page)
        require(self.read()["value"] == "", "The enrolled field must start empty")

    def read(self):
        require(self._count == 1, "Unexpected browser request or navigation")
        value = self._observer.value()
        return {"value": value, "enrollment_digest": self.field.digest,
                "document_identity": canonical_digest(list(self._observer.identity))}

    def fill_once(self, expected_identity):
        require(not self._filled and self.read() == {"value": "", "enrollment_digest": self.field.digest,
                "document_identity": expected_identity}, "The pinned empty field changed before fill")
        self._filled = True
        node_id = self._observer.identity[2]
        node = self._effect.send("DOM.describeNode", {"backendNodeId": node_id})["node"]
        require(node["backendNodeId"] == node_id and node["nodeName"] == "INPUT", "Pinned textbox is unavailable")
        self._effect.send("DOM.focus", {"backendNodeId": node_id})
        self._effect.send("Input.insertText", {"text": MARKER})
        return True
