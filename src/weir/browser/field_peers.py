"""Authenticate a fixed browser operation on a private, inherited Linux Unix socket."""

import json
import os
import secrets
import socket
import struct

from weir.browser.enrolled_fill import require


def peer_main(role):
    """Originate the fixed method on this principal's private controller session."""
    with socket.socket(fileno=os.dup(0)) as sock:
        sock.send(b"ready")
        filled = False
        while True:
            data = sock.recv(2048)
            if not data:
                return
            job = json.loads(data)
            nonce, target = job["nonce"], job["target"]
            if target is None:
                sock.send(json.dumps({"nonce": nonce, "method": "ready-" + role}).encode())
                continue
            if role == "fill" and filled:
                sock.send(json.dumps({"nonce": nonce, "method": "spent"}).encode())
                continue
            request = {"nonce": nonce, "method": role, "target": target}
            sock.send(json.dumps(request).encode())
            response = json.loads(sock.recv(2048))
            if response.get("nonce") != nonce or "result" not in response:
                return
            result = response["result"]
            if role == "fill":
                filled = True
                if result is not True:
                    return
            elif not isinstance(result, dict) or set(result) != {"value", "document_identity", "enrollment_digest"}:
                return
            sock.send(json.dumps({"nonce": nonce, "result": result}).encode())


class FieldPeer:
    def __init__(self, sock, pid, uid, operation):
        require(pid > 1 and uid not in (0, os.geteuid()) and operation in {"read", "fill"},
                "The field role requires a separate unprivileged principal")
        self.socket = sock
        self.pid, self.uid, self.operation = pid, uid, operation
        sock.settimeout(5)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        require(self._receive() == b"ready", "Field role failed to initialize")

    def _receive(self):
        size = struct.calcsize("3i")
        data, controls, flags, _ = self.socket.recvmsg(2048, socket.CMSG_SPACE(size))
        require(not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
                and len(controls) == 1 and controls[0][:2] == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS)
                and struct.unpack("3i", controls[0][2])[:2] == (self.pid, self.uid),
                "The field role's kernel identity changed")
        return data

    def ready(self):
        nonce = secrets.token_hex(24)
        self.socket.send(json.dumps({"nonce": nonce, "target": None}).encode())
        require(json.loads(self._receive()) == {"nonce": nonce, "method": "ready-" + self.operation},
                "The field principal is unavailable")

    def serve(self, method, target, callback):
        """Dispatch only a peer-originated, authenticated call matching its fixed capability."""
        nonce = secrets.token_hex(24)
        self.socket.send(json.dumps({"nonce": nonce, "target": target}).encode())
        call = json.loads(self._receive())
        require(method == self.operation and call == {"nonce": nonce, "method": self.operation, "target": target},
                "The field role cannot perform that operation")
        result = callback(target)
        response = {"nonce": nonce, "result": result}
        self.socket.send(json.dumps(response).encode())
        require(json.loads(self._receive()) == response, "The role lost its browser result")
        return result
