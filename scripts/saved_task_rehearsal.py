"""Run the approval, task site and witness for a fresh private Mission Control rehearsal."""

import argparse
import asyncio
import base64
import contextlib
import json
import os
import secrets
import signal
import socket
import stat
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("init", "serve"))
    parser.add_argument(
        "directory", type=Path, help="new private directory for init, existing one for serve"
    )
    parser.add_argument(
        "--mission-control", type=Path, required=True, help="built Mission Control checkout"
    )
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--weir-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--fade-python", type=Path, default=Path(sys.executable))
    parser.add_argument(
        "--port", type=int, required=False, default=3100, help="loopback port of private web server"
    )
    return parser.parse_args()


class PrivateSite:
    def __init__(self, args):
        if sys.platform != "linux":
            raise ValueError("Run this private fixture on Linux.")
        self.root = args.directory.absolute()
        if self.root != self.root.resolve() or len(os.fsencode(self.root / "reader.sock")) >= 104:
            raise ValueError("The rehearsal needs a short, direct directory path.")
        self.mc = args.mission_control.resolve(strict=True)
        self.node = args.node.resolve(strict=True)
        # Preserve venv executable paths. Resolving symlinks changes their interpreter environment.
        self.weir = args.weir_python.absolute()
        self.fade = args.fade_python.absolute()
        self.port = args.port
        self.site_cli = self.mc / "dist-relay/relay/saved-task-site.js"
        self.common = {
            "PATH": str(self.node.parent) + ":/usr/bin:/bin",
            "HOME": str(self.root),
            "LANG": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
            "NEXT_TELEMETRY_DISABLED": "1",
        }
        self.site_env = {
            **self.common,
            "MC_WEIR_SAVED_TASK_REHEARSAL": "true",
            "MC_WEBAUTHN_RP_ID": "saved-task.test",
            "MC_WEBAUTHN_ORIGIN": "https://saved-task.test",
            "MC_WEIR_SAVED_TASK_PINS": str(self.root / "pins.json"),
            "MC_WEIR_SAVED_TASK_DB": str(self.root / "site.db"),
            "MISSION_CONTROL_DB_PATH": str(self.root / "site.db"),
        }

    def initialize(self):
        self.root.mkdir(mode=0o700)
        (self.root / "attempts").mkdir(mode=0o700)
        (self.root / "state").mkdir(mode=0o700)
        owner, fade = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        pins = {
            "deployment": "rehearsal-" + secrets.token_hex(12),
            "tenant": 1,
            "workspace": 1,
            "owner": "mc:user:1",
            "owner_key": base64.b64encode(owner.public_key().public_bytes_raw()).decode(),
            "fade_key": base64.b64encode(fade.public_key().public_bytes_raw()).decode(),
        }
        secret_files = {
            "pins.json": json.dumps(pins).encode(),
            "owner.pem": owner.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            "fade.key": fade.private_bytes_raw(),
            "login": secrets.token_urlsafe(32).encode(),
            "web-secret": secrets.token_urlsafe(40).encode(),
            "api-key": secrets.token_urlsafe(40).encode(),
        }
        for name, data in secret_files.items():
            with os.fdopen(
                os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as out:
                out.write(data)
        subprocess.run([self.node, self.site_cli, "init"], env=self.site_env, check=True)

    def roles(self):
        site = [str(self.node), str(self.site_cli)]
        return {
            "reader": (site + ["reader"], self.site_env),
            "effect": (site + ["effect"], self.site_env),
            "issuer": (
                site + ["issuer"],
                {**self.site_env, "MC_WEIR_SAVED_TASK_KEY": str(self.root / "owner.pem")},
            ),
            "fade": (
                [str(self.fade), "-m", "fade.saved_task"],
                {
                    **self.common,
                    "FADE_SAVED_TASK_REHEARSAL": "1",
                    "FADE_SAVED_TASK_KEY": str(self.root / "fade.key"),
                    "FADE_SAVED_TASK_PINS": str(self.root / "pins.json"),
                },
            ),
            "weir": (
                [str(self.weir), "-m", "weir.saved_task"],
                {
                    **self.common,
                    "WEIR_SAVED_TASK_REHEARSAL": "1",
                    "WEIR_SAVED_TASK_ROOT": str(self.root),
                },
            ),
        }

    def web(self):
        env = {
            **self.site_env,
            "MC_REMOTE_WEBAUTHN_ENABLED": "true",
            "MC_REMOTE_DEVICE_ID": "saved-task-rehearsal",
            "MC_ALLOWED_HOSTS": "saved-task.test,127.0.0.1,localhost",
            "MC_WEIR_SAVED_TASK_SOCKET": str(self.root / "weir.sock"),
            "MISSION_CONTROL_DATA_DIR": str(self.root / "state"),
            "MISSION_CONTROL_TEST_MODE": "1",
            "AUTH_USER": "fixture-owner",
            "AUTH_PASS": (self.root / "login").read_text(),
            "AUTH_SECRET": (self.root / "web-secret").read_text(),
            "API_KEY": (self.root / "api-key").read_text(),
            "NODE_ENV": "production",
            "HOSTNAME": "127.0.0.1",
            "PORT": str(self.port),
        }
        return [
            str(self.node),
            str(self.mc / "node_modules/next/dist/bin/next"),
            "start",
            "--hostname",
            "127.0.0.1",
            "--port",
            str(self.port),
        ], env

    async def serve(self):
        if {name for _, name in socket.if_nameindex()} != {"lo"}:
            raise ValueError(
                "Run the rehearsal in a private Linux network namespace with only loopback."
            )
        info = self.root.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("The rehearsal directory must belong only to this local user.")
        if any(
            (self.mc / n).exists()
            for n in (".env", ".env.local", ".env.production", ".env.production.local")
        ):
            raise ValueError(
                "Use a private Mission Control build without deployment environment files."
            )
        done = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_running_loop().add_signal_handler(sig, done.set)
        async with contextlib.AsyncExitStack() as stack:
            for role, (argv, env) in self.roles().items():

                async def handle(
                    reader, writer, argv=argv, env=env, budget=65 if role == "weir" else 12
                ):
                    try:
                        data = await asyncio.wait_for(read_bounded(reader), 10)
                        proc = await asyncio.create_subprocess_exec(
                            *argv,
                            env=env,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                        )
                        try:
                            stdout, _ = await asyncio.wait_for(proc.communicate(data), budget)
                        finally:
                            if proc.returncode is None:
                                proc.kill()
                                await proc.wait()
                        if len(stdout) > 32_768:
                            raise ValueError("oversized response")
                        writer.write(stdout)
                        await writer.drain()
                    except (ValueError, OSError, TimeoutError):
                        writer.write(b'{"ok":false}\n')
                    finally:
                        writer.close()

                socket_path = self.root / (role + ".sock")
                if socket_path.exists():
                    raise ValueError("The private rehearsal socket is already in use.")
                server = await asyncio.start_unix_server(handle, str(socket_path))
                socket_path.chmod(0o600)
                stack.callback(socket_path.unlink, missing_ok=True)
                await stack.enter_async_context(server)
            args, env = self.web()
            with (self.root / "web.log").open("ab") as log:
                web = await asyncio.create_subprocess_exec(
                    *args, cwd=self.mc, env=env, stdout=log, stderr=log
                )
                try:
                    async with asyncio.TaskGroup() as group:
                        stopped = group.create_task(done.wait())
                        ended = group.create_task(web.wait())
                        await asyncio.wait((stopped, ended), return_when=asyncio.FIRST_COMPLETED)
                        for task in (stopped, ended):
                            if not task.done():
                                task.cancel()
                    if not done.is_set():
                        raise RuntimeError(
                            "Private Mission Control exited. See the private web log."
                        )
                finally:
                    if web.returncode is None:
                        web.terminate()
                        try:
                            await asyncio.wait_for(web.wait(), 10)
                        except TimeoutError:
                            web.kill()
                            await web.wait()


async def read_bounded(reader):
    chunks = bytearray()
    while len(chunks) <= 32_768:
        data = await reader.read(min(4096, 32_769 - len(chunks)))
        if not data:
            return bytes(chunks)
        chunks.extend(data)
    raise ValueError("oversized request")


if __name__ == "__main__":
    options = arguments()
    fixture = PrivateSite(options)
    if options.operation == "init":
        fixture.initialize()
    else:
        asyncio.run(fixture.serve())
