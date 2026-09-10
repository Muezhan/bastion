"""Bastion master: accepts registrations from slaves and lets an operator
attach to any of them by name to run commands.
"""

import asyncio
import hashlib
import hmac
import json
import ssl
import sys
from pathlib import Path

from bastion.common import send_msg, recv_msg


class ClientConn:
    def __init__(self, name, writer):
        self.name = name
        self.writer = writer
        self.out_queue = asyncio.Queue()


class State:
    def __init__(self, auth):
        self.auth = auth  # name -> sha256(token) hex
        self.clients = {}  # name -> ClientConn


def load_auth(path):
    return json.loads(Path(path).read_text())


def check_token(state, name, token):
    expected = state.auth.get(name)
    if expected is None:
        return False
    actual = hashlib.sha256(token.encode()).hexdigest()
    return hmac.compare_digest(expected, actual)


async def handle_client(reader, writer, state):
    peer = writer.get_extra_info("peername")
    name = None
    try:
        msg = await recv_msg(reader)
        if not msg or msg.get("type") != "register":
            writer.close()
            return

        name = msg.get("name")
        token = msg.get("token", "")
        if not name or not check_token(state, name, token):
            await send_msg(writer, {"type": "register_fail", "reason": "bad credentials"})
            writer.close()
            return
        if name in state.clients:
            await send_msg(writer, {"type": "register_fail", "reason": "already connected"})
            writer.close()
            return

        await send_msg(writer, {"type": "register_ok"})
        conn = ClientConn(name, writer)
        state.clients[name] = conn
        print(f"[+] '{name}' connected ({peer})")

        while True:
            msg = await recv_msg(reader)
            if msg is None:
                break
            await conn.out_queue.put(msg)
    except (ConnectionError, ValueError, ssl.SSLError):
        pass
    finally:
        if name and state.clients.get(name) and state.clients[name].writer is writer:
            del state.clients[name]
            print(f"[-] '{name}' disconnected")
        writer.close()


async def shell_session(state, name):
    conn = state.clients.get(name)
    if not conn:
        print(f"no such client: {name}")
        return

    print(f"-- attached to '{name}'; type 'exit' to detach --")
    while True:
        try:
            line = await asyncio.to_thread(input, f"{name}$ ")
        except EOFError:
            print()
            return

        if line.strip() in ("exit", "quit"):
            return
        if not line.strip():
            continue
        if name not in state.clients:
            print(f"[{name}] disconnected")
            return

        try:
            await send_msg(conn.writer, {"type": "cmd", "cmd": line})
        except (ConnectionError, OSError):
            print(f"[{name}] connection lost")
            state.clients.pop(name, None)
            return

        try:
            msg = await asyncio.wait_for(conn.out_queue.get(), timeout=300)
        except asyncio.TimeoutError:
            print(f"[{name}] timed out waiting for output")
            continue

        if msg is None:
            print(f"[{name}] disconnected")
            state.clients.pop(name, None)
            return

        if msg.get("type") == "output":
            if msg.get("stdout"):
                sys.stdout.write(msg["stdout"])
            if msg.get("stderr"):
                sys.stderr.write(msg["stderr"])
            code = msg.get("returncode")
            if code not in (0, None):
                print(f"[exit code {code}]")


async def repl(state):
    print("bastion master ready. commands: list, use <name>, exit")
    while True:
        try:
            line = await asyncio.to_thread(input, "bastion> ")
        except EOFError:
            print()
            return

        line = line.strip()
        if not line:
            continue
        if line == "list":
            if not state.clients:
                print("(no clients connected)")
            for n in state.clients:
                print(n)
        elif line.startswith("use "):
            await shell_session(state, line.split(maxsplit=1)[1].strip())
        elif line in ("exit", "quit"):
            return
        else:
            print("unknown command. try: list, use <name>, exit")


def build_ssl_context(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    return ctx


async def serve(host, port, certfile, keyfile, auth_path):
    state = State(load_auth(auth_path))
    ssl_ctx = build_ssl_context(certfile, keyfile)

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, state), host, port, ssl=ssl_ctx
    )
    print(f"listening on {host}:{port}")

    async with server:
        serve_task = asyncio.create_task(server.serve_forever())
        repl_task = asyncio.create_task(repl(state))
        _, pending = await asyncio.wait(
            {serve_task, repl_task}, return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()


def run_serve(host, port, certfile, keyfile, auth_path):
    try:
        asyncio.run(serve(host, port, certfile, keyfile, auth_path))
    except KeyboardInterrupt:
        pass
