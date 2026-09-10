"""Framing and small helpers shared by master.py and slave.py."""

import asyncio
import hashlib
import json
import os
import struct

# Cap a single message (mainly command output) so a runaway command can't
# exhaust memory on either end.
MAX_MESSAGE_SIZE = 50 * 1024 * 1024


async def send_msg(writer, payload):
    data = json.dumps(payload).encode("utf-8")
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()


async def recv_msg(reader):
    """Returns the decoded message dict, or None on clean EOF/disconnect."""
    try:
        header = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None
    (length,) = struct.unpack(">I", header)
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"message too large: {length} bytes")
    try:
        data = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None
    return json.loads(data.decode("utf-8"))


def cert_fingerprint(der_bytes):
    return hashlib.sha256(der_bytes).hexdigest()


def subprocess_env():
    """Environment for spawning external programs from a PyInstaller
    onefile binary. The bootloader points LD_LIBRARY_PATH at its own
    extraction dir so bundled libssl/libcrypto get picked up by this
    process, but that leaks into every child process too - a dynamically
    linked binary the child runs can end up loading our bundled (often
    mismatched) libs and fail with missing symbol versions. Restore the
    original value PyInstaller stashed away before spawning children.
    No-op outside a PyInstaller bundle (LD_LIBRARY_PATH_ORIG is unset).
    """
    env = os.environ.copy()
    original = env.pop("LD_LIBRARY_PATH_ORIG", None)
    if original is not None:
        env["LD_LIBRARY_PATH"] = original
    else:
        env.pop("LD_LIBRARY_PATH", None)
    return env
