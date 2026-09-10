"""Framing and small helpers shared by master.py and slave.py."""

import asyncio
import hashlib
import json
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
