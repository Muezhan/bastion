"""Bastion slave: dials out to the master, registers under a name, and runs
whatever commands the master sends. Runs the commands as whatever OS user
this process runs as - run it as root only if you want the master to have
root on this box.
"""

import asyncio
import hmac
import ssl

from bastion.common import send_msg, recv_msg, cert_fingerprint, subprocess_env


async def run_cmd(cmd):
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=subprocess_env(),
    )
    stdout, stderr = await proc.communicate()
    return {
        "type": "output",
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
        "returncode": proc.returncode,
    }


def build_ssl_context():
    # We don't rely on a CA chain - trust is established by pinning the
    # master's certificate fingerprint instead (checked right after connect).
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def connect_once(host, port, name, token, fingerprint):
    ctx = build_ssl_context()
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)

    if fingerprint:
        ssl_obj = writer.get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True)
        actual = cert_fingerprint(der)
        if not hmac.compare_digest(actual, fingerprint.lower()):
            print(
                f"FATAL: master certificate fingerprint mismatch "
                f"(expected {fingerprint}, got {actual}) - possible MITM, aborting"
            )
            writer.close()
            raise SystemExit(1)

    await send_msg(writer, {"type": "register", "name": name, "token": token})
    reply = await recv_msg(reader)
    if not reply or reply.get("type") != "register_ok":
        reason = reply.get("reason") if reply else "no response"
        print(f"registration failed: {reason}")
        writer.close()
        return

    print(f"registered as '{name}', awaiting commands...")
    while True:
        msg = await recv_msg(reader)
        if msg is None:
            print("connection closed by master")
            return
        if msg.get("type") == "cmd":
            result = await run_cmd(msg["cmd"])
            await send_msg(writer, result)


async def run_client_loop(host, port, name, token, fingerprint, insecure):
    if not fingerprint and not insecure:
        print("refusing to connect without a fingerprint (or explicit insecure mode for testing)")
        raise SystemExit(1)

    backoff = 2
    while True:
        try:
            await connect_once(host, port, name, token, fingerprint)
            backoff = 2
        except SystemExit:
            raise
        except (ConnectionError, OSError, ssl.SSLError) as e:
            print(f"connection error: {e}")

        print(f"reconnecting in {backoff}s...")
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60)


def run_client(host, port, name, token, fingerprint, insecure):
    try:
        asyncio.run(run_client_loop(host, port, name, token, fingerprint, insecure))
    except KeyboardInterrupt:
        pass
