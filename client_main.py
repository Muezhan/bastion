#!/usr/bin/env python3
"""bastion-client: single entry point for the slave agent. Dials out to the
master, registers under a name, and runs whatever commands the master sends
as this process's own OS user.
"""

import argparse

from bastion.slave_core import run_client


def main():
    parser = argparse.ArgumentParser(prog="bastion-client", description=__doc__)
    parser.add_argument("--host", required=True, help="master's hostname or IP")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--name", required=True, help="this slave's registered name")
    parser.add_argument("--token", required=True, help="this slave's secret token")
    parser.add_argument(
        "--fingerprint",
        help="sha256 fingerprint of the master's TLS cert (from 'bastion-server fingerprint'); strongly recommended",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip certificate pinning - testing only, vulnerable to MITM",
    )
    args = parser.parse_args()

    run_client(args.host, args.port, args.name, args.token, args.fingerprint, args.insecure)


if __name__ == "__main__":
    main()
