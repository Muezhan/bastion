#!/usr/bin/env python3
"""bastion-server: single entry point for everything that runs on the
master (bastion) host - serving connections and managing client
credentials/certs.

Subcommands:
  serve          start the master and its operator console
  add-client     register a new slave, prints its one-time token
  remove-client  revoke a slave's credential
  list-clients   list configured slave names
  gen-cert       generate a self-signed TLS cert for this master (needs openssl)
  fingerprint    print a cert's sha256 fingerprint (to pin on slaves)
"""

import argparse
import sys

from bastion import credentials, tls
from bastion.master_core import run_serve


def cmd_serve(args):
    run_serve(args.host, args.port, args.cert, args.key, args.auth)


def cmd_add_client(args):
    token = credentials.add_client(args.auth, args.name)
    print(f"added '{args.name}'")
    print("give this token to the client - it is shown once and not stored anywhere:")
    print(f"  {token}")


def cmd_remove_client(args):
    if credentials.remove_client(args.auth, args.name):
        print(f"removed '{args.name}'")
    else:
        print(f"no such client: {args.name}")
        sys.exit(1)


def cmd_list_clients(args):
    for name in credentials.list_clients(args.auth):
        print(name)


def cmd_gen_cert(args):
    certfile, keyfile = tls.gen_cert(args.out, args.common_name)
    print(f"generated {certfile} and {keyfile}")
    print(f"fingerprint: {tls.fingerprint_of_file(certfile)}")


def cmd_fingerprint(args):
    print(tls.fingerprint_of_file(args.certfile))


def main():
    parser = argparse.ArgumentParser(prog="bastion-server", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="start the master and operator console")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8443)
    p_serve.add_argument("--cert", default="certs/master.crt")
    p_serve.add_argument("--key", default="certs/master.key")
    p_serve.add_argument("--auth", default="clients.json")
    p_serve.set_defaults(func=cmd_serve)

    p_add = sub.add_parser("add-client", help="register a new slave")
    p_add.add_argument("name")
    p_add.add_argument("--auth", default="clients.json")
    p_add.set_defaults(func=cmd_add_client)

    p_rm = sub.add_parser("remove-client", help="revoke a slave's credential")
    p_rm.add_argument("name")
    p_rm.add_argument("--auth", default="clients.json")
    p_rm.set_defaults(func=cmd_remove_client)

    p_ls = sub.add_parser("list-clients", help="list configured slave names")
    p_ls.add_argument("--auth", default="clients.json")
    p_ls.set_defaults(func=cmd_list_clients)

    p_cert = sub.add_parser("gen-cert", help="generate a self-signed TLS cert (needs openssl)")
    p_cert.add_argument("common_name", nargs="?", default="bastion-master")
    p_cert.add_argument("--out", default="certs")
    p_cert.set_defaults(func=cmd_gen_cert)

    p_fp = sub.add_parser("fingerprint", help="print a cert's sha256 fingerprint")
    p_fp.add_argument("certfile")
    p_fp.set_defaults(func=cmd_fingerprint)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
