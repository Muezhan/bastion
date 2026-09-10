"""Manage the master's client credential store (name -> sha256(token) hex)."""

import hashlib
import json
import secrets
from pathlib import Path


def load(path):
    p = Path(path)
    if p.exists():
        return json.loads(p.read_text())
    return {}


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n")


def add_client(path, name):
    data = load(path)
    token = secrets.token_urlsafe(32)
    data[name] = hashlib.sha256(token.encode()).hexdigest()
    save(path, data)
    return token


def remove_client(path, name):
    data = load(path)
    removed = data.pop(name, None) is not None
    if removed:
        save(path, data)
    return removed


def list_clients(path):
    return list(load(path).keys())
