"""Настройки: переменные окружения, а если их нет — файл settings.env в корне проекта."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETTINGS_FILE = ROOT / "settings.env"


def _load_settings_file(path):
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


_load_settings_file(SETTINGS_FILE)

HOST = os.environ.get("HOST") or "127.0.0.1"
PORT = int(os.environ.get("PORT") or 8090)
DATA_DIR = Path(os.environ.get("DATA_DIR") or ROOT / "data")

AUTH_MODES = ("none", "basic", "authentik")
AUTH = (os.environ.get("AUTH") or "none").strip().lower()
AUTH_USER = os.environ.get("AUTH_USER") or ""
AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD") or ""
AUTHENTIK_LOGOUT = "/outpost.goauthentik.io/sign_out"


def check():
    if AUTH not in AUTH_MODES:
        sys.exit(f"AUTH={AUTH!r}: допустимо {', '.join(AUTH_MODES)}")
    if AUTH == "basic" and not (AUTH_USER and AUTH_PASSWORD):
        sys.exit("AUTH=basic: задайте AUTH_USER и AUTH_PASSWORD")
