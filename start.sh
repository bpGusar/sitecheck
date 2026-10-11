#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  if ! command -v python3 >/dev/null; then
    echo "Не найден python3. Установите Python 3.10 или новее: https://www.python.org/downloads/"
    exit 1
  fi
  python3 -m venv .venv
fi

if ! .venv/bin/python -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  echo "Нужен Python 3.10 или новее, а найден $(.venv/bin/python --version)."
  echo "Установите новый Python с https://www.python.org/downloads/, удалите папку .venv и запустите снова."
  exit 1
fi

if ! cmp -s requirements.txt .venv/requirements.txt; then
  echo "Первый запуск или обновление: ставлю зависимости и Chromium, это несколько минут…"
  .venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
  .venv/bin/python -m playwright install chromium
  cp requirements.txt .venv/requirements.txt
fi

exec .venv/bin/python -m app.main
