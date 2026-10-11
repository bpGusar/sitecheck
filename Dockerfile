# Образ Playwright уже содержит Chromium и все его системные зависимости.
# Версия образа должна совпадать с playwright в requirements.txt.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

ENV PYTHONUNBUFFERED=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app

CMD ["python3", "-m", "app.main"]
