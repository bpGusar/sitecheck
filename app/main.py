"""HTTP-API и раздача UI. Проверки идут строго по одной (Chromium тяжёлый)."""
import asyncio
import base64
import binascii
import json
import logging
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import tldextract
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from . import adlists, asn, checker, config, route

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
log = logging.getLogger("sitecheck")
logging.getLogger("httpx").setLevel(logging.WARNING)

STATIC = Path(__file__).parent / "static"
RESULTS = config.DATA_DIR / "results"
HISTORY_LIMIT = 50
TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
CHECK_LIMIT = 600  # страховка: одна повисшая проверка не должна стопорить очередь

JOBS: dict[str, dict] = {}
QUEUE: asyncio.Queue = asyncio.Queue()


def _save(job):
    RESULTS.mkdir(parents=True, exist_ok=True)
    tmp = RESULTS / f"{job['id']}.json.part"
    tmp.write_text(json.dumps(job, ensure_ascii=False))
    tmp.replace(RESULTS / f"{job['id']}.json")
    files = sorted(RESULTS.glob("*.json"), key=lambda p: p.stat().st_mtime)
    for old in files[:-HISTORY_LIMIT]:
        old.unlink(missing_ok=True)


def _load_history():
    if not RESULTS.exists():
        return
    for p in sorted(RESULTS.glob("*.json"), key=lambda p: p.stat().st_mtime):
        try:
            job = json.loads(p.read_text())
            JOBS[job["id"]] = job
        except Exception:
            log.warning("не прочитал %s", p)


async def _worker():
    while True:
        job_id = await QUEUE.get()
        job = JOBS[job_id]
        job["state"] = "running"

        def progress(msg):
            job["progress"] = msg

        try:
            job["result"] = await asyncio.wait_for(checker.run_check(job["url"], progress), CHECK_LIMIT)
            job["state"] = "done"
        except asyncio.TimeoutError:
            job["state"] = "error"
            job["error"] = f"проверка не уложилась в {CHECK_LIMIT // 60} минут и была прервана"
        except Exception as e:
            log.exception("проверка %s упала", job["url"])
            job["state"] = "error"
            job["error"] = str(e) or e.__class__.__name__
        job["progress"] = None
        job["finished"] = time.time()
        try:
            _save(job)
        except OSError:
            log.exception("не сохранил результат")


@asynccontextmanager
async def lifespan(_app):
    _load_history()
    worker = asyncio.create_task(_worker())
    for db in (*asn.LOCAL_DBS, adlists.ADLISTS, route.CLOUDFRONT):  # скачать базы заранее, не на первой проверке
        db.refresh_in_background()
    yield
    worker.cancel()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)


def _basic_ok(header):
    scheme, _, token = (header or "").partition(" ")
    if scheme.lower() != "basic":
        return False
    try:
        user, sep, password = base64.b64decode(token, validate=True).decode("utf-8").partition(":")
    except (binascii.Error, UnicodeDecodeError):
        return False
    user_ok = secrets.compare_digest(user.encode(), config.AUTH_USER.encode())
    password_ok = secrets.compare_digest(password.encode(), config.AUTH_PASSWORD.encode())
    return bool(sep) and user_ok and password_ok


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    if config.AUTH == "basic" and not _basic_ok(request.headers.get("authorization")):
        return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="sitecheck", charset="UTF-8"'})
    return await call_next(request)


class CheckIn(BaseModel):
    url: str


@app.post("/api/check")
async def create_check(body: CheckIn):
    try:
        url = checker.normalize_url(body.url)
    except ValueError as e:
        raise HTTPException(400, str(e))
    adlists.ADLISTS.refresh_in_background()
    route.CLOUDFRONT.refresh_in_background()
    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "id": job_id,
        "url": url,
        "state": "queued",
        "progress": "В очереди…",
        "created": time.time(),
    }
    await QUEUE.put(job_id)
    return {"id": job_id}


@app.get("/api/check/{job_id}")
async def get_check(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "нет такой проверки")
    result = job.get("result") or {}
    hosts = result.get("hosts", [])
    ads = adlists.ADLISTS.classify(
        [h["host"] for h in hosts if h["role"] != "main"],
        [h["host"] for h in hosts if h["role"] == "main"],
    )
    out = {**job, "bases": {h["host"]: _base_domain(h["host"]) for h in hosts}, "ads": ads}
    if hosts:
        out["route"] = route.build(result, ads, _base_domain)
    return out


def _base_domain(host):
    return TLD(host).top_domain_under_public_suffix or host


@app.get("/api/history")
async def history():
    items = sorted(JOBS.values(), key=lambda j: j["created"], reverse=True)[:HISTORY_LIMIT]
    out = []
    for j in items:
        r = j.get("result") or {}
        hosts = r.get("hosts", [])
        out.append(
            {
                "id": j["id"],
                "url": j["url"],
                "state": j["state"],
                "created": j["created"],
                "main_status": (r.get("main") or {}).get("status"),
                "hosts": len(hosts),
                "failed": sum(1 for h in hosts if h["status"] in ("fail", "partial") or h["ips_failed"]),
            }
        )
    return out


@app.get("/api/me")
async def me(request: Request):
    if config.AUTH == "authentik":
        return {
            "username": request.headers.get("x-authentik-username"),
            "name": request.headers.get("x-authentik-name"),
            "logout": config.AUTHENTIK_LOGOUT,
        }
    if config.AUTH == "basic":
        return {"username": config.AUTH_USER, "name": None, "logout": None}
    return {"username": None, "name": None, "logout": None}


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


def _warn_exposure():
    local = config.HOST in ("127.0.0.1", "localhost", "::1")
    if config.AUTH == "none" and not local:
        log.warning("HOST=%s без авторизации: страница открыта всем, кто видит этот адрес", config.HOST)
    if config.AUTH == "authentik" and not local:
        log.warning("AUTH=authentik и HOST=%s: в обход прокси можно подделать заголовки authentik", config.HOST)
    if config.AUTH == "basic" and not local:
        log.warning("AUTH=basic без HTTPS: пароль идёт по сети открытым текстом, используйте только в доверенной сети")


if __name__ == "__main__":
    config.check()
    _warn_exposure()
    shown = "localhost" if config.HOST in ("127.0.0.1", "0.0.0.0", "::") else config.HOST
    log.info("страница: http://%s:%d (вход: %s, данные: %s)", shown, config.PORT, config.AUTH, config.DATA_DIR)
    uvicorn.run(app, host=config.HOST, port=config.PORT)
