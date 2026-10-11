"""Одна проверка: браузер → DNS всеми резолверами → ASN всеми источниками → проба IP."""
import asyncio
import time
from urllib.parse import urlsplit

from playwright.async_api import Error as PWError
from playwright.async_api import async_playwright

from . import asn as asnmod
from . import resolve

NAV_TIMEOUT_MS = 30_000
IDLE_TIMEOUT_MS = 10_000
SETTLE_SECONDS = 4
SCROLL_TIMEOUT = 10
BROWSER_LIMIT = 80

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)

# Ошибки, которые не говорят о недоступности: запрос отменила сама страница
# или браузер отказался использовать уже полученный ответ.
BENIGN_ERRORS = (
    "net::ERR_ABORTED",
    "net::ERR_BLOCKED_BY_CLIENT",
    "net::ERR_BLOCKED_BY_RESPONSE",
    "net::ERR_BLOCKED_BY_ORB",
    "net::ERR_CACHE_MISS",
)

PROBE_FAIL = {
    "tcp_timeout", "tcp_refused", "tcp_reset", "tls_timeout", "tls_reset",
    "http_freeze", "http_timeout", "http_reset",
}
PROBE_SKIPPED = {"no_route", "bogon", "error"}
STUCK_TYPES = {"document", "stylesheet", "script", "image", "font"}
STUCK_ERROR = "ответ не догрузился (завис)"


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("нужен адрес сайта, например example.com или https://example.com")
    return raw


class HostStats:
    def __init__(self):
        self.requests = 0
        self.ok = 0
        self.errors = {}  # текст ошибки → количество
        self.benign = 0
        self.browser_ips = set()
        self.schemes = set()
        self.ports = set()
        self.example_failed = None


def _host_of(url):
    try:
        p = urlsplit(url)
    except ValueError:
        return None, None, None
    if p.scheme not in ("http", "https", "ws", "wss") or not p.hostname:
        return None, None, None
    tls = p.scheme in ("https", "wss")
    return p.hostname.lower().rstrip("."), tls, p.port or (443 if tls else 80)


async def _run_browser(url, stats, progress):
    main = {"error": None, "http_status": None, "final_url": None, "redirects": []}
    pending = set()
    inflight = {}
    responded = set()

    def st(u):
        host, tls, port = _host_of(u)
        if not host:
            return None
        s = stats.setdefault(host, HostStats())
        s.schemes.add("https" if tls else "http")
        s.ports.add(port)
        return s

    def on_request(req):
        if s := st(req.url):
            s.requests += 1
            if req.resource_type in STUCK_TYPES:
                inflight[req] = s

    def on_finished(req):
        inflight.pop(req, None)

    async def on_response(resp):
        s = st(resp.url)
        if not s:
            return
        s.ok += 1
        try:
            addr = await resp.server_addr()
            if addr and addr.get("ipAddress"):
                s.browser_ips.add(addr["ipAddress"].strip("[]"))
        except PWError:
            pass

    def on_response_sync(resp):
        responded.add(resp.request)
        t = asyncio.ensure_future(on_response(resp))
        pending.add(t)
        t.add_done_callback(pending.discard)

    def on_failed(req):
        inflight.pop(req, None)
        s = st(req.url)
        if not s:
            return
        err = (req.failure or "unknown").strip()
        if err.startswith(BENIGN_ERRORS):
            s.benign += 1
        else:
            s.errors[err] = s.errors.get(err, 0) + 1
            s.example_failed = s.example_failed or req.url

    def on_websocket(ws):
        if s := st(ws.url):
            s.requests += 1
            ws.on("socketerror", lambda e: on_ws_error(s, e))

    def on_ws_error(s, e):
        key = f"WebSocket: {e}"
        s.errors[key] = s.errors.get(key, 0) + 1

    async def drive(browser):
        ctx = await browser.new_context(
            user_agent=USER_AGENT,
            locale="ru-RU",
            viewport={"width": 1366, "height": 900},
            service_workers="block",  # иначе запросы воркера не видны в событиях
        )
        ctx.on("request", on_request)
        ctx.on("response", on_response_sync)
        ctx.on("requestfailed", on_failed)
        ctx.on("requestfinished", on_finished)
        page = await ctx.new_page()
        page.on("websocket", on_websocket)

        progress("Открываю сайт в браузере…")
        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
            if resp:
                main["http_status"] = resp.status
                r = resp.request.redirected_from
                while r:
                    main["redirects"].insert(0, r.url)
                    r = r.redirected_from
        except PWError as e:
            msg = str(e).splitlines()[0]
            main["error"] = msg.removeprefix("Page.goto: ")
        main["final_url"] = page.url if page.url not in ("about:blank", "") else None

        if main["error"]:
            # Страница не загрузилась (часто это блокировка): даём ещё пару секунд
            # на уже начатые запросы и не ждём догрузки.
            progress("Сайт не загрузился, собираю то, что успело прийти…")
            await asyncio.sleep(3)
            return
        progress("Жду догрузки и прокручиваю страницу…")
        await _quiet(page.wait_for_load_state("load", timeout=NAV_TIMEOUT_MS), NAV_TIMEOUT_MS / 1000 + 2)
        await _quiet(page.wait_for_load_state("networkidle", timeout=IDLE_TIMEOUT_MS), IDLE_TIMEOUT_MS / 1000 + 2)
        await _quiet(
            page.evaluate(
                """async () => {
                    for (let i = 0; i < 12; i++) {
                        window.scrollBy(0, window.innerHeight);
                        await new Promise(r => setTimeout(r, 300));
                    }
                    window.scrollTo(0, 0);
                }"""
            ),
            SCROLL_TIMEOUT,
        )
        await asyncio.sleep(SETTLE_SECONDS)
        await _quiet(page.wait_for_load_state("networkidle", timeout=IDLE_TIMEOUT_MS // 2), IDLE_TIMEOUT_MS / 2000 + 2)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        try:
            # Жёсткий лимит на весь браузерный этап: любой вызов Playwright может
            # повиснуть на полузагруженной странице (например, при «заморозке» ТСПУ).
            await asyncio.wait_for(drive(browser), BROWSER_LIMIT)
        except asyncio.TimeoutError:
            main["error"] = main["error"] or f"страница не загрузилась за {BROWSER_LIMIT} с"
        finally:
            if pending:
                await asyncio.wait(pending, timeout=5)
            for req, s in inflight.items():
                s.errors[STUCK_ERROR] = s.errors.get(STUCK_ERROR, 0) + 1
                if req in responded:
                    s.ok -= 1
            await _quiet(browser.close(), 10)
        # выход из async_playwright гасит драйвер, а вместе с ним и Chromium
    return main


async def _quiet(aw, timeout):
    """Ждать не дольше timeout секунд и не падать: этот шаг не обязателен."""
    try:
        await asyncio.wait_for(aw, timeout)
    except (asyncio.TimeoutError, PWError):
        pass


def _host_status(s: HostStats):
    failed = sum(s.errors.values())
    if s.ok and failed:
        return "partial"
    if s.ok:
        return "ok"
    if failed:
        return "fail"
    return "unknown"


async def run_check(raw_url, progress):
    t0 = time.time()
    url = normalize_url(raw_url)
    main_host = urlsplit(url).hostname.lower().rstrip(".")
    stats: dict[str, HostStats] = {}
    resolve._HAS_V6 = resolve._has_ipv6_route()

    main = await _run_browser(url, stats, progress)
    stats.setdefault(main_host, HostStats())
    main_hosts = {main_host}
    for u in main["redirects"] + ([main["final_url"]] if main["final_url"] else []):
        h, _, _ = _host_of(u)
        if h:
            main_hosts.add(h)

    hosts = sorted(stats)
    progress(f"Резолвлю {len(hosts)} доменов через {len(resolve.RESOLVERS)} DNS…")
    dns_sem = asyncio.Semaphore(40)
    dns_results = dict(
        zip(hosts, await asyncio.gather(*(resolve.resolve_host(h, dns_sem) for h in hosts)))
    )

    # Итоговый список IP домена = объединение всех резолверов + фактический IP браузера.
    host_ips: dict[str, dict[str, list[str]]] = {}
    for h in hosts:
        m: dict[str, list[str]] = {}
        for ip in sorted(stats[h].browser_ips):
            m.setdefault(ip, []).append("browser")
        for rid, r in dns_results[h].items():
            for ip in r["ips"]:
                m.setdefault(ip, []).append(rid)
        host_ips[h] = m

    all_ips = {ip for m in host_ips.values() for ip in m}
    public_ips = [ip for ip in all_ips if not resolve.is_bogon(ip)]

    progress(f"Проверяю доступность {sum(len(m) for m in host_ips.values())} пар домен/IP и ищу ASN для {len(public_ips)} IP…")
    probe_sem = asyncio.Semaphore(48)

    async def probe_host(h):
        s = stats[h]
        use_tls = "https" in s.schemes or not s.schemes
        port = 443 if use_tls else 80
        if s.ports and len(s.ports) == 1:
            port = next(iter(s.ports))
        ips = list(host_ips[h])
        res = await asyncio.gather(*(resolve.probe(h, ip, port, use_tls, probe_sem) for ip in ips))
        return h, dict(zip(ips, res)), port, use_tls

    probe_task = asyncio.gather(*(probe_host(h) for h in hosts))
    asn_task = asnmod.lookup_all(public_ips)
    probes_list, (asn_per_ip, asn_info, asn_sources) = await asyncio.gather(probe_task, asn_task)
    probes = {h: (p, port, tls) for h, p, port, tls in probes_list}

    def asn_list(ip):
        return sorted(set(asn_per_ip.get(ip, {}).values()))

    host_rows = []
    for h in hosts:
        s = stats[h]
        p, port, tls = probes[h]
        ips = []
        for ip, srcs in host_ips[h].items():
            ips.append(
                {
                    "ip": ip,
                    "family": 6 if ":" in ip else 4,
                    "kind": resolve.ip_kind(ip),
                    "sources": srcs,
                    "asns": asn_list(ip),
                    "probe": p[ip],
                }
            )
        ips.sort(key=lambda x: (x["family"], x["ip"]))
        dns_errors = [r["error"] for r in dns_results[h].values() if r["error"]]
        no_dns = not ips and len(dns_errors) == len(resolve.RESOLVERS)
        ips_failed = sum(1 for i in ips if i["probe"]["status"] in PROBE_FAIL)
        ips_checked = sum(1 for i in ips if i["probe"]["status"] not in PROBE_SKIPPED)
        status = _host_status(s)
        # Браузер мог дойти через VPN/fake-IP, но прямые IP при этом режутся — это тоже проблема.
        if status == "ok" and ips_failed:
            status = "partial"
        elif status == "unknown":
            if no_dns or (ips_checked and ips_failed == ips_checked):
                status = "fail"
            elif ips_failed:
                status = "partial"
            elif ips_checked:
                status = "ok"
        if h == main_host and main["error"]:
            status = "fail"
        host_rows.append(
            {
                "host": h,
                "role": "main" if h in main_hosts else "related",
                "status": status,
                "requests": s.requests,
                "ok": s.ok,
                "benign": s.benign,
                "errors": s.errors,
                "example_failed": s.example_failed,
                "probe_port": port,
                "probe_tls": tls,
                "ips": ips,
                "asns": sorted({a for i in ips for a in i["asns"]}),
                "cnames": sorted({c for r in dns_results[h].values() for c in r["cnames"]}),
                "no_dns": no_dns,
                "ips_failed": ips_failed,
            }
        )

    # ASN: имя берём из самого «говорящего» источника
    asns_out = {}
    for a, info in asn_info.items():
        names = info["names"]
        best = next((names[k] for k in ("ripestat", "cymru", "ipapi", "ipinfo", "ipdb", "iptoasn") if names.get(k)), "")
        asns_out[a] = {"asn": a, "name": best, "names": names}

    main_row = next(r for r in host_rows if r["host"] == main_host)
    return {
        "url": url,
        "main_host": main_host,
        "main": {**main, "status": main_row["status"]},
        "hosts": host_rows,
        "asns": asns_out,
        "asn_by_ip": asn_per_ip,
        "asn_sources": asn_sources,
        "dns": dns_results,
        "resolvers": {k: v[0] for k, v in resolve.RESOLVERS.items()},
        "probe_labels": resolve.PROBE_LABELS,
        "has_ipv6": resolve._HAS_V6,
        "started": t0,
        "duration": round(time.time() - t0, 1),
    }
