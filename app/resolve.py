"""Резолвинг доменов всеми доступными способами и проверка доступности IP."""
import asyncio
import errno
import ipaddress
import socket
import ssl

import dns.asyncquery
import dns.message
import dns.rdatatype

# id → (подпись, тип, адрес)
RESOLVERS = {
    "system": ("Системный (как у браузера)", "system", None),
    "udp-cloudflare": ("1.1.1.1 (UDP)", "udp", "1.1.1.1"),
    "udp-google": ("8.8.8.8 (UDP)", "udp", "8.8.8.8"),
    "udp-yandex": ("77.88.8.8 (UDP, Яндекс)", "udp", "77.88.8.8"),
    "doh-cloudflare": ("Cloudflare DoH", "doh", "https://cloudflare-dns.com/dns-query"),
    "doh-google": ("Google DoH", "doh", "https://dns.google/dns-query"),
    "doh-quad9": ("Quad9 DoH", "doh", "https://dns.quad9.net/dns-query"),
    "doh-adguard": ("AdGuard DoH (без фильтров)", "doh", "https://unfiltered.adguard-dns.com/dns-query"),
    "doh-yandex": ("Яндекс DoH", "doh", "https://common.dot.dns.yandex.net/dns-query"),
}

DNS_TIMEOUT = 5.0


def _short_err(e: BaseException) -> str:
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)) or "timed out" in str(e).lower():
        return "таймаут"
    return (str(e) or e.__class__.__name__)[:120]


async def _system(host):
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM), DNS_TIMEOUT
        )
    except socket.gaierror as e:
        if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            return {"ips": [], "cnames": [], "error": "NXDOMAIN / нет записей"}
        raise
    return {"ips": sorted({i[4][0] for i in infos}), "cnames": [], "error": None}


async def _query(kind, where, host):
    ips, cnames, rcodes = set(), [], []
    for rdtype in ("A", "AAAA"):
        q = dns.message.make_query(host, rdtype)
        if kind == "udp":
            resp = await dns.asyncquery.udp_with_fallback(q, where, timeout=DNS_TIMEOUT)
            resp = resp[0]
        else:
            resp = await dns.asyncquery.https(q, where, timeout=DNS_TIMEOUT)
        rcodes.append(resp.rcode())
        for rrset in resp.answer:
            for rd in rrset:
                if rd.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    ips.add(rd.address)
                elif rd.rdtype == dns.rdatatype.CNAME:
                    c = rd.target.to_text(omit_final_dot=True)
                    if c not in cnames:
                        cnames.append(c)
    err = None
    if not ips:
        err = "NXDOMAIN" if 3 in rcodes else "нет A/AAAA записей"
    return {"ips": sorted(ips), "cnames": cnames, "error": err}


async def resolve_host(host, sem):
    """{resolver_id: {"ips", "cnames", "error"}} для одного домена."""

    async def one(rid):
        _, kind, where = RESOLVERS[rid]
        async with sem:
            try:
                if kind == "system":
                    return rid, await _system(host)
                return rid, await asyncio.wait_for(_query(kind, where, host), DNS_TIMEOUT * 3)
            except Exception as e:
                return rid, {"ips": [], "cnames": [], "error": _short_err(e)}

    return dict(await asyncio.gather(*(one(r) for r in RESOLVERS)))


# ── Проверка доступности IP ────────────────────────────────────────────

PROBE_TIMEOUT = 6.0

PROBE_LABELS = {
    "ok": "доступен",
    "tcp_timeout": "TCP: таймаут",
    "tcp_refused": "TCP: соединение отклонено",
    "tcp_reset": "TCP: сброс",
    "tls_timeout": "TLS: таймаут рукопожатия",
    "tls_reset": "TLS: сброс соединения",
    "tls_error": "TLS: ошибка",
    "http_freeze": "заморозка: данные оборвались (похоже на ТСПУ)",
    "http_timeout": "HTTP: нет ответа",
    "http_reset": "HTTP: соединение сброшено",
    "no_route": "нет маршрута (у вас нет IPv6?)",
    "bogon": "служебный адрес (loopback и т.п.), не проверялся",
    "error": "ошибка",
}


FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")


def ip_kind(ip):
    """public — обычный адрес; fakeip — подменный адрес VPN/прокси-клиента (sing-box, mihomo…):
    трафик на него уходит в туннель; private — частный (заглушка провайдера/роутера);
    local — loopback и т.п., такие не проверяем, иначе попадём в сервисы самого хоста."""
    a = ipaddress.ip_address(ip)
    if a.version == 4 and a in FAKE_IP_NET:
        return "fakeip"
    if a.is_loopback or a.is_unspecified or a.is_link_local or a.is_multicast or a.is_reserved:
        return "local"
    if not a.is_global:
        return "private"
    return "public"


def is_bogon(ip):
    return ip_kind(ip) != "public"


def _has_ipv6_route():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 53))  # UDP connect ничего не отправляет
        s.close()
        return True
    except OSError:
        return False


async def probe(host, ip, port, use_tls, sem):
    """TCP-соединение и (для HTTPS) TLS-рукопожатие с SNI домена.

    Сертификат не проверяем: важен факт, пропускают ли соединение.
    Проверка с SNI важна, потому что DPI часто режет именно по имени в ClientHello.
    """
    if ip_kind(ip) == "local":
        return {"status": "bogon", "detail": None}
    if ":" in ip and not _HAS_V6:
        return {"status": "no_route", "detail": None}
    async with sem:
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), PROBE_TIMEOUT)
        except asyncio.TimeoutError:
            return {"status": "tcp_timeout", "detail": None}
        except ConnectionRefusedError:
            return {"status": "tcp_refused", "detail": None}
        except ConnectionResetError:
            return {"status": "tcp_reset", "detail": None}
        except OSError as e:
            if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL):
                return {"status": "no_route" if ":" in ip else "tcp_timeout", "detail": e.strerror}
            return {"status": "error", "detail": str(e)[:120]}
        tcp_ms = round((loop.time() - t0) * 1000)
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    await asyncio.wait_for(writer.start_tls(ctx, server_hostname=host), PROBE_TIMEOUT)
                except asyncio.TimeoutError:
                    return {"status": "tls_timeout", "detail": f"TCP {tcp_ms} мс"}
                except (ConnectionResetError, BrokenPipeError):
                    return {"status": "tls_reset", "detail": f"TCP {tcp_ms} мс"}
                except ssl.SSLError as e:
                    # сервер ответил, но не TLS-хендшейком — сеть пропускает, считаем доступным
                    return {"status": "tls_error", "detail": (e.reason or str(e))[:120]}
                except OSError as e:
                    return {"status": "tls_reset", "detail": str(e)[:120]}
            status, detail = await _http(reader, writer, host)
            prefix = f"TCP {tcp_ms} мс" + (", TLS ок" if use_tls else "")
            return {"status": status, "detail": f"{prefix}, {detail}"}
        finally:
            writer.close()


HTTP_FIRST_BYTE = 8.0
HTTP_STALL = 6.0
HTTP_ENOUGH = 128 * 1024  # столько прошло без обрыва — значит, не «заморозка»


def _complete(buf: bytes) -> bool:
    """Пришёл ли ответ целиком (сервер мог не закрыть соединение после него)."""
    head, sep, body = buf.partition(b"\r\n\r\n")
    if not sep:
        return False
    headers = head.decode("latin-1").lower()
    for line in headers.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        if name.strip() == "content-length" and value.strip().isdigit():
            return len(body) >= int(value.strip())
    if "transfer-encoding: chunked" in headers:
        return body.endswith(b"0\r\n\r\n")
    code = headers[9:12]
    return code in ("204", "304") or code.startswith("1")


async def _http(reader, writer, host):
    """GET / и чтение ответа. ТСПУ часто пропускает TCP и TLS, но после ~16 КБ
    перестаёт передавать данные — это видно только по обрыву посреди ответа."""
    req = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
        "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    )
    buf = b""
    try:
        writer.write(req.encode())
        await writer.drain()
        while len(buf) < HTTP_ENOUGH:
            chunk = await asyncio.wait_for(reader.read(65536), HTTP_STALL if buf else HTTP_FIRST_BYTE)
            if not chunk:
                break
            buf += chunk
            if _complete(buf):
                break
    except asyncio.TimeoutError:
        if not buf:
            return "http_timeout", f"нет ответа за {HTTP_FIRST_BYTE:.0f} с"
        return "http_freeze", f"получено {len(buf) / 1024:.1f} КБ, дальше тишина"
    except (ConnectionResetError, BrokenPipeError):
        if not buf:
            return "http_reset", "сброс после запроса"
        return "http_freeze", f"сброс после {len(buf) / 1024:.1f} КБ"
    except (ssl.SSLError, OSError):
        if not buf:
            return "http_reset", "обрыв после запроса"
    if not buf:
        return "http_reset", "соединение закрыто без ответа"
    code = buf[9:12].decode("latin-1", "replace")
    return "ok", f"HTTP {code}, {len(buf) / 1024:.1f} КБ"


_HAS_V6 = _has_ipv6_route()
