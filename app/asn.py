"""Определение ASN по IP из нескольких независимых источников.

Каждый источник возвращает {ip: (asn, name)}; результаты потом сливаются,
и у каждого ASN остаётся список источников, которые его подтвердили.
"""
import asyncio
import bisect
import csv
import gzip
import ipaddress
import logging
import os
import time

import dns.asyncresolver
import dns.reversename
import httpx

from . import config

log = logging.getLogger("asn")

DATA_DIR = str(config.DATA_DIR)
DB_MAX_AGE = 24 * 3600

SOURCES = {
    "iptoasn": "iptoasn.com (локальная база)",
    "ipdb": "ip-location-db (локальная база)",
    "cymru": "Team Cymru (DNS)",
    "ripestat": "RIPEstat",
    "ipapi": "ip-api.com",
    "ipinfo": "ipinfo.io",
}

HTTP_TIMEOUT = httpx.Timeout(10.0)


def _rows_iptoasn(path):
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 5:
                yield p[0], p[1], int(p[2]), p[4]


def _rows_csv(path):
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for p in csv.reader(f):
            if len(p) >= 4:
                yield p[0], p[1], int(p[2]), p[3]


class LocalDb:
    """Локальная база диапазонов IP → ASN. Качается в фоне и обновляется раз в сутки;
    пока скачивается, проверки идут без неё (не ждут)."""

    def __init__(self, name, files, parser):
        self.name = name
        self.files = files  # [(url, путь)]
        self.parser = parser
        self.tables = {4: ([], []), 6: ([], [])}
        self.loaded_at = 0.0
        self.error = None
        self.task = None

    @property
    def ready(self):
        return bool(self.tables[4][0])

    def _mtime(self):
        try:
            return min(os.path.getmtime(p) for _, p in self.files)
        except OSError:
            return None

    def refresh_in_background(self):
        if self.task and not self.task.done():
            return
        self.task = asyncio.create_task(self._refresh())

    async def _refresh(self):
        m = self._mtime()
        if m is None or time.time() - m > DB_MAX_AGE:
            try:
                for url, path in self.files:
                    await self._download(url, path)
                self.error = None
            except Exception as e:  # старая база лучше, чем никакой
                self.error = f"не удалось скачать базу: {e or e.__class__.__name__}"
                log.warning("%s: %s", self.name, self.error)
        m = self._mtime()
        if m and m > self.loaded_at:
            try:
                self.tables = await asyncio.to_thread(self._load)
                self.loaded_at = m
            except Exception as e:
                self.error = f"не удалось прочитать базу: {e}"
                log.warning("%s: %s", self.name, self.error)

    async def _download(self, url, path):
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = path + ".part"
        timeout = httpx.Timeout(60.0, read=120.0)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            async with c.stream("GET", url) as r:
                r.raise_for_status()
                with open(tmp, "wb") as f:
                    async for chunk in r.aiter_bytes():
                        f.write(chunk)
        os.replace(tmp, path)
        log.info("%s: скачан %s", self.name, url)

    def _load(self):
        tables = {4: ([], []), 6: ([], [])}
        for _, path in self.files:
            for start_s, end_s, asn, name in self.parser(path):
                if asn == 0:  # «Not routed»
                    continue
                start = ipaddress.ip_address(start_s)
                starts, rows = tables[start.version]
                starts.append(int(start))
                rows.append((int(ipaddress.ip_address(end_s)), asn, name))
        for v in (4, 6):  # на случай, если файл не отсортирован
            starts, rows = tables[v]
            order = sorted(range(len(starts)), key=starts.__getitem__)
            tables[v] = ([starts[i] for i in order], [rows[i] for i in order])
        log.info("%s: загружено %d + %d диапазонов", self.name, len(tables[4][0]), len(tables[6][0]))
        return tables

    def lookup(self, ip: str):
        addr = ipaddress.ip_address(ip)
        starts, rows = self.tables[addr.version]
        i = bisect.bisect_right(starts, int(addr)) - 1
        if i >= 0 and int(addr) <= rows[i][0]:
            return rows[i][1], rows[i][2]
        return None

    async def source(self, ips):
        self.refresh_in_background()
        if not self.ready:
            raise RuntimeError(self.error or "база ещё скачивается, будет в следующих проверках")
        return {ip: r for ip in ips if (r := self.lookup(ip))}


IPTOASN = LocalDb(
    "iptoasn",
    [("https://iptoasn.com/data/ip2asn-combined.tsv.gz", os.path.join(DATA_DIR, "ip2asn-combined.tsv.gz"))],
    _rows_iptoasn,
)
IPDB = LocalDb(
    "ip-location-db",
    [
        ("https://cdn.jsdelivr.net/npm/@ip-location-db/asn/asn-ipv4.csv", os.path.join(DATA_DIR, "asn-ipv4.csv")),
        ("https://cdn.jsdelivr.net/npm/@ip-location-db/asn/asn-ipv6.csv", os.path.join(DATA_DIR, "asn-ipv6.csv")),
    ],
    _rows_csv,
)
LOCAL_DBS = (IPTOASN, IPDB)


async def _txt(resolver, name):
    ans = await resolver.resolve(name, "TXT", lifetime=6)
    return b"".join(ans[0].strings).decode(errors="replace")


async def _src_cymru(ips):
    resolver = dns.asyncresolver.Resolver()
    sem = asyncio.Semaphore(20)
    out, names = {}, {}

    async def origin(ip):
        addr = ipaddress.ip_address(ip)
        rev = dns.reversename.from_address(ip).to_text(omit_final_dot=True)
        if addr.version == 4:
            q = rev.removesuffix(".in-addr.arpa") + ".origin.asn.cymru.com"
        else:
            q = rev.removesuffix(".ip6.arpa") + ".origin6.asn.cymru.com"
        async with sem:
            try:
                txt = await _txt(resolver, q)
            except Exception:
                return
        # "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"; при MOAS может быть "13335 209242 | ..."
        first = txt.split("|")[0].split()
        if first:
            out[ip] = int(first[0])

    await asyncio.gather(*(origin(ip) for ip in ips))

    async def asname(asn):
        async with sem:
            try:
                txt = await _txt(resolver, f"AS{asn}.asn.cymru.com")
                names[asn] = txt.split("|")[-1].strip()
            except Exception:
                names[asn] = ""

    await asyncio.gather(*(asname(a) for a in set(out.values())))
    if ips and not out:
        raise RuntimeError("нет ответов от asn.cymru.com")
    return {ip: (asn, names.get(asn, "")) for ip, asn in out.items()}


async def _src_ripestat(ips):
    sem = asyncio.Semaphore(8)
    out = {}
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:

        async def one(ip):
            async with sem:
                try:
                    r = await c.get(
                        "https://stat.ripe.net/data/prefix-overview/data.json",
                        params={"resource": ip, "sourceapp": "sitecheck-lan"},
                    )
                    r.raise_for_status()
                    asns = r.json()["data"].get("asns") or []
                except Exception:
                    return
            if asns:
                out[ip] = (int(asns[0]["asn"]), asns[0].get("holder") or "")

        await asyncio.gather(*(one(ip) for ip in ips))
    if ips and not out:
        raise RuntimeError("нет ответов от stat.ripe.net")
    return out


async def _src_ipapi(ips):
    out = {}
    ips = list(ips)
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
        for i in range(0, len(ips), 100):  # batch-лимит бесплатного API
            r = await c.post(
                "http://ip-api.com/batch",
                params={"fields": "status,query,as,asname"},
                json=ips[i : i + 100],
            )
            r.raise_for_status()
            for row in r.json():
                as_field = row.get("as") or ""  # "AS13335 Cloudflare, Inc."
                if row.get("status") == "success" and as_field.startswith("AS"):
                    num, _, name = as_field.partition(" ")
                    out[row["query"]] = (int(num[2:]), name or row.get("asname", ""))
    return out


async def _src_ipinfo(ips):
    sem = asyncio.Semaphore(8)
    out, errors = {}, []
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:

        async def one(ip):
            async with sem:
                try:
                    r = await c.get(f"https://ipinfo.io/{ip}/json")
                    r.raise_for_status()
                    org = r.json().get("org") or ""  # "AS15169 Google LLC"
                except Exception as e:
                    errors.append(str(e))
                    return
            if org.startswith("AS"):
                num, _, name = org.partition(" ")
                out[ip] = (int(num[2:]), name)

        await asyncio.gather(*(one(ip) for ip in ips))
    if ips and not out and errors:
        raise RuntimeError(errors[0])
    return out


_FUNCS = {
    "iptoasn": IPTOASN.source,
    "ipdb": IPDB.source,
    "cymru": _src_cymru,
    "ripestat": _src_ripestat,
    "ipapi": _src_ipapi,
    "ipinfo": _src_ipinfo,
}


async def lookup_all(ips):
    """Опрашивает все источники параллельно.

    Возвращает (per_ip, asns, sources):
      per_ip  = {ip: {source: asn}}
      asns    = {asn: {"names": {source: name}}}
      sources = {source: {"label", "found", "error"}}
    """
    ips = sorted(set(ips))
    names = list(_FUNCS)
    results = await asyncio.gather(
        *(asyncio.wait_for(_FUNCS[n](ips), 90) for n in names), return_exceptions=True
    )
    per_ip = {ip: {} for ip in ips}
    asns = {}
    sources = {}
    for name, res in zip(names, results):
        if isinstance(res, BaseException):
            err = str(res) or res.__class__.__name__
            sources[name] = {"label": SOURCES[name], "found": 0, "error": err}
            continue
        sources[name] = {"label": SOURCES[name], "found": len(res), "error": None}
        for ip, (asn, asname) in res.items():
            per_ip.setdefault(ip, {})[name] = asn
            entry = asns.setdefault(asn, {"names": {}})
            if asname:
                entry["names"][name] = asname
    return per_ip, asns, sources
