"""Блок «Что добавить в прокси/VPN»: какие домены и IP из недоступного стоит добавлять в маршрутизацию,
а какие — нет (ротация, общий CDN, вероятная заглушка провайдера)."""
import ipaddress
import json
import logging
import os

from . import asn

log = logging.getLogger("route")

CDN_ASNS = {
    13335: "Cloudflare",
    209242: "Cloudflare",
    54113: "Fastly",
    20940: "Akamai",
    16625: "Akamai",
    16702: "Akamai",
    21342: "Akamai",
    15169: "Google",
    60068: "CDN77",
    200325: "BunnyCDN",
    22822: "Edgio",
    19551: "Imperva",
    30148: "Sucuri",
}


class CloudFront(asn.LocalDb):
    """У Amazon один ASN на всё, поэтому CloudFront отличаем по официальному списку подсетей AWS."""

    def __init__(self):
        url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
        super().__init__("aws-ip-ranges", [(url, os.path.join(asn.DATA_DIR, "aws-ip-ranges.json"))], None)
        self.tables = None

    @property
    def ready(self):
        return self.tables is not None

    def _load(self):
        with open(self.files[0][1], encoding="utf-8") as f:
            data = json.load(f)
        nets = [
            ipaddress.ip_network(p.get("ip_prefix") or p["ipv6_prefix"])
            for p in data.get("prefixes", []) + data.get("ipv6_prefixes", [])
            if p.get("service") == "CLOUDFRONT"
        ]
        log.info("CloudFront: %d подсетей", len(nets))
        return nets

    def has(self, ip):
        if not self.ready:
            return False
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in self.tables if n.version == addr.version)


CLOUDFRONT = CloudFront()


def _cdn(ip):
    for a in ip["asns"]:
        if a in CDN_ASNS:
            return CDN_ASNS[a]
    if CLOUDFRONT.has(ip["ip"]):
        return "CloudFront"
    return None


def _rotating(dns):
    answers = []
    for r in dns.values():
        ips = {ip for ip in r["ips"] if ipaddress.ip_address(ip).is_global}
        if ips:
            answers.append(ips)
    if len(answers) < 3:
        return False
    top = max(sum(ip in a for a in answers) for a in answers for ip in a)
    return top * 2 < len(answers)


def _doubt(ip, rotating, resolvers):
    if rotating:
        return "ротация: каждый DNS отдаёт свои адреса, этот скоро сменится"
    if cdn := _cdn(ip):
        return f"общий CDN ({cdn}): вместе с ним в туннель уйдут чужие сайты"
    dns_sources = set(ip["sources"]) - {"browser"}
    if "browser" not in ip["sources"] and len(dns_sources) == 1:
        rid = next(iter(dns_sources))
        return f"вернул только один DNS ({resolvers.get(rid, rid)}) — возможно, заглушка провайдера"
    return None


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def build(result, ads, base_of):
    hosts = [h for h in result["hosts"] if h["status"] in ("fail", "partial") and h["host"] not in ads]
    good, doubt, domain_only = {}, {}, []
    for h in hosts:
        public = [i for i in h["ips"] if i["kind"] == "public"]
        if not public:
            reason = "не резолвится ни одним DNS" if h["no_dns"] else "нет публичных IP"
            domain_only.append({"host": h["host"], "reason": reason})
            continue
        rotating = _rotating(result["dns"].get(h["host"], {}))
        usable = 0
        for i in public:
            reason = _doubt(i, rotating, result["resolvers"])
            entry = (doubt if reason else good).setdefault(i["ip"], {"ip": i["ip"], "hosts": [], "reason": reason})
            entry["hosts"].append(h["host"])
            usable += not reason
        if not usable:
            reason = "адреса ротируются — IP не помогут" if rotating else "годных IP нет — см. «под вопросом»"
            domain_only.append({"host": h["host"], "reason": reason})
    for ip in good:
        doubt.pop(ip, None)

    def key(e):
        a = ipaddress.ip_address(e["ip"])
        return a.version, a

    return {
        "domains": sorted({base_of(h["host"]) for h in hosts if not _is_ip(h["host"])}),
        "ips": sorted(good.values(), key=key),
        "doubt": sorted(doubt.values(), key=key),
        "domain_only": domain_only,
    }
