"""Реклама, аналитика, соцсети и прочие трекеры: домены, без которых сайт работает
(их режут блокировщики). Источники — AdGuard DNS filter и Disconnect (как в Firefox)."""
import json
import logging
import os
import re

from . import asn

log = logging.getLogger("adlists")

ADGUARD_RULE = re.compile(r"^(@@)?\|\|([a-z0-9._-]+)\^(?:\$important)?$")
DISCONNECT = "https://cdn.jsdelivr.net/gh/disconnectme/disconnect-tracking-protection@master/"
CATEGORIES = {
    "Advertising": "реклама",
    "Analytics": "аналитика",
    "Social": "соцсеть",
    "FingerprintingInvasive": "трекер",
    "FingerprintingGeneral": "трекер",
    "Cryptomining": "майнер",
}


def _suffixes(host):
    parts = host.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


class AdLists(asn.LocalDb):
    """Качается в фоне раз в сутки, как базы ASN; пока не скачано — домены не помечаются."""

    def __init__(self):
        files = [
            ("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "adguard-dns-filter.txt"),
            (DISCONNECT + "services.json", "disconnect-services.json"),
            (DISCONNECT + "entities.json", "disconnect-entities.json"),
        ]
        super().__init__("adlists", [(u, os.path.join(asn.DATA_DIR, n)) for u, n in files], None)
        self.tables = None

    @property
    def ready(self):
        return self.tables is not None

    def _load(self):
        adguard_path, services_path, entities_path = (p for _, p in self.files)
        block, allow = set(), set()
        with open(adguard_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if m := ADGUARD_RULE.match(line.strip()):
                    (allow if m[1] else block).add(m[2])

        tracker = {}
        with open(services_path, encoding="utf-8") as f:
            categories = json.load(f)["categories"]
        for cat, label in CATEGORIES.items():
            for item in categories.get(cat, []):
                for company, props in item.items():
                    for domains in props.values():
                        if isinstance(domains, list):
                            for d in domains:
                                tracker.setdefault(d, (label, company))

        owner = {}
        with open(entities_path, encoding="utf-8") as f:
            for name, e in json.load(f)["entities"].items():
                for d in e.get("properties", []) + e.get("resources", []):
                    owner.setdefault(d, name)

        log.info("AdGuard %d (+%d исключений), Disconnect %d", len(block), len(allow), len(tracker))
        return {"block": block, "allow": allow, "tracker": tracker, "owner": owner}

    def classify(self, hosts, main_hosts):
        if not self.ready:
            return {}
        t = self.tables
        site_owners = {t["owner"].get(s) for h in main_hosts for s in _suffixes(h)} - {None}
        out = {}
        for h in hosts:
            sfx = _suffixes(h)
            hit = next((t["tracker"][s] for s in sfx if s in t["tracker"]), None)
            same_owner = any(t["owner"].get(s) in site_owners for s in sfx)
            if hit and not same_owner:
                out[h] = {"label": hit[0], "source": f"Disconnect: {hit[1]}"}
            elif any(s in t["block"] for s in sfx) and not any(s in t["allow"] for s in sfx):
                out[h] = {"label": "реклама/трекер", "source": "AdGuard DNS filter"}
        return out


ADLISTS = AdLists()
