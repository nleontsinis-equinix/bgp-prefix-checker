#!/usr/bin/env python3
# filename: check_prefixes.py
# version: 3.4
#
# Multi-provider BGP visibility checker with origin ASN/company reporting,
# deduplicated origins, and a separate "not propagated" report.
#
# Providers: RIPEstat, BGPView, Cloudflare Radar (configurable), bgproutes.io (configurable),
# Team Cymru (WHOIS), RADb IRR (WHOIS - registration evidence only).
#
# Usage (see --help for more):
#   python3 check_prefixes.py -r prefixes.txt
#   python3 check_prefixes.py -r prefixes.txt --json
#   python3 check_prefixes.py -r prefixes.txt --providers ripe,bgpview,teamcymru
#   python3 check_prefixes.py -r prefixes.txt --report-file /tmp/not_propagated.txt
#   CF_RADAR_API_BASE=... CF_API_TOKEN=... python3 check_prefixes.py -r prefixes.txt --providers cloudflare
#   BGPROUTES_HTTP_BASE=... python3 check_prefixes.py -r prefixes.txt --providers bgproutes

import argparse
import ipaddress
import sys
import time
import logging
import json
import os
import socket
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any, Tuple, Iterable, Set
import requests
from functools import lru_cache

# ---------------------------------
# Constants / Endpoints
# ---------------------------------
RIPE_PREFIX_OVERVIEW = "https://stat.ripe.net/data/prefix-overview/data.json"
BGPVIEW_PREFIX = "https://api.bgpview.io/prefix/"          # e.g., .../1.1.1.0/24
BGPVIEW_IP = "https://api.bgpview.io/ip/"                   # e.g., .../1.1.1.1

# Cloudflare Radar (configure via env; do not hardcode private endpoints)
# Example (adjust per official docs/account):
#   export CF_RADAR_API_BASE="https://api.cloudflare.com/client/v4/radar/bgp/routes/prefix"
#   export CF_API_TOKEN="<TOKEN>"
CF_RADAR_API_BASE = os.getenv("CF_RADAR_API_BASE", "").rstrip("/")
CF_API_TOKEN = os.getenv("CF_API_TOKEN", "")

# bgproutes.io (HTTP API base configurable)
#   export BGPROUTES_HTTP_BASE="https://api.bgproutes.io"   (set to the correct base)
BGPROUTES_HTTP_BASE = os.getenv("BGPROUTES_HTTP_BASE", "").rstrip("/")

TEAM_CYMRU_WHOIS_HOST = os.getenv("TEAM_CYMRU_WHOIS_HOST", "whois.cymru.com")
RADB_WHOIS_HOST = os.getenv("RADB_WHOIS_HOST", "whois.radb.net")
WHOIS_PORT = 43

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "check-prefix-visibility/3.4"})

# ---------------------------------
# Logging
# ---------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("check_prefixes")

# ---------------------------------
# HTTP helper with backoff (+ simple cache)
# ---------------------------------
def _sleep_backoff(backoff: float, attempt: int):
    time.sleep(backoff * (attempt + 1))

def _params_key(params: Optional[Dict[str, Any]]) -> Tuple[Tuple[str, Any], ...]:
    if not params:
        return tuple()
    return tuple(sorted(params.items()))

@lru_cache(maxsize=1024)
def get_json_cached(url: str, params_key: Tuple[Tuple[str, Any], ...], timeout: int, retries: int, backoff: float) -> Dict[str, Any]:
    params = dict(params_key)
    for attempt in range(retries):
        try:
            r = SESSION.get(url, params=params, timeout=timeout)
            if r.status_code == 429 and attempt < retries - 1:
                _sleep_backoff(backoff, attempt)
                continue
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            if attempt == retries - 1:
                raise RuntimeError(f"HTTP error: {e}")
            _sleep_backoff(backoff, attempt)
    return {}

def get_json(url: str, params: Optional[Dict[str, Any]] = None, timeout: int = 10,
             retries: int = 3, backoff: float = 0.8) -> Dict[str, Any]:
    return get_json_cached(url, _params_key(params), timeout, retries, backoff)

# ---------------------------------
# Parsing and normalization
# ---------------------------------
def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def is_prefix(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False

def normalize_prefix(value: str) -> str:
    return str(ipaddress.ip_network(value, strict=False))

def pick_representative_ip(net: ipaddress._BaseNetwork):
    if isinstance(net, ipaddress.IPv4Network):
        try:
            return net.network_address + 1
        except Exception:
            return net.network_address
    else:
        return net.network_address

def is_subnet_of(a: ipaddress._BaseNetwork, b: ipaddress._BaseNetwork) -> bool:
    if a.version != b.version:
        return False
    return (a.network_address in b) and (a.broadcast_address in b)

# ---------------------------------
# Result models
# ---------------------------------
@dataclass
class ProviderResult:
    visible: Optional[bool]       # True/False, or None if unknown / not supported
    metric: Optional[float]       # Optional numeric visibility metric
    evidence: str                 # Short textual evidence / note
    provider: str                 # Provider name

@dataclass(frozen=True)
class OriginRecord:
    asn: int
    name: str
    sources: Tuple[str, ...]   # providers that reported this origin

# ---------------------------------
# Provider Interface
# ---------------------------------
class PrefixVisibilityProvider:
    name = "Base"
    def check_exact_prefix(self, prefix: str) -> ProviderResult:
        raise NotImplementedError
    def covering_prefix_for_ip(self, ip: str) -> Optional[str]:
        return None
    def more_specifics(self, prefix: str) -> List[str]:
        return []
    def origins_for_prefix(self, prefix: str) -> List[Tuple[int, str]]:
        return []

# ---------------------------------
# RIPEstat Provider (prefix-overview)
# ---------------------------------
class RipeProvider(PrefixVisibilityProvider):
    name = "RIPEstat"

    def _prefix_overview(self, resource: str) -> Dict[str, Any]:
        js = get_json(RIPE_PREFIX_OVERVIEW, {"resource": resource})
        if not isinstance(js, dict):
            return {}
        return js.get("data", {}) or {}

    def _extract_announced_space(self, data: Dict[str, Any]) -> List[str]:
        candidates: List[str] = []
        space = data.get("announced_space") or []
        if isinstance(space, list):
            for item in space:
                if isinstance(item, str):
                    candidates.append(item)
                elif isinstance(item, dict):
                    for key in ("prefix", "resource", "cidr"):
                        val = item.get(key)
                        if isinstance(val, str):
                            candidates.append(val)
        return candidates

    def check_exact_prefix(self, prefix: str) -> ProviderResult:
        d = self._prefix_overview(prefix)
        if not d:
            return ProviderResult(None, None, "no data", self.name)
        announced = bool(d.get("announced"))
        vis_val: Optional[float] = None
        vis_raw = d.get("visibility")
        try:
            if vis_raw is not None:
                vis_val = float(vis_raw)
        except (TypeError, ValueError):
            vis_val = None
        if vis_val is not None:
            return ProviderResult((announced and vis_val > 0.0), vis_val, f"visibility={vis_val}", self.name)
        return ProviderResult(announced, None, "announced flag only", self.name)

    def covering_prefix_for_ip(self, ip: str) -> Optional[str]:
        d = self._prefix_overview(ip)
        if not d:
            return None
        for cand in self._extract_announced_space(d):
            try:
                return normalize_prefix(cand)
            except Exception:
                continue
        res = d.get("resource")
        if isinstance(res, str) and "/" in res:
            try:
                return normalize_prefix(res)
            except Exception:
                pass
        block = d.get("block") or {}
        if isinstance(block, dict):
            br = block.get("resource")
            if isinstance(br, str) and "/" in br:
                try:
                    return normalize_prefix(br)
                except Exception:
                    pass
        return None

    def more_specifics(self, prefix: str) -> List[str]:
        net = ipaddress.ip_network(prefix, strict=False)
        probe_ip = pick_representative_ip(net)
        d = self._prefix_overview(str(probe_ip))
        if not d:
            return []
        found: List[str] = []
        for cand in self._extract_announced_space(d):
            try:
                cnet = ipaddress.ip_network(cand, strict=False)
                if is_subnet_of(cnet, net) and cnet != net:
                    found.append(str(cnet))
            except ValueError:
                continue
        unique = sorted(
            set(found),
            key=lambda x: (
                ipaddress.ip_network(x, strict=False).version,
                ipaddress.ip_network(x, strict=False).prefixlen,
            ),
        )
        return unique

# ---------------------------------
# BGPView Provider
# ---------------------------------
class BGPViewProvider(PrefixVisibilityProvider):
    name = "BGPView"

    def check_exact_prefix(self, prefix: str) -> ProviderResult:
        js = get_json(f"{BGPVIEW_PREFIX}{prefix}", {})
        if not js or "data" not in js:
            return ProviderResult(None, None, "no data", self.name)
        data = js["data"]
        announced = bool(data.get("prefix"))
        prefixes_list = data.get("prefixes") or data.get("related_prefixes") or []
        metric = float(len(prefixes_list)) if isinstance(prefixes_list, list) else None
        return ProviderResult(announced, metric, f"paths={int(metric) if metric else 0}", self.name)

    def covering_prefix_for_ip(self, ip: str) -> Optional[str]:
        js = get_json(f"{BGPVIEW_IP}{ip}", {})
        if not js or "data" not in js:
            return None
        data = js["data"]
        best: Optional[ipaddress._BaseNetwork] = None
        for p in data.get("prefixes", []) or []:
            try:
                net = ipaddress.ip_network(p.get("prefix"), strict=False)
                if ipaddress.ip_address(ip) in net:
                    if best is None or net.prefixlen > best.prefixlen:
                        best = net
            except Exception:
                continue
        return str(best) if best else None

    def origins_for_prefix(self, prefix: str) -> List[Tuple[int, str]]:
        js = get_json(f"{BGPVIEW_PREFIX}{prefix}", {})
        if not js or "data" not in js:
            return []
        data = js["data"]
        origins: Set[Tuple[int, str]] = set()

        for a in (data.get("asns") or []):
            try:
                asn = a.get("asn") or a.get("asn_number") or a.get("id")
                name = a.get("name") or a.get("description_short") or a.get("description") or "unknown"
                if asn:
                    origins.add((int(asn), str(name)))
            except Exception:
                continue

        def pull(pfx_list):
            for p in pfx_list:
                asn = None
                name = "unknown"
                asp = p.get("asn")
                if isinstance(asp, dict):
                    asn = asp.get("asn") or asp.get("asn_number")
                    name = asp.get("name") or asp.get("description_short") or "unknown"
                elif isinstance(asp, int):
                    asn = asp
                if asn:
                    origins.add((int(asn), name))

        for key in ("prefixes", "related_prefixes"):
            lst = data.get(key) or []
            if isinstance(lst, list):
                pull(lst)

        return sorted(origins, key=lambda x: x[0])

# ---------------------------------
# Cloudflare Radar Provider (configurable)
# ---------------------------------
class CloudflareRadarProvider(PrefixVisibilityProvider):
    name = "CloudflareRadar"

    def check_exact_prefix(self, prefix: str) -> ProviderResult:
        if not CF_RADAR_API_BASE or not CF_API_TOKEN:
            return ProviderResult(None, None, "not configured", self.name)
        headers = {"Authorization": f"Bearer {CF_API_TOKEN}"}
        try:
            r = SESSION.get(CF_RADAR_API_BASE, params={"prefix": prefix}, headers=headers, timeout=10)
            if r.status_code == 401:
                return ProviderResult(None, None, "unauthorized", self.name)
            if r.status_code == 404:
                return ProviderResult(False, None, "not found", self.name)
            r.raise_for_status()
            js = r.json()
        except requests.RequestException as e:
            return ProviderResult(None, None, f"http error: {e}", self.name)

        data = js if isinstance(js, dict) else {}
        result = data.get("result") or data.get("data") or {}
        routes = result.get("routes") or result.get("bgp_routes") or []
        visible = bool(routes)
        metric = float(len(routes)) if isinstance(routes, list) else None
        return ProviderResult(visible, metric, f"routes={int(metric) if metric else 0}", self.name)

# ---------------------------------
# bgproutes.io Provider (configurable)
# ---------------------------------
class BGPRoutesIOProvider(PrefixVisibilityProvider):
    name = "bgproutes.io"

    def check_exact_prefix(self, prefix: str) -> ProviderResult:
        if not BGPROUTES_HTTP_BASE:
            return ProviderResult(None, None, "not configured", self.name)
        paths = [
            f"{BGPROUTES_HTTP_BASE}/prefix",
            f"{BGPROUTES_HTTP_BASE}/api/v1/prefix",
            f"{BGPROUTES_HTTP_BASE}/api/prefix",
        ]
        js = None
        err = None
        for url in paths:
            try:
                js = get_json(url, {"prefix": prefix})
                if js:
                    break
            except Exception as e:
                err = str(e)
        if not js:
            return ProviderResult(None, None, f"no data ({err or 'tried multiple endpoints'})", self.name)
        routes = js.get("routes") or js.get("data") or js.get("results") or []
        if isinstance(routes, dict):
            routes = routes.get("routes") or []
        visible = bool(routes)
        metric = float(len(routes)) if isinstance(routes, list) else None
        return ProviderResult(visible, metric, f"routes={int(metric) if metric else 0}", self.name)

# ---------------------------------
# Team Cymru (WHOIS over TCP) — origin & name
# ---------------------------------
class TeamCymruProvider(PrefixVisibilityProvider):
    name = "TeamCymru"

    def _query(self, payload: str, timeout: int = 8) -> str:
        with socket.create_connection((TEAM_CYMRU_WHOIS_HOST, WHOIS_PORT), timeout=timeout) as s:
            s.send(payload.encode("ascii", errors="ignore"))
            s.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data.decode("utf-8", errors="ignore"))
            return "".join(chunks)

    def check_exact_prefix(self, prefix: str) -> ProviderResult:
        try:
            ip = str(pick_representative_ip(ipaddress.ip_network(prefix, strict=False)))
            q = f"begin\nverbose\n{ip}\nend\n"
            resp = self._query(q)
            lines = [ln for ln in resp.splitlines() if "|" in ln and not ln.lower().startswith(("as", "as|"))]
            observed = any("/" in ln for ln in lines)
            count = sum(1 for ln in lines if "/" in ln)
            return ProviderResult(observed, float(count) if count else None, f"rows={count}", self.name)
        except Exception as e:
            return ProviderResult(None, None, f"error: {e}", self.name)

    def origins_for_prefix(self, prefix: str) -> List[Tuple[int, str]]:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            ip = str(pick_representative_ip(net))
            q = f"begin\nverbose\n{ip}\nend\n"
            resp = self._query(q)
            want = normalize_prefix(prefix)
            origins: Set[Tuple[int, str]] = set()
            for ln in resp.splitlines():
                if "|" not in ln or ln.lower().startswith(("as", "as|")):
                    continue
                parts = [p.strip() for p in ln.split("|")]
                if len(parts) < 7:
                    continue
                asn_s, _, bgp_pfx, _, _, _, as_name = parts[:7]
                if not asn_s.isdigit():
                    continue
                try:
                    if normalize_prefix(bgp_pfx) == want:
                        origins.add((int(asn_s), as_name or "unknown"))
                except Exception:
                    continue
            return sorted(origins, key=lambda x: x[0])
        except Exception:
            return []

# ---------------------------------
# RADb IRR (WHOIS over TCP) - registration evidence, not visibility
# ---------------------------------
class RADbIRRProvider(PrefixVisibilityProvider):
    name = "RADbIRR"

    def _query(self, q: str, timeout: int = 8) -> str:
        with socket.create_connection((RADB_WHOIS_HOST, WHOIS_PORT), timeout=timeout) as s:
            s.send(q.encode("ascii", errors="ignore"))
            s.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data.decode("utf-8", errors="ignore"))
            return "".join(chunks)

    def check_exact_prefix(self, prefix: str) -> ProviderResult:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            obj = "route6" if net.version == 6 else "route"
            q = f"-T {obj} {prefix}\n"
            resp = self._query(q)
            registered = ("route:" in resp) or ("route6:" in resp)
            return ProviderResult(None, None, "registered" if registered else "not registered", self.name)
        except Exception as e:
            return ProviderResult(None, None, f"error: {e}", self.name)

# ---------------------------------
# Provider factory / selection
# ---------------------------------
ALL_PROVIDER_CLASSES = {
    "ripe": RipeProvider,
    "bgpview": BGPViewProvider,
    "cloudflare": CloudflareRadarProvider,
    "bgproutes": BGPRoutesIOProvider,
    "teamcymru": TeamCymruProvider,
    "radb": RADbIRRProvider,
}

def build_providers(selection: Iterable[str]) -> List[PrefixVisibilityProvider]:
    selected = []
    for key in selection:
        cls = ALL_PROVIDER_CLASSES.get(key.lower())
        if not cls:
            raise ValueError(f"Unknown provider: {key}")
        selected.append(cls())
    return selected

# ---------------------------------
# Core helpers
# ---------------------------------
def summarize_provider_findings(findings: List[ProviderResult]) -> Tuple[bool, List[str], List[str]]:
    visible_providers = [f.provider for f in findings if f.visible is True]
    any_visible = len(visible_providers) > 0
    aux = []
    for f in findings:
        if f.visible is None:
            if f.evidence and f.evidence != "not configured":
                aux.append(f"{f.provider}:{f.evidence}")
        elif f.visible is False:
            aux.append(f"{f.provider}:not visible")
    return any_visible, visible_providers, aux

def collect_origins(prefix: str, providers: List[PrefixVisibilityProvider]) -> List[OriginRecord]:
    """
    Deduplicate by ASN. Prefer non-'unknown' names. Merge provider sources.
    """
    by_asn: Dict[int, Dict[str, Any]] = {}
    for p in providers:
        if hasattr(p, "origins_for_prefix"):
            try:
                for asn, name in p.origins_for_prefix(prefix):
                    entry = by_asn.setdefault(asn, {"name": "unknown", "sources": set()})
                    if entry["name"] == "unknown" and name and name != "unknown":
                        entry["name"] = name
                    entry["sources"].add(p.name)
            except Exception:
                continue
    records = [
        OriginRecord(asn=asn, name=info["name"], sources=tuple(sorted(info["sources"])))
        for asn, info in sorted(by_asn.items())
    ]
    return records

# ---------------------------------
# Main per-item logic
# ---------------------------------
def check_item(item: str, providers: List[PrefixVisibilityProvider],
               exact_only: bool, debug: bool) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "input": item,
        "normalized": None,
        "type": "ip" if is_ip(item) else ("prefix" if is_prefix(item) else "invalid"),
        "status": None,
        "providers": [],
        "more_specifics": [],
        "covering_prefix": None,
        "origins": [],
    }

    if out["type"] == "invalid":
        out["status"] = "Invalid input (not IP or CIDR)"
        return out

    covering = None
    ripe = next((p for p in providers if isinstance(p, RipeProvider)), None)
    bgpv = next((p for p in providers if isinstance(p, BGPViewProvider)), None)

    if out["type"] == "ip":
        if ripe:
            covering = ripe.covering_prefix_for_ip(item)
        if not covering and bgpv:
            covering = bgpv.covering_prefix_for_ip(item)
        if not covering:
            out["status"] = "No advertised prefix found"
            return out
        out["covering_prefix"] = covering
        findings: List[ProviderResult] = []
        for p in providers:
            try:
                res = p.check_exact_prefix(covering)
            except Exception as e:
                res = ProviderResult(None, None, f"error: {e}", p.name)
            findings.append(res)
        any_visible, visible_prov, aux = summarize_provider_findings(findings)
        out["providers"] = [asdict(f) for f in findings]
        out["normalized"] = covering
        origin_list = collect_origins(covering, providers)
        out["origins"] = [asdict(o) for o in origin_list]
        if any_visible:
            out["status"] = f"Propagated as {covering} via {','.join(visible_prov)}"
        else:
            out["status"] = f"Not Propagated ({covering})" + (f" [{'; '.join(aux)}]" if aux else "")
        return out

    # Prefix path
    pref = normalize_prefix(item)
    out["normalized"] = pref

    findings: List[ProviderResult] = []
    for p in providers:
        try:
            findings.append(p.check_exact_prefix(pref))
        except Exception as e:
            findings.append(ProviderResult(None, None, f"error: {e}", p.name))

    any_visible, visible_prov, aux = summarize_provider_findings(findings)
    out["providers"] = [asdict(f) for f in findings]
    origin_list = collect_origins(pref, providers)
    out["origins"] = [asdict(o) for o in origin_list]

    if any_visible:
        out["status"] = f"Propagated as {pref} via {','.join(visible_prov)}"
    elif exact_only:
        out["status"] = f"Not Propagated ({pref})" + (f" [{'; '.join(aux)}]" if aux else "")
    else:
        ms: List[str] = []
        if ripe:
            try:
                ms = ripe.more_specifics(pref)
            except Exception:
                ms = []
        out["more_specifics"] = ms
        if ms:
            shown = ", ".join(ms[:3])
            suffix = "" if len(ms) <= 3 else f" (+{len(ms)-3} more)"
            out["status"] = f"Propagated via more-specific {shown}{suffix}"
        else:
            out["status"] = f"Not Propagated ({pref})" + (f" [{'; '.join(aux)}]" if aux else "")

    return out

def check_entries(entries: List[str], providers: List[PrefixVisibilityProvider],
                  exact_only: bool = False, debug: bool = False) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    details: Dict[str, Any] = {}
    for raw in entries:
        item = raw.strip()
        if not item:
            continue
        try:
            res = check_item(item, providers, exact_only, debug)
            results[item] = res["status"]
            details[item] = res
            if debug:
                logger.debug(json.dumps(res, indent=2))
        except Exception as e:
            results[item] = f"Error: {e}"
    results["_details"] = details
    return results

# ---------------------------------
# Non-propagated report
# ---------------------------------
def write_not_propagated_report(entries: List[str], results: Dict[str, Any], report_file: str) -> int:
    """
    Writes a separate report containing only items that are not propagated or
    have no advertised prefix. Returns count of entries written.
    """
    if report_file.strip() in ("", "-"):
        return 0

    lines: List[str] = []
    for item in entries:
        status = results.get(item, "")
        if status.startswith("Not Propagated") or "No advertised prefix" in status:
            det = results.get("_details", {}).get(item, {})
            origins = det.get("origins", [])
            origin_text = ", ".join(f"AS{o['asn']} ({o['name']})" for o in origins) if origins else "unknown"
            lines.append(f"{item}: {status} | origin(s): {origin_text}")

    try:
        with open(report_file, "w", encoding="utf-8") as f:
            for ln in lines:
                f.write(ln + "\n")
        return len(lines)
    except Exception as e:
        logger.error(f"Failed to write report '{report_file}': {e}")
        return 0

# ---------------------------------
# File I/O
# ---------------------------------
def read_lines(file_path: str) -> List[str]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except Exception as e:
        raise RuntimeError(f"Failed to read input file '{file_path}': {e}")

# ---------------------------------
# CLI
# ---------------------------------
def main() -> int:
    description = (
        "Check global BGP visibility for IPs/prefixes using multiple providers "
        "(RIPEstat, BGPView, Cloudflare Radar, bgproutes.io, Team Cymru, RADb IRR). "
        "Reports origin ASN + company name (deduplicated) and writes a separate report for non-propagated items."
    )
    epilog = (
        "Examples:\n"
        "  python3 check_prefixes.py -r prefixes.txt\n"
        "  python3 check_prefixes.py -r prefixes.txt --json\n"
        "  python3 check_prefixes.py -r prefixes.txt --providers ripe,bgpview,teamcymru\n"
        "  python3 check_prefixes.py -r prefixes.txt --report-file /tmp/not_propagated.txt\n"
        "  CF_RADAR_API_BASE=... CF_API_TOKEN=... python3 check_prefixes.py -r prefixes.txt --providers cloudflare\n"
        "  BGPROUTES_HTTP_BASE=... python3 check_prefixes.py -r prefixes.txt --providers bgproutes\n"
        "\n"
        "Provider notes:\n"
        "  - Cloudflare Radar and bgproutes.io require environment variables to be set, otherwise they show 'not configured'.\n"
        "  - RADb IRR is an IRR registration check (not a visibility signal).\n"
    )

    parser = argparse.ArgumentParser(
        prog="check_prefixes.py",
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-r", "--resource-file", required=True,
                        help="Path to file with IPs and/or CIDRs (one per line). Lines starting with '#' are ignored.")
    parser.add_argument("--exact-only", action="store_true",
                        help="Require exact-prefix visibility (disable more-specifics fallback).")
    parser.add_argument("--providers", default="ripe,bgpview,cloudflare,bgproutes,teamcymru,radb",
                        help="Comma-separated providers to use. Supported: ripe,bgpview,cloudflare,bgproutes,teamcymru,radb")
    parser.add_argument("--providers-list", action="store_true",
                        help="Print supported provider keys and exit.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")
    parser.add_argument("--report-file", default="not_propagated_report.txt",
                        help="Write non-propagated items to this file. Use '-' to disable. Default: not_propagated_report.txt")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds. Default: 10")
    parser.add_argument("--retries", type=int, default=3, help="HTTP retries. Default: 3")
    parser.add_argument("--backoff", type=float, default=0.8, help="HTTP backoff factor. Default: 0.8")
    parser.add_argument("--version", action="version", version="check_prefixes.py 3.4")

    args = parser.parse_args()

    if args.providers_list:
        print("Supported providers:")
        for key in sorted(ALL_PROVIDER_CLASSES.keys()):
            print(f"  - {key}")
        return 0

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # Thread per-run HTTP params via wrapper of cached function
    global get_json_cached
    old_func = get_json_cached
    def get_json_cached_with_args(url, params_key, _timeout=args.timeout, _retries=args.retries, _backoff=args.backoff):
        return old_func(url, params_key, _timeout, _retries, _backoff)
    get_json_cached = get_json_cached_with_args  # type: ignore

    try:
        entries = read_lines(args.resource_file)
        if not entries:
            logger.error("No entries found in file.")
            return 1

        providers = build_providers([p.strip() for p in args.providers.split(",") if p.strip()])

        results = check_entries(entries, providers, exact_only=args.exact_only, debug=args.debug)

        # Main output
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for item in entries:
                status = results.get(item, "unknown")
                det = results["_details"].get(item, {})
                origins = det.get("origins", [])
                if origins:
                    origin_text = ", ".join(f"AS{o['asn']} ({o['name']})" for o in origins[:3])
                    if len(origins) > 3:
                        origin_text += f" (+{len(origins)-3} more)"
                    print(f"{item}: {status} | origin(s): {origin_text}")
                else:
                    print(f"{item}: {status} | origin(s): unknown")

        # Separate not-propagated report
        written = write_not_propagated_report(entries, results, args.report_file)
        if args.report_file.strip() not in ("", "-"):
            print(f"\n[INFO] Non-propagated report: {args.report_file} ({written} entries)")

        return 0
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
