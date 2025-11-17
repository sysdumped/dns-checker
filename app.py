import asyncio
from typing import List, Dict, Any

import httpx
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import whois

app = FastAPI(title="DNS Checker (Country ECS + WHOIS + Email Auth)")

COUNTRY_POINTS: List[Dict[str, Any]] = [
    {"code": "IT", "name": "Italy", "ecs": "151.0.0.0/24", "geo": {"lat": 41.9028, "lng": 12.4964, "label": "Rome"}},
    {"code": "FR", "name": "France", "ecs": "62.210.0.0/24", "geo": {"lat": 48.8566, "lng": 2.3522, "label": "Paris"}},
    {"code": "DE", "name": "Germany", "ecs": "91.0.0.0/24", "geo": {"lat": 52.5200, "lng": 13.4050, "label": "Berlin"}},
    {"code": "ES", "name": "Spain", "ecs": "83.36.0.0/24", "geo": {"lat": 40.4168, "lng": -3.7038, "label": "Madrid"}},
    {"code": "GB", "name": "United Kingdom", "ecs": "81.2.69.0/24", "geo": {"lat": 51.5072, "lng": -0.1276, "label": "London"}},
    {"code": "US", "name": "United States", "ecs": "8.8.8.0/24", "geo": {"lat": 37.7749, "lng": -122.4194, "label": "San Francisco"}},
    {"code": "BR", "name": "Brazil", "ecs": "200.147.0.0/24", "geo": {"lat": -23.5505, "lng": -46.6333, "label": "São Paulo"}},
    {"code": "AR", "name": "Argentina", "ecs": "181.30.0.0/24", "geo": {"lat": -34.6037, "lng": -58.3816, "label": "Buenos Aires"}},
    {"code": "CA", "name": "Canada", "ecs": "24.48.0.0/24", "geo": {"lat": 45.5017, "lng": -73.5673, "label": "Montréal"}},
    {"code": "AU", "name": "Australia", "ecs": "1.1.1.0/24", "geo": {"lat": -33.8688, "lng": 151.2093, "label": "Sydney"}},
    {"code": "JP", "name": "Japan", "ecs": "27.0.0.0/24", "geo": {"lat": 35.6762, "lng": 139.6503, "label": "Tokyo"}},
    {"code": "KR", "name": "South Korea", "ecs": "1.234.0.0/24", "geo": {"lat": 37.5665, "lng": 126.9780, "label": "Seoul"}},
    {"code": "SG", "name": "Singapore", "ecs": "116.12.0.0/24", "geo": {"lat": 1.3521, "lng": 103.8198, "label": "Singapore"}},
    {"code": "IN", "name": "India", "ecs": "49.32.0.0/24", "geo": {"lat": 28.6139, "lng": 77.2090, "label": "New Delhi"}},
    {"code": "ZA", "name": "South Africa", "ecs": "105.0.0.0/24", "geo": {"lat": -26.2041, "lng": 28.0473, "label": "Johannesburg"}},
    {"code": "AE", "name": "United Arab Emirates", "ecs": "94.200.0.0/24", "geo": {"lat": 25.2048, "lng": 55.2708, "label": "Dubai"}},
]

VALID_TYPES = {"A", "AAAA", "CNAME", "TXT", "MX", "NS"}


@app.get("/")
async def index():
    return FileResponse("static/index.html")


@app.get("/api/check")
async def check(name: str = Query(..., min_length=1), rtype: str = Query("A")):
    rtype = rtype.upper()
    if rtype not in VALID_TYPES:
        return JSONResponse({"error": f"Tipo record non supportato: {rtype}"}, status_code=400)

    async with httpx.AsyncClient(timeout=httpx.Timeout(6.0)) as client:
        async def query_country(cp: Dict[str, Any]):
            params = {"name": name, "type": rtype, "edns_client_subnet": cp["ecs"]}
            try:
                resp = await client.get("https://dns.google/resolve", params=params)
                resp.raise_for_status()
                data = resp.json()
                answers = [
                    {"data": a.get("data"), "ttl": a.get("TTL"), "type": a.get("type")}
                    for a in (data.get("Answer") or [])
                ]
                return {
                    "resolver": f"{cp['name']} ({cp['code']})",
                    "transport": "doh-ecs",
                    "status": "ok",
                    "rcode": data.get("Status"),
                    "answers": answers,
                    "geo": cp.get("geo"),
                }
            except Exception as e:
                return {
                    "resolver": f"{cp['name']} ({cp['code']})",
                    "transport": "doh-ecs",
                    "status": "error",
                    "error": str(e),
                    "geo": cp.get("geo"),
                }

        results = await asyncio.gather(*[query_country(cp) for cp in COUNTRY_POINTS])

    results_sorted = sorted(results, key=lambda x: (x.get("status") != "ok", x.get("resolver")))
    return {"query": {"name": name, "type": rtype}, "results": results_sorted}


@app.get("/api/whois")
async def whois_lookup(domain: str = Query(..., min_length=1)):
    domain = domain.strip()

    def do_whois() -> Dict[str, Any]:
        try:
            w = whois.whois(domain)
            def conv(val):
                if isinstance(val, (list, tuple)):
                    return [str(v) for v in val]
                return str(val) if val is not None else None
            return {
                "domain_name": conv(w.domain_name),
                "registrar": conv(w.registrar),
                "creation_date": conv(w.creation_date),
                "expiration_date": conv(w.expiration_date),
                "name_servers": conv(w.name_servers),
                "status": conv(w.status),
            }
        except Exception as e:
            return {"error": str(e)}

    data = await asyncio.to_thread(do_whois)
    data["query_domain"] = domain
    return data


async def _fetch_txt(client: httpx.AsyncClient, name: str) -> Dict[str, Any]:
    params = {"name": name, "type": "TXT"}
    try:
        resp = await client.get("https://dns.google/resolve", params=params)
        resp.raise_for_status()
        data = resp.json()
        status = data.get("Status")
        records = []
        for a in data.get("Answer") or []:
            d = a.get("data", "")
            if isinstance(d, str) and d.startswith('"') and d.endswith('"'):
                d = d[1:-1]
            records.append(d)
        return {"ok": status == 0 and len(records) > 0, "rcode": status, "records": records}
    except Exception as e:
        return {"ok": False, "error": str(e), "records": []}


@app.get("/api/email_auth")
async def email_auth(domain: str = Query(..., min_length=1), dkim_selector: str = Query("", alias="dkim_selector")):
    domain = domain.strip().lower().rstrip(".")
    selector = dkim_selector.strip()
    result: Dict[str, Any] = {"domain": domain}

    async with httpx.AsyncClient(timeout=httpx.Timeout(6.0)) as client:
        spf_fqdn = domain
        dmarc_fqdn = f"_dmarc.{domain}"
        bimi_fqdn = f"default._bimi.{domain}"
        dkim_fqdn = f"{selector}._domainkey.{domain}" if selector else None

        spf_task = _fetch_txt(client, spf_fqdn)
        dmarc_task = _fetch_txt(client, dmarc_fqdn)
        bimi_task = _fetch_txt(client, bimi_fqdn)
        if dkim_fqdn:
            dkim_task = _fetch_txt(client, dkim_fqdn)
            spf_res, dmarc_res, bimi_res, dkim_res = await asyncio.gather(spf_task, dmarc_task, bimi_task, dkim_task)
        else:
            spf_res, dmarc_res, bimi_res = await asyncio.gather(spf_task, dmarc_task, bimi_task)
            dkim_res = None

    def filter_by_prefix(res: Dict[str, Any] | None, prefix: str):
        if not res:
            return res
        recs = res.get("records") or []
        res["records"] = [r for r in recs if isinstance(r, str) and r.lower().startswith(prefix)]
        res["ok"] = res.get("ok", False) and len(res["records"]) > 0
        return res

    result["spf"] = filter_by_prefix(spf_res, "v=spf1")
    result["dmarc"] = filter_by_prefix(dmarc_res, "v=dmarc1")
    if dkim_fqdn:
        result["dkim"] = filter_by_prefix(dkim_res, "v=dkim1")
        if result["dkim"] is not None:
            result["dkim"]["name"] = dkim_fqdn
        else:
            result["dkim"] = {"name": dkim_fqdn, "ok": False, "records": []}
    else:
        result["dkim"] = {"name": None, "ok": False, "records": [], "note": "Nessun selector DKIM specificato"}
    if result["spf"] is not None:
        result["spf"]["name"] = spf_fqdn
    if result["dmarc"] is not None:
        result["dmarc"]["name"] = dmarc_fqdn
    result["bimi"] = bimi_res
    if result["bimi"] is not None:
        result["bimi"]["name"] = bimi_fqdn

    return result


app.mount("/static", StaticFiles(directory="static"), name="static")
