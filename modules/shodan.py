import os

try:
    import shodan as shodan_lib
except ImportError:
    shodan_lib = None  # type: ignore


def analyze_shodan(ip: str) -> dict:
    if shodan_lib is None:
        return {"source": "Shodan", "ip": ip, "error": "shodan library not installed"}
    try:
        api = shodan_lib.Shodan(os.environ["SHODAN_API_KEY"])
        host = api.host(ip)
        ports = host.get("ports", [])
        vulns = list(host.get("vulns", {}).keys())
        services = []
        for item in host.get("data", []):
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": (item.get("data", "")[:200]).strip(),
            })
        return {
            "source": "Shodan",
            "ip": ip,
            "hostnames": host.get("hostnames", []),
            "org": host.get("org", ""),
            "isp": host.get("isp", ""),
            "country_name": host.get("country_name", ""),
            "city": host.get("city", ""),
            "latitude": host.get("latitude"),
            "longitude": host.get("longitude"),
            "os": host.get("os", ""),
            "ports": ports,
            "vulns": vulns,
            "services": services[:10],
            "tags": host.get("tags", []),
            "error": None,
        }
    except Exception as exc:
        return {"source": "Shodan", "ip": ip, "error": str(exc)}
