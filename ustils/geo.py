from geoip2fast import GeoIP2Fast

_geo = GeoIP2Fast()


def lookup_location(ip_address: str) -> dict:
    """Offline IP -> country/city lookup. Never raises; unknown IPs resolve to empty fields."""
    try:
        result = _geo.lookup(ip_address)
        return {
            "country": result.country_name or None,
            "country_code": result.country_code or None,
            "city": result.city.name or None,
            "is_private": result.is_private,
        }
    except Exception:
        return {"country": None, "country_code": None, "city": None, "is_private": None}
