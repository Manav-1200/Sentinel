"""
detection/geoip_lookup.py
============================
Resolves a source IP to geographic/ASN information (country, city,
lat/lon, ASN/org) for use in alerts and the future dashboard (Phase 4).

Why this exists as its own module:
------------------------------------
Neither the anomaly detector, DDoS tracker, nor port-scan tracker have
any concept of geography — they only ever see IP addresses as opaque
strings. GeoIP enrichment is a purely additive, presentation-layer
concern: "where in the world is this attacker" is useful context for
a human looking at an alert, but must never influence detection
verdicts themselves. This module is called ONLY when producing an
alert (see response/alerting.py) or a stored block record (see
response/blocker.py) — never inside the hot per-flow detection path,
since a lookup (even a fast local one) has no business gating whether
a flow is flagged.

Two supported methods (config.yaml -> geoip.method):
------------------------------------------------------
  - "maxmind": offline lookup against a local GeoLite2-City.mmdb
    file (via the `geoip2` library). No network calls at runtime,
    no rate limits, sub-millisecond lookups. This is the right choice
    for the final deployed product, consistent with the same
    "zero external API dependency at runtime" philosophy already
    applied to the Phase 2 classifier (see detection/classifier.py).
    Requires downloading a GeoLite2-City.mmdb file once (free MaxMind
    account) and pointing geoip.maxmind_db_path at it.
  - "api": online lookup against ip-api.com's free tier (45
    requests/minute, no API key required). Useful for quick testing
    without setting up a MaxMind account, or as an automatic fallback
    if the configured .mmdb file is missing. NOT recommended for the
    final deployed product — it's a live runtime dependency and is
    rate-limited, which matters if Sentinel is ever handling a real
    high-volume attack with many distinct source IPs to resolve at
    once.

Private/reserved IPs (RFC 1918, loopback, link-local) are never sent
to either backend — there is no meaningful geography for them, and
sending them to a live third-party API would be a pointless (and
mildly leaky) network call. These resolve instantly to a
LOCAL_NETWORK placeholder result instead.

Caching:
---------
An in-memory LRU-style cache (max size = geoip.cache_size) avoids
re-resolving the same IP repeatedly — important both for the "api"
method's rate limit and for keeping "maxmind" lookups (already fast)
essentially free on repeat offenders, who by definition get looked up
many times.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("sentinel.geoip")


@dataclass
class GeoIPResult:
    """
    Result of a GeoIP lookup. Every field except `ip` and `resolved`
    is Optional — a partial or failed lookup must never crash a
    caller that expects to build an alert message. Callers should
    always handle None fields gracefully (e.g. "Unknown" in display
    text), never assume they're populated.
    """
    ip: str
    resolved: bool  # False if the lookup failed or IP is private/reserved
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    org: Optional[str] = None
    is_private: bool = False
    error: Optional[str] = None

    def display_str(self) -> str:
        """Short human-readable summary, safe to drop straight into an alert."""
        if self.is_private:
            return "local network"
        if not self.resolved:
            return "location unknown"
        parts = [p for p in (self.city, self.country) if p]
        location = ", ".join(parts) if parts else "location unknown"
        if self.org:
            return f"{location} ({self.org})"
        return location


class GeoIPLookup:
    """
    Resolves IPs to geographic info per config.yaml's `geoip` section.
    Thread-safe (a single instance is meant to be shared across the
    whole pipeline, same pattern as LLMAnalyser/trackers).
    """

    def __init__(self, config: dict):
        geoip_config = config.get("geoip", {})
        self.method: str = geoip_config.get("method", "api")
        self.maxmind_db_path: str = geoip_config.get("maxmind_db_path", "data/GeoLite2-City.mmdb")
        self.cache_size: int = int(geoip_config.get("cache_size", 1000))

        self._cache: "OrderedDict[str, GeoIPResult]" = OrderedDict()
        self._lock = threading.Lock()

        self._maxmind_reader = None
        if self.method == "maxmind":
            self._maxmind_reader = self._try_open_maxmind_reader()
            if self._maxmind_reader is None:
                logger.warning(
                    "geoip.method is 'maxmind' but the database could not be opened "
                    "(path: %s). Falling back to 'api' method for this session — "
                    "fix geoip.maxmind_db_path in config.yaml to use offline lookups.",
                    self.maxmind_db_path,
                )
                self.method = "api"

        self._requests = None
        if self.method == "api":
            try:
                import requests  # noqa: F401 local import, optional dependency
                self._requests = requests
            except ImportError:
                logger.warning(
                    "geoip.method is 'api' but the 'requests' library is not installed. "
                    "GeoIP lookups will return unresolved results until it's installed "
                    "(pip install requests) or geoip.method is switched to 'maxmind'."
                )

    def lookup(self, ip: str) -> GeoIPResult:
        """
        Resolve one IP address. Always returns a GeoIPResult, never
        raises — a failed or unavailable lookup returns
        resolved=False with `error` set, so callers can always safely
        build an alert/log message without a try/except of their own.
        """
        if self._is_private_or_reserved(ip):
            return GeoIPResult(ip=ip, resolved=False, is_private=True)

        with self._lock:
            cached = self._cache.get(ip)
            if cached is not None:
                # Move to the end -> most-recently-used, for the LRU eviction below.
                self._cache.move_to_end(ip)
                return cached

        if self.method == "maxmind" and self._maxmind_reader is not None:
            result = self._lookup_maxmind(ip)
        elif self.method == "api" and self._requests is not None:
            result = self._lookup_api(ip)
        else:
            result = GeoIPResult(ip=ip, resolved=False, error="no GeoIP backend available")

        self._store_in_cache(ip, result)
        return result

    # ------------------------------------------------------------
    # Internal — private/reserved IP filtering
    # ------------------------------------------------------------

    @staticmethod
    def _is_private_or_reserved(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # Not a parseable IP at all — treat as unresolvable rather
            # than crashing; callers still get a well-formed result.
            return False
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )

    # ------------------------------------------------------------
    # Internal — maxmind backend
    # ------------------------------------------------------------

    def _try_open_maxmind_reader(self):
        try:
            import geoip2.database
        except ImportError:
            logger.warning(
                "geoip.method is 'maxmind' but the 'geoip2' library is not installed "
                "(pip install geoip2). Falling back to 'api' method for this session."
            )
            return None

        try:
            return geoip2.database.Reader(self.maxmind_db_path)
        except OSError as e:
            logger.warning("Could not open MaxMind database at '%s': %s", self.maxmind_db_path, e)
            return None

    def _lookup_maxmind(self, ip: str) -> GeoIPResult:
        import geoip2.errors

        try:
            response = self._maxmind_reader.city(ip)
        except geoip2.errors.AddressNotFoundError:
            return GeoIPResult(ip=ip, resolved=False, error="address not found in database")
        except Exception as e:
            logger.debug("MaxMind lookup failed for %s: %s", ip, e)
            return GeoIPResult(ip=ip, resolved=False, error=str(e))

        return GeoIPResult(
            ip=ip,
            resolved=True,
            country=response.country.name,
            country_code=response.country.iso_code,
            city=response.city.name,
            latitude=response.location.latitude,
            longitude=response.location.longitude,
            # GeoLite2-City doesn't carry ASN/org — that's a separate
            # GeoLite2-ASN database. Left as None here; if you later
            # add that .mmdb too, wire a second reader and populate
            # these fields the same way.
            asn=None,
            org=None,
        )

    # ------------------------------------------------------------
    # Internal — api backend (ip-api.com free tier)
    # ------------------------------------------------------------

    def _lookup_api(self, ip: str) -> GeoIPResult:
        try:
            response = self._requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,city,lat,lon,as,isp"},
                timeout=3,
            )
            data = response.json()
        except Exception as e:
            logger.debug("GeoIP API lookup failed for %s: %s", ip, e)
            return GeoIPResult(ip=ip, resolved=False, error=str(e))

        if data.get("status") != "success":
            return GeoIPResult(ip=ip, resolved=False, error=data.get("message", "lookup failed"))

        asn_field = data.get("as")  # e.g. "AS15169 Google LLC"
        asn_number = None
        if asn_field and asn_field.startswith("AS"):
            try:
                asn_number = int(asn_field.split()[0][2:])
            except (ValueError, IndexError):
                asn_number = None

        return GeoIPResult(
            ip=ip,
            resolved=True,
            country=data.get("country"),
            country_code=data.get("countryCode"),
            city=data.get("city"),
            latitude=data.get("lat"),
            longitude=data.get("lon"),
            asn=asn_number,
            org=data.get("isp"),
        )

    # ------------------------------------------------------------
    # Internal — cache management
    # ------------------------------------------------------------

    def _store_in_cache(self, ip: str, result: GeoIPResult) -> None:
        with self._lock:
            self._cache[ip] = result
            self._cache.move_to_end(ip)
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)  # evict least-recently-used