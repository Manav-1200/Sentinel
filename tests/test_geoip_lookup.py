"""
tests/test_geoip_lookup.py
==============================
Unit tests for detection/geoip_lookup.py (GeoIPLookup).

No real network or MaxMind DB is touched — `requests` and `geoip2`
are mocked. Focus areas: private/reserved IPs never hit a backend at
all, lookups never raise regardless of backend failure, and the LRU
cache behaves correctly (both hit/no-second-call and eviction order).
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from detection.geoip_lookup import GeoIPLookup, GeoIPResult


def make_config(**geoip_overrides):
    geoip = {"method": "api", "cache_size": 3}
    geoip.update(geoip_overrides)
    return {"geoip": geoip}


# ------------------------------------------------------------
# Private / reserved IP short-circuit
# ------------------------------------------------------------

class TestPrivateIpShortCircuit:
    @pytest.mark.parametrize("ip", [
        "192.168.10.67", "10.0.0.5", "172.17.0.2", "127.0.0.1", "169.254.1.1",
    ])
    def test_private_and_reserved_ips_never_hit_a_backend(self, ip):
        lookup = GeoIPLookup(make_config())
        with patch.object(lookup, "_requests") as mock_requests:
            result = lookup.lookup(ip)

        assert result.is_private is True
        assert result.resolved is False
        mock_requests.get.assert_not_called()

    def test_private_ip_display_str_says_local_network(self):
        lookup = GeoIPLookup(make_config())
        result = lookup.lookup("192.168.1.1")
        assert result.display_str() == "local network"


# ------------------------------------------------------------
# API backend
# ------------------------------------------------------------

class TestApiBackend:
    def test_successful_lookup_populates_fields(self):
        lookup = GeoIPLookup(make_config(method="api"))
        fake_response = MagicMock()
        fake_response.json.return_value = {
            "status": "success", "country": "Nepal", "countryCode": "NP",
            "city": "Kathmandu", "lat": 27.7, "lon": 85.3,
            "as": "AS17501 WorldLink", "isp": "WorldLink Communications",
        }
        with patch.object(lookup, "_requests") as mock_requests:
            mock_requests.get.return_value = fake_response
            result = lookup.lookup("203.0.114.5")

        assert result.resolved is True
        assert result.city == "Kathmandu"
        assert result.asn == 17501
        assert result.org == "WorldLink Communications"

    def test_api_failure_returns_unresolved_never_raises(self):
        lookup = GeoIPLookup(make_config(method="api"))
        with patch.object(lookup, "_requests") as mock_requests:
            mock_requests.get.side_effect = RuntimeError("network unreachable")
            result = lookup.lookup("203.0.114.6")

        assert result.resolved is False
        assert result.error is not None

    def test_api_status_failure_message_returns_unresolved(self):
        lookup = GeoIPLookup(make_config(method="api"))
        fake_response = MagicMock()
        fake_response.json.return_value = {"status": "fail", "message": "rate limited"}
        with patch.object(lookup, "_requests") as mock_requests:
            mock_requests.get.return_value = fake_response
            result = lookup.lookup("203.0.114.7")

        assert result.resolved is False
        assert result.error == "rate limited"

    def test_malformed_asn_field_does_not_crash(self):
        lookup = GeoIPLookup(make_config(method="api"))
        fake_response = MagicMock()
        fake_response.json.return_value = {
            "status": "success", "country": "Nepal", "as": "not-an-asn-string",
        }
        with patch.object(lookup, "_requests") as mock_requests:
            mock_requests.get.return_value = fake_response
            result = lookup.lookup("203.0.114.8")

        assert result.resolved is True
        assert result.asn is None

    def test_no_requests_library_available_returns_unresolved(self):
        lookup = GeoIPLookup(make_config(method="api"))
        lookup._requests = None  # simulate 'requests' not installed
        result = lookup.lookup("203.0.114.9")
        assert result.resolved is False
        assert result.error == "no GeoIP backend available"


# ------------------------------------------------------------
# MaxMind backend
# ------------------------------------------------------------

class TestMaxmindBackend:
    def test_maxmind_falls_back_to_api_when_db_cannot_be_opened(self):
        with patch("detection.geoip_lookup.GeoIPLookup._try_open_maxmind_reader", return_value=None):
            lookup = GeoIPLookup(make_config(method="maxmind"))
        assert lookup.method == "api"

    def test_maxmind_successful_lookup_populates_fields(self):
        fake_reader = MagicMock()
        fake_city_response = MagicMock()
        fake_city_response.country.name = "Nepal"
        fake_city_response.country.iso_code = "NP"
        fake_city_response.city.name = "Kathmandu"
        fake_city_response.location.latitude = 27.7
        fake_city_response.location.longitude = 85.3
        fake_reader.city.return_value = fake_city_response

        with patch("detection.geoip_lookup.GeoIPLookup._try_open_maxmind_reader", return_value=fake_reader):
            lookup = GeoIPLookup(make_config(method="maxmind"))

        result = lookup.lookup("203.0.114.10")
        assert result.resolved is True
        assert result.city == "Kathmandu"
        assert result.country == "Nepal"


# ------------------------------------------------------------
# Caching
# ------------------------------------------------------------

class TestCaching:
    def test_second_lookup_of_same_ip_uses_cache_not_a_new_network_call(self):
        lookup = GeoIPLookup(make_config(method="api"))
        fake_response = MagicMock()
        fake_response.json.return_value = {"status": "success", "country": "Nepal"}
        with patch.object(lookup, "_requests") as mock_requests:
            mock_requests.get.return_value = fake_response
            lookup.lookup("203.0.114.20")
            lookup.lookup("203.0.114.20")

        assert mock_requests.get.call_count == 1

    def test_cache_evicts_least_recently_used_entry_beyond_cache_size(self):
        lookup = GeoIPLookup(make_config(method="api", cache_size=2))
        fake_response = MagicMock()
        fake_response.json.return_value = {"status": "success", "country": "Nepal"}
        with patch.object(lookup, "_requests") as mock_requests:
            mock_requests.get.return_value = fake_response
            lookup.lookup("203.0.114.21")
            lookup.lookup("203.0.114.22")
            lookup.lookup("203.0.114.23")  # should evict .21 (least recently used)

        assert "203.0.114.21" not in lookup._cache
        assert "203.0.114.22" in lookup._cache
        assert "203.0.114.23" in lookup._cache


# ------------------------------------------------------------
# Malformed input
# ------------------------------------------------------------

class TestMalformedInput:
    def test_non_ip_string_does_not_crash_lookup(self):
        lookup = GeoIPLookup(make_config(method="api"))
        fake_response = MagicMock()
        fake_response.json.return_value = {"status": "success", "country": "Nepal"}
        with patch.object(lookup, "_requests") as mock_requests:
            mock_requests.get.return_value = fake_response
            result = lookup.lookup("not-an-ip")

        assert isinstance(result, GeoIPResult)