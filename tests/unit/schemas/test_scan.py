"""Tests for scan schemas."""
import pytest
from xscan.schemas.scan import Target, Scan, ScanProfile, ScanStatus


class TestTarget:
    def test_from_url_with_scheme(self):
        t = Target.from_url("https://example.com/app")
        assert t.host == "example.com"
        assert t.scheme == "https"
        assert t.url == "https://example.com/app"

    def test_from_url_adds_https(self):
        t = Target.from_url("example.com")
        assert t.url.startswith("https://")
        assert t.host == "example.com"

    def test_from_url_strips_trailing_slash(self):
        t = Target.from_url("https://example.com/")
        assert not t.url.endswith("/")

    def test_from_url_http_scheme(self):
        t = Target.from_url("http://internal.corp")
        assert t.scheme == "http"

    def test_from_url_with_port(self):
        t = Target.from_url("https://example.com:8443")
        assert t.port == 8443


class TestScan:
    def test_default_status_is_pending(self):
        scan = Scan(
            target=Target.from_url("https://example.com"),
            profile=ScanProfile.BALANCED,
        )
        assert scan.status == ScanStatus.PENDING

    def test_id_is_generated(self):
        scan = Scan(target=Target.from_url("https://example.com"))
        assert len(scan.id) == 8
        assert scan.id.isupper()

    def test_two_scans_have_different_ids(self):
        a = Scan(target=Target.from_url("https://a.com"))
        b = Scan(target=Target.from_url("https://b.com"))
        assert a.id != b.id
