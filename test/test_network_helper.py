import pytest
from assemblyline_service_utilities.common.network_helper import convert_url_to_https


@pytest.mark.parametrize("method, url, expected_url", [
    # A case that doesn't go anywhere due to scheme
    ("get", "ftp://blah.com/blah.exe", "ftp://blah.com/blah.exe"),
    # A case that doesn't go anywhere due to method
    ("get", "http://blah.com/blah.exe", "http://blah.com/blah.exe"),
    # A case that doesn't go anywhere due to lack of port
    ("connect", "http://blah.com/blah.exe", "http://blah.com/blah.exe"),
    # A case that doesn't go anywhere due to lack of port, with weird casing
    ("CoNnEcT", "hTtP://blah.com/blah.exe", "hTtP://blah.com/blah.exe"),
    # A case that goes places! Port in netloc
    ("connect", "http://blah.com:443", "https://blah.com"),
    # A case that goes places! Port in path
    ("connect", "http://blah.com/blah.exe:443", "https://blah.com/blah.exe"),
    # A case that goes places! With weird casing
    ("CoNnEcT", "hTtP://blah.com:443", "https://blah.com"),
])
def test_convert_url_to_https(method, url, expected_url):
    assert convert_url_to_https(method, url) == expected_url
