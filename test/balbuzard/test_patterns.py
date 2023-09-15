import re

import pytest

from assemblyline_service_utilities.common.balbuzard.patterns import PatternMatch


@pytest.mark.parametrize("data,ip", [(b"12.2.1.3.0", None)])
def test_PAT_IP(data, ip):
    match = re.search(PatternMatch.PAT_IP, data)
    if ip is None:
        assert match is None
    else:
        assert match.group() == ip


@pytest.mark.parametrize(
    "data,domain",
    [
        (b"config.edge.skype.com0", b"config.edge.skype.com"),
        (b"domain.com-", None),
    ],
)
def test_PAT_DOMAIN(data, domain):
    match = re.search(PatternMatch.PAT_DOMAIN, data)
    if domain is None:
        assert match is None
    else:
        assert match.group() == domain


@pytest.mark.parametrize(
    "url",
    [
        b"https://www.google.com.account.login:.@example.com",
        b"https://@example.com",
        b"https://:@example.com",
        b"https://google.com@micrsoft.com@adobe.com@example.com/path/to?param=value1&_param=value2&trailing_url=https%3A%2F%2Fmalicious.com",
        # Example URIs from https://en.wikipedia.org/wiki/Uniform_Resource_Identifier#Example_URIs
        b"https://john.doe@www.example.com:123/forum/questions/?tag=networking&order=newest#top",
        b"http://[2001:db8::7]/c=GB?objectClass?one",
        b"ftp://192.0.2.16:80/",
        b"http://editing.com/resource/file.php?command=checkout",
    ],
)
def test_PAT_URL_basic_auth(url):
    assert re.match(PatternMatch.PAT_URL, url).span() == (0, len(url))


@pytest.mark.parametrize(
    ("url", "suffix_len"),
    [
        (b"function('https://example.com/')", 2),
        (b"full sentence with a url https://example.com/.", 1),
        (b"part of a phrase with a url https://example.com/,", 1),
        (b"barefunction(https://example.com)", 1),
    ],
)
def test_PAT_URL_in_context(url, suffix_len):
    assert re.search(PatternMatch.PAT_URL, url).end() == len(url) - suffix_len
