import re

import pytest

from assemblyline_service_utilities.common.balbuzard.patterns import PatternMatch


@pytest.mark.parametrize('url', [
    b'https://www.google.com.account.login:.@example.com',
    b'https://@example.com',
    b'https://:@example.com'
])
def test_PAT_URL_basic_auth(url):
    assert re.match(PatternMatch.PAT_URL, url).span() == (0, len(url))
