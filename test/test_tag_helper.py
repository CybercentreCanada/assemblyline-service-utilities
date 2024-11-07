import os

import pytest
from assemblyline_service_utilities.common.tag_helper import _get_regex_for_tag, _validate_tag, add_tag
from assemblyline_v4_service.common.result import ResultSection

from assemblyline.odm.base import DOMAIN_ONLY_REGEX, FULL_URI, IP_REGEX, URI_PATH
from . import setup_module, teardown_module

setup_module()

@pytest.mark.parametrize(
    "value, expected_tags, tags_were_added",
    [
        ("", {}, False),
        ("blah", {"blah": ["blah"]}, True),
        ([], {}, False),
        (["blah"], {"blah": ["blah"]}, True),
        (["blah", "blahblah"], {"blah": ["blah", "blahblah"]}, True)
    ]
)
def test_add_tag(value, expected_tags, tags_were_added):
    res_sec = ResultSection("blah")
    tag = "blah"
    safelist = {"match": {"domain": ["blah.ca"]}}
    assert add_tag(res_sec, tag, value, safelist) == tags_were_added
    assert res_sec.tags == expected_tags


def test_get_regex_for_tag():
    assert _get_regex_for_tag("network.dynamic.domain") == DOMAIN_ONLY_REGEX
    assert _get_regex_for_tag("network.dynamic.ip") == IP_REGEX
    assert _get_regex_for_tag("network.dynamic.uri") == FULL_URI
    assert _get_regex_for_tag("network.dynamic.uri_path") == URI_PATH
    assert _get_regex_for_tag("network.port") is None


@pytest.mark.parametrize(
    "tag, value, expected_tags, added_tag",
    [
        # Empty values
        ("", "", {}, (False, False)),
        ("blah", "", {}, (False, False)),
        # Normal run without regex match
        ("blah", "blah", {"blah": ["blah"]}, (True, False)),
        # Normal run with regex match
        ("network.static.uri_path", "/blah", {"network.static.uri_path": ["/blah"]}, (True, False)),
        # No regex match for ip
        ("network.static.ip", "blah", {}, (False, False)),
        # Regex match for ip
        ("network.static.ip", "1.1.1.1", {"network.static.ip": ["1.1.1.1"]}, (True, False)),
        # No regex match for domain
        ("network.static.domain", "blah", {}, (False, False)),
        # Regex match but not valid domain
        ("network.static.domain", "blah.blah", {}, (False, False)),
        # Regex match, but FP found (the determination of the FP is no longer handled in this method)
        ("network.static.domain", "microsoft.net", {"network.static.domain": ["microsoft.net"]}, (True, False)),
        # Regex match, but FP found (the determination of the FP is no longer handled in this method)
        ("network.static.domain", "blah.py", {"network.static.domain": ["blah.py"]}, (True, False)),
        # Safelisted domain value
        ("network.static.domain", "blah.ca", {}, (False, True)),
        # Valid URI with invalid domain
        ("network.static.uri", "http://blah.blah/blah", {"file.string.extracted": ["http://blah.blah/blah"]}, (True, False)),
        # URI with valid domain
        ("network.dynamic.uri", "http://blah.com/blah", {"network.dynamic.uri": ["http://blah.com/blah"],
         "network.dynamic.domain": ["blah.com"], "network.dynamic.uri_path": ["/blah"]}, (True, False)),
        # URI with valid IP
        ("network.dynamic.uri", "http://1.1.1.1/blah", {"network.dynamic.uri": ["http://1.1.1.1/blah"], "network.dynamic.ip": ["1.1.1.1"], "network.dynamic.uri_path": ["/blah"]}, (True, False)),
        # Invalid URI with no URI regex match
        ("network.static.uri", "C:\\file.js?blah/blah.exe", {"file.string.extracted": ["C:\\file.js?blah/blah.exe"]}, (True, False)),
        # Safelisted domain value in URI
        ("network.static.uri", "http://blah.ca/blah", {"network.static.uri": ["http://blah.ca/blah"], "network.static.uri_path": ["/blah"]}, (True, False)),
        # Domain value tagged as URI
        ("network.static.uri", "www.blah.ca", {"network.static.domain": ["www.blah.ca"]}, (True, False)),
    ]
)
def test_validate_tag(tag, value, expected_tags, added_tag):
    res_sec = ResultSection("blah")
    safelist = {"match": {"network.static.domain": ["blah.ca"]}}
    assert _validate_tag(res_sec, tag, value, safelist) == added_tag
    assert res_sec.tags == expected_tags

teardown_module()
