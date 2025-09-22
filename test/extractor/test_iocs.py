import pytest

import assemblyline_service_utilities.common.extractor.iocs as iocs


@pytest.mark.parametrize(
    ("data", "tags"),
    [
        (b"example.com", {"network.static.domain": {"example.com"}}),
        (
            b"username@example.com",
            {
                "network.email.address": {"username@example.com"},
                "network.static.domain": {"example.com"},
            },
        ),
        (
            b"https://example.com",
            {
                "network.static.domain": {"example.com"},
                "network.static.uri": {"https://example.com"},
            },
        ),
        (b"127.0.0.1", {"network.static.ip": {"127.0.0.1"}}),
    ],
)
def test_find_ioc_tags_jn(data: bytes, tags: dict[str, set[str]]):
    assert iocs.find_ioc_tags(data, network_only=True) == tags

