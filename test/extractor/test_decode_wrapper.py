"""Tests for Multidecoder wrapper."""

import pytest
from multidecoder.decoders import filename

from assemblyline_service_utilities.common.extractor import decode_wrapper as dw


@pytest.mark.parametrize(
    ("multidecoder_type", "assemblyline_type"),
    [
        (filename.EXECUTABLE_TYPE, "file.name.extracted"),
        (filename.LIBRARY_TYPE, "file.name.extracted"),
    ],
)
def test_map_tag_type(multidecoder_type: str, assemblyline_type: str) -> None:
    dw.map_tag_type(multidecoder_type) == assemblyline_type
