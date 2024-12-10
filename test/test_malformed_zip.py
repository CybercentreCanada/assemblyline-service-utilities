"""Malformed Zip Tests"""

from __future__ import annotations

import io

from assemblyline_service_utilities.common.malformed_zip import zip_span

def test_zip_span():
    assert zip_span(
        io.BytesIO(b"prepended contentPK\5\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0b\0ZIP Commentappended content")
    ) == (17, 50)
    
