from io import BytesIO

from assemblyline_service_utilities.common.icap import IcapClient

import pytest

# It is allowed to simply not include any headers.
# though the body may LOOK like a header
no_header_body = b'\r\n'.join([
    b'ICAP/1.0 100 Continue',
    b'',
    b'Not-Header: Value',
])


def test_no_header():
    code, status, headers = IcapClient.parse_headers(no_header_body)
    assert code == 100
    assert status == b'Continue'
    assert len(headers) == 0


# Headers may contain separator characters in the value
single_header_body = b'\r\n'.join([
    b'ICAP/1.0 130 Not sure really',
    b'X-A-Header: A message:\tMore-Message',
    b'',
    b'Not-Header: Value',
])


def test_single_header():
    code, status, headers = IcapClient.parse_headers(single_header_body)
    assert code == 130
    assert status == b'Not sure really'
    assert headers == {
        'X-A-HEADER': 'A message:\tMore-Message'
    }


# You can have multiple headers.
# header names are case insensitive
multiple_header_body = b'\r\n'.join([
    b'ICAP/1.0 200 Ok',
    b'DaTe:     whenever really',
    b'X-A-Header: A message\t(@More-Message)',
    b'',
    b'Not-Header: Value',
])


def test_multiple_headers():
    code, status, headers = IcapClient.parse_headers(multiple_header_body)
    assert code == 200
    assert status == b'Ok'
    assert headers == {
        'X-A-HEADER': 'A message\t(@More-Message)',
        'DATE': 'whenever really',
    }


# Header values may be multi line by putting a space or tab on the continuation line
# it is valid to interpret the newline and space/tab in the continuation as a space.
# A number of special characters are also allowed with the text in a header
multiple_line_header_body = b'\r\n'.join([
    b'ICAP/1.0 200 Ok',
    b'DaTe:     whenever really',
    b'X-A-Header:',
    b' - A',
    b' : B',
    b' > C',
    b'\t= 123',
    b'X-B-Header: ()<>@,;:\\\"/[]?={} \t',
    b'',
    b'Not-Header: Value',
])


def test_header_multiple_lines():
    code, status, headers = IcapClient.parse_headers(multiple_line_header_body)
    assert code == 200
    assert status == b'Ok'
    assert headers == {
        'X-A-HEADER': ' - A : B > C = 123',
        'X-B-HEADER': '()<>@,;:\\\"/[]?={} \t',
        'DATE': 'whenever really'
    }


def test_single_chunk_encoding():
    data = b'1234567890' * 100

    # Encode 1kb as a single chunk with chunk size 2k
    encoder = IcapClient.chunk_encode(BytesIO(data), 1 << 11)
    packet = next(encoder)
    with pytest.raises(StopIteration):
        next(encoder)
    assert len(data) <= len(packet) <= len(data) + 100

    # Decode that chunk into a block
    output = []
    for chunk in IcapClient.chunk_decode(BytesIO(packet)):
        output.append(chunk)
    assert b''.join(output) == data


def test_multiple_chunk_encoding():
    data = b'1234567890' * 100001

    # Encode a buffer into multiple chunks
    encoded = []
    for chunk in IcapClient.chunk_encode(BytesIO(data), 1 << 11):
        encoded.append(chunk)
    assert len(encoded) > 1

    # Decode that chunk into a block
    output = []
    for chunk in IcapClient.chunk_decode(BytesIO(b''.join(encoded))):
        output.append(chunk)
    assert b''.join(output) == data
