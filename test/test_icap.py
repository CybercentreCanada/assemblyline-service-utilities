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


eset_headers = b'ICAP/1.0 200 OK\r\nISTag: "tag-tag"\r\nEncapsulated: res-hdr=0, res-body=70\r\nX-Infection-Found: Type=0; Resolution=0; Threat=Bad/Guy.A;\r\nX-Virus-ID: Virus\r\nX-Response-Info: Blocked\r\n\r\nHTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n0\r\n\r\n\r\n'


def test_eset_headers():
    code, status, headers = IcapClient.parse_headers(eset_headers)
    assert code == 200
    assert status == b'OK'
    assert headers == {
        'ENCAPSULATED': 'res-hdr=0, res-body=70',
        'ISTAG': '"tag-tag"',
        'X-INFECTION-FOUND': 'Type=0; Resolution=0; Threat=Bad/Guy.A;',
        'X-RESPONSE-INFO': 'Blocked',
        'X-VIRUS-ID': 'Virus',
    }


bitdefender_headers = b'ICAP/1.0 200 OK\r\nService: Bitdefender ICAP Server 1.5\r\nService-ID: BDIS\r\nISTag: "tag"\r\nX-Infection-Found: Type=0; Resolution=2; Threat=Bad.Guy.1;\r\nX-Virus-ID: Bad.Guy.1\r\nX-Violations-Found: 1\r\n\tthisisasha256thisisasha256thisisasha256thisisasha256thisisasha25\r\n\tBad.Guy.1\r\n\t0\r\n\t0\r\nConnection: keep-alive\r\nEncapsulated: res-hdr=0, res-body=70\r\n\r\nHTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n5f\r\n<html><body>The file download has been blocked due to a detected virus infection.</body></html>\r\n0\r\n\r\n'


def test_bitdefender_headers():
    code, status, headers = IcapClient.parse_headers(bitdefender_headers)
    assert code == 200
    assert status == b'OK'
    assert headers == {
        'CONNECTION': 'keep-alive',
        'ENCAPSULATED': 'res-hdr=0, res-body=70',
        'ISTAG': '"tag"',
        'SERVICE': 'Bitdefender ICAP Server 1.5',
        'SERVICE-ID': 'BDIS',
        'X-INFECTION-FOUND': 'Type=0; Resolution=2; Threat=Bad.Guy.1;',
        'X-VIOLATIONS-FOUND': '1 '
                              'thisisasha256thisisasha256thisisasha256thisisasha256thisisasha25 '
                              'Bad.Guy.1 '
                              '0 '
                              '0',
        'X-VIRUS-ID': 'Bad.Guy.1',
    }


withsecure_headers = b'ICAP/1.0 200 OK\r\nServer: F-Secure ICAP Server\r\nISTag: "FSAV-1970-01-01_01"\r\nConnection: keep-alive\r\nExpires: Sun, 1 Dec 1970 00:00:00 GMT\r\nX-FSecure-Scan-Result: infected\r\nX-FSecure-Infection-Name: "Bad.GUY/Named.blah"\r\nX-FSecure-ORSP-FRS-Duration: 0.000000\r\nX-FSecure-FSAV-Duration: 0.026597\r\nX-FSecure-Transaction-Duration: 0.042538\r\nX-FSecure-All-Scan-Results: %5B%7B%22type%22%3A%22infected%22%2C%22result%22%3A%22Bad.GUY%2FNamed.blah%22%2C%22engine%22%3A%22aquarius%22%2C%22filename%22%3A%22%22%2C%22details%22%3A%7B%22Type%22%3A0%2C%22Danger%22%3A0%2C%22Behaviour%22%3A0%2C%22FSEType%22%3A0%7D%7D%5D\r\nX-FSecure-Versions: F-Secure Corporation Aquarius/1.0.000/1970-01-01_01 F-Secure Corporation Hydra/1.0.000/1970-01-01_01 F-Secure Corporation FMLib/1.0.000.00  (shahash)/1970-01-01_01  fsicapd/1.0.000\r\nX-Definition-Info: 1970-01-01_01\r\nEncapsulated: res-hdr=0, res-body=73\r\n\r\nHTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: 1781\r\n\r\n6f5\r\n<html>\n  <head>\n    <style type="text/css">\n      html body {\n      background: #e5e5e5;\n      margin: 0;\n      font-family: Arial, Helvetica, sans-serif;\n      font-weight: normal;\n      font-size: 0.75em\n      line-height: 1em\n      margin: 0 0 0.67em 0\n      color: #000000\n      }\n\n      h1 {\n      font-family: Arial, Helvetica, sans-serif;\n      font-weight: bold;\n      font-size: 3.13em\n      line-height: 0.96em\n      margin: 0.15em 0 0.56em 0;\n      color: #ea2839\n      }\n\n      h3 {\n      font-family: Arial, Helvetica, sans-serif;\n      font-weight: normal;\n      font-size: 1.06em\n      line-height: 1.18em;\n      margin: 1.3em 0 0.6em 0;\n      color: #000000\n      }\n\n      #heading {\n      padding: 0.5em;\n      padding-left: 3em;\n      }\n\n      #message {\n      padding-left: 1em;\n      background: #f2f2f2;\n      border-top: 1px #b3b3b3 solid;\n      border-bottom: 1px #b3b3b3 solid;\n      }\n\n      #result {\n      font-family: Arial, Helvetica, sans-serif;\n      font-weight: bold;\n      font-size: 1.06em\n      line-height: 1.18em;\n      margin-left: 2em;\n      color: #000000\n      }\n\n      #footer {\n      color: #999999;\n      margin: 0.5em;\n      font-size: 12px;\n      }\n    </style>\n    <title>403 Forbidden - WithSecure ICAP service</title>\n  </head>\n  <body>\n    <div id="heading">\n      <h1>Malware detected!<h1>\n    </div>\n\n    <div id="message">\n      <p><h3>WithSecure ICAP service has blocked your request.</h3></p>\n\n      <p>The content you were trying to access was detected as the following malware:\n      </p>\n\n      <p>\n      <div id="result">\n\tBad.GUY/Named.blah\n      </div>\n      </p>\n    </div>\n    <div id="footer">\n      Generated by: F-Secure ICAP Server (build 2.0.266, database FSAV-1970-01-01_01)\n    </div>\n  </body>\n</html>\n\r\n0\r\n\r\n'


def test_withsecure_headers():
    code, status, headers = IcapClient.parse_headers(withsecure_headers)
    assert code == 200
    assert status == b'OK'
    assert headers == {
        'CONNECTION': 'keep-alive',
        'ENCAPSULATED': 'res-hdr=0, res-body=73',
        'EXPIRES': 'Sun, 1 Dec 1970 00:00:00 GMT',
        'ISTAG': '"FSAV-1970-01-01_01"',
        'SERVER': 'F-Secure ICAP Server',
        'X-DEFINITION-INFO': '1970-01-01_01',
        'X-FSECURE-ALL-SCAN-RESULTS': '%5B%7B%22type%22%3A%22infected%22%2C%22result%22%3A%22Bad.GUY%2FNamed.blah%22%2C%22engine%22%3A%22aquarius%22%2C%22filename%22%3A%22%22%2C%22details%22%3A%7B%22Type%22%3A0%2C%22Danger%22%3A0%2C%22Behaviour%22%3A0%2C%22FSEType%22%3A0%7D%7D%5D',
        'X-FSECURE-FSAV-DURATION': '0.026597',
        'X-FSECURE-INFECTION-NAME': '"Bad.GUY/Named.blah"',
        'X-FSECURE-ORSP-FRS-DURATION': '0.000000',
        'X-FSECURE-SCAN-RESULT': 'infected',
        'X-FSECURE-TRANSACTION-DURATION': '0.042538',
        'X-FSECURE-VERSIONS': 'F-Secure Corporation Aquarius/1.0.000/1970-01-01_01 '
                              'F-Secure Corporation Hydra/1.0.000/1970-01-01_01 '
                              'F-Secure Corporation FMLib/1.0.000.00  '
                              '(shahash)/1970-01-01_01  fsicapd/1.0.000',
    }


sophos_headers = b'ICAP/1.0 200 OK\r\nISTag: "1-02-3-44-5-6-07-8888-99999999"\r\nService: Sophos Anti-Virus SAVDI/ICAP\r\nDate: Sun, 1 Jan 1970 00:00:00 GMT\r\nX-HRESULT: 12345678\r\nX-Virus-ID: Bad/Guy-A\r\nX-Infection-Found: Type=0; Resolution=2; Threat=Bad/Guy-A;\r\nX-Violations-Found: 1\r\n      -\r\n      Bad/Guy-A\r\n      -\r\n      0\r\nEncapsulated: res-hdr=0, null-body=237\r\n\r\nHTTP/1.1 200 OK:  403 Forbidden\r\nHTTP/1.1 200 OK: \r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\nContent-Type: text/plain\r\nX-Blocked: Virus found during virus scan\r\nX-Blocked-By: Sophos Anti-Virus\r\nVia: Sophos Anti-Virus SAVDI/ICAP\r\n\r\n'


def test_sophos_headers():
    code, status, headers = IcapClient.parse_headers(sophos_headers)
    assert code == 200
    assert status == b'OK'
    assert headers == {
        'DATE': 'Sun, 1 Jan 1970 00:00:00 GMT',
        'ENCAPSULATED': 'res-hdr=0, null-body=237',
        'ISTAG': '"1-02-3-44-5-6-07-8888-99999999"',
        'SERVICE': 'Sophos Anti-Virus SAVDI/ICAP',
        'X-HRESULT': '12345678',
        'X-INFECTION-FOUND': 'Type=0; Resolution=2; Threat=Bad/Guy-A;',
        'X-VIOLATIONS-FOUND': '1      -      Bad/Guy-A      -      0',
        'X-VIRUS-ID': 'Bad/Guy-A',
    }


skyhigh_headers = b'ICAP/1.0 200 OK\r\nISTag: "123456-.1.123-123456-123456"\r\nEncapsulated: res-hdr=0, res-body=121\r\n\r\nHTTP/1.1 403 VirusFound\r\nContent-Type: text/html\r\nCache-Control: no-cache\r\nContent-Length: 396\r\nX-Frame-Options: deny\r\n\r\n18C\r\nX-Virus-ID:Bad-GUY!ABCD1234ABCD\nX-Engine-Version:AM-DAT=1234|AM-Engine=1234.1970.1234|Avira-Engine=1.2.34.567|Avira-Savapi=1.23.4|Avira-VDF=1.23.4.567|MFE-DAT=12345|MFE-Engine=1234.5678|PLATFORM=x64\nX-Avira-Version:Avira-Engine=1.2.34.567|Avira-Savapi=1.23.4|Avira-VDF=1.23.4.567|PLATFORM=x64\nX-MGAM-Version:AM-DAT=1234|AM-Engine=1234.1970.1234|MFE-DAT=12345|MFE-Engine=1234.5678|PLATFORM=x64\r\n0\r\n\r\n'


def test_skyhigh_headers():
    code, status, headers = IcapClient.parse_headers(skyhigh_headers)
    assert code == 200
    assert status == b'OK'
    assert headers == {
        'ENCAPSULATED': 'res-hdr=0, res-body=121',
        'ISTAG': '"123456-.1.123-123456-123456"',
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
