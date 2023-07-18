import os
import socket
from typing import Optional, Generator
import io

from assemblyline.common.str_utils import safe_str

ICAP_OK = b'ICAP/1.0 200 OK'


# noinspection PyBroadException
class IcapClient(object):
    """
    A limited Internet Content Adaptation Protocol client.

    Currently only supports RESPMOD as that is all that is required to interop
    with most ICAP based AV servers.
    """

    RESP_CHUNK_SIZE = 65565
    MAX_RETRY = 3

    def __init__(self, host, port, respmod_service="av/respmod", action="", timeout=30, number_of_retries=MAX_RETRY):
        self.host = host
        self.port = port
        self.service = respmod_service
        self.action = action
        self.socket = None
        self.timeout = timeout
        self.kill = False
        self.number_of_retries = number_of_retries
        self.successful_connection = False

    def scan_data(self, data: io.BufferedIOBase, name: Optional[str] = None) -> Optional[bytes]:
        return self._do_respmod(name or 'filetoscan', data)

    def scan_local_file(self, filepath: str) -> Optional[bytes]:
        filename = os.path.basename(filepath)
        with open(filepath, 'rb') as handle:
            return self.scan_data(handle, filename)

    def options_respmod(self) -> Optional[bytes]:
        request = f"OPTIONS icap://{self.host}:{self.port}/{self.service} ICAP/1.0\r\n\r\n"

        for i in range(self.number_of_retries):
            if self.kill:
                self.kill = False
                return None
            try:
                if not self.socket:
                    self.socket = socket.create_connection((self.host, self.port), timeout=self.timeout)
                    self.successful_connection = True
                self.socket.sendall(request.encode())
                response = temp_resp = self.socket.recv(self.RESP_CHUNK_SIZE)
                while len(temp_resp) == self.RESP_CHUNK_SIZE:
                    temp_resp = self.socket.recv(self.RESP_CHUNK_SIZE)
                    response += temp_resp
                if not response or not response.startswith(ICAP_OK):
                    raise Exception(f"Unexpected OPTIONS response: {response}")
                return response
            except Exception:
                self.successful_connection = False
                try:
                    if self.socket:
                        self.socket.close()
                except Exception:
                    pass
                self.socket = None
                if i == (self.number_of_retries-1):
                    raise

        raise Exception("Icap server refused to respond.")

    @staticmethod
    def chunk_encode(stream: io.BufferedIOBase, chunk_size=8160) -> Generator[bytes, None, None]:
        """Take a stream of data and transform it into HTTP chunked encoding (which ICAP uses)."""
        read = 0
        buffer = bytearray(chunk_size)
        while True:
            read = stream.readinto(buffer)

            out = b''

            if read > 0:
                out = b"%X\r\n" % read
                out += buffer[:read]
                out += b'\r\n'

            if read < chunk_size:
                out += b"0\r\n\r\n"

            yield out

            if read < chunk_size:
                break

    @staticmethod
    def chunk_decode(stream: io.BufferedIOBase) -> Generator[bytes, None, None]:
        """Take an http chunked encoding body and pull out the raw data as chunks come in."""
        while True:
            # Read the head of the chunk and parse the length out
            line = stream.readline().strip()
            length_string, _, _ = line.partition(b';')
            length = int(length_string, 16)
            if length == 0:
                break

            # Read the chunk data and present it
            data = stream.read(length)
            yield data

            # Read the newline that follows the data, should be nothing but a \r\n in this read
            eol = stream.readline().strip()
            assert eol == b'', b'unexpected content: ' + eol

    def _do_respmod(self, filename: str, data: io.BufferedIOBase) -> Optional[bytes]:
        # ICAP RESPMOD req-hdr is the start of the original (in this case fake) HTTP request.
        respmod_req_hdr = "GET /{FILENAME} HTTP/1.1\r\n\r\n".format(FILENAME=safe_str(filename))

        # ICAP RESPMOD res-hdr is the start of the HTTP response for above request.
        respmod_res_hdr = (
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n\r\n")

        res_hdr_offset = len(respmod_req_hdr)
        res_bdy_offset = len(respmod_res_hdr) + res_hdr_offset

        # The ICAP RESPMOD header. Note:
        # res-hdr offset should match the start of the GET request above.
        # res-body offset should match the start of the response above.

        respmod_icap_hdr = (
            f"RESPMOD icap://{self.host}:{self.port}/{self.service}{self.action} ICAP/1.0\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Allow: 204\r\n"
            f"Encapsulated: req-hdr=0, res-hdr={res_hdr_offset}, res-body={res_bdy_offset}\r\n\r\n"
        )

        serialized_head_and_prefix = b"%s%s%s" % (respmod_icap_hdr.encode(), respmod_req_hdr.encode(),
                                                  respmod_res_hdr.encode())

        for i in range(self.number_of_retries):
            if self.kill:
                self.kill = False
                return None
            try:
                # Open a connection to the ICAP server
                if not self.socket:
                    self.socket = socket.create_connection((self.host, self.port), timeout=self.timeout)
                    self.successful_connection = True

                # Send the request head and the head of the encapsulated fake request that contains our file
                self.socket.sendall(serialized_head_and_prefix)

                # Stream the rest of the file to be scanned as the body of the encapsulated request
                for chunk in self.chunk_encode(data):
                    self.socket.sendall(chunk)

                # Wait for the response from the server and pack it into a single buffer
                # The response should be the ICAP headers followed by:
                # - the request rewritten as an error message because it found a virus and
                #   replaced the body with an error
                # - an empty body with a 204 status, because the file is unmodified.
                #   this doesn't mean the file is safe, just that the icap server didn't feel the
                #   need to outright replace it
                # - in principle it could also be the request we sent being echoed back to us
                #   in a modified or unmodified state, but one of the two above should be more common
                response = temp_resp = self.socket.recv(self.RESP_CHUNK_SIZE)
                while len(temp_resp) == self.RESP_CHUNK_SIZE:
                    temp_resp = self.socket.recv(self.RESP_CHUNK_SIZE)
                    response += temp_resp
                return response

            except Exception:
                self.successful_connection = False
                try:
                    if self.socket:
                        self.socket.close()
                except Exception:
                    pass
                self.socket = None
                if i == (self.number_of_retries-1):
                    raise

        raise Exception("Icap server refused to respond.")

    @staticmethod
    def parse_headers(body: bytes) -> tuple[int, bytes, dict[str, str]]:
        """Take an ICAP request body and parse out the status and header sections."""
        def next_line():
            nonlocal body
            line, _, body = body.partition(b'\n')
            return line.strip(b'\r')

        # Handle the status line
        status_line = next_line()
        protocol, _, status_line = status_line.partition(b' ')
        if protocol != b'ICAP/1.0':
            raise ValueError("Unknown protocol: " + protocol.decode())
        status_code_string, _, status_message = status_line.partition(b' ')
        status_code = int(status_code_string)

        # pull out header lines
        pending = next_line()
        headers: dict[str, str] = {}
        while len(pending) > 0:
            # Handle the first line of a header, which must have the name in it
            header_name, _, content = pending.partition(b':')
            content = content.lstrip()

            # Handle when the content is wrapped in quotes
            if content and (
                    content.startswith(b'\"') and content.endswith(b'\"')) or (
                    content.startswith(b"\'") and content.endswith(b"\'")):
                content = content[1:-1]

            pending = next_line()

            # Handle a header extended over multiple lines
            while len(pending) > 0 and pending[0] in (ord(b' '), ord(b'\t')):
                content = content + b' ' + pending[1:].lstrip()
                pending = next_line()

            # The is case insensitive and should be a single token
            headers[header_name.decode().upper().strip()] = content.decode()

        return status_code, status_message, headers

    def close(self):
        self.kill = True
        try:
            if self.socket:
                self.socket.close()
        except Exception:
            pass
