"""Interface to help services use Multidecoder."""

from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from typing import TYPE_CHECKING

import magic
from multidecoder.multidecoder import Multidecoder

if TYPE_CHECKING:
    from multidecoder.node import Node

EXTRACT_FILETYPES = ["application", "document", "exec", "image", "Microsoft", "text"]

STATIC_TAG_MAP = {
    "network.domain": "network.static.domain",
    "network.ip": "network.static.ip",
    "windows.unc.path": "network.static.unc_path",
    "network.url": "network.static.uri",
}

DYNAMIC_TAG_MAP = {
    "network.domain": "network.dynamic.domain",
    "network.ip": "network.dynamic.ip",
    "windows.unc.path": "network.dynamic.unc_path",
    "network.url": "network.dynamic.uri",
}

TAG_MAP = {
    "network.email": "network.email.address",
    "powershell.cmdlet": "file.powershell.cmdlet",
}

BLACKLIST = {
    "archive",
    "av.name",
    "cryptography",
    "debugger.device.name",
    "enable_content",
    "environment.windows",
    "event",
    "guid",
    "network.protocol",
    "network.string",
    "oid",
    "privilege",
    "ransomware.string",
    "sandbox.id",
    "security_identifier",
    "vba.name",
    "windows.registry",
}


def map_tag_type(tag_type: str, *, dynamic: object = False) -> str | None:
    """Convert Multidecoder node types to Assemblyline tag types."""
    if tag_type in TAG_MAP:
        return TAG_MAP[tag_type]
    if tag_type in STATIC_TAG_MAP:
        return DYNAMIC_TAG_MAP[tag_type] if dynamic else STATIC_TAG_MAP[tag_type]
    if tag_type in BLACKLIST:
        return "file.string.blacklisted"
    if tag_type.startswith("api"):
        return "file.string.api"
    if tag_type.startswith("filename"):
        return "file.name.extracted"
    return None


def get_tree_tags(tree: Node, *, dynamic: object = False) -> dict[str, set[bytes]]:
    """Get Assemblyline tags from Multidecoder tree."""
    tags: dict[str, set[bytes]] = defaultdict(set)
    for node in tree:
        if tag_type := map_tag_type(node.type, dynamic=dynamic):
            tags[tag_type].add(node.value)
    return tags


class DecoderWrapper:
    """Wrapper for Multidecoder() object with helper methods for common tasks."""

    def __init__(self, working_directory: str) -> None:
        self.multidecoder = Multidecoder()
        self.working_directory = working_directory
        self.extracted_files: set[str] = set()

    def ioc_tags(self, data: bytes, *, dynamic: object = False) -> dict[str, set[bytes]]:
        """Extract tags from data using multidecoder.

        Network tags are tagged as network.dynamic if dynamic is truthy,
        otherwise they are tagged network.static.
        """
        tree = self.multidecoder.scan(data)
        return get_tree_tags(tree, dynamic=dynamic)

    def extract_files(self, tree: Node, min_size: int) -> set[str]:
        """Extract node values with a good filetype if the size is at least min_size."""
        files: set[str] = set()
        for node in tree:
            if len(node.value) < min_size:
                continue
            if node.type == "pe_file":
                ext = ".exe"
            elif node.obfuscation.startswith("decoded.base64"):
                ext = "_b64"  # technically .b64 is for still encoded files
            elif node.obfuscation.startswith("decoded.hexadecimal"):
                ext = "_hex"
            else:
                continue
            file_hash = hashlib.sha256(node.value).hexdigest()
            file_name = file_hash[:8] + ext
            file_path = os.path.join(self.working_directory, file_name)
            if file_path not in self.extracted_files:
                magic_type = magic.Magic().from_buffer(node.value)
                mime_type = magic.Magic(mime=True).from_buffer(node.value)
                if any(
                    (file_type in mime_type and "octet-stream" not in mime_type) or file_type in magic_type
                    for file_type in EXTRACT_FILETYPES
                ):
                    with open(file_path, "wb") as f:
                        f.write(node.value)
                    self.extracted_files.add(file_path)
            files.add(file_path)
        return files
