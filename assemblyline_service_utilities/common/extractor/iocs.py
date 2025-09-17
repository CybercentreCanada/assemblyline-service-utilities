"""IOC search."""

from assemblyline_service_utilities.common.extractor.decode_wrapper import get_tree_tags

from multidecoder.multidecoder import Multidecoder
from multidecoder.registry import build_registry, get_analyzers


def find_ioc_tags(data: bytes, network_only: object = False, dynamic: object = False) -> dict[str, set[str]]:
    """Find IOCs in data.

    Searches for Indicators Of Compromise (IOCs) that are present in
    plaintext in the data. If network_only is True then only network IOCs
    are returned. If dynamic is true network iocs' tag type uses dynamic
    instead of static (i.e. "network.dynamic.domain" instead of
    "network.static.domain").

    IOCs are returned in tag structure format: a dictionary where the keys
    are tag types and the values are sets of tags of that type.
    """
    if network_only:
        registry = get_analyzers(include={"codec", "network"})
    else:
        registry = build_registry(include={"codec", "filename", "network", "path"})
    md = Multidecoder(registry)
    tree = md.scan(data)
    tags = get_tree_tags(tree, dynamic=dynamic)
    return {tag_type: {value.decode() for value in tag_values} for tag_type, tag_values in tags.items()}
