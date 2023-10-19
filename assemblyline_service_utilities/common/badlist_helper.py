from re import search
from typing import Dict, List
from urllib.parse import urlparse

from assemblyline.odm.base import DOMAIN_REGEX, IP_REGEX, URI_REGEX


def is_tag_badlisted(
        value: str, tags: List[str],
        badlist: Dict[str, List[str]],
        substring: bool = False) -> bool:
    """
    This method determines if a given value has any badlisted components.
    :param value: The value to be checked if it has been badlisted
    :param tags: The tags which will be used for grabbing specific values from the badlist
    :param badlist: The badlist, product of a service using self.get_api_interface().get_badlist().
    :param substring: A flag that indicates if we should check if the value is contained within the match
    :return: A boolean indicating if the value has been badlisted
    """
    if not value or not tags or not badlist:
        return False

    for tag in tags:
        if tag in badlist:
            for badlist_match in badlist[tag]:
                if value.lower() == badlist_match.lower():
                    return True
                elif substring and badlist_match.lower() in value.lower():
                    return True

    return False


def contains_badlisted_value(val: str, badlist: Dict[str, List[str]]) -> bool:
    """
    This method checks if a given value is part of a badlist
    :param val: The given value
    :param badlist: A dictionary containing matches and regexes for use in badlisting values
    :return: A boolean representing if the given value is part of a badlist
    """
    if not val or not isinstance(val, str):
        return False
    ip = search(IP_REGEX, val)
    url = search(URI_REGEX, val)
    domain = search(DOMAIN_REGEX, val)
    if ip is not None:
        ip = ip.group()
        return is_tag_badlisted(ip, ["network.dynamic.ip"], badlist)
    elif domain is not None:
        domain = domain.group()
        return is_tag_badlisted(domain, ["network.dynamic.domain"], badlist)
    elif url is not None:
        url_pieces = urlparse(url.group())
        domain = url_pieces.netloc
        return is_tag_badlisted(domain, ["network.dynamic.domain"], badlist)
    return False
