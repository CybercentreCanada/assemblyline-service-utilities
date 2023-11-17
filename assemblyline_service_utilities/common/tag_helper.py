from re import match, search
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import quote_plus, urlparse, urlunparse

from assemblyline_service_utilities.common.safelist_helper import is_tag_safelisted
from assemblyline_v4_service.common.result import ResultSection

from assemblyline.common.net import is_valid_domain, is_valid_ip
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.base import DOMAIN_ONLY_REGEX, DOMAIN_REGEX, FULL_URI, IP_REGEX, URI_PATH


def add_tag(
    result_section: ResultSection,
    tag: str,
    value: Union[Any, List[Any]],
    safelist: Dict[str, Dict[str, List[str]]] = None,
) -> bool:
    """
    This method adds the value(s) as a tag to the ResultSection. Can take a list of values or a single value.
    :param result_section: The ResultSection that the tag will be added to
    :param tag: The tag type that the value will be tagged under
    :param value: The value, a single item or a list, that will be tagged under the tag type
    :param safelist: The safelist containing matches and regexs. The product of a
                     service using self.get_api_interface().get_safelist().
    :return: Tag was successfully added
    """
    if safelist is None:
        safelist = {}

    tags_were_added = False
    if not value:
        return tags_were_added

    if isinstance(value, list):
        for item in value:
            # If one tag is added, then return True
            tags_were_added, _ = _validate_tag(result_section, tag, item, safelist) or tags_were_added
    else:
        tags_were_added, _ = _validate_tag(result_section, tag, value, safelist)
    return tags_were_added


def _get_regex_for_tag(tag: str) -> str:
    """
    This method returns a regular expression used for validating a certain tag type
    :param tag: The type of tag
    :return: The relevant regular expression
    """
    reg_to_match: Optional[str] = None
    if tag.endswith(".domain"):
        reg_to_match = DOMAIN_ONLY_REGEX
    elif tag.endswith(".uri_path"):
        reg_to_match = URI_PATH
    elif tag.endswith(".uri"):
        reg_to_match = FULL_URI
    elif tag.endswith(".ip"):
        reg_to_match = IP_REGEX
    return reg_to_match


def _validate_tag(
    result_section: ResultSection, tag: str, value: Any, safelist: Dict[str, Dict[str, List[str]]] = None
) -> Tuple[bool, bool]:
    """
    This method validates the value relative to the tag type before adding the value as a tag to the ResultSection.
    :param result_section: The ResultSection that the tag will be added to
    :param tag: The tag type that the value will be tagged under
    :param value: The item that will be tagged under the tag type
    :param safelist: The safelist containing matches and regexs. The product of a
                     service using self.get_api_interface().get_safelist().
    :return: A tuple of boolean indicating if tag was successfully added,
        and boolean indicating if value is safelisted
    """
    if safelist is None:
        safelist = {}

    if not value:
        return False, False

    if tag.startswith("network.static."):
        network_tag_type = "static"
    else:
        network_tag_type = "dynamic"

    regex = _get_regex_for_tag(tag)

    # We frequently see URIs that don't follow standards, but we still want to grab all the
    # information we can from this
    if regex and not match(regex, value) and not tag.endswith(".uri"):
        return (False, False)

    if tag.endswith(".ip") and not is_valid_ip(value):
        return (False, False)

    if tag.endswith(".domain") and not is_valid_domain(value):
        return (False, False)

    if is_tag_safelisted(value, [tag], safelist):
        return (False, True)

    # if "uri" is in the tag, let's try to extract its domain/ip and tag it.
    if tag.endswith(".uri"):
        # First try to get the domain
        valid_domain = False
        domain = search(DOMAIN_REGEX, value)
        tag_is_safelisted = False
        if domain:
            domain = domain.group()
            valid_domain, tag_is_safelisted = _validate_tag(
                result_section, f"network.{network_tag_type}.domain", domain, safelist
            )
        # Then try to get the IP
        valid_ip = False
        ip = search(IP_REGEX, value)
        if ip:
            ip = ip.group()
            valid_ip, tag_is_safelisted = _validate_tag(result_section, f"network.{network_tag_type}.ip", ip, safelist)

        # So we have unique value that has a valid domain / ip
        if (value not in [domain, ip] and (valid_domain or valid_ip)) or tag_is_safelisted:
            return _tag_uri(value, result_section, network_tag_type, safelist)
        elif value in [domain, ip]:
            return (True, False)
        else:
            # Might as well tag this while we're here
            result_section.add_tag("file.string.extracted", safe_str(value))
    else:
        result_section.add_tag(tag, safe_str(value))

    return (True, False)


def _tag_uri(
    url: str,
    result_section: ResultSection,
    network_tag_type: str = "dynamic",
    safelist: Dict[str, Dict[str, List[str]]] = None,
) -> Tuple[bool, bool]:
    """
    This method tags components of a URI
    :param url: The url to be analyzed
    :param result_section: The ResultSection that the tag will be added to
    :param safelist: The safelist containing matches and regexs. The product of a
                     service using self.get_api_interface().get_safelist().
    :return: A tuple of boolean indicating if tag was successfully added,
        and boolean indicating if value is safelisted
    """
    # Extract URI
    uri_match = match(FULL_URI, url)

    # Let's try to UrlEncode it, sometimes the queries are not UrlEncoded by default
    if not uri_match:
        parsed_url = urlparse(url)
        url_encoded = urlunparse(
            [
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                quote_plus(parsed_url.query),
                parsed_url.fragment,
            ]
        )
        uri_match = match(FULL_URI, url_encoded)

        if uri_match:
            url = url_encoded

    if uri_match:
        # url could have changed from quote_plus, so we should check the safelist again
        if is_tag_safelisted(url, ["network.dynamic.uri", "network.static.uri"], safelist):
            return (False, True)
        result_section.add_tag(f"network.{network_tag_type}.uri", url)
        # Extract URI path
        if "//" in url:
            url = url.split("//")[1]
        uri_path_match = search(URI_PATH, url)
        if uri_path_match:
            uri_path = uri_path_match.group(0)
            result_section.add_tag(f"network.{network_tag_type}.uri_path", uri_path)

        return (True, False)

    return (False, False)
