from urllib.parse import urlparse, urlunparse


def convert_url_to_https(method: str, url: str) -> str:
    """
    This method should be called when a proxy is used in a sandbox's architecture.
    The resulting URIs seen in the sandbox could take the form of http://blah.com:443
    due to TLS decryption + forwarding, so we want to convert these URIs to the
    original format when tagging them / reporting them in a service.
    """
    parsed_url = urlparse(url)

    # We can only do this if the scheme is http
    if parsed_url.scheme.lower() != "http":
        return url

    # We can only do this if the method is connect
    if method.lower() != "connect":
        return url

    # We can only do this if the port is 443
    if ":443" not in url:
        return url

    # Wow, we actually have a case that fits? Let's do this!
    parsed_netloc = parsed_url.netloc

    # Handle the :443 in the netloc, if applicable
    if parsed_netloc.endswith(":443"):
        parsed_netloc, _, _ = parsed_netloc.partition(":443")

    parsed_path = parsed_url.path

    # Handle the :443 in the path, if applicable
    if parsed_path.endswith(":443"):
        parsed_path, _, _ = parsed_path.partition(":443")

    https_url = urlunparse(
        ("https", parsed_netloc, parsed_path, parsed_url.params, parsed_url.query, parsed_url.fragment)
    )
    return https_url
