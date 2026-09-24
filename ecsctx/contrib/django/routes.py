"""The URL path a log line carries, with the route parameters that are
credentials masked. Shared by ``api_logging`` and ``LoggingContextMiddleware``,
the two places that log ``url.path``.
"""

from ecsctx.masking import key_field_type, mask_by_field_type


def loggable_path(request):
    """The path, with each route parameter whose name the engine classifies
    masked as that type: ``/v1/cards/<str:token>/`` carries a card token as a
    segment, and ``url.path`` shipped it whole.
    """
    path = request.path
    if (match := request.resolver_match) is None:
        return path
    for name, value in match.kwargs.items():
        # An empty value would match everywhere.
        if (text := str(value)) and (field_type := key_field_type(name)):
            path = _mask_in_path(path, text, mask_by_field_type(text, field_type))
    return path


def _mask_in_path(path, text, mask):
    """``path`` with each segment that is ``text`` masked. Replacing ``text``
    anywhere in the path also hit segments that merely contain it: ``1234``
    beside a token of ``23`` lost its middle, and a token that starts with an
    api key's value kept its tail in clear once the key was masked.
    """
    segments = path.split("/")
    if text in segments:
        return "/".join(mask if segment == text else segment for segment in segments)
    # A value that shares its segment (a regex route's `(?P<token>[^/.]+)\.pdf`)
    # or spans several (`<path:token>`) is masked wherever it appears: a
    # mangled neighbour beats a credential in clear.
    return path.replace(text, mask)
