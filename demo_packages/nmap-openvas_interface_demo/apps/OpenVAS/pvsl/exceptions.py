# -*-v coding: utf-8 -*-
"""
pyvas exceptions
~~~~~~~~~~~~~~~~
"""

from __future__ import unicode_literals, print_function


class Error(Exception):
    """PyVAS Base Exception."""


class ResultError(Error):
    """Invalid response from Server."""

    def __str__(self):
        return "Invalid result: response from %s is invalid: %s" % self.args


class AuthenticationError(Error):
    """Authentication Failed"""


class RequestError(Error):
    """There was an ambiguous exception that occured while handling you
    request.
    """

    def __init__(self, *args, **kwargs):
        """Initialize RequestError with `request` and `response` objects."""
        self.response = kwargs.pop("response", None)
        self.request = kwargs.pop("request", None)
        if (self.response is not None and
                not self.request and
                hasattr(self.response, "request")):
            self.request = self.response.request
        super(RequestError, self).__init__(*args, **kwargs)


class HTTPError(RequestError):
    """An HTTP error occured."""


class ElementExists(HTTPError):
    """Attempt to create an element that already exists."""


class ElementNotFound(HTTPError):
    """404: Failed to find an element with given parameters."""


class InvalidArgumentError(HTTPError):
    """Invalid argument provided by client."""


class ServerError(HTTPError):
    """Unexpected error occured on the OpenVAS server."""
