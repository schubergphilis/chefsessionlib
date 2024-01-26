#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: chefsessionlib.py
#
# Copyright 2024 Costas Tyfoxylos, Daan de Goede
#
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

"""
Main code for chefsessionlib.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import base64
import datetime
import hashlib
import logging
import re
import textwrap
from typing import Union, Dict

import requests
import rsa
from requests import Request, Session, PreparedRequest
from rsa import transform

from .chefsessionlibexceptions import (InvalidPrivateKey,
                                       InvalidAuthentication,
                                       InvalidAuthenticationVersion)

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>, Daan de Goede <ddegoede@schubergphilis.com>'
__docformat__ = 'google'
__date__ = '18-01-2024'
__copyright__ = 'Copyright 2024, Costas Tyfoxylos, Daan de Goede'
__credits__ = ["Costas Tyfoxylos, Daan de Goede"]
__license__ = 'Apache Software License 2.0'
__maintainer__ = 'Costas Tyfoxylos, Daan de Goede'
__email__ = '<ctyfoxylos@schubergphilis.com>, <ddegoede@schubergphilis.com>'
__status__ = 'Development'  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''chefsessionlib'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

ENCODING = 'utf_8'
USER_AGENT = 'python/cheflib'
VALID_AUTHENTICATION_VERSIONS = ['1.0', '1.1', '1.3']
CHUNK_SIZE = 60


class ChefSession(Session):
    """Implements a chef server authentication scheme on a requests Session."""

    # pylint: disable=too-many-arguments
    def __init__(self,
                 user_id: str,
                 private_key_contents: str,
                 client_version: str = '12.0.2',
                 authentication_version: str = '1.0',
                 api_version: int = 1,
                 user_agent: str = USER_AGENT):
        super().__init__()
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self._user_id = user_id
        self.server_version = client_version
        self.authentication_version = authentication_version
        self.api_version = api_version
        self._private_key = self._validate_private_key(private_key_contents.encode(ENCODING))
        self._update_with_default_headers(user_agent)

    @property
    def authentication_version(self) -> str:
        """The authentication version to use for the server.

        Returns:
            The authenticated version provided to the constructor. Defaults to '1.0'.

        """
        return self._authentication_version

    @authentication_version.setter
    def authentication_version(self, value: str) -> None:
        """Set the authentication version after validating it from a list of supported ones.

        Args:
            value: The version string.

        Returns:
            None

        """
        if value not in VALID_AUTHENTICATION_VERSIONS:
            raise InvalidAuthenticationVersion(f'Version {value} is not a supported authentication version.'
                                               f'Supported versions: "{VALID_AUTHENTICATION_VERSIONS}"')
        self._authentication_version = value

    def _update_with_default_headers(self, user_agent: str) -> None:
        """Updates the session headers with default headers for all calls.

        Args:
            user_agent: The user agent string.

        Returns:
            None

        """
        default_headers = {'X-Chef-Version': self.server_version,
                           'Accept': 'application/json',
                           'Content-Type': 'application/json',
                           'User-Agent': user_agent}
        self._logger.debug(f'Updating session headers with default headers: "{default_headers}"')
        self.headers.update(default_headers)

    @staticmethod
    def _validate_private_key(contents: bytes) -> rsa.PrivateKey:
        """Validates the contents provided as a valid rsa private key.

        Args:
            contents: The contents of a private key.

        Returns:
            The rsa.PrivateKey object of the valid contents

        Raises:
            InvalidPrivateKey if the contents cannot be loaded as a valid rsa.PrivateKey.

        """
        try:
            key = rsa.PrivateKey.load_pkcs1(contents)
        except Exception:
            raise InvalidPrivateKey('Something went wrong with importing PEM file!') from None
        return key

    @property
    def user_id(self) -> str:
        """The user id provided."""
        return self._user_id

    @property
    def canonical_user_id(self) -> str:
        """The canonical user id.

        Depending on the authentication version a different representation of the provided user id is calculated.
        For authentication version 1.1 the provided user id gets its digest hashed with sha1 and the result is b64
        encoded and then decoded to utf-8.

        Returns:
            A string of the appropriate representation of the user id based on the authentication version used.

        """
        if self.authentication_version == '1.1':
            return base64.b64encode(hashlib.sha1(self.user_id.encode(ENCODING)).digest()).decode(ENCODING)
        return self.user_id

    @property
    def hashing_method(self) -> str:
        """The name of the hashing method to be used according to the requested authentication method.

        Returns:
            The name of the method.

        """
        if self.authentication_version == '1.3':
            return 'sha256'
        return 'sha1'

    @property
    def _hashing_method(self) -> Union[hashlib.sha1, hashlib.sha256]:
        """The hashlib method according to the chosen authentication version.

        It is returned as a property so its usage is a little nicer since this would return a callable of the method
        required which would need to be called first and then passed the arguments.
        Making this a property makes its usage nicer like
            `self._hashing_method(data).digest()`
        instead of
            `self._hashing_method()(data).digest()`
        if this was set a normal method.

        Returns:
            The appropriate hashing method of hashlib according to the authentication version as a callable.

        """
        return getattr(hashlib, self.hashing_method)

    def _digest_and_encode(self, data: str) -> str:
        """Create hash, b64 encode the digest, and split every 60 char if data more than that.

        Args:
            data: The text to encode.

        Returns:
            A list of CHUNK_SIZE items.

        """
        if not isinstance(data, bytes):
            data = data.encode(ENCODING)
        b64 = base64.b64encode(self._hashing_method(data).digest()).decode(ENCODING)
        return '\n'.join(textwrap.wrap(b64, CHUNK_SIZE))

    @staticmethod
    def get_current_timestamp() -> datetime:
        """The current timestamp.

        Returns:
            The current timestamp with the appropriate format.

        """
        datetime_format = '%Y-%m-%dT%H:%M:%SZ'
        return datetime.datetime.utcnow().strftime(datetime_format)

    @staticmethod
    def canonical_path(path: str) -> str:
        """Enforces the rules for the canonical path.

        The rules of the canonical path are:
            The authentication method does not support consecutive slashes so those are replace with a single one
                if present.
            Only the url portion of a path is used for the authentication so the parameters part is discarded
            If the path is more than one character (/ is a valid path to request) then any possible trailing slashes
                are removed.

        Args:
            path: The path requested.

        Returns:
            The canonical path according to the rules.

        """
        canonical_path_regex = re.compile(r'/+')
        path = path.split('?')[0]
        path = canonical_path_regex.sub('/', path)
        if len(path) > 1:
            path = path.rstrip('/')
        return path

    def _sign_header(self) -> str:
        """The appropriate sign header for the authenticated method used.

        Returns:
            The appropriate sign header for the authenticated method used.

        """
        sign_header = f'version={self.authentication_version}'
        if self.authentication_version == '1.3':
            return sign_header
        return f'algorithm={self.hashing_method};{sign_header}'

    def _get_chef_request(self, method: str, path: str, hashed_body: str, timestamp: str) -> bytes:
        r"""Calculates a '\n' concatenated byte string of the appropriate headers based on the authentication version.

        Args:
            method: The HTTP verb of the method to use.
            path: The path on the server requested.
            hashed_body: The hashed body according to the authentication version chosen.
            timestamp: The timestamp of the request in the appropriate format.

        Returns:
            The byte string of the request headers in the appropriate format.

        """
        headers = {}
        # the following headers dict requires to be an ordered dict (python >= 3.7)
        # as the dict is signed. So the order of the keys cannot be changed.
        # See https://docs.chef.io/server/api_chef_server/#authentication-headers
        path = self.canonical_path(path)
        if self.authentication_version in ['1.0', '1.1']:
            headers = {'Method': method,
                       'Hashed Path': self._digest_and_encode(path),
                       'X-Ops-Content-Hash': hashed_body,
                       'X-Ops-Timestamp': timestamp,
                       'X-Ops-UserId': self.canonical_user_id}
        if self.authentication_version == '1.3':
            headers = {'Method': method,
                       'Path': path,
                       'X-Ops-Content-Hash': hashed_body,
                       'X-Ops-Sign': 'version=1.3',
                       'X-Ops-Timestamp': timestamp,
                       'X-Ops-UserId': self.canonical_user_id,
                       'X-Ops-Server-API-Version': '1'}
        self._logger.debug(f'Authentication version is set to {self.authentication_version}, '
                           f'constructed headers: "{headers}"')
        return '\n'.join([f'{key}:{value}' for key, value in headers.items()]).encode()

    def _sign(self, data: bytes) -> bytes:
        signed = b''
        if self.authentication_version in ['1.0', '1.1']:
            padded = rsa.pkcs1._pad_for_signing(data, 256)  # noqa
            payload = transform.bytes2int(padded)
            encrypted = self._private_key.blinded_encrypt(payload)
            signed = transform.int2bytes(encrypted, 256)
        if self.authentication_version == '1.3':
            signed = rsa.sign(data, self._private_key, 'SHA-256')
        return signed

    def _get_signed_headers(self, chef_request: bytes) -> Dict:
        """Signs the constructed headers according to the authentication version used.

        Args:
            chef_request: The canonical request constructed by the request components.

        Returns:
            A dictionary of indexed authorization headers with the parts of the signature.

        """
        signed = self._sign(chef_request)
        signed_b64 = base64.b64encode(signed).decode()
        self._logger.debug(f'Authentication version is set to {self.authentication_version}, '
                           f'\n\tsigned payload calculated: "{signed}"\n\t'
                           f'b64 encoded to: "{signed_b64}"')
        headers = {f'X-Ops-Authorization-{index}': segment
                   for index, segment in enumerate(textwrap.wrap(signed_b64, CHUNK_SIZE), 1)}
        self._logger.debug(f'Constructed authenticated headers: "{headers}"')
        return headers

    def _authenticate_request(self, request: PreparedRequest, timestamp: str) -> PreparedRequest:
        """Intercepted request of the session that gets enriched with the authentication mechanism.

        Args:
            request: The request of the user.
            timestamp: The timestamp of the request in the appropriate format.

        Returns:
            The enriched request with the authentication according to the version set.

        """
        body = self._digest_and_encode(request.body or '')
        chef_request = self._get_chef_request(request.method,
                                              request.path_url,
                                              body,
                                              timestamp)
        signed_headers = self._get_signed_headers(chef_request)
        auth_headers = {
            'X-Ops-Server-API-Version': self.api_version,
            'X-Ops-Sign': self._sign_header(),
            'X-Ops-UserId': self.user_id,
            'X-Ops-Timestamp': timestamp,
            'X-Ops-Content-Hash': body,
        }
        auth_headers.update(signed_headers)
        request.headers.update(auth_headers)
        self._logger.debug(f'Updated request headers with: "{auth_headers}"')
        return request

    #  pylint: disable=too-many-locals
    def request(self, method, url, params=None, data=None, headers=None, cookies=None, files=None, auth=None,
                timeout=None, allow_redirects=True, proxies=None, hooks=None, stream=None, verify=None, cert=None,
                json=None, ) -> requests.Response:
        """Verbatim copy of the request method of requests.Session.

        Hijacks the request, applies the authentication headers and checks the response status code for success.

        Returns:
            The response object if the status code is not 401

        Raises:
            InvalidAuthentication if the status code is set to 401.

        """
        req = Request(method=method.upper(), url=url, headers=headers, files=files, data=data or {}, json=json,
                      params=params or {}, auth=auth, cookies=cookies, hooks=hooks)
        prep = self.prepare_request(req)
        proxies = proxies or {}
        settings = self.merge_environment_settings(prep.url, proxies, stream, verify, cert)
        # Send the request.
        send_kwargs = {"timeout": timeout, "allow_redirects": allow_redirects, }
        send_kwargs.update(settings)
        # we are hijacking and enriching our request here before sending.
        prep = self._authenticate_request(prep, self.get_current_timestamp())
        resp = self.send(prep, **send_kwargs)
        if resp.status_code == 401:
            raise InvalidAuthentication(resp.text)
        return resp
