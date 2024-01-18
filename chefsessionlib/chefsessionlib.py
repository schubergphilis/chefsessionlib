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

import rsa
from requests import Request, Session
from rsa import transform

from chefsessionlibexceptions import InvalidPrivateKey, InvalidAuthenticationVersion

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

    def __init__(self,
                 user_id,
                 private_key_contents,
                 client_version='12.0.2',
                 authentication_version='1.0',
                 api_version=1,
                 user_agent=USER_AGENT):
        super().__init__()
        self._user_id = user_id
        self.server_version = client_version
        self.authentication_version = authentication_version
        self.api_version = api_version
        self._private_key = self._validate_private_key(private_key_contents)
        self._update_with_default_headers(user_agent)

    # @classmethod
    # def from_pem_file(cls, username, pem_path):
    #     contents = open(path).read()
    #     # username, key_path = ChefSession._parse_configuration(contents)
    #     return cls(username, contents)
    #
    # @classmethod
    # def from_configuratipon_file(cls, username, path):
    #     contents = open(path).read()
    #     # username, key_path = ChefSession._parse_configuration(contents)
    #     return cls(username, contents)
    #
    # @classmethod
    # def autoconfigure(cls):
    #
    # @staticmethod
    # def _get_configuration_file_path():
    #     # seach for  knife.rb or config.rb depending on os checking all paths
    #
    #
    # @staticmethod
    # def _parse_configuration():
    #     return username, key_path
    #
    # @staticmethod
    # def _get_chef_settings_by_ruby():

    @property
    def authentication_version(self):
        return self._authentication_version

    @authentication_version.setter
    def authentication_version(self, value):
        if value not in VALID_AUTHENTICATION_VERSIONS:
            raise InvalidAuthenticationVersion(f'authentication version {value} is not in supported versions: {", ".join(VALID_AUTHENTICATION_VERSIONS)}!')
        self._authentication_version = value

    def _update_with_default_headers(self, user_agent):
        default_headers = {'X-Chef-Version': self.server_version,
                           'Accept': 'application/json',
                           'Content-Type': 'application/json',
                           'User-Agent': user_agent}
        self.headers.update(default_headers)

    @staticmethod
    def _validate_private_key(contents):
        try:
            key = rsa.PrivateKey.load_pkcs1(contents)
        except Exception:
            raise InvalidPrivateKey(f'Something went wrong with importing PEM file {contents}!')
        return key

    @property
    def user_id(self):
        return self._user_id

    @property
    def canonical_user_id(self):
        if self.authentication_version == '1.1':
            return base64.b64encode(hashlib.sha1(self.user_id.encode(ENCODING)).digest()).decode(ENCODING)
        return self.user_id

    @property
    def hashing_method(self):
        if self.authentication_version == '1.3':
            return 'sha256'
        return 'sha1'

    def _get_hashing_method(self):
        return getattr(hashlib, self.hashing_method)

    def _digest_and_encode(self, data):
        """Create hash, b64 encode the digest, and split every 60 char if data more than that."""
        if not isinstance(data, bytes):
            data = data.encode(ENCODING)
        b64 = base64.b64encode(self._get_hashing_method()(data).digest()).decode(ENCODING)
        return '\n'.join(textwrap.wrap(b64, CHUNK_SIZE))

    @staticmethod
    def get_current_timestamp():
        datetime_format = '%Y-%m-%dT%H:%M:%SZ'
        return datetime.datetime.utcnow().strftime(datetime_format)

    @staticmethod
    def canonical_path(path):
        canonical_path_regex = re.compile(r'/+')
        path = path.split('?')[0]
        path = canonical_path_regex.sub('/', path)
        if len(path) > 1:
            path = path.rstrip('/')
        return path

    def _sign_header(self):
        sign_header = f'version={self.authentication_version}'
        if self.authentication_version == '1.3':
            return sign_header
        return f'algorithm={self.hashing_method};{sign_header}'

    def _get_chef_request(self, method, path, hashed_body, timestamp):
        """Return the canonical request string."""
        headers = {}
        # the following headers dict requires to be an ordered dict (python >= 3.7)
        # as the dict is signed. So the order of the keys cannot be changed.
        # See https://docs.chef.io/server/api_chef_server/#authentication-headers
        if self.authentication_version in ['1.0', '1.1']:
            headers = {'Method': method,
                       'Hashed Path': self._digest_and_encode(self.canonical_path(path)),
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
        return '\n'.join([f'{key}:{value}' for key, value in headers.items()]).encode()

    def _get_signed_headers(self, chef_request):
        signed = ''
        if self.authentication_version in ['1.0', '1.1']:
            padded = rsa.pkcs1._pad_for_signing(chef_request, 256)  # noqa
            payload = transform.bytes2int(padded)
            encrypted = self._private_key.blinded_encrypt(payload)
            signed = transform.int2bytes(encrypted, 256)
        if self.authentication_version == '1.3':
            signed = rsa.sign(chef_request, self._private_key, 'SHA-256')
        signed_b64 = base64.b64encode(signed).decode()
        return {f'X-Ops-Authorization-{index}': segment
                for index, segment in enumerate(textwrap.wrap(signed_b64, CHUNK_SIZE), 1)}

    def _authenticate_request(self, request):
        timestamp = self.get_current_timestamp()
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
        return request

    def request(self, method, url, params=None, data=None, headers=None, cookies=None, files=None, auth=None,
                timeout=None, allow_redirects=True, proxies=None, hooks=None, stream=None, verify=None, cert=None,
                json=None, ):
        req = Request(method=method.upper(), url=url, headers=headers, files=files, data=data or {}, json=json,
                      params=params or {}, auth=auth, cookies=cookies, hooks=hooks)
        prep = self.prepare_request(req)
        proxies = proxies or {}
        settings = self.merge_environment_settings(prep.url, proxies, stream, verify, cert)
        # Send the request.
        send_kwargs = {"timeout": timeout, "allow_redirects": allow_redirects, }
        send_kwargs.update(settings)
        prep = self._authenticate_request(prep)  # we are hijacking and enriching our request here before sending.
        resp = self.send(prep, **send_kwargs)
        return resp
